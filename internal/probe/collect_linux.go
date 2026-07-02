//go:build linux

package probe

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Collect gathers a host-state snapshot from /proc and key filesystem locations.
// It is best-effort: per-item failures are recorded in CollectorErrors rather
// than aborting the whole scan.
func Collect() (*Snapshot, error) {
	s := &Snapshot{
		Schema:      SchemaSnapshot,
		CollectedAt: time.Now().UTC(),
		Facts:       map[string]any{},
	}
	s.Host = collectHostInfo()
	s.Processes = collectProcesses(os.Getpid(), &s.CollectorErrors)
	s.ListeningSockets = collectListeners()
	s.Accounts = collectAccounts()
	s.Persistence = collectPersistence(s.Accounts)
	s.KernelModules = collectModules()
	s.SuspiciousFiles = collectSuspiciousFiles()
	s.KernelLog = collectKernelLog(&s.CollectorErrors)
	s.PromiscInterfaces = promiscInterfaces(s.KernelLog)
	s.OutOfTreeModules = outOfTreeModules(s.KernelLog)
	s.PAMModules = collectPAM()
	s.PthFiles = collectPythonPth()
	s.ImmutableFiles = collectImmutable()
	kallsymsMods, suspKsyms := collectKallsyms()
	s.HiddenModules = collectHiddenModules(kallsymsMods)
	s.SuspiciousKsyms = suspKsyms
	s.AtJobs = collectAtJobs()
	s.SudoRules = collectSudoers()
	s.NfsExports = collectNfsExports()
	s.WorldWritableSensitive = collectWorldWritableSensitive()
	s.PathHijack = collectPathHijack()
	s.OutboundConns = collectOutboundConns()
	s.PasswordlessAccounts = collectPasswordless()
	s.PrivGroupMembers = collectPrivGroupMembers(s.Accounts)
	s.WebShells = collectWebShells()
	s.BpfPinned = collectBpfPinned()
	s.BpfPrograms = collectBpfPrograms()
	s.PackageHooks = collectPackageHooks()
	s.WebServerModules = collectWebServerModules()
	s.ModprobeCommands = collectModprobeCommands()
	s.LdSoConf = collectLdSoConf()
	s.EnvPreload = collectEnvPreload()
	s.SuidBinaries = collectSuidBinaries()
	s.WritablePersistence = collectWritablePersistence()
	s.DangerousCapabilities = collectDangerousCapabilities()
	s.CronPathHijack = collectCronPathHijack()
	s.NsswitchUnusual = collectNsswitchModules()
	s.ProcMountHides = collectProcMountHides()
	s.SysctlHardeningOff = collectSysctlHardening()
	s.UnverifiedRepos = collectUnverifiedRepos()
	s.SshTunnels = collectSshTunnels(s.Processes)
	s.InitramfsHooks = collectInitramfsHooks()
	s.K8sStaticPods = collectK8sStaticPods()
	s.ExposedKubeconfigs = collectExposedKubeconfig()
	s.ShellHistoryTampering = collectHistoryTampering(s.Accounts)
	s.TamperedLogs = collectTamperedLogs()
	s.SuspiciousShells = collectSuspiciousShells(s.Accounts)
	s.WritableSuid = collectWritableSuid()
	s.XdgAutostart = collectXdgAutostart(s.Accounts)
	s.SshClientCommands = collectSshClientConfig(s.Accounts)
	s.LibVersions = collectLibVersions()
	s.SystemdTimers = collectSystemdTimers()
	s.SelinuxDisabled = collectSelinux()
	s.DnfPlugins = collectDnfPlugins()
	s.UdevRules = collectUdev()
	s.BinfmtEntries = collectBinfmt()
	s.StartupScripts = collectStartupScripts()
	s.ShellInit = collectShellInit(s.Accounts)
	s.Supervisor = collectSupervisor()
	s.HiddenPIDs = collectHiddenPIDs()
	collectTaint(s.Facts)
	s.Facts["ld_so_preload_exists"] = fileExists("/etc/ld.so.preload")
	s.Facts["core_pattern"] = strings.TrimSpace(readFile("/proc/sys/kernel/core_pattern"))
	s.Facts["docker_sock"] = dockerSockExposed()
	s.Facts["kernel_lockdown"] = parseLockdown(readFile("/sys/kernel/security/lockdown"))
	// Yama ptrace_scope: surface the runtime value as a fact ONLY when 0 is a
	// genuine weakening, not the distro default. RHEL/Fedora ship ptrace_scope=0 as
	// their vendor default (Debian/Ubuntu ship 1); flagging that everywhere is pure
	// noise. So a runtime 0 that matches the vendor-shipped default is suppressed.
	if v, err := strconv.Atoi(strings.TrimSpace(readFile("/proc/sys/kernel/yama/ptrace_scope"))); err == nil {
		if !(v == 0 && yamaVendorDefault() == 0) {
			s.Facts["yama_ptrace_scope"] = v
		}
	}
	collectSSHDFacts(s.Facts)
	return s, nil
}

// parseLockdown extracts the active mode from /sys/kernel/security/lockdown,
// e.g. "[none] integrity confidentiality" -> "none". Empty if unavailable.
func parseLockdown(s string) string {
	i := strings.IndexByte(s, '[')
	j := strings.IndexByte(s, ']')
	if i >= 0 && j > i {
		return s[i+1 : j]
	}
	return ""
}

// collectPathHijack returns PATH entries that are a hijack risk: the current
// directory (empty or ".") or a world-writable directory, from the system PATH
// (/etc/environment, /etc/profile).
func collectPathHijack() []string {
	var raw []string
	for _, line := range nonEmptyLines(readFile("/etc/environment")) {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "PATH=") {
			raw = append(raw, pathValue(t))
		}
	}
	for _, line := range nonEmptyLines(readFile("/etc/profile")) {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "export PATH=") || strings.HasPrefix(t, "PATH=") {
			raw = append(raw, pathValue(t))
		}
	}
	seen := map[string]bool{}
	var bad []string
	for _, pv := range raw {
		for _, d := range strings.Split(pv, ":") {
			d = strings.TrimSpace(d)
			if seen[d] {
				continue
			}
			seen[d] = true
			if d == "" || d == "." {
				bad = append(bad, "(cwd in PATH)")
			} else if fi, err := os.Stat(d); err == nil && fi.IsDir() && fi.Mode().Perm()&0o002 != 0 {
				bad = append(bad, d)
			}
		}
	}
	return bad
}

func pathValue(line string) string {
	v := line[strings.Index(line, "=")+1:]
	return strings.Trim(strings.TrimSpace(v), `"'`)
}

// fileCaps returns the hex of a file's security.capability xattr, or "" if none.
func fileCaps(path string) string {
	buf := make([]byte, 64)
	n, err := unix.Getxattr(path, "security.capability", buf)
	if err != nil || n <= 0 {
		return ""
	}
	return hex.EncodeToString(buf[:n])
}

// collectSSHDFacts extracts a few sshd_config directives that, pointed at unusual
// targets, indicate an SSH backdoor (ForceCommand, AuthorizedKeysCommand).
func collectSSHDFacts(facts map[string]any) {
	files := []string{"/etc/ssh/sshd_config"}
	if extra, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		files = append(files, extra...)
	}
	get := func(key string) string {
		for _, f := range files {
			for _, line := range nonEmptyLines(readFile(f)) {
				t := strings.TrimSpace(line)
				if t == "" || strings.HasPrefix(t, "#") {
					continue
				}
				fields := strings.Fields(t)
				if len(fields) >= 2 && strings.EqualFold(fields[0], key) {
					return strings.Join(fields[1:], " ")
				}
			}
		}
		return ""
	}
	facts["sshd_force_command"] = get("ForceCommand")
	facts["sshd_authorized_keys_command"] = get("AuthorizedKeysCommand")
	facts["sshd_permit_root_login"] = get("PermitRootLogin")
}

// dockerSockExposed reports whether the Docker control socket is present and
// group/other-accessible (a common container-escape / privilege path).
func dockerSockExposed() bool {
	for _, p := range []string{"/var/run/docker.sock", "/run/docker.sock"} {
		if fi, err := os.Stat(p); err == nil {
			// Only world (other) access is the misconfiguration/escape signal; the
			// default root:docker 0660 socket (group access) is by design and noisy.
			if fi.Mode()&0o006 != 0 {
				return true
			}
		}
	}
	return false
}

// collectKernelLog reads the kernel ring buffer from /dev/kmsg. Opened
// non-blocking so reads return EAGAIN once the buffer is drained (rather than
// blocking for new messages); raw unix.Read bypasses the Go poller. Requires
// CAP_SYSLOG / root and is subject to kernel.dmesg_restrict.
func collectKernelLog(errs *[]string) []KernelLogEntry {
	const maxRecords = 2000
	fd, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		*errs = append(*errs, "kmsg open: "+err.Error())
		return nil
	}
	defer unix.Close(fd)

	var out []KernelLogEntry
	buf := make([]byte, 8192)
	for {
		n, err := unix.Read(fd, buf)
		if err == unix.EAGAIN {
			break // drained
		}
		if err == unix.EPIPE {
			continue // a record was overwritten; move on
		}
		if err != nil || n == 0 {
			break
		}
		if e, ok := parseKmsg(string(buf[:n])); ok {
			out = append(out, e)
		}
	}
	// /dev/kmsg streams oldest->newest; on a long-uptime host the buffer holds far
	// more than maxRecords, and the security-relevant events (a fresh promiscuous-mode
	// enter, an exploit segfault, a module taint) are the NEWEST. Keep the tail, not
	// the head, so we don't miss recent events behind days of old boot spam.
	if len(out) > maxRecords {
		out = out[len(out)-maxRecords:]
	}
	return out
}

// parseKmsg decodes a /dev/kmsg record: "priority,seq,timestamp,flags;message".
func parseKmsg(rec string) (KernelLogEntry, bool) {
	semi := strings.IndexByte(rec, ';')
	if semi < 0 {
		return KernelLogEntry{}, false
	}
	msg := rec[semi+1:]
	if nl := strings.IndexByte(msg, '\n'); nl >= 0 {
		msg = msg[:nl] // drop continuation lines
	}
	e := KernelLogEntry{Message: strings.TrimSpace(msg)}
	fields := strings.Split(rec[:semi], ",")
	if len(fields) >= 3 {
		e.Priority, _ = strconv.Atoi(fields[0])
		e.Seq, _ = strconv.ParseInt(fields[1], 10, 64)
		e.TimestampUs, _ = strconv.ParseInt(fields[2], 10, 64)
	}
	return e, e.Message != ""
}

// collectShellInit scans shell rc/profile files for hiding aliases, download
// cradles, and PROMPT_COMMAND backdoors.
func collectShellInit(accounts []Account) []StartupScript {
	files := []string{"/etc/profile", "/etc/bash.bashrc", "/etc/bashrc"}
	for _, a := range accounts {
		if a.Home == "" {
			continue
		}
		for _, fn := range []string{".bashrc", ".bash_profile", ".profile", ".zshrc"} {
			files = append(files, a.Home+"/"+fn)
		}
	}
	seen := map[string]bool{}
	var out []StartupScript
	for _, p := range files {
		if seen[p] {
			continue
		}
		seen[p] = true
		data := readFile(p)
		if data == "" {
			continue
		}
		var hits []string
		for _, line := range nonEmptyLines(data) {
			if looksLikeCradle(line) || aliasHiding(line) || promptCommandBackdoor(line) {
				hits = append(hits, strings.TrimSpace(line))
			}
		}
		if len(hits) > 0 {
			out = append(out, StartupScript{Path: p, SuspiciousLines: hits})
		}
	}
	return out
}

// aliasHiding flags aliases/functions that filter output to hide artifacts, e.g.
// alias ls='ls | grep -v evil' (a benign `ls --color` alias does not match).
func aliasHiding(line string) bool {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "alias ") && !strings.Contains(t, "()") {
		return false
	}
	return strings.Contains(t, "grep -v") || strings.Contains(t, "egrep -v") ||
		strings.Contains(t, "/tmp/") || strings.Contains(t, "/dev/shm/")
}

func promptCommandBackdoor(line string) bool {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "PROMPT_COMMAND") && !strings.Contains(t, "PROMPT_COMMAND=") {
		return false
	}
	return strings.Contains(t, "curl") || strings.Contains(t, "wget") ||
		strings.Contains(t, "base64") || strings.Contains(t, "/dev/tcp/") || strings.Contains(t, "eval")
}

// collectSupervisor parses supervisord program definitions and their commands.
func collectSupervisor() []SupervisorProg {
	files := []string{"/etc/supervisord.conf"}
	if extra, err := filepath.Glob("/etc/supervisor/conf.d/*.conf"); err == nil {
		files = append(files, extra...)
	}
	if extra, err := filepath.Glob("/etc/supervisor/*.conf"); err == nil {
		files = append(files, extra...)
	}
	var out []SupervisorProg
	for _, f := range files {
		var prog string
		for _, line := range nonEmptyLines(readFile(f)) {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "[program:") {
				prog = strings.TrimSuffix(strings.TrimPrefix(t, "[program:"), "]")
				continue
			}
			if strings.HasPrefix(t, "command") && strings.Contains(t, "=") {
				cmd := strings.TrimSpace(t[strings.Index(t, "=")+1:])
				out = append(out, SupervisorProg{Path: f, Program: prog, Command: cmd})
			}
		}
	}
	return out
}

// collectHiddenPIDs brute-forces PIDs and reports those that are stat-accessible
// (a live process exists) but never appear in a /proc readdir — the signature of
// a rootkit hiding processes from getdents. Two readdir passes bracket the scan
// to filter out processes that merely started/exited during collection.
func collectHiddenPIDs() []int {
	maxPID := 65536
	if m, err := strconv.Atoi(strings.TrimSpace(readFile("/proc/sys/kernel/pid_max"))); err == nil && m < maxPID {
		maxPID = m
	}
	listed := readProcPidSet()
	var candidates []int
	for pid := 2; pid <= maxPID; pid++ {
		if listed[pid] {
			continue
		}
		// A thread's /proc/<tid> is stat-accessible but TIDs never appear in the
		// /proc readdir, so require Tgid==pid to count it as a real (process) entry
		// rather than a thread — otherwise every thread is a false "hidden process".
		if tgid, ok := readTgid(pid); ok && tgid == pid {
			candidates = append(candidates, pid)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	// Re-verify each candidate to kill race-condition false positives, common on busy
	// container hosts. A genuinely rootkit-hidden process is STILL ALIVE (stat-
	// accessible as a process) yet STILL ABSENT from the /proc readdir. So a candidate
	// only counts if, on the second pass, it is both (a) still not listed AND (b) still
	// a live process. This drops: a process that STARTED mid-scan (now listed) and a
	// transient process that EXITED mid-scan (no longer stat-accessible) — the latter
	// being the FP the first re-read missed.
	after := readProcPidSet()
	var hidden []int
	for _, pid := range candidates {
		if after[pid] {
			continue // started mid-scan
		}
		if tgid, ok := readTgid(pid); ok && tgid == pid { // still a live, unlisted process
			hidden = append(hidden, pid)
		}
	}
	return hidden
}

// readTgid returns the thread-group id (Tgid) from /proc/<pid>/status. For a real
// process Tgid==pid; for a thread it is the leader's pid.
func readTgid(pid int) (int, bool) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := sc.Text(); strings.HasPrefix(line, "Tgid:") {
			tgid, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Tgid:")))
			return tgid, err == nil
		}
	}
	return 0, false
}

func readProcPidSet() map[int]bool {
	set := map[int]bool{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return set
	}
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			set[pid] = true
		}
	}
	return set
}

// suspiciousRemotePorts are common miner-pool / C2 destination ports.
var suspiciousRemotePorts = map[int]bool{
	3333: true, 4444: true, 5555: true, 7777: true, 9999: true, 14444: true,
	3032: true, 5790: true, 1337: true, 31337: true, 6666: true, 45700: true,
}

// collectOutboundConns parses established connections from /proc/net/tcp{,6} and
// keeps those whose remote port is a known miner-pool / C2 port.
func collectOutboundConns() []Conn {
	var out []Conn
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 || fields[3] != "01" { // 01 = ESTABLISHED
				continue
			}
			ip, port := parseHexAddr(fields[2]) // rem_address
			if suspiciousRemotePorts[port] {
				out = append(out, Conn{Proto: "tcp", RAddr: ip, RPort: port})
			}
		}
		f.Close()
	}
	return out
}

// collectPasswordless returns accounts whose /etc/shadow password field is empty
// (login with no password). Readable only as root.
func collectPasswordless() []string {
	f, err := os.Open("/etc/shadow")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) >= 2 && fields[1] == "" {
			out = append(out, fields[0])
		}
	}
	return out
}

// collectPrivGroupMembers returns members of privileged groups, flagging those
// whose login shell is nologin/false (a service account in sudo/docker = backdoor).
func collectPrivGroupMembers(accounts []Account) []GroupMember {
	nologin := map[string]bool{}
	for _, a := range accounts {
		nologin[a.Name] = strings.HasSuffix(a.Shell, "nologin") || strings.HasSuffix(a.Shell, "false")
	}
	// Only root-equivalent groups (sudo/wheel = sudo; docker/lxd = host root via
	// the daemon). NOT adm (log read) or root-gid secondary, which legitimately
	// contain service accounts like syslog.
	priv := map[string]bool{"sudo": true, "wheel": true, "docker": true, "lxd": true}
	var out []GroupMember
	for _, line := range nonEmptyLines(readFile("/etc/group")) {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) < 4 || !priv[fields[0]] || fields[3] == "" {
			continue
		}
		for _, m := range strings.Split(fields[3], ",") {
			m = strings.TrimSpace(m)
			if m == "" || m == "root" {
				continue
			}
			out = append(out, GroupMember{Group: fields[0], Member: m, Nologin: nologin[m]})
		}
	}
	return out
}

// collectLibVersions resolves the version of key shared libraries by reading the
// real (versioned) filename behind the SONAME symlink. Used for supply-chain
// checks such as the liblzma / xz-utils backdoor (CVE-2024-3094).
func collectLibVersions() []LibVersion {
	dirs := []string{
		"/lib", "/usr/lib", "/lib64", "/usr/lib64",
		"/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
		"/lib/aarch64-linux-gnu", "/usr/lib/aarch64-linux-gnu",
	}
	libs := map[string]string{"liblzma.so.5": "liblzma"} // soname -> short name
	seen := map[string]bool{}
	var out []LibVersion
	for _, dir := range dirs {
		for soname, name := range libs {
			p := dir + "/" + soname
			real, err := filepath.EvalSymlinks(p)
			if err != nil {
				if fi, e := os.Stat(p); e != nil || fi.IsDir() {
					continue
				}
				real = p
			}
			if seen[real] {
				continue
			}
			seen[real] = true
			// real filename is e.g. liblzma.so.5.6.1 -> version "5.6.1"
			base := filepath.Base(real)
			ver := strings.TrimPrefix(base, "liblzma.so.")
			if ver != base {
				out = append(out, LibVersion{Name: name, Path: real, Version: ver})
			}
		}
	}
	return out
}

// toolMarkers maps a content substring unique to an offensive tool to its label.
// toolMarkers map distinctive content strings (import paths, banners) to a tool
// label. Import-path markers are essentially zero-FP: a binary only embeds e.g.
// "fatedier/frp" if it is frp. Covers privesc-enum, tunneling/proxy and C2 tools.
var toolMarkers = map[string]string{
	"PEASS-ng":                    "linpeas",
	"linpeas":                     "linpeas",
	"DominicBreuker/pspy":         "pspy",
	"jpillora/chisel":             "chisel",
	"github.com/bishopfox/sliver": "sliver",
	// tunneling / reverse proxies (lateral movement, C2 egress)
	"fatedier/frp":           "frp",
	"nicocha30/ligolo-ng":    "ligolo-ng",
	"ligolo-ng":              "ligolo-ng",
	"ginuerzh/gost":          "gost",
	"go-gost/":               "gost",
	"cloudflare/cloudflared": "cloudflared",
	"ehang-io/nps":           "nps",
	"EddieIvan01/iox":        "iox",
	"esrrhs/pingtunnel":      "pingtunnel",
	"kost/revsocks":          "revsocks",
	"sshuttle":               "sshuttle",
	// C2 frameworks / implants
	"Ne0nd0g/merlin":            "merlin",
	"jm33-m0/emp3r0r":           "emp3r0r",
	"emp3r0r":                   "emp3r0r",
	"github.com/Ne0nd0g/merlin": "merlin",
	// session hijack / miner / DNS tunnels
	"nelhage/reptyr":   "reptyr",
	"xmrig":            "xmrig",
	"github.com/xmrig": "xmrig",
	"dnscat":           "dnscat2",
	"iodine":           "iodine",
	"ngrok.com":        "ngrok",
	"gsocket":          "gsocket",
}

// fileToolMarker reads the head of a file and returns a matched offensive-tool
// label, or "" — a deterministic content match (not filename), so low-FP.
func fileToolMarker(path string, size int64) string {
	if size <= 0 || size > 100<<20 {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 256<<10)
	n, _ := f.Read(buf)
	content := string(buf[:n])
	for marker, label := range toolMarkers {
		if strings.Contains(content, marker) {
			return label
		}
	}
	return ""
}

// collectWebShells scans common web roots for files containing webshell code
// patterns (PHP/JSP). Deterministic content match keeps false positives low.
func collectWebShells() []StartupScript {
	roots := []string{
		"/var/www", "/var/www/html", "/usr/share/nginx/html",
		"/srv/www", "/srv/http", "/var/www/localhost/htdocs",
	}
	exts := map[string]bool{".php": true, ".phtml": true, ".php5": true, ".php7": true,
		".inc": true, ".jsp": true, ".jspx": true, ".asp": true, ".aspx": true}
	seen := map[string]bool{}
	var out []StartupScript
	for _, root := range roots {
		walkDirBounded(root, 6, func(path string, info os.FileInfo) {
			if seen[path] || !info.Mode().IsRegular() || info.Size() > 2<<20 {
				return
			}
			if !exts[strings.ToLower(filepath.Ext(path))] {
				return
			}
			seen[path] = true
			var hits []string
			for _, line := range nonEmptyLines(readFile(path)) {
				if webshellHit(line) {
					hits = append(hits, strings.TrimSpace(line))
					if len(hits) >= 5 {
						break
					}
				}
			}
			if len(hits) > 0 {
				out = append(out, StartupScript{Path: path, SuspiciousLines: hits})
			}
		})
	}
	return out
}

// webshellHit reports whether a source line looks like a webshell: a code-exec
// sink fed from an HTTP superglobal, an eval'd base64 blob, or a /e preg_replace.
func webshellHit(line string) bool {
	l := line
	sink := strings.Contains(l, "eval(") || strings.Contains(l, "assert(") ||
		strings.Contains(l, "system(") || strings.Contains(l, "exec(") ||
		strings.Contains(l, "passthru(") || strings.Contains(l, "shell_exec(") ||
		strings.Contains(l, "popen(") || strings.Contains(l, "proc_open(") ||
		strings.Contains(l, "Runtime.getRuntime().exec")
	tainted := strings.Contains(l, "$_POST") || strings.Contains(l, "$_GET") ||
		strings.Contains(l, "$_REQUEST") || strings.Contains(l, "$_COOKIE") ||
		strings.Contains(l, "$_SERVER[\"HTTP") || strings.Contains(l, "getParameter(")
	if sink && tainted {
		return true
	}
	if strings.Contains(l, "base64_decode(") && (strings.Contains(l, "eval(") || strings.Contains(l, "$_")) {
		return true
	}
	if strings.Contains(l, "preg_replace") && strings.Contains(l, "/e") {
		return true
	}
	return false
}

// collectBpfPinned lists pinned BPF objects directly at the root of /sys/fs/bpf.
// Top-level pins are the rootkit/eBPF-backdoor persistence style; orchestrators
// (cilium, systemd) nest their pins under subdirectories, so this stays low-FP.
func collectBpfPinned() []string {
	entries, err := os.ReadDir("/sys/fs/bpf")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, "/sys/fs/bpf/"+e.Name())
		}
	}
	return out
}

// bpfAttrObjID is the bpf() attr for the *_GET_NEXT_ID and *_GET_FD_BY_ID
// commands. The leading u32 is start_id (NEXT_ID) or prog_id (GET_FD_BY_ID).
type bpfAttrObjID struct {
	ID        uint32 // start_id / prog_id
	NextID    uint32
	OpenFlags uint32
}

// bpfAttrInfo is the bpf() attr for BPF_OBJ_GET_INFO_BY_FD.
type bpfAttrInfo struct {
	BpfFD   uint32
	InfoLen uint32
	Info    uint64 // pointer to a bpfProgInfo
}

// bpfProgInfo mirrors the leading fields of the kernel's struct bpf_prog_info.
// The kernel fills only min(info_len, sizeof(kernel struct)) bytes, so covering
// the prefix up to gpl_compatible is enough; later fields are intentionally
// omitted. Field offsets must match the kernel ABI (all u64 are 8-aligned here).
type bpfProgInfo struct {
	Type            uint32
	ID              uint32
	Tag             [8]uint8
	JitedProgLen    uint32
	XlatedProgLen   uint32
	JitedProgInsns  uint64
	XlatedProgInsns uint64
	LoadTime        uint64
	CreatedByUID    uint32
	NrMapIDs        uint32
	MapIDs          uint64
	Name            [16]uint8
	Ifindex         uint32
	Flags           uint32 // gpl_compatible:1, jited:1, ... (bitfield)
}

// bpfProgTypeNames maps enum bpf_prog_type values to short human names. Only the
// types worth surfacing are named; anything else renders as "type<N>".
var bpfProgTypeNames = map[uint32]string{
	1: "socket_filter", 2: "kprobe", 3: "sched_cls", 4: "sched_act",
	5: "tracepoint", 6: "xdp", 7: "perf_event", 8: "cgroup_skb",
	9: "cgroup_sock", 13: "sock_ops", 14: "sk_skb", 15: "cgroup_device",
	16: "sk_msg", 17: "raw_tracepoint", 18: "cgroup_sock_addr",
	21: "sk_reuseport", 22: "flow_dissector", 23: "cgroup_sysctl",
	25: "cgroup_sockopt", 26: "tracing", 27: "struct_ops", 28: "ext",
	29: "lsm", 30: "sk_lookup", 31: "syscall", 32: "netfilter",
}

func bpfProgTypeName(t uint32) string {
	if n, ok := bpfProgTypeNames[t]; ok {
		return n
	}
	return "type" + strconv.FormatUint(uint64(t), 10)
}

// bpfSyscall invokes bpf(2). Returns the raw return value and errno (0 on ok).
func bpfSyscall(cmd int, attr unsafe.Pointer, size uintptr) (uintptr, syscall.Errno) {
	r, _, e := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
	return r, e
}

// collectBpfPrograms enumerates loaded eBPF programs via bpf(BPF_PROG_GET_NEXT_ID)
// and reads each program's metadata through a transient fd (BPF_OBJ_GET_INFO_BY_FD).
// This is fully agentless (one syscall walk, no attach) and surfaces eBPF rootkits
// that hook syscalls or sniff packets even when they pin nothing under /sys/fs/bpf.
// Requires CAP_SYS_ADMIN (the probe runs as root); without it the walk simply
// yields nothing rather than erroring.
func collectBpfPrograms() []BpfProg {
	var out []BpfProg
	var id uint32
	for {
		next := bpfAttrObjID{ID: id}
		if _, e := bpfSyscall(unix.BPF_PROG_GET_NEXT_ID, unsafe.Pointer(&next), unsafe.Sizeof(next)); e != 0 {
			break // ENOENT = end of list; EPERM = not privileged
		}
		id = next.NextID

		fa := bpfAttrObjID{ID: id}
		fd, e := bpfSyscall(unix.BPF_PROG_GET_FD_BY_ID, unsafe.Pointer(&fa), unsafe.Sizeof(fa))
		if e != 0 {
			continue
		}
		var info bpfProgInfo
		ia := bpfAttrInfo{
			BpfFD:   uint32(fd),
			InfoLen: uint32(unsafe.Sizeof(info)),
			Info:    uint64(uintptr(unsafe.Pointer(&info))),
		}
		_, e = bpfSyscall(unix.BPF_OBJ_GET_INFO_BY_FD, unsafe.Pointer(&ia), unsafe.Sizeof(ia))
		unix.Close(int(fd))
		if e != 0 {
			continue
		}
		out = append(out, BpfProg{
			ID:   info.ID,
			Type: bpfProgTypeName(info.Type),
			Name: unix.ByteSliceToString(info.Name[:]),
			Tag:  hex.EncodeToString(info.Tag[:]),
			GPL:  info.Flags&1 == 1,
		})
	}
	return out
}

// referencesWritableDir reports whether s contains a path under a user-writable
// directory (the classic dropper locations), used to judge hook/module commands.
func referencesWritableDir(s string) bool {
	for _, d := range []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/home/"} {
		if strings.Contains(s, d) {
			return true
		}
	}
	return false
}

// quotedStrings returns the contents of every double-quoted run in s. APT config
// expresses hook commands as quoted strings (e.g. `{"/path/cmd";};`).
func quotedStrings(s string) []string {
	var out []string
	for {
		i := strings.IndexByte(s, '"')
		if i < 0 {
			break
		}
		s = s[i+1:]
		j := strings.IndexByte(s, '"')
		if j < 0 {
			break
		}
		if c := strings.TrimSpace(s[:j]); c != "" {
			out = append(out, c)
		}
		s = s[j+1:]
	}
	return out
}

// collectPackageHooks scans /etc/apt/apt.conf{,.d/*} for hook directives
// (Pre-Invoke/Post-Invoke/Pre-Install-Pkgs under DPkg:: or APT::Update::) whose
// command is a download cradle or runs from a writable path. These run as root on
// every apt/dpkg invocation, a stealthy persistence vector. Only suspicious hooks
// are kept, so legit hooks (unattended-upgrades, command-not-found) don't FP.
func collectPackageHooks() []PackageHook {
	files := []string{"/etc/apt/apt.conf"}
	if g, err := filepath.Glob("/etc/apt/apt.conf.d/*"); err == nil {
		files = append(files, g...)
	}
	hookNames := []string{"Pre-Invoke", "Post-Invoke", "Pre-Install-Pkgs"}
	var out []PackageHook
	for _, f := range files {
		data := readFile(f)
		if data == "" {
			continue
		}
		curr := ""
		for _, line := range strings.Split(data, "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "//") || strings.HasPrefix(t, "#") {
				continue
			}
			for _, h := range hookNames {
				if strings.Contains(t, h) {
					if b := strings.IndexByte(t, '{'); b >= 0 {
						curr = strings.TrimSpace(t[:b])
					} else {
						curr = t
					}
				}
			}
			if curr == "" {
				continue
			}
			for _, cmd := range quotedStrings(t) {
				if looksLikeCradle(cmd) || referencesWritableDir(cmd) {
					out = append(out, PackageHook{Path: f, Manager: "apt", Directive: curr, Command: cmd})
				}
			}
			if strings.Contains(t, "}") {
				curr = ""
			}
		}
	}
	return out
}

// collectWebServerModules scans apache/nginx configs for modules loaded from a
// writable path (LoadModule / load_module). A web-server module is loaded into
// the server process with its privileges, so one from /tmp etc. is a backdoor.
// Standard module dirs are skipped, so the dozens of stock modules don't FP.
func collectWebServerModules() []WebServerModule {
	type src struct {
		server string
		globs  []string
	}
	sources := []src{
		{"apache", []string{"/etc/apache2/apache2.conf", "/etc/apache2/mods-enabled/*", "/etc/apache2/conf-enabled/*", "/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*", "/etc/httpd/conf.modules.d/*"}},
		{"nginx", []string{"/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*", "/etc/nginx/modules-enabled/*"}},
	}
	var out []WebServerModule
	for _, s := range sources {
		var files []string
		for _, g := range s.globs {
			if m, err := filepath.Glob(g); err == nil {
				files = append(files, m...)
			}
		}
		for _, f := range files {
			for _, line := range nonEmptyLines(readFile(f)) {
				t := strings.TrimSpace(line)
				if strings.HasPrefix(t, "#") {
					continue
				}
				fields := strings.Fields(strings.TrimRight(t, ";"))
				var mod string
				switch {
				case s.server == "apache" && len(fields) >= 3 && fields[0] == "LoadModule":
					mod = fields[2]
				case s.server == "nginx" && len(fields) >= 2 && fields[0] == "load_module":
					mod = strings.Trim(fields[1], `"`)
				default:
					continue
				}
				if referencesWritableDir(mod) {
					out = append(out, WebServerModule{Path: f, Server: s.server, Module: mod})
				}
			}
		}
	}
	return out
}

// collectModprobeCommands scans modprobe.d for install/remove directives that run
// an arbitrary command when a module is (un)loaded — a root-executed persistence
// trick (the kernel never loads the named module; the command runs instead). Only
// commands that are a download cradle or reference a writable path are kept, so
// the common legit pipelines (lsmod|rmmod && modprobe, /bin/false stubs) don't FP.
func collectModprobeCommands() []ModprobeCommand {
	var files []string
	for _, g := range []string{"/etc/modprobe.d/*.conf", "/lib/modprobe.d/*.conf", "/usr/lib/modprobe.d/*.conf", "/run/modprobe.d/*.conf"} {
		if m, err := filepath.Glob(g); err == nil {
			files = append(files, m...)
		}
	}
	var out []ModprobeCommand
	for _, f := range files {
		data := readFile(f)
		if data == "" {
			continue
		}
		data = strings.ReplaceAll(data, "\\\n", " ") // join line continuations
		for _, line := range nonEmptyLines(data) {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "#") {
				continue
			}
			fields := strings.Fields(t)
			if len(fields) < 3 || (fields[0] != "install" && fields[0] != "remove") {
				continue
			}
			cmd := strings.Join(fields[2:], " ")
			if !looksLikeCradle(cmd) && !referencesWritableDir(cmd) {
				continue
			}
			out = append(out, ModprobeCommand{Path: f, Directive: fields[0], Module: fields[1], Command: cmd})
		}
	}
	return out
}

// collectLdSoConf scans /etc/ld.so.conf{,.d/*} for library search directories
// under a writable path — a system-wide dynamic-linker hijack (attacker .so is
// preferred for every dynamically linked binary). `include` lines are skipped.
func collectLdSoConf() []LdConfEntry {
	files := []string{"/etc/ld.so.conf"}
	if m, err := filepath.Glob("/etc/ld.so.conf.d/*.conf"); err == nil {
		files = append(files, m...)
	}
	var out []LdConfEntry
	for _, f := range files {
		for _, line := range nonEmptyLines(readFile(f)) {
			t := strings.TrimSpace(line)
			if !strings.HasPrefix(t, "/") { // skip 'include ...' and comments
				continue
			}
			if referencesWritableDir(t) {
				out = append(out, LdConfEntry{Path: f, Dir: t})
			}
		}
	}
	return out
}

// collectEnvPreload scans global shell/env files for LD_PRELOAD (a userland
// rootkit / SSH-key re-adder loaded into every process) or an LD_LIBRARY_PATH
// pointing at a writable dir. LD_PRELOAD here is almost always malicious; the
// LD_LIBRARY_PATH case is gated on writability to stay low-FP.
func collectEnvPreload() []StartupScript {
	files := []string{"/etc/environment", "/etc/profile", "/etc/bash.bashrc"}
	if m, err := filepath.Glob("/etc/profile.d/*"); err == nil {
		files = append(files, m...)
	}
	var out []StartupScript
	for _, f := range files {
		var hits []string
		for _, line := range nonEmptyLines(readFile(f)) {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "#") {
				continue
			}
			switch {
			case strings.Contains(t, "LD_PRELOAD"), strings.Contains(t, "LD_AUDIT"):
				hits = append(hits, t)
			case strings.Contains(t, "LD_LIBRARY_PATH") && referencesWritableDir(t):
				hits = append(hits, t)
			}
		}
		if len(hits) > 0 {
			out = append(out, StartupScript{Path: f, SuspiciousLines: hits})
		}
	}
	return out
}

// gtfobinsSuid is the set of binaries that grant a shell / arbitrary file access
// when SUID (GTFOBins "SUID" category). None of these is ever legitimately SUID,
// so a SUID bit on one is a strong privesc/persistence signal. Standard SUID
// binaries (sudo/su/mount/passwd/...) are deliberately absent.
var gtfobinsSuid = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true, "csh": true,
	"tcsh": true, "fish": true, "rbash": true,
	"vim": true, "vi": true, "view": true, "rvim": true, "nvim": true, "nano": true,
	"pico": true, "emacs": true, "ed": true, "less": true, "more": true, "man": true,
	"awk": true, "gawk": true, "mawk": true, "nawk": true, "sed": true,
	"python": true, "perl": true, "ruby": true, "php": true, "lua": true, "node": true,
	"tclsh": true, "gdb": true,
	"tar": true, "zip": true, "unzip": true, "cpio": true, "rsync": true,
	"cp": true, "mv": true, "dd": true, "tee": true,
	"strace": true, "ltrace": true,
	"nc": true, "ncat": true, "netcat": true, "socat": true,
	"env": true, "nmap": true, "expect": true, "make": true, "busybox": true,
	"flock": true, "xargs": true, "find": true, "chroot": true, "capsh": true,
	"nohup": true, "stdbuf": true, "taskset": true, "scp": true, "ssh": true,
	"wget": true, "curl": true, "git": true, "ftp": true, "start-stop-daemon": true,
}

// gtfobinsSuidMatch matches a binary basename against gtfobinsSuid, tolerating a
// version suffix (python3.11, perl5.34, lua5.4) so versioned interpreters match.
func gtfobinsSuidMatch(base string) bool {
	base = strings.ToLower(base)
	if gtfobinsSuid[base] {
		return true
	}
	for name := range gtfobinsSuid {
		if rest, ok := strings.CutPrefix(base, name); ok && rest != "" &&
			strings.Trim(rest, "0123456789.-") == "" {
			return true
		}
	}
	return false
}

// collectSuidBinaries walks the standard binary dirs for SUID files whose name is
// a GTFOBins shell-escape/interpreter. /tmp,/dev/shm etc. are covered separately
// by collectSuspiciousFiles, so this focuses on the system bin/lib/opt trees.
func collectSuidBinaries() []FileEntry {
	dirs := []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt", "/usr/lib"}
	seen := map[string]bool{}
	var out []FileEntry
	for _, dir := range dirs {
		walkDirBounded(dir, 4, func(path string, info os.FileInfo) {
			mode := info.Mode()
			if mode.IsDir() || !mode.IsRegular() || mode&os.ModeSetuid == 0 {
				return
			}
			if !gtfobinsSuidMatch(filepath.Base(path)) || seen[path] {
				return
			}
			seen[path] = true
			fe := FileEntry{Path: path, Mode: octalMode(mode), SUID: true}
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				fe.UID = int(st.Uid)
			}
			out = append(out, fe)
		})
	}
	return out
}

// collectWritablePersistence returns root-executed config files (systemd units,
// cron, sudoers.d, init scripts, ld.so.preload) that are writable by a non-root
// user — other-writable, or group-writable by a non-root group. A non-root user
// who can edit such a file owns root-executed persistence.
// nonRootReadable reports whether a path is readable by a non-root principal
// (other-readable, or group-readable by a non-root group).
func nonRootReadable(fi os.FileInfo) bool {
	perm := fi.Mode().Perm()
	if perm&0o004 != 0 {
		return true
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && perm&0o040 != 0 && st.Gid != 0 {
		return true
	}
	return false
}

// k8sStandardStaticPods are the legit control-plane static pod manifest names;
// a NON-standard static pod with privileged/host* settings is the persistence
// signal ("static hidden pod"), while these are expected to be privileged.
var k8sStandardStaticPods = map[string]bool{
	"kube-apiserver": true, "kube-controller-manager": true,
	"kube-scheduler": true, "etcd": true, "kube-proxy": true,
}

// collectK8sStaticPods scans /etc/kubernetes/manifests for non-standard static
// pod manifests with high-risk settings (privileged, hostPID/Network/IPC, a
// container-runtime socket / hostPath mount, or a cradle command). Kubelet runs
// these directly — a dropped manifest is root-level container persistence.
func collectK8sStaticPods() []StartupScript {
	files, _ := filepath.Glob("/etc/kubernetes/manifests/*")
	var out []StartupScript
	for _, f := range files {
		base := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(f), ".yaml"), ".yml")
		if k8sStandardStaticPods[base] {
			continue
		}
		data := readFile(f)
		if data == "" {
			continue
		}
		noSpace := strings.ReplaceAll(strings.ToLower(data), " ", "")
		var hits []string
		for _, m := range []string{"privileged:true", "hostpid:true", "hostnetwork:true", "hostipc:true"} {
			if strings.Contains(noSpace, m) {
				hits = append(hits, m)
			}
		}
		if strings.Contains(noSpace, "hostpath:") {
			hits = append(hits, "hostPath mount")
		}
		for _, s := range []string{"docker.sock", "containerd.sock", "crio.sock"} {
			if strings.Contains(noSpace, s) {
				hits = append(hits, "runtime socket: "+s)
			}
		}
		for _, line := range nonEmptyLines(data) {
			if looksLikeCradle(line) {
				hits = append(hits, strings.TrimSpace(line))
			}
		}
		if len(hits) > 0 {
			out = append(out, StartupScript{Path: f, SuspiciousLines: sortedUnique(hits)})
		}
	}
	return out
}

// collectExposedKubeconfig finds kubeconfig/admin files that embed credentials
// (client-key-data / certs / tokens) yet are readable by a non-root user.
func collectExposedKubeconfig() []string {
	var files []string
	for _, g := range []string{"/etc/kubernetes/*.conf", "/root/.kube/config", "/home/*/.kube/config"} {
		if m, err := filepath.Glob(g); err == nil {
			files = append(files, m...)
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		if seen[f] {
			continue
		}
		seen[f] = true
		fi, err := os.Stat(f)
		if err != nil || fi.IsDir() || !nonRootReadable(fi) {
			continue
		}
		data := readFile(f)
		if strings.Contains(data, "client-key-data") || strings.Contains(data, "client-certificate-data") || strings.Contains(data, "token:") {
			out = append(out, f)
		}
	}
	return out
}

// nonRootWritable reports whether a path is writable by a non-root principal:
// other-writable, or group-writable by a non-root group.
func nonRootWritable(fi os.FileInfo) bool {
	perm := fi.Mode().Perm()
	if perm&0o002 != 0 {
		return true
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && perm&0o020 != 0 && st.Gid != 0 {
		return true
	}
	return false
}

func collectWritablePersistence() []string {
	files := []string{"/etc/crontab", "/etc/rc.local", "/etc/ld.so.preload"}
	for _, g := range []string{
		"/etc/systemd/system/*.service", "/etc/systemd/system/*.timer",
		"/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*",
		"/etc/cron.weekly/*", "/etc/cron.monthly/*",
		"/etc/sudoers.d/*", "/etc/init.d/*",
	} {
		if m, err := filepath.Glob(g); err == nil {
			files = append(files, m...)
		}
	}
	// Persistence DIRECTORIES: if a non-root user can write the dir itself, they
	// can drop a new root-executed unit/cron/sudoers entry into it.
	dirs := []string{
		"/etc/systemd/system", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
		"/etc/cron.weekly", "/etc/cron.monthly", "/etc/sudoers.d", "/etc/init.d",
		"/etc/profile.d", "/etc/update-motd.d", "/etc/ld.so.conf.d",
	}
	var out []string
	for _, p := range files {
		fi, err := os.Stat(p)
		if err != nil || fi.IsDir() {
			continue
		}
		if nonRootWritable(fi) {
			out = append(out, p)
		}
	}
	for _, d := range dirs {
		fi, err := os.Stat(d)
		if err != nil || !fi.IsDir() {
			continue
		}
		if nonRootWritable(fi) {
			out = append(out, d+"/ (writable directory)")
		}
	}
	return out
}

// capBitNames maps capability bit numbers to names (only those used for evidence).
var capBitNames = map[uint]string{
	0: "cap_chown", 1: "cap_dac_override", 2: "cap_dac_read_search", 3: "cap_fowner",
	6: "cap_setgid", 7: "cap_setuid", 16: "cap_sys_module", 17: "cap_sys_rawio",
	19: "cap_sys_ptrace", 21: "cap_sys_admin",
}

// dangerousCapBits are the capabilities that grant straightforward privilege
// escalation (full file access, setuid, module load, ptrace, admin). Network caps
// (cap_net_raw on ping) and the like are intentionally excluded as benign.
var dangerousCapBits = map[uint]bool{0: true, 1: true, 2: true, 3: true, 6: true, 7: true, 16: true, 17: true, 19: true, 21: true}

// decodeDangerousCaps parses a hex security.capability xattr (VFS_CAP_DATA, LE)
// and returns the names of any dangerous capabilities in its permitted set. All
// dangerous caps live in bits 0-31, so only permitted[0] (bytes 4:8) is needed.
func decodeDangerousCaps(hexstr string) []string {
	b, err := hex.DecodeString(hexstr)
	if err != nil || len(b) < 8 {
		return nil
	}
	permitted := binary.LittleEndian.Uint32(b[4:8])
	var out []string
	for bit := uint(0); bit < 32; bit++ {
		if permitted&(1<<bit) != 0 && dangerousCapBits[bit] {
			out = append(out, capBitNames[bit])
		}
	}
	return out
}

// collectDangerousCapabilities walks the system binary trees for files carrying a
// privilege-escalation file capability. Known legit holders (snap-confine,
// newuidmap/newgidmap for user namespaces) are allowlisted so they don't FP.
// capScanDirs are the binary/library trees walked for SUID + file-capability
// checks. /lib,/lib64,/usr/lib64 are included so a capability planted on the
// dynamic linker (e.g. cap_setuid on ld-linux, EDR-T6170) is caught on both
// usrmerge and split-/usr layouts; duplicate paths are deduped by real path.
var capScanDirs = []string{
	"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin",
	"/opt", "/usr/lib", "/usr/lib64", "/lib", "/lib64",
}

// realPath resolves symlinks so the same file reached via /lib and /usr/lib (or
// /lib64) dedups to one entry; falls back to the input on error.
func realPath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

func collectDangerousCapabilities() []FileEntry {
	allow := map[string]bool{"snap-confine": true, "newuidmap": true, "newgidmap": true}
	seen := map[string]bool{}
	var out []FileEntry
	for _, dir := range capScanDirs {
		walkDirBounded(dir, 6, func(path string, info os.FileInfo) {
			mode := info.Mode()
			if mode.IsDir() || !mode.IsRegular() || allow[filepath.Base(path)] {
				return
			}
			caps := fileCaps(path)
			if caps == "" {
				return
			}
			danger := decodeDangerousCaps(caps)
			real := realPath(path)
			if len(danger) == 0 || seen[real] {
				return
			}
			seen[real] = true
			fe := FileEntry{Path: path, Mode: octalMode(mode), Caps: strings.Join(danger, ",")}
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				fe.UID = int(st.Uid)
			}
			out = append(out, fe)
		})
	}
	return out
}

// pathValueHijack reports whether a PATH value contains a hijackable element: an
// empty element (`::`, leading/trailing `:`), the current dir (`.`), or a dir
// under a user-writable location.
func pathValueHijack(val string) bool {
	for _, e := range strings.Split(val, ":") {
		e = strings.TrimSpace(e)
		if e == "" || e == "." {
			return true
		}
		for _, w := range []string{"/tmp", "/dev/shm", "/var/tmp", "/home"} {
			if e == w || strings.HasPrefix(e, w+"/") {
				return true
			}
		}
	}
	return false
}

// collectCronPathHijack scans cron files for a PATH= assignment that includes a
// writable or relative directory — root cron jobs then resolve bare command names
// from an attacker-controlled directory (T1574.007).
func collectCronPathHijack() []string {
	files := []string{"/etc/crontab"}
	for _, g := range []string{"/etc/cron.d/*", "/var/spool/cron/crontabs/*", "/var/spool/cron/*"} {
		if m, err := filepath.Glob(g); err == nil {
			files = append(files, m...)
		}
	}
	var out []string
	for _, f := range files {
		for _, line := range nonEmptyLines(readFile(f)) {
			t := strings.TrimSpace(line)
			eq := strings.IndexByte(t, '=')
			if eq < 0 || strings.TrimSpace(t[:eq]) != "PATH" {
				continue
			}
			if pathValueHijack(strings.TrimSpace(t[eq+1:])) {
				out = append(out, f+": "+t)
			}
		}
	}
	return out
}

// nsswitchStdModules is the set of standard glibc/vendor NSS service modules.
// A module in /etc/nsswitch.conf outside this set implies a custom libnss_*.so,
// a known credential/persistence backdoor vector (e.g. libnss-based rootkits).
var nsswitchStdModules = map[string]bool{
	"files": true, "compat": true, "dns": true, "db": true, "nis": true,
	"nisplus": true, "hesiod": true, "mymachines": true, "systemd": true,
	"sss": true, "ldap": true, "winbind": true, "resolve": true, "myhostname": true,
	"cache": true, "mdns": true, "mdns4": true, "mdns6": true, "mdns_minimal": true,
	"mdns4_minimal": true, "mdns6_minimal": true, "wins": true, "gw_name": true, "role": true,
}

// collectNsswitchModules returns "database: module" entries from /etc/nsswitch.conf
// whose module is outside the standard set. Action tokens ([NOTFOUND=return]) are
// skipped. A custom NSS module is loaded into every name-resolution path.
func collectNsswitchModules() []string {
	data := readFile("/etc/nsswitch.conf")
	if data == "" {
		return nil
	}
	var out []string
	for _, line := range nonEmptyLines(data) {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		colon := strings.IndexByte(t, ':')
		if colon < 0 {
			continue
		}
		db := strings.TrimSpace(t[:colon])
		for _, tok := range strings.Fields(t[colon+1:]) {
			if strings.HasPrefix(tok, "[") || strings.HasSuffix(tok, "]") {
				continue // action token like [NOTFOUND=return]
			}
			if !nsswitchStdModules[strings.ToLower(tok)] {
				out = append(out, db+": "+tok)
			}
		}
	}
	return out
}

// historyTampering reports whether a shell-rc line disables command history
// (HISTFILE=/dev/null or empty, HISTSIZE/HISTFILESIZE=0, unset HISTFILE,
// set +o history) — a common anti-forensics step. HISTSIZE=1000 etc. is ignored.
func historyTampering(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return false
	}
	low := strings.ToLower(t)
	if strings.Contains(low, "set +o history") {
		return true
	}
	if strings.HasPrefix(low, "unset ") && strings.Contains(low, "histfile") {
		return true
	}
	s := strings.TrimSpace(strings.TrimPrefix(low, "export "))
	for _, kv := range []struct{ k, v string }{
		{"histfile", "/dev/null"}, {"histsize", "0"}, {"histfilesize", "0"},
	} {
		if val, ok := strings.CutPrefix(s, kv.k+"="); ok {
			if strings.Trim(strings.TrimSpace(val), `"'`) == kv.v {
				return true
			}
		}
	}
	if v, ok := strings.CutPrefix(s, "histfile="); ok {
		if v := strings.TrimSpace(v); v == "" || v == `""` || v == "''" {
			return true
		}
	}
	return false
}

// collectHistoryTampering scans global and per-account shell rc files for lines
// that disable command history.
func collectHistoryTampering(accounts []Account) []StartupScript {
	files := []string{"/etc/profile", "/etc/bash.bashrc", "/etc/bashrc"}
	for _, a := range accounts {
		if a.Home == "" {
			continue
		}
		for _, fn := range []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zshenv"} {
			files = append(files, a.Home+"/"+fn)
		}
	}
	seen := map[string]bool{}
	var out []StartupScript
	for _, p := range files {
		if seen[p] {
			continue
		}
		seen[p] = true
		var hits []string
		for _, line := range nonEmptyLines(readFile(p)) {
			if historyTampering(line) {
				hits = append(hits, strings.TrimSpace(line))
			}
		}
		if len(hits) > 0 {
			out = append(out, StartupScript{Path: p, SuspiciousLines: hits})
		}
	}
	return out
}

// collectTamperedLogs returns key log files that have been replaced by a symlink
// (classic log-wiping anti-forensics, e.g. ln -sf /dev/null /var/log/auth.log).
// Logs are regular files, so any symlink here is suspicious.
func collectTamperedLogs() []string {
	logs := []string{
		"/var/log/auth.log", "/var/log/syslog", "/var/log/messages", "/var/log/secure",
		"/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog", "/var/log/audit/audit.log",
		"/var/log/kern.log", "/var/log/cron", "/var/log/faillog",
	}
	var out []string
	for _, p := range logs {
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		target, _ := os.Readlink(p)
		out = append(out, p+" -> "+target)
	}
	return out
}

// loginInterpreters are interpreters that, used as a login shell, indicate a
// backdoor account (interactive code execution on login). Real shells
// (bash/sh/zsh) and nologin/false/sync are intentionally absent.
var loginInterpreters = map[string]bool{
	"python": true, "perl": true, "ruby": true, "php": true, "lua": true,
	"node": true, "awk": true, "gawk": true, "tclsh": true, "expect": true,
}

// loginInterpreterMatch matches a shell basename against loginInterpreters,
// tolerating a version suffix (python3.11, perl5.34).
func loginInterpreterMatch(base string) bool {
	base = strings.ToLower(base)
	if loginInterpreters[base] {
		return true
	}
	for name := range loginInterpreters {
		if rest, ok := strings.CutPrefix(base, name); ok && rest != "" &&
			strings.Trim(rest, "0123456789.-") == "" {
			return true
		}
	}
	return false
}

// collectSuspiciousShells returns accounts whose login shell is an interpreter or
// lives under a writable path — both classic backdoor-account signals.
func collectSuspiciousShells(accounts []Account) []string {
	var out []string
	for _, a := range accounts {
		sh := strings.TrimSpace(a.Shell)
		if sh == "" {
			continue
		}
		if referencesWritableDir(sh) || loginInterpreterMatch(filepath.Base(sh)) {
			out = append(out, a.Name+": "+sh)
		}
	}
	return out
}

// collectXdgAutostart scans system and per-account XDG autostart .desktop entries
// for an Exec= line that is a download cradle or runs from a writable path — a GUI
// login persistence vector (T1547.013). Entries from /usr/bin etc. don't match.
func collectXdgAutostart(accounts []Account) []StartupScript {
	files, _ := filepath.Glob("/etc/xdg/autostart/*.desktop")
	for _, a := range accounts {
		if a.Home == "" {
			continue
		}
		if m, err := filepath.Glob(a.Home + "/.config/autostart/*.desktop"); err == nil {
			files = append(files, m...)
		}
	}
	seen := map[string]bool{}
	var out []StartupScript
	for _, f := range files {
		if seen[f] {
			continue
		}
		seen[f] = true
		var hits []string
		for _, line := range nonEmptyLines(readFile(f)) {
			t := strings.TrimSpace(line)
			if !strings.HasPrefix(t, "Exec=") {
				continue
			}
			cmd := strings.TrimSpace(strings.TrimPrefix(t, "Exec="))
			if looksLikeCradle(cmd) || referencesWritableDir(cmd) {
				hits = append(hits, cmd)
			}
		}
		if len(hits) > 0 {
			out = append(out, StartupScript{Path: f, SuspiciousLines: hits})
		}
	}
	return out
}

// collectSshClientConfig scans ssh client configs for a LocalCommand (run on the
// client at connect time when PermitLocalCommand is on — rarely legit) or a
// ProxyCommand that is a cradle / runs from a writable path. Both give exec on
// every outbound ssh, a stealthy persistence/lateral vector.
func collectSshClientConfig(accounts []Account) []StartupScript {
	files := []string{"/etc/ssh/ssh_config"}
	if m, err := filepath.Glob("/etc/ssh/ssh_config.d/*"); err == nil {
		files = append(files, m...)
	}
	for _, a := range accounts {
		if a.Home != "" {
			files = append(files, a.Home+"/.ssh/config")
		}
	}
	seen := map[string]bool{}
	var out []StartupScript
	for _, f := range files {
		if seen[f] {
			continue
		}
		seen[f] = true
		var hits []string
		for _, line := range nonEmptyLines(readFile(f)) {
			t := strings.TrimSpace(line)
			low := strings.ToLower(t)
			if strings.HasPrefix(low, "#") {
				continue
			}
			switch {
			case strings.HasPrefix(low, "localcommand"):
				hits = append(hits, t)
			case strings.HasPrefix(low, "proxycommand") && (looksLikeCradle(t) || referencesWritableDir(t)):
				hits = append(hits, t)
			}
		}
		if len(hits) > 0 {
			out = append(out, StartupScript{Path: f, SuspiciousLines: hits})
		}
	}
	return out
}

// collectWritableSuid walks the system binary trees for SUID/SGID files that are
// also writable by group or other — a trivially exploitable privilege escalation
// (anyone can overwrite the file that runs as its owner). Legit SUID is 04755.
func collectWritableSuid() []FileEntry {
	seen := map[string]bool{}
	var out []FileEntry
	for _, dir := range append(capScanDirs, "/etc") {
		walkDirBounded(dir, 6, func(path string, info os.FileInfo) {
			mode := info.Mode()
			if mode.IsDir() || !mode.IsRegular() {
				return
			}
			real := realPath(path)
			if mode&(os.ModeSetuid|os.ModeSetgid) == 0 || mode.Perm()&0o022 == 0 || seen[real] {
				return
			}
			seen[real] = true
			fe := FileEntry{Path: path, Mode: octalMode(mode), SUID: mode&os.ModeSetuid != 0}
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				fe.UID = int(st.Uid)
			}
			out = append(out, fe)
		})
	}
	return out
}

// sudoGtfoBin returns the basename of the first GTFOBins shell-escape binary
// granted by an absolute path in a sudoers line, else "". A sudo grant to
// find/vim/awk/python/... is a direct privilege escalation (GTFOBins). The plain
// `ALL` grant has no path token, so the standard %sudo/%admin lines don't match.
// sudoExtraGtfo are binaries that are a sudo-privesc but rarely legit scoped sudo
// grants (unlike systemctl/apt which ops teams grant). iptables-save/-restore can
// write arbitrary files as root (e.g. overwrite /root/.ssh/authorized_keys, T6315).
var sudoExtraGtfo = map[string]bool{
	"iptables-save": true, "iptables-restore": true,
	"ip6tables-save": true, "ip6tables-restore": true, "nft": true,
}

func sudoGtfoBin(line string) string {
	for _, tok := range strings.Fields(line) {
		tok = strings.Trim(tok, ",")
		if !strings.HasPrefix(tok, "/") {
			continue
		}
		if b := filepath.Base(tok); gtfobinsSuidMatch(b) || sudoExtraGtfo[b] {
			return b
		}
	}
	return ""
}

// collectInitramfsHooks scans initramfs-tools hooks/scripts and dracut config for
// a download cradle / reverse shell. A hook here is baked into the initrd and runs
// at every boot as root (a stealthy persistence vector, EDR-T6250). Distro-shipped
// dracut module trees under /usr/lib are excluded to stay low-FP.
func collectInitramfsHooks() []StartupScript {
	var files []string
	walkDirBounded("/etc/initramfs-tools", 3, func(path string, info os.FileInfo) {
		if info.Mode().IsRegular() {
			files = append(files, path)
		}
	})
	for _, g := range []string{"/usr/share/initramfs-tools/hooks/*", "/etc/dracut.conf.d/*", "/etc/dracut.conf"} {
		if m, err := filepath.Glob(g); err == nil {
			files = append(files, m...)
		}
	}
	var out []StartupScript
	for _, p := range files {
		var hits []string
		for _, line := range nonEmptyLines(readFile(p)) {
			if looksLikeCradle(line) {
				hits = append(hits, strings.TrimSpace(line))
			}
		}
		if len(hits) > 0 {
			out = append(out, StartupScript{Path: p, SuspiciousLines: hits})
		}
	}
	return out
}

// collectSshTunnels returns live ssh client processes acting as a tunnel/pivot
// (dynamic SOCKS, remote forward, or persistent background tunnel).
func collectSshTunnels(procs []Process) []string {
	var out []string
	for _, p := range procs {
		if k := sshTunnelKind(p.Cmdline); k != "" {
			out = append(out, k+": "+p.Cmdline)
		}
	}
	return out
}

// collectUnverifiedRepos finds package repositories that accept unsigned packages
// (apt trusted=yes / allow-insecure, deb822 Trusted: yes, yum/dnf gpgcheck=0) —
// a supply-chain backdoor enabler (EDR-T6213/T6144).
func collectUnverifiedRepos() []string {
	seen := map[string]bool{}
	var out []string
	add := func(f, detail string) {
		e := f + ": " + detail
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	aptFiles := []string{"/etc/apt/sources.list"}
	if m, err := filepath.Glob("/etc/apt/sources.list.d/*"); err == nil {
		aptFiles = append(aptFiles, m...)
	}
	for _, f := range aptFiles {
		for _, line := range nonEmptyLines(readFile(f)) {
			if aptRepoInsecure(line) {
				add(f, strings.TrimSpace(line))
			}
		}
	}
	yumFiles := []string{"/etc/dnf/dnf.conf", "/etc/yum.conf"}
	for _, g := range []string{"/etc/yum.repos.d/*.repo", "/etc/dnf/*.conf"} {
		if m, err := filepath.Glob(g); err == nil {
			yumFiles = append(yumFiles, m...)
		}
	}
	for _, f := range yumFiles {
		for _, line := range nonEmptyLines(readFile(f)) {
			if yumGpgcheckOff(line) {
				add(f, strings.TrimSpace(line))
			}
		}
	}
	return out
}

// collectSysctlHardening scans sysctl config for lines that persistently disable
// a kernel hardening control (the config-file counterpart of the runtime Yama
// check). Only ADMIN-intent locations are scanned: /etc/sysctl.conf, /etc/sysctl.d
// and the runtime /run/sysctl.d. Vendor dirs (/usr/lib/sysctl.d, /lib/sysctl.d) are
// deliberately excluded — they hold distro DEFAULTS, and RHEL/Fedora ship
// kernel.yama.ptrace_scope=0 there by default (10-default-yama-scope.conf), which
// is not "someone disabling hardening" (it caused a false positive on every
// RHEL-family host, doubled by the /lib -> /usr/lib symlink).
// yamaVendorDefault returns the distro's vendor-shipped kernel.yama.ptrace_scope
// default (from /usr/lib/sysctl.d, /lib/sysctl.d) or -1 if none ships one. Used to
// tell a genuine weakening (runtime 0 where the vendor default is 1, e.g. on
// Debian/Ubuntu) from the RHEL/Fedora default (vendor ships 0).
func yamaVendorDefault() int {
	var files []string
	for _, g := range []string{"/usr/lib/sysctl.d/*.conf", "/lib/sysctl.d/*.conf"} {
		if m, err := filepath.Glob(g); err == nil {
			files = append(files, m...)
		}
	}
	def := -1
	for _, f := range files {
		for _, line := range nonEmptyLines(readFile(f)) {
			t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "-"))
			key, val, ok := strings.Cut(t, "=")
			if !ok || strings.ReplaceAll(strings.TrimSpace(key), "/", ".") != "kernel.yama.ptrace_scope" {
				continue
			}
			if n, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
				def = n // later drop-ins win (lexical order is close enough for the default)
			}
		}
	}
	return def
}

func collectSysctlHardening() []string {
	files := []string{"/etc/sysctl.conf"}
	for _, g := range []string{"/etc/sysctl.d/*.conf", "/run/sysctl.d/*.conf"} {
		if m, err := filepath.Glob(g); err == nil {
			files = append(files, m...)
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		for _, line := range nonEmptyLines(readFile(f)) {
			if kv := sysctlHardeningDisabled(line); kv != "" {
				e := f + ": " + kv
				if !seen[e] {
					seen[e] = true
					out = append(out, e)
				}
			}
		}
	}
	return out
}

// collectSystemdTimers returns every *.timer unit paired with the ExecStart of
// the .service it activates. A timer is systemd's cron; a time-triggered service
// running from a writable path or carrying a reverse shell is durable persistence
// the .service ExecStart scan alone would only catch if the service were enabled.
func collectSystemdTimers() []SystemdTimer {
	dirs := []string{"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}
	// Index service ExecStart by unit name so a timer can resolve its target.
	execByUnit := map[string]string{}
	for _, d := range dirs {
		files, _ := filepath.Glob(d + "/*.service")
		for _, f := range files {
			name := filepath.Base(f)
			if _, seen := execByUnit[name]; seen {
				continue // first match wins (etc overrides lib)
			}
			for _, line := range nonEmptyLines(readFile(f)) {
				if t := strings.TrimSpace(line); strings.HasPrefix(t, "ExecStart=") {
					execByUnit[name] = strings.TrimSpace(strings.TrimPrefix(t, "ExecStart="))
					break
				}
			}
		}
	}
	var out []SystemdTimer
	seen := map[string]bool{}
	for _, d := range dirs {
		files, _ := filepath.Glob(d + "/*.timer")
		for _, f := range files {
			name := filepath.Base(f)
			if seen[name] {
				continue
			}
			seen[name] = true
			tm := SystemdTimer{Name: name, Unit: strings.TrimSuffix(name, ".timer") + ".service"}
			var sched []string
			for _, line := range nonEmptyLines(readFile(f)) {
				t := strings.TrimSpace(line)
				switch {
				case strings.HasPrefix(t, "Unit="):
					tm.Unit = strings.TrimSpace(strings.TrimPrefix(t, "Unit="))
				case strings.HasPrefix(t, "OnCalendar="), strings.HasPrefix(t, "OnBootSec="),
					strings.HasPrefix(t, "OnUnitActiveSec="), strings.HasPrefix(t, "OnStartupSec="):
					sched = append(sched, t)
				}
			}
			tm.OnCalendar = strings.Join(sched, " ")
			tm.ExecStart = execByUnit[tm.Unit]
			out = append(out, tm)
		}
	}
	return out
}

// collectSelinux reports SELinux being disabled where it is installed: a
// non-enforcing /etc/selinux/config (RPM/SELinux distros) or a kernel cmdline
// that turns it off (selinux=0 / enforcing=0). On distros without SELinux the
// config file is absent, so nothing is reported — keeping this low-FP.
func collectSelinux() []string {
	var out []string
	if cfg := readFile("/etc/selinux/config"); cfg != "" {
		if mode := selinuxConfigMode(cfg); mode != "" {
			out = append(out, "/etc/selinux/config: SELINUX="+mode)
		}
	}
	cmdlines := []string{readFile("/proc/cmdline")}
	for _, line := range nonEmptyLines(readFile("/etc/default/grub")) {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "GRUB_CMDLINE_LINUX") {
			if _, v, ok := strings.Cut(t, "="); ok {
				cmdlines = append(cmdlines, v)
			}
		}
	}
	for _, c := range cmdlines {
		if tok := selinuxBootDisable(c); tok != "" {
			out = append(out, "kernel cmdline: "+tok)
			break
		}
	}
	return out
}

// collectDnfPlugins finds dnf/yum plugin Python files writable by a non-root
// user. Plugins execute as root on every package transaction, so a writable one
// lets a non-root user run code as root on the next dnf/yum run (T1546). Only
// non-root-writable files are reported; the dirs are absent on non-RPM distros.
func collectDnfPlugins() []DnfPlugin {
	var globs []string
	for _, base := range []string{
		"/usr/lib/python3*/site-packages/dnf-plugins", // RHEL/Fedora
		"/usr/lib/python3*/dist-packages/dnf-plugins", // Debian-packaged dnf
		"/usr/lib/yum-plugins",
	} {
		globs = append(globs, base+"/*.py")
	}
	var out []DnfPlugin
	seen := map[string]bool{}
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		for _, p := range matches {
			if seen[p] {
				continue
			}
			fi, err := os.Lstat(p)
			if err != nil || !fi.Mode().IsRegular() || !nonRootWritable(fi) {
				continue
			}
			seen[p] = true
			out = append(out, DnfPlugin{Path: p, Plugin: strings.TrimSuffix(filepath.Base(p), ".py")})
		}
	}
	return out
}

// collectProcMountHides finds bind mounts whose mount point is /proc/<pid> — a
// rootkit hides a process by mounting an empty/fake dir over its /proc entry
// (the PID still appears in readdir, so the hidden-process readdir check misses
// it). Read from /proc/self/mountinfo; legit systems never mount over /proc/<pid>.
func collectProcMountHides() []string {
	data := readFile("/proc/self/mountinfo")
	if data == "" {
		return nil
	}
	var out []string
	for _, line := range nonEmptyLines(data) {
		f := strings.Fields(line)
		if len(f) < 5 { // field 5 (index 4) is the mount point
			continue
		}
		mp := f[4]
		if rest, ok := strings.CutPrefix(mp, "/proc/"); ok {
			if _, err := strconv.Atoi(rest); err == nil {
				out = append(out, mp)
			}
		}
	}
	return out
}

// collectSudoers collects notable sudoers lines (NOPASSWD/SETENV/writable-path
// commands) from /etc/sudoers and /etc/sudoers.d/*. The rule decides which are
// dangerous; we keep the line so analysts see the exact grant.
func collectSudoers() []SudoRule {
	files := []string{"/etc/sudoers"}
	if extra, err := filepath.Glob("/etc/sudoers.d/*"); err == nil {
		files = append(files, extra...)
	}
	var out []SudoRule
	for _, f := range files {
		for _, line := range nonEmptyLines(readFile(f)) {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "@includedir") {
				continue
			}
			gtfo := sudoGtfoBin(t)
			envKeepLD := strings.Contains(t, "env_keep") && strings.Contains(t, "LD_")
			if gtfo != "" || envKeepLD || strings.Contains(t, "NOPASSWD") || strings.Contains(t, "SETENV") ||
				strings.Contains(t, "/tmp/") || strings.Contains(t, "/dev/shm/") || strings.Contains(t, "/home/") {
				out = append(out, SudoRule{Path: f, Line: t, GtfoBin: gtfo})
			}
		}
	}
	return out
}

// collectNfsExports returns the active export definitions from /etc/exports.
func collectNfsExports() []string {
	var out []string
	for _, line := range nonEmptyLines(readFile("/etc/exports")) {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	return out
}

// collectWorldWritableSensitive returns sensitive files writable by "other".
func collectWorldWritableSensitive() []string {
	sensitive := []string{
		"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers",
		"/etc/ssh/sshd_config", "/etc/crontab", "/etc/ld.so.preload",
	}
	var out []string
	for _, p := range sensitive {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode().Perm()&0o002 != 0 {
			out = append(out, p)
		}
	}
	return out
}

// collectUdev scans admin/runtime udev rules (not the distro /lib set) for
// directives that execute programs — RUN+= / IMPORT{program}.
func collectUdev() []UdevRule {
	var out []UdevRule
	for _, dir := range []string{"/etc/udev/rules.d", "/run/udev/rules.d"} {
		files, err := filepath.Glob(dir + "/*.rules")
		if err != nil {
			continue
		}
		for _, f := range files {
			for _, line := range nonEmptyLines(readFile(f)) {
				t := strings.TrimSpace(line)
				if t == "" || strings.HasPrefix(t, "#") {
					continue
				}
				if strings.Contains(t, "RUN") || strings.Contains(t, "IMPORT{program}") {
					out = append(out, UdevRule{Path: f, Rule: t})
				}
			}
		}
	}
	return out
}

// collectBinfmt reads registered binfmt_misc handlers and their interpreters.
func collectBinfmt() []BinfmtEntry {
	entries, err := os.ReadDir("/proc/sys/fs/binfmt_misc")
	if err != nil {
		return nil
	}
	var out []BinfmtEntry
	for _, e := range entries {
		name := e.Name()
		if name == "register" || name == "status" {
			continue
		}
		for _, line := range nonEmptyLines(readFile("/proc/sys/fs/binfmt_misc/" + name)) {
			if strings.HasPrefix(line, "interpreter ") {
				out = append(out, BinfmtEntry{Name: name, Interpreter: strings.TrimSpace(strings.TrimPrefix(line, "interpreter "))})
			}
		}
	}
	return out
}

// collectStartupScripts scans boot/login-time script locations for lines that
// look like a download cradle or reverse shell.
func collectStartupScripts() []StartupScript {
	var paths []string
	paths = append(paths, "/etc/rc.local", "/etc/rc.d/rc.local")
	for _, g := range []string{"/etc/grub.d/*", "/etc/init.d/*", "/etc/profile.d/*", "/etc/update-motd.d/*"} {
		if files, err := filepath.Glob(g); err == nil {
			paths = append(paths, files...)
		}
	}
	var out []StartupScript
	for _, p := range paths {
		data := readFile(p)
		if data == "" {
			continue
		}
		var hits []string
		for _, line := range nonEmptyLines(data) {
			if looksLikeCradle(line) {
				hits = append(hits, strings.TrimSpace(line))
			}
		}
		if len(hits) > 0 {
			out = append(out, StartupScript{Path: p, SuspiciousLines: hits})
		}
	}
	return out
}

func looksLikeCradle(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return false
	}
	for _, pat := range []string{"/dev/tcp/", "bash -i", "sh -i", "mkfifo", "base64 -d", "ncat ", "nc -e"} {
		if strings.Contains(t, pat) {
			return true
		}
	}
	// curl/wget piped into a shell
	if (strings.Contains(t, "curl ") || strings.Contains(t, "wget ")) &&
		(strings.Contains(t, "|sh") || strings.Contains(t, "| sh") || strings.Contains(t, "|bash") || strings.Contains(t, "| bash")) {
		return true
	}
	return false
}

// collectPAM parses /etc/pam.d/* into module references. A module given by an
// absolute path outside the standard security dirs is a strong backdoor signal.
func collectPAM() []PAMEntry {
	files, err := filepath.Glob("/etc/pam.d/*")
	if err != nil {
		return nil
	}
	var out []PAMEntry
	for _, f := range files {
		svc := filepath.Base(f)
		for _, line := range nonEmptyLines(readFile(f)) {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "@") {
				continue
			}
			fields := strings.Fields(t)
			if len(fields) < 3 {
				continue
			}
			mod := fields[2]
			e := PAMEntry{Service: svc, Type: strings.TrimPrefix(fields[0], "-"), Module: filepath.Base(mod)}
			if strings.HasPrefix(mod, "/") {
				e.Path = mod
			}
			if len(fields) > 3 {
				e.Args = strings.Join(fields[3:], " ")
			}
			out = append(out, e)
		}
	}
	return out
}

// collectPythonPth finds *.pth files in site/dist-packages that contain code
// (lines starting with "import"), which Python executes on every startup.
func collectPythonPth() []PthFile {
	globs := []string{
		"/usr/lib/python*/site-packages/*.pth",
		"/usr/lib/python*/dist-packages/*.pth",
		"/usr/local/lib/python*/site-packages/*.pth",
		"/usr/local/lib/python*/dist-packages/*.pth",
	}
	var out []PthFile
	for _, g := range globs {
		files, err := filepath.Glob(g)
		if err != nil {
			continue
		}
		for _, f := range files {
			var imports []string
			for _, line := range nonEmptyLines(readFile(f)) {
				t := strings.TrimSpace(line)
				// .pth executes lines starting with "import"; flag only those that
				// also carry a code-execution indicator. Plain namespace/setuptools
				// .pth lines (os.path/importlib/os.environ) are benign and skipped.
				if (strings.HasPrefix(t, "import ") || strings.HasPrefix(t, "import\t")) && pthLooksMalicious(t) {
					imports = append(imports, t)
				}
			}
			if len(imports) > 0 {
				out = append(out, PthFile{Path: f, ImportLines: imports})
			}
		}
	}
	return out
}

// pthLooksMalicious reports whether a .pth import line carries a code-execution
// indicator, separating real payloads from benign namespace/setuptools boilerplate.
func pthLooksMalicious(line string) bool {
	// Note: __import__() is intentionally NOT here — legit namespace/setuptools
	// .pth files use it for dynamic imports; it is too common to flag.
	for _, p := range []string{
		"os.system", "subprocess", ".popen", "popen(", "exec(", "eval(",
		"socket.", "base64", "pty.", "/dev/tcp", "urllib",
		"compile(", "marshal.loads", "requests.", "fromhex",
	} {
		if strings.Contains(line, p) {
			return true
		}
	}
	return false
}

// collectImmutable checks the immutable (chattr +i) attribute on sensitive files;
// attackers set it to keep a backdoor from being removed.
func collectImmutable() []string {
	sensitive := []string{
		"/etc/passwd", "/etc/shadow", "/etc/ld.so.preload", "/etc/crontab",
		"/etc/sudoers", "/root/.ssh/authorized_keys",
	}
	var out []string
	for _, p := range sensitive {
		if isImmutable(p) {
			out = append(out, p)
		}
	}
	return out
}

// fsImmutableFL is FS_IMMUTABLE_FL from <linux/fs.h>.
const fsImmutableFL = 0x00000010

func isImmutable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	flags, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return false
	}
	return flags&fsImmutableFL != 0
}

// collectHiddenModules flags LKM rootkits hiding from the module list: modules in
// /proc/modules but absent from /sys/module, and modules that still own symbols in
// /proc/kallsyms ([mod]) yet are absent from /proc/modules (didn't scrub kallsyms).
func collectHiddenModules(kallsymsMods map[string]bool) []string {
	proc := map[string]bool{}
	for _, line := range nonEmptyLines(readFile("/proc/modules")) {
		if f := strings.Fields(line); len(f) > 0 {
			proc[f[0]] = true
		}
	}
	sys := map[string]bool{}
	if entries, err := os.ReadDir("/sys/module"); err == nil {
		for _, e := range entries {
			sys[e.Name()] = true
		}
	}
	seen := map[string]bool{}
	var hidden []string
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			hidden = append(hidden, name)
		}
	}
	for name := range proc {
		if !sys[name] {
			add(name)
		}
	}
	// Pseudo-modules: kallsyms tags BPF programs as [bpf] and ftrace trampolines as
	// [ftrace] / [__builtin__ftrace] — built-in, never in /proc/modules, not rootkits.
	// The __builtin__* family appears once an eBPF tool (e.g. our own Tetragon sensor)
	// installs ftrace/bpf trampolines; excluding it avoids flagging the sensor host.
	pseudo := map[string]bool{"bpf": true, "ftrace": true}
	for name := range kallsymsMods {
		if !pseudo[name] && !strings.HasPrefix(name, "__builtin__") && !proc[name] && !sys[name] {
			add(name)
		}
	}
	return hidden
}

// collectKallsyms reads /proc/kallsyms and returns (1) the set of module names
// owning symbols (the "[mod]" suffix) and (2) symbols whose names match known
// rootkit/hooking patterns. kallsyms addresses may be zeroed by kptr_restrict, but
// names and module attribution remain visible to root.
func collectKallsyms() (map[string]bool, []string) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	mods := map[string]bool{}
	var suspicious []string
	suspSeen := map[string]bool{}
	patterns := []string{"diamorphine", "kovid", "reptile", "suterusu", "khook",
		"ftrace_hook", "rootkit", "r00t", "module_hide", "hide_tcp", "hook_kill",
		"hacked_", "magic_packet"}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		name := fields[2]
		if len(fields) >= 4 { // 4th field is "[module]"
			mods[strings.Trim(fields[3], "[]")] = true
		}
		lower := strings.ToLower(name)
		for _, p := range patterns {
			if strings.Contains(lower, p) && !suspSeen[name] {
				suspSeen[name] = true
				suspicious = append(suspicious, name)
				break
			}
		}
	}
	return mods, suspicious
}

// collectAtJobs scans the at(1) spool for jobs carrying suspicious content.
func collectAtJobs() []StartupScript {
	var dirs []string
	for _, d := range []string{"/var/spool/cron/atjobs", "/var/spool/at", "/var/spool/atjobs"} {
		dirs = append(dirs, d)
	}
	var out []StartupScript
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			p := filepath.Join(d, e.Name())
			var hits []string
			for _, line := range nonEmptyLines(readFile(p)) {
				if looksLikeCradle(line) {
					hits = append(hits, strings.TrimSpace(line))
				}
			}
			if len(hits) > 0 {
				out = append(out, StartupScript{Path: p, SuspiciousLines: hits})
			}
		}
	}
	return out
}

// collectTaint records the kernel taint bitmask and the security-relevant flags
// (F=forced module load, O=out-of-tree, E=unsigned, P=proprietary).
func collectTaint(facts map[string]any) {
	n, _ := strconv.Atoi(strings.TrimSpace(readFile("/proc/sys/kernel/tainted")))
	facts["kernel_tainted"] = n
	var b strings.Builder
	for bit, ch := range map[int]byte{0: 'P', 1: 'F', 12: 'O', 13: 'E'} {
		if n&(1<<bit) != 0 {
			b.WriteByte(ch)
		}
	}
	facts["kernel_taint_chars"] = b.String()
}

// collectAccounts parses /etc/passwd.
func collectAccounts() []Account {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Account
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(fields[2])
		gid, _ := strconv.Atoi(fields[3])
		out = append(out, Account{Name: fields[0], UID: uid, GID: gid, Home: fields[5], Shell: fields[6]})
	}
	return out
}

func collectHostInfo() HostInfo {
	h := HostInfo{Arch: runtime.GOARCH}
	h.Hostname = strings.TrimSpace(readFile("/proc/sys/kernel/hostname"))
	h.Kernel = strings.TrimSpace(readFile("/proc/sys/kernel/osrelease"))
	h.OS = osPrettyName()
	if up := strings.Fields(readFile("/proc/uptime")); len(up) > 0 {
		if f, err := strconv.ParseFloat(up[0], 64); err == nil {
			h.UptimeSec = int64(f)
			h.BootTime = time.Now().UTC().Add(-time.Duration(f) * time.Second)
		}
	}
	return h
}

func osPrettyName() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return ""
}

func collectProcesses(selfPID int, errs *[]string) []Process {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		*errs = append(*errs, "read /proc: "+err.Error())
		return nil
	}
	var procs []Process
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a pid dir
		}
		if pid == selfPID {
			continue // never report the ephemeral probe itself
		}
		base := "/proc/" + e.Name()
		p := Process{PID: pid}

		// exe: detect deleted (suffix " (deleted)") and memfd-backed executables.
		if target, err := os.Readlink(base + "/exe"); err == nil {
			if strings.HasSuffix(target, " (deleted)") {
				p.ExeDeleted = true
				target = strings.TrimSuffix(target, " (deleted)")
			}
			if strings.HasPrefix(target, "/memfd:") || strings.HasPrefix(target, "memfd:") {
				p.ExeMemfd = true
			}
			p.Exe = target
		}
		p.Comm = strings.TrimSpace(readFile(base + "/comm"))
		p.Cmdline = readCmdline(base + "/cmdline")
		if cwd, err := os.Readlink(base + "/cwd"); err == nil {
			p.Cwd = cwd
		}
		// Empty environ on a real (exe-backed) process is an anti-forensics signal
		// (BPFDoor wipes it). Only set it when we could actually read environ, so a
		// permission-denied read on another user's process is not a false positive.
		if p.Exe != "" {
			if data, err := os.ReadFile(base + "/environ"); err == nil && len(data) == 0 {
				p.EnvironEmpty = true
			}
		}
		readProcStatus(base+"/status", &p)
		procs = append(procs, p)
	}
	markPacketSniffers(procs)
	return procs
}

// markPacketSniffers flags processes holding an AF_PACKET (raw) socket — the
// network-sniffing primitive used by BPFDoor and packet backdoors. Maps the
// packet-socket inodes from /proc/net/packet to owning PIDs via /proc/*/fd.
func markPacketSniffers(procs []Process) {
	inodes := packetSocketInodes()
	if len(inodes) == 0 {
		return
	}
	inodeToPID := socketInodeToPID()
	pidHasPacket := map[int]bool{}
	for ino := range inodes {
		if pid, ok := inodeToPID[ino]; ok {
			pidHasPacket[pid] = true
		}
	}
	for i := range procs {
		if pidHasPacket[procs[i].PID] {
			procs[i].PacketSocket = true
		}
	}
}

// packetSocketInodes returns the inode set from /proc/net/packet (one per AF_PACKET socket).
func packetSocketInodes() map[string]bool {
	f, err := os.Open("/proc/net/packet")
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) >= 9 {
			out[fields[8]] = true // Inode is the last column
		}
	}
	return out
}

// socketInodeToPID scans /proc/*/fd for socket:[inode] symlinks.
func socketInodeToPID() map[string]int {
	out := map[string]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir("/proc/" + e.Name() + "/fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink("/proc/" + e.Name() + "/fd/" + fd.Name())
			if err != nil {
				continue
			}
			if strings.HasPrefix(target, "socket:[") {
				ino := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
				out[ino] = pid
			}
		}
	}
	return out
}

func readCmdline(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

func readProcStatus(path string, p *Process) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "PPid:"):
			p.PPID, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
		case strings.HasPrefix(line, "Uid:"):
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fields) > 0 {
				p.UID, _ = strconv.Atoi(fields[0])
			}
		}
	}
}

func collectListeners() []Socket {
	var out []Socket
	out = append(out, parseProcNet("/proc/net/tcp", "tcp")...)
	out = append(out, parseProcNet("/proc/net/tcp6", "tcp")...)
	return out
}

// parseProcNet parses /proc/net/tcp{,6}; only LISTEN sockets (state 0x0A) are kept.
// PID/comm mapping (via /proc/*/fd socket inodes) is left for a later pass.
func parseProcNet(path, proto string) []Socket {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Socket
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // header
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		ip, port := parseHexAddr(fields[1])
		out = append(out, Socket{Proto: proto, LAddr: ip, LPort: port})
	}
	return out
}

func parseHexAddr(s string) (string, int) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0
	}
	port, _ := strconv.ParseInt(parts[1], 16, 32)
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", int(port)
	}
	switch len(raw) {
	case 4: // IPv4, little-endian
		v := binary.LittleEndian.Uint32(raw)
		ip := net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
		return ip.String(), int(port)
	case 16:
		return net.IP(raw).String(), int(port)
	}
	return "", int(port)
}

func collectPersistence(accounts []Account) Persistence {
	var p Persistence
	// ld.so.preload
	p.LDPreload.LDSoPreload = "/etc/ld.so.preload"
	for _, line := range nonEmptyLines(readFile("/etc/ld.so.preload")) {
		p.LDPreload.Entries = append(p.LDPreload.Entries, strings.TrimSpace(line))
	}
	// cron: /etc/crontab + /etc/cron.d/*
	p.Cron = append(p.Cron, parseCronFile("/etc/crontab")...)
	if files, err := filepath.Glob("/etc/cron.d/*"); err == nil {
		for _, f := range files {
			p.Cron = append(p.Cron, parseCronFile(f)...)
		}
	}
	p.SystemdUnits = collectSystemdUnits()
	p.AuthorizedKeys = collectAuthorizedKeys(accounts)
	return p
}

// collectSystemdUnits parses ExecStart from .service unit files in the common
// search paths. Used to spot services that launch from writable/tmp locations.
func collectSystemdUnits() []SystemdUnit {
	var out []SystemdUnit
	dirs := []string{"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}
	for _, d := range dirs {
		files, err := filepath.Glob(d + "/*.service")
		if err != nil {
			continue
		}
		for _, f := range files {
			var u SystemdUnit
			u.Name = filepath.Base(f)
			var pre, env []string
			for _, line := range nonEmptyLines(readFile(f)) {
				t := strings.TrimSpace(line)
				switch {
				case strings.HasPrefix(t, "ExecStart="):
					u.ExecStart = strings.TrimSpace(strings.TrimPrefix(t, "ExecStart="))
				case strings.HasPrefix(t, "ExecStartPre="), strings.HasPrefix(t, "ExecStartPost="), strings.HasPrefix(t, "ExecReload="):
					pre = append(pre, strings.TrimSpace(t[strings.IndexByte(t, '=')+1:]))
				case strings.HasPrefix(t, "Environment="):
					env = append(env, strings.TrimSpace(strings.TrimPrefix(t, "Environment=")))
				}
			}
			u.ExecPre = strings.Join(pre, " | ")
			u.Environment = strings.Join(env, " ")
			if u.ExecStart != "" || u.ExecPre != "" || u.Environment != "" {
				out = append(out, u)
			}
		}
	}
	return out
}

// collectAuthorizedKeys reads authorized_keys for each account's home and marks
// whether the owning account is a service account (nologin/false shell).
func collectAuthorizedKeys(accounts []Account) []AuthKeysFile {
	nologin := map[string]bool{}
	homes := map[string]string{}
	for _, a := range accounts {
		homes[a.Name] = a.Home
		nologin[a.Name] = strings.HasSuffix(a.Shell, "nologin") || strings.HasSuffix(a.Shell, "false")
	}
	var out []AuthKeysFile
	for name, home := range homes {
		if home == "" {
			continue
		}
		for _, fn := range []string{"authorized_keys", "authorized_keys2"} {
			path := home + "/.ssh/" + fn
			data := readFile(path)
			if data == "" {
				continue
			}
			akf := AuthKeysFile{Path: path, Owner: name, OwnerNologin: nologin[name]}
			for _, line := range nonEmptyLines(data) {
				t := strings.TrimSpace(line)
				if t == "" || strings.HasPrefix(t, "#") {
					continue
				}
				akf.Keys = append(akf.Keys, parseAuthKey(t))
			}
			if len(akf.Keys) > 0 {
				out = append(out, akf)
			}
		}
	}
	return out
}

func parseAuthKey(line string) AuthKey {
	fields := strings.Fields(line)
	// Find the key-type token (options, if any, precede it).
	typeIdx := -1
	for i, f := range fields {
		if strings.HasPrefix(f, "ssh-") || strings.HasPrefix(f, "ecdsa-") || strings.HasPrefix(f, "sk-") {
			typeIdx = i
			break
		}
	}
	var k AuthKey
	if typeIdx < 0 || typeIdx+1 >= len(fields) {
		return k
	}
	k.Type = fields[typeIdx]
	sum := sha256.Sum256([]byte(fields[typeIdx+1]))
	k.SHA256 = hex.EncodeToString(sum[:])
	if typeIdx > 0 {
		k.Options = strings.Join(fields[:typeIdx], " ")
	}
	if typeIdx+2 < len(fields) {
		k.Comment = strings.Join(fields[typeIdx+2:], " ")
	}
	return k
}

// collectSuspiciousFiles does a shallow, bounded walk of writable/volatile dirs
// looking for setuid binaries, hidden executables, and files carrying capabilities
// — all unusual there.
func collectSuspiciousFiles() []FileEntry {
	var out []FileEntry
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm", "/dev"} {
		walkDirBounded(dir, 3, func(path string, info os.FileInfo) {
			mode := info.Mode()
			if mode.IsDir() || !mode.IsRegular() {
				return
			}
			base := filepath.Base(path)
			suid := mode&os.ModeSetuid != 0
			hidden := strings.HasPrefix(base, ".")
			execable := mode.Perm()&0o111 != 0
			caps := fileCaps(path)
			tool := fileToolMarker(path, info.Size())
			if !suid && !(hidden && execable) && caps == "" && tool == "" {
				return
			}
			fe := FileEntry{Path: path, Mode: octalMode(mode), SUID: suid, Hidden: hidden, Caps: caps, Tool: tool}
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				fe.UID = int(st.Uid)
			}
			out = append(out, fe)
		})
	}
	return out
}

// octalMode renders permission bits including setuid/setgid/sticky (e.g. "4755").
func octalMode(m os.FileMode) string {
	v := uint32(m.Perm())
	if m&os.ModeSetuid != 0 {
		v |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		v |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		v |= 0o1000
	}
	return fmt.Sprintf("%04o", v)
}

// walkDirBounded walks dir up to maxDepth levels, ignoring errors per entry.
func walkDirBounded(dir string, maxDepth int, fn func(string, os.FileInfo)) {
	var walk func(string, int)
	walk = func(d string, depth int) {
		entries, err := os.ReadDir(d)
		if err != nil {
			return
		}
		for _, e := range entries {
			p := filepath.Join(d, e.Name())
			info, err := e.Info()
			if err != nil {
				continue
			}
			if e.IsDir() {
				if depth < maxDepth {
					walk(p, depth+1)
				}
				continue
			}
			fn(p, info)
		}
	}
	walk(dir, 0)
}

func parseCronFile(path string) []CronEntry {
	var out []CronEntry
	for _, line := range nonEmptyLines(readFile(path)) {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, CronEntry{Path: path, Line: t})
	}
	return out
}

func collectModules() []KernelModule {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []KernelModule
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		m := KernelModule{Name: name, Signed: true}
		// Best-effort taint flags: 'O' = out-of-tree, 'E' = unsigned.
		if taint := strings.TrimSpace(readFile("/sys/module/" + name + "/taint")); taint != "" {
			m.OutOfTree = strings.Contains(taint, "O")
			m.Signed = !strings.Contains(taint, "E")
		}
		out = append(out, m)
	}
	return out
}

// --- helpers ---

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

var _ = fmt.Sprintf // reserved for future structured errors
