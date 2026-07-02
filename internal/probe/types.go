// Package probe defines the wire contracts shared between bladedr-server and
// bladedr-probe: the rule bundle (server -> probe), the scan result and the
// host state snapshot (probe -> server). All three are versioned via a `schema`
// field so collectors can add fields without breaking older servers.
package probe

import "time"

// Schema identifiers for the three contracts (DESIGN section 4).
const (
	SchemaRuleBundle = "bladedr.rulebundle/v1"
	SchemaScanResult = "bladedr.scanresult/v1"
	SchemaSnapshot   = "bladedr.snapshot/v1"
)

// ----------------------------------------------------------------------------
// Input: rule bundle (server -> probe). Carries only the match logic; rule
// metadata (severity/score/mitre) stays on the server and is attached during
// enrichment, so scoring can be re-tuned without re-scanning.
// ----------------------------------------------------------------------------

type RuleBundle struct {
	Schema        string       `json:"schema"`
	BundleVersion string       `json:"bundle_version"`
	Rules         []BundleRule `json:"rules"`
}

// BundleRule is the probe-side view of a rule: an optional collection to iterate
// (Foreach), a CEL boolean (When), evidence expressions and dedup-key
// expressions. When Foreach is empty the rule is host-level (evaluated once).
type BundleRule struct {
	ID       string            `json:"id"`
	Foreach  string            `json:"foreach,omitempty"`
	When     string            `json:"when"`
	Evidence map[string]string `json:"evidence,omitempty"`
	Dedup    []string          `json:"dedup,omitempty"`
}

// ----------------------------------------------------------------------------
// Output: scan result (probe -> server).
// ----------------------------------------------------------------------------

type ScanResult struct {
	Schema          string    `json:"schema"`
	ProbeVersion    string    `json:"probe_version"`
	BundleVersion   string    `json:"bundle_version"`
	CollectedAt     time.Time `json:"collected_at"`
	Host            HostInfo  `json:"host"`
	Findings        []Finding `json:"findings"`
	CollectorErrors []string  `json:"collector_errors"`
	// StateDigest is a compact per-category set of stable item identities (listening
	// ports, modules, accounts, authorized keys, cron, systemd units) used by the
	// server's baseline/drift engine. Always present; small.
	StateDigest map[string][]string `json:"state_digest,omitempty"`
	// Snapshot is populated only when the probe is run with --emit-snapshot; it
	// allows re-evaluating new rules against old state without re-entering the host.
	Snapshot *Snapshot `json:"snapshot,omitempty"`
}

// Finding is a single rule match produced on the host. The server enriches it
// (severity/score/mitre/host context/tags) into a stored observation.
type Finding struct {
	RuleID     string         `json:"rule_id"`
	Evidence   map[string]any `json:"evidence"`
	DedupKey   string         `json:"dedup_key"`
	ObservedAt time.Time      `json:"observed_at"`
}

// ----------------------------------------------------------------------------
// Host state snapshot. This is the structure the CEL rules are evaluated
// against; field names match the `snapshot.*` / `item.*` paths used in rules.
// ----------------------------------------------------------------------------

type Snapshot struct {
	Schema                 string            `json:"schema"`
	ProbeVersion           string            `json:"probe_version"`
	CollectedAt            time.Time         `json:"collected_at"`
	Host                   HostInfo          `json:"host"`
	Processes              []Process         `json:"processes"`
	ListeningSockets       []Socket          `json:"listening_sockets"`
	Persistence            Persistence       `json:"persistence"`
	KernelModules          []KernelModule    `json:"kernel_modules"`
	SuspiciousFiles        []FileEntry       `json:"suspicious_files"`
	Accounts               []Account         `json:"accounts"`
	KernelLog              []KernelLogEntry  `json:"kernel_log"`
	PAMModules             []PAMEntry        `json:"pam_modules"`
	PthFiles               []PthFile         `json:"pth_files"`
	ImmutableFiles         []string          `json:"immutable_files"`
	HiddenModules          []string          `json:"hidden_modules"` // in /proc/modules but not /sys/module
	UdevRules              []UdevRule        `json:"udev_rules"`
	BinfmtEntries          []BinfmtEntry     `json:"binfmt_entries"`
	StartupScripts         []StartupScript   `json:"startup_scripts"`
	ShellInit              []StartupScript   `json:"shell_init"`               // .bashrc/profile with suspicious lines
	Supervisor             []SupervisorProg  `json:"supervisor"`               // supervisord programs
	HiddenPIDs             []int             `json:"hidden_pids"`              // stat-accessible but not in /proc readdir
	AtJobs                 []StartupScript   `json:"at_jobs"`                  // at(1) spool jobs with suspicious lines
	SuspiciousKsyms        []string          `json:"suspicious_ksyms"`         // /proc/kallsyms symbols matching rootkit names
	SudoRules              []SudoRule        `json:"sudo_rules"`               // notable sudoers lines (NOPASSWD/SETENV/writable)
	NfsExports             []string          `json:"nfs_exports"`              // /etc/exports lines
	WorldWritableSensitive []string          `json:"world_writable_sensitive"` // sensitive files writable by other
	PathHijack             []string          `json:"path_hijack"`              // cwd/world-writable entries in system PATH
	OutboundConns          []Conn            `json:"outbound_conns"`           // established conns to suspicious remote ports
	PasswordlessAccounts   []string          `json:"passwordless_accounts"`    // /etc/shadow entries with empty hash
	PrivGroupMembers       []GroupMember     `json:"priv_group_members"`       // members of sudo/wheel/docker/root/...
	WebShells              []StartupScript   `json:"web_shells"`               // web-root files with webshell code patterns
	BpfPinned              []string          `json:"bpf_pinned"`               // pinned objects under /sys/fs/bpf
	BpfPrograms            []BpfProg         `json:"bpf_programs"`             // loaded eBPF programs (bpf(BPF_PROG_GET_NEXT_ID))
	PackageHooks           []PackageHook     `json:"package_hooks"`            // suspicious apt/dpkg hooks (cradle/writable command)
	WebServerModules       []WebServerModule `json:"web_server_modules"`       // apache/nginx modules loaded from a writable path
	ModprobeCommands       []ModprobeCommand `json:"modprobe_commands"`        // modprobe.d install/remove running an arbitrary command
	LdSoConf               []LdConfEntry     `json:"ld_so_conf"`               // ld.so.conf{,.d} library dirs under a writable path
	EnvPreload             []StartupScript   `json:"env_preload"`              // global env files setting LD_PRELOAD / writable LD_LIBRARY_PATH
	SuidBinaries           []FileEntry       `json:"suid_binaries"`            // SUID shell-escape/interpreter binaries (GTFOBins privesc)
	WritablePersistence    []string          `json:"writable_persistence"`     // root-executed config files writable by a non-root user
	DangerousCapabilities  []FileEntry       `json:"dangerous_capabilities"`   // binaries with a privesc file capability (Caps = decoded names)
	CronPathHijack         []string          `json:"cron_path_hijack"`         // cron PATH= lines with a writable/relative dir
	NsswitchUnusual        []string          `json:"nsswitch_unusual"`         // nsswitch.conf modules outside the standard set (libnss backdoor)
	ProcMountHides         []string          `json:"proc_mount_hides"`         // bind mounts over /proc/<pid> (process-hiding rootkit)
	SysctlHardeningOff     []string          `json:"sysctl_hardening_off"`     // sysctl config disabling a hardening control (ptrace_scope=0, ...)
	UnverifiedRepos        []string          `json:"unverified_repos"`         // pkg repos accepting unsigned packages (apt trusted=yes / dnf gpgcheck=0)
	SshTunnels             []string          `json:"ssh_tunnels"`              // live ssh client tunnels (-D SOCKS / -R / persistent -N -f)
	InitramfsHooks         []StartupScript   `json:"initramfs_hooks"`          // initramfs/dracut hook with a cradle (boot-time persistence)
	K8sStaticPods          []StartupScript   `json:"k8s_static_pods"`          // non-standard privileged/host* static pod manifests (k8s persistence)
	ExposedKubeconfigs     []string          `json:"exposed_kubeconfigs"`      // kubeconfig/admin.conf with creds, readable by non-root
	PromiscInterfaces      []string          `json:"promisc_interfaces"`       // non-virtual NICs in promiscuous mode (sniffer); bridges/taps filtered
	OutOfTreeModules       []string          `json:"out_of_tree_modules"`      // taint/out-of-tree dmesg loads, minus legit DKMS (zfs/nvidia/vbox/...)
	ShellHistoryTampering  []StartupScript   `json:"shell_history_tampering"`  // shell rc disabling history (HISTFILE=/dev/null, HISTSIZE=0, unset)
	TamperedLogs           []string          `json:"tampered_logs"`            // /var/log files replaced by a symlink (e.g. to /dev/null)
	SuspiciousShells       []string          `json:"suspicious_shells"`        // accounts whose login shell is an interpreter or under a writable path
	WritableSuid           []FileEntry       `json:"writable_suid"`            // SUID/SGID binaries also writable by group/other (trivial privesc)
	XdgAutostart           []StartupScript   `json:"xdg_autostart"`            // XDG autostart .desktop entries with a cradle/writable Exec
	SshClientCommands      []StartupScript   `json:"ssh_client_commands"`      // ssh_config LocalCommand / cradle ProxyCommand (exec on connect)
	LibVersions            []LibVersion      `json:"lib_versions"`             // versions of key shared libraries (supply-chain)
	SystemdTimers          []SystemdTimer    `json:"systemd_timers"`           // .timer units with the ExecStart of the service they activate (time-triggered persistence)
	SelinuxDisabled        []string          `json:"selinux_disabled"`         // SELinux turned off where it is installed (/etc/selinux/config or kernel cmdline)
	DnfPlugins             []DnfPlugin       `json:"dnf_plugins"`              // dnf/yum plugin files writable by a non-root user (runs as root every transaction)
	Facts                  map[string]any    `json:"facts"`
	CollectorErrors        []string          `json:"collector_errors"`
}

type HostInfo struct {
	Hostname  string    `json:"hostname"`
	Kernel    string    `json:"kernel"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	BootTime  time.Time `json:"boot_time,omitempty"`
	UptimeSec int64     `json:"uptime_s"`
}

type Process struct {
	PID          int       `json:"pid"`
	PPID         int       `json:"ppid"`
	UID          int       `json:"uid"`
	Comm         string    `json:"comm"`
	Exe          string    `json:"exe"`
	ExeDeleted   bool      `json:"exe_deleted"`
	ExeMemfd     bool      `json:"exe_memfd"`
	Cmdline      string    `json:"cmdline"`
	Cwd          string    `json:"cwd"`
	EnvironEmpty bool      `json:"environ_empty"` // /proc/PID/environ wiped (BPFDoor anti-forensics)
	PacketSocket bool      `json:"packet_socket"` // holds an AF_PACKET (raw) socket — a sniffer
	StartTime    time.Time `json:"start_time,omitempty"`
	Listening    []Socket  `json:"listening,omitempty"`
}

type Socket struct {
	Proto string `json:"proto"`
	LAddr string `json:"laddr"`
	LPort int    `json:"lport"`
	PID   int    `json:"pid,omitempty"`
	Comm  string `json:"comm,omitempty"`
}

// Conn is an established outbound connection whose remote port matches a known
// miner-pool / C2 port set (collected from /proc/net/tcp{,6}).
type Conn struct {
	Proto string `json:"proto"`
	RAddr string `json:"raddr"`
	RPort int    `json:"rport"`
}

// GroupMember is a member of a privileged group (sudo/wheel/docker/root/...).
// A service (nologin) account in such a group is a classic privilege backdoor.
type GroupMember struct {
	Group   string `json:"group"`
	Member  string `json:"member"`
	Nologin bool   `json:"nologin"`
}

type Persistence struct {
	Cron           []CronEntry    `json:"cron"`
	SystemdUnits   []SystemdUnit  `json:"systemd_units"`
	AuthorizedKeys []AuthKeysFile `json:"authorized_keys"`
	LDPreload      LDPreload      `json:"ld_preload"`
	ShellRC        []FileEntry    `json:"shell_rc"`
}

type CronEntry struct {
	Path   string `json:"path"`
	User   string `json:"user"`
	Line   string `json:"line"`
	SHA256 string `json:"sha256"`
}

type SystemdUnit struct {
	Name        string `json:"name"`
	ExecStart   string `json:"exec_start"`
	Enabled     bool   `json:"enabled"`
	ExecPre     string `json:"exec_pre"`    // ExecStartPre/ExecStartPost/ExecReload commands, joined
	Environment string `json:"environment"` // Environment= values, joined (e.g. an LD_PRELOAD injection)
}

// SystemdTimer is a *.timer unit together with the ExecStart of the .service it
// activates. A timer is the systemd equivalent of cron; a time-triggered unit
// whose service runs from a writable path or embeds a reverse shell is durable
// persistence that the .service scan alone misses (T1053.006).
type SystemdTimer struct {
	Name       string `json:"name"`        // foo.timer
	Unit       string `json:"unit"`        // the activated unit (foo.service)
	OnCalendar string `json:"on_calendar"` // OnCalendar=/OnBootSec=/... schedule, joined
	ExecStart  string `json:"exec_start"`  // ExecStart of the activated service
}

// DnfPlugin is a dnf/yum plugin Python file writable by a non-root user. Plugins
// run as root on every package transaction, so a writable one is a root-executed
// persistence vector on RPM-based distros (T1546).
type DnfPlugin struct {
	Path   string `json:"path"`   // the plugin .py file
	Plugin string `json:"plugin"` // plugin name (basename without .py)
}

type AuthKeysFile struct {
	Path         string    `json:"path"`
	Owner        string    `json:"owner"`         // account that owns this authorized_keys
	OwnerNologin bool      `json:"owner_nologin"` // owner has a nologin/false shell (service acct)
	Keys         []AuthKey `json:"keys"`
}

type AuthKey struct {
	Type    string `json:"type"`
	Comment string `json:"comment"`
	SHA256  string `json:"sha256"`
	Options string `json:"options"` // options preceding the key (command=, environment=, ...)
}

type LDPreload struct {
	LDSoPreload string   `json:"ld_so_preload"`
	Entries     []string `json:"entries"`
}

type KernelModule struct {
	Name      string `json:"name"`
	OutOfTree bool   `json:"out_of_tree"`
	Signed    bool   `json:"signed"`
}

// KernelLogEntry is one record from the kernel ring buffer (/dev/kmsg, i.e.
// dmesg). Point-in-time readable, so it fits the agentless model; surfaces module
// loads/taints, exploitation segfaults/oops, promiscuous mode, BPF events, etc.
type KernelLogEntry struct {
	Priority    int    `json:"priority"`
	Seq         int64  `json:"seq"`
	TimestampUs int64  `json:"timestamp_us"`
	Message     string `json:"message"`
}

// Account is a local user account (/etc/passwd). UID 0 accounts other than root
// are a classic persistence/privilege backdoor.
type Account struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Home  string `json:"home"`
	Shell string `json:"shell"`
}

// SudoRule is a notable line from /etc/sudoers(.d): NOPASSWD, SETENV, or a
// command path in a writable directory — all privilege-escalation enablers.
type SudoRule struct {
	Path    string `json:"path"`
	Line    string `json:"line"`
	GtfoBin string `json:"gtfo_bin"` // basename of a granted GTFOBins shell-escape binary, else ""
}

// SupervisorProg is a supervisord [program:*] whose command may point at a
// writable/tmp path (persistence under a process supervisor).
type SupervisorProg struct {
	Path    string `json:"path"`
	Program string `json:"program"`
	Command string `json:"command"`
}

// UdevRule is a custom udev rule that runs a program (RUN+=/IMPORT{program}) —
// a known root-executed persistence vector.
type UdevRule struct {
	Path string `json:"path"`
	Rule string `json:"rule"`
}

// BinfmtEntry is a registered binfmt_misc handler; an interpreter under a
// writable path is a shadow-execution / persistence trick.
type BinfmtEntry struct {
	Name        string `json:"name"`
	Interpreter string `json:"interpreter"`
}

// StartupScript is a boot/login-time script (rc.local, init.d, profile.d,
// update-motd.d) carrying suspicious lines (download cradle, reverse shell).
type StartupScript struct {
	Path            string   `json:"path"`
	SuspiciousLines []string `json:"suspicious_lines"`
}

// PAMEntry is a line from /etc/pam.d/*. A Module referenced by absolute Path
// outside the standard security dirs is a classic PAM backdoor.
type PAMEntry struct {
	Service string `json:"service"`
	Type    string `json:"type"`
	Module  string `json:"module"`
	Args    string `json:"args"` // module args (matched by rules: expose_authtok, script paths)
	Path    string `json:"path"` // absolute module path when given, else "" (matched by rules)
}

// PthFile is a Python *.pth file that contains executable import lines (run on
// interpreter startup — a stealthy persistence/execution vector).
type PthFile struct {
	Path        string   `json:"path"`
	ImportLines []string `json:"import_lines"`
}

type FileEntry struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`
	UID    int    `json:"uid"`
	SUID   bool   `json:"suid"`
	SHA256 string `json:"sha256"`
	Hidden bool   `json:"hidden"`
	Caps   string `json:"caps"` // file capabilities (security.capability xattr), hex; "" if none
	Tool   string `json:"tool"` // matched offensive-tool marker (pspy/linpeas/chisel/...), "" if none
}

// ModprobeCommand is an /etc/modprobe.d install/remove directive whose command
// is not a benign modprobe/true/false control — i.e. an arbitrary command run as
// root when a module is (un)loaded, a classic event-triggered persistence vector.
type ModprobeCommand struct {
	Path      string `json:"path"`
	Directive string `json:"directive"` // install / remove
	Module    string `json:"module"`
	Command   string `json:"command"`
}

// LdConfEntry is a library search directory added via /etc/ld.so.conf{,.d} that
// lives under a writable path — a dynamic-linker hijack (attacker .so is picked
// up system-wide). Only writable dirs are collected (T1574.006).
type LdConfEntry struct {
	Path string `json:"path"` // the ld.so.conf file declaring it
	Dir  string `json:"dir"`  // the writable library directory
}

// PackageHook is a package-manager hook (APT::Update::Pre-Invoke,
// DPkg::Pre-Invoke/Post-Invoke/Pre-Install-Pkgs) whose command runs a download
// cradle or a binary from a writable path — a root-executed persistence vector
// triggered on every apt/dpkg run. Only suspicious hooks are collected.
type PackageHook struct {
	Path      string `json:"path"`      // config file under /etc/apt
	Manager   string `json:"manager"`   // apt
	Directive string `json:"directive"` // the hook directive name
	Command   string `json:"command"`   // the shell command the hook runs
}

// WebServerModule is an apache/nginx module loaded from a writable path
// (LoadModule / load_module), i.e. a web-server module backdoor (T6347).
type WebServerModule struct {
	Path   string `json:"path"`   // web-server config file declaring the module
	Server string `json:"server"` // apache / nginx
	Module string `json:"module"` // module path loaded from a writable dir
}

// BpfProg is a loaded eBPF program enumerated agentlessly via
// bpf(BPF_PROG_GET_NEXT_ID) + BPF_OBJ_GET_INFO_BY_FD. eBPF rootkits/backdoors
// (boopkit, TripleCross, ebpfkit) load programs that hook syscalls
// (kprobe/fentry/tracing on getdents/sys_bpf to hide objects) or sniff and
// trigger on packets (xdp/socket_filter/sched_cls for packet-activated C2).
// Enumerating loaded programs catches these even when nothing is pinned.
type BpfProg struct {
	ID   uint32 `json:"id"`
	Type string `json:"type"`           // human program type: kprobe, tracing, xdp, sched_cls, ...
	Name string `json:"name"`           // program name (<=16 bytes, from BTF/ELF), often empty
	Tag  string `json:"tag"`            // 8-byte instruction hash (hex), stable per program
	GPL  bool   `json:"gpl_compatible"` // licensed GPL (required for many tracing helpers)
}

// LibVersion is the version of a key shared library, for supply-chain checks
// (e.g. the liblzma / xz-utils backdoor, CVE-2024-3094, versions 5.6.0/5.6.1).
type LibVersion struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Version string `json:"version"`
}
