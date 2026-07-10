# bladedr — detection coverage (Linux MITRE ATT&CK / EDR-T matrix)

Mapping of the techniques in the matrix onto bladedr's two tiers. Living document —
updated as rules are added.

**Legend**
- ✅ **agentless-now** — state-based rule implemented (`internal/rules/builtin/`)
- ⏳ **agentless-planned** — detectable from state (a persistent artifact), collector/rule to add
- 🔬 **eBPF (Phase 2)** — ephemeral/behavioural; needs an eBPF sensor. Much of this is
  covered by `linux-probe-shield` (Tetragon) — see the "policy" notes

## Why the split

An agentless scan is a **point-in-time snapshot of state**: it sees what the attacker
*left behind* (a module, a key, a cron entry, an account, a modified file, a listener).
**Ephemeral** techniques (exec, injection, fileless, C2 traffic, live masquerading)
disappear between scans — only a continuous eBPF sensor catches them. Most of the matrix
under *Execution, Defense Evasion (runtime), C2, Credential Access, Discovery* is eBPF by nature.

---

## Implemented agentless rules

| rule_id | technique | MITRE | EDR-T (examples) |
|---|---|---|---|
| `deleted-running-binary` | running process, binary deleted | T1055/T1620 | T6041 |
| `memfd-fileless-exec` | exec from anonymous memfd | T1620 | T6037, T6188 |
| `exec-from-world-writable` | exec from /tmp,/dev/shm,/var/tmp | T1059 | T6041, T6039 |
| `masquerade-kernel-thread` | userland posing as [kworker] | T1036.004 | T6038, T6171, T6140 |
| `hidden-process` | reachable via /proc/PID, hidden from readdir | T1014 | T6046, T6253 |
| `process-empty-environ` | exe-backed process with wiped /proc/PID/environ | T1070.004 | T6325 (BPFDoor) |
| `packet-sniffer-process` | process holds an AF_PACKET raw socket | T1040 | T6325, T6012 |
| `suspicious-port-listener` | listener on backdoor port | T1571 | T6123.* |
| `ld-so-preload-rootkit` | entry in /etc/ld.so.preload | T1574.006 | T6046, T6235, T6327, T6422 |
| `cron-download-cradle` | cron with curl/wget \| sh | T1053.003 | T6093 |
| `cron-suspicious-command` | cron runs interpreter / GTFOBins shell escape | T1053.003/T1059 | T6093 |
| `miner-c2-outbound-connection` | established conn to known miner-pool / C2 port | T1071/T1496 | T6252, T6126.* |
| `ssh-tunnel-process` | live ssh client tunnel: -D SOCKS / -R / persistent -N -f | T1572/T1090 | T6033, T6189 |
| `passwordless-account` | /etc/shadow entry with empty password | T1098/T1078 | credential |
| `service-account-in-privileged-group` | nologin account in sudo/wheel/docker/lxd | T1098 | privesc |
| `at-job-cradle` | at(1) job with cradle/revshell | T1053.002 | T6179 |
| `systemd-suspicious-execstart` | unit ExecStart from /tmp,/home,… | T1543.002 | T6015 |
| `ssh-key-in-service-account` | authorized_keys in nologin account | T1098.004 | T6423, T6235 |
| `authorized-keys-suspicious-option` | key with environment= / command= cradle | T1098.004/T1556 | T6235, T6315 |
| `sshd-backdoor-directive` | sshd_config ForceCommand/AuthorizedKeysCommand from /tmp | T1098.004/T1556 | T6423, T6104 |
| `shell-rc-backdoor` | .bashrc/profile alias-hiding / cradle / PROMPT_COMMAND | T1546.004 | T6089 |
| `supervisor-command-writable` | supervisord command= from /tmp/shell | T1543 | T6431 |
| `udev-run-backdoor` | udev RUN+= from /tmp or shell | T1546 | T6179 |
| `binfmt-interpreter-writable` | binfmt_misc interpreter from writable | T1546 | T6407 |
| `startup-script-cradle` | rc.local/init.d/profile.d/motd cradle/revshell | T1037.004 | T6093, T6123.* |
| `initramfs-hook-cradle` | initramfs/dracut hook with a cradle/reverse shell (boot persistence) | T1542.001/T1037 | T6250 |
| `pam-module-unusual-path` | PAM module from an absolute path outside /lib | T1556.003 | T6164 |
| `webshell-in-webroot` | webshell code pattern in a web-root file | T1505.003 | T6011, T6017, T6347 |
| `liblzma-xz-backdoor` | liblzma 5.6.0/5.6.1 (xz backdoor) | T1195.001 | T6233 |
| `package-repo-unverified` | pkg repo accepts unsigned packages (apt trusted=yes / dnf gpgcheck=0) | T1195.001/T1553 | T6213, T6144 |
| `offensive-tool-on-disk` | pspy/LinPEAS/chisel/sliver/frp/ligolo/gost/cloudflared/xmrig/dnscat2/... by content marker | T1588.002/T1105 | T6040, T6251, T6357, T6252, T6115 |
| `ebpf-pinned-object-toplevel` (opt-in, off) | top-level pinned BPF object in /sys/fs/bpf | T1014 | T6151, T6152 |
| `ebpf-program-rootkit-name` | loaded eBPF prog (bpf(BPF_PROG_GET_NEXT_ID)) with offensive name (bad-bpf/ebpfkit/boopkit/TripleCross) | T1014/T1547.006 | T6151, T6152, T6253 |
| `package-manager-hook-backdoor` | apt/dpkg hook (Pre/Post-Invoke, Pre-Install-Pkgs) running a cradle/writable command | T1546.016 | T6213 |
| `web-server-module-writable` | apache/nginx module (LoadModule/load_module) from a writable path | T1505.003 | T6347 |
| `modprobe-install-command` | modprobe.d install/remove runs a cradle/writable command | T1546/T1547.006 | T6093 |
| `ld-so-conf-writable-path` | ld.so.conf{,.d} library dir under a writable path (linker hijack) | T1574.006 | T6046 |
| `global-ld-preload` | LD_PRELOAD/LD_AUDIT / writable LD_LIBRARY_PATH in a global env file | T1574.006 | T6046, T6235 |
| `systemd-exec-directive-writable` | systemd ExecStartPre/Post/Reload from a writable path | T1543.002 | T6015 |
| `systemd-unit-ld-preload` | systemd unit injects LD_PRELOAD/LD_AUDIT via Environment= | T1574.006 | T6046 |
| `systemd-execstart-reverse-shell` | systemd ExecStart embeds a reverse-shell / decode cradle | T1543.002 | T6015 |
| `systemd-timer-suspicious` | .timer activates a service from a writable path / reverse shell | T1053.006 | persistence |
| `dnf-plugin-writable` | dnf/yum plugin file writable by a non-root user (runs as root each transaction) | T1546 | T6213 |
| `selinux-disabled` | SELinux disabled/permissive where installed (config or kernel cmdline) | T1562.001 | T6293 |
| `suid-shell-escape-binary` | SUID bit on a GTFOBins shell-escape/interpreter (bash/python/find/...) | T1548.001 | privesc |
| `writable-persistence-file` | systemd/cron/sudoers.d/init file writable by a non-root user | T1543/T1053.003 | persistence |
| `dangerous-file-capability` | binary with a privesc file capability (cap_setuid/dac_override/sys_admin/...) | T1548.001 | privesc |
| `cron-path-hijack` | cron PATH= with a writable/relative directory | T1574.007 | privesc |
| `pam-exec-backdoor` | PAM pam_exec/pam_python with expose_authtok or a writable-path script | T1556.003 | T6164 |
| `nsswitch-unusual-module` | non-standard NSS module in nsswitch.conf (libnss backdoor) | T1556 | persistence |
| `shell-history-disabled` | shell rc disables history (HISTFILE=/dev/null, HISTSIZE=0, unset) | T1070.003 | anti-forensics |
| `log-file-symlinked` | system log replaced by a symlink (e.g. to /dev/null) | T1070.002 | anti-forensics |
| `login-shell-suspicious` | account login shell is an interpreter or under a writable path | T1136.001/T1078.003 | persistence |
| `writable-suid-binary` | SUID/SGID binary also writable by group/other (trivial privesc) | T1548.001 | privesc |
| `process-reverse-shell-cmdline` | live process cmdline is a reverse/bind shell (/dev/tcp, nc -e, pty.spawn) | T1059.004 | C2 |
| `sudo-gtfobins-binary` | sudoers grants a GTFOBins binary (find/vim/awk/iptables-save/...) | T1548.003 | T6315 |
| `xdg-autostart-suspicious` | XDG autostart .desktop Exec is a cradle / writable path | T1547.013 | persistence |
| `sudo-env-keep-ld` | sudoers env_keep preserves LD_PRELOAD/LD_LIBRARY_PATH/LD_AUDIT | T1548.003/T1574.006 | privesc |
| `ssh-config-localcommand` | ssh client config LocalCommand / cradle ProxyCommand (exec on connect) | T1546/T1059.004 | persistence |
| `proc-bind-mount-hidden-process` | bind mount over /proc/<pid> (process-hiding rootkit) | T1564.001/T1014 | T6053 |
| `yama-ptrace-scope-disabled` | kernel.yama.ptrace_scope=0 (injection hardening off) | T1562.001 | T6282 |
| `sysctl-hardening-disabled` | sysctl config sets ptrace_scope/kptr_restrict/bpf/dmesg = 0 | T1562.001 | T6282/T6293 |
| `python-pth-code-execution` | .pth with code-exec import | T1546 | T6139 |
| `unexpected-uid0-account` | UID 0 account != root | T1136.001/T1078.003 | persistence |
| `sudoers-dangerous-rule` | NOPASSWD: ALL / SETENV / writable-path command | T1548.003 | privesc |
| `nfs-no-root-squash` | /etc/exports with no_root_squash | T1548 | privesc |
| `suid-in-writable-path` | SUID binary in /tmp,/dev/shm,/var/tmp,/dev | T1548.001 | T6187 |
| `file-capability-in-writable` | file caps (xattr) in a writable path | T1548 | privesc |
| `path-hijack-entry` | cwd / world-writable dir in system PATH | T1574.007 | privesc |
| `docker-socket-exposed` | docker.sock world (other)-accessible | T1610/T1611 | T6147, T6417 |
| `k8s-static-pod-suspicious` | non-standard privileged/host* static pod manifest (k8s node persistence) | T1610/T1543 | K8s |
| `k8s-kubeconfig-exposed` | kubeconfig/admin.conf with creds readable by non-root | T1552.001 | K8s |
| `kernel-lockdown-disabled` (opt-in, off) | kernel lockdown = none | T1562.001 | hardening |
| `core-pattern-pipe-handler` | core_pattern=\|program | T1611/T1547 | T6051, T6417 |
| `hidden-executable-in-writable` | hidden exec in /tmp,/dev/shm,/dev | T1564.001 | T6039, T6041 |
| `immutable-sensitive-file` | sensitive file chattr +i | T1222.002 | T6133 |
| `world-writable-sensitive-file` | /etc/passwd,shadow,sudoers,… world-writable | T1222.002 | privesc |
| `unsigned-out-of-tree-module` | unsigned out-of-tree module loaded | T1547.006 | T6023, T6154, T6155, T6163 |
| `hidden-kernel-module` | in /proc/modules or kallsyms, hidden from /sys/module | T1014 | T6023, T6163, T6155 |
| `kernel-forced-module-taint` | taint F (insmod -f) | T1547.006 | T6107 |
| `kallsyms-rootkit-symbol` | kallsyms symbol matching a known rootkit/hook | T1014 | T6023, T6163, T6289 |
| `kernel-promiscuous-mode` | interface in promiscuous mode (sniffing) | T1040 | T6012 |
| `kernel-exploit-segfault` | segfault of a /tmp binary (exploitation trace) | T1203/T1068 | T6261, T6354, T6119 |
| `kernel-out-of-tree-module-load` | dmesg: kernel-tainting module load | T1547.006 | T6023, T6395, T6107 |
| `kernel-oops-or-gpf` | dmesg: Oops / GPF / kernel BUG | T1068 | T6230, T6231, T6360 |

Public-sourced per-technique telemetry/IOC map (the rule backlog): see [TELEMETRY.md](TELEMETRY.md).

**85 builtin rules + user rules** (added via the API, CEL-validated, merged by `id`; a user
rule can also override or, with `enabled: false`, disable a builtin of the same `id`). See README → "Rules".

Validated by a unit test (every rule fires on a malicious fixture, benign entries do not). The
collectors and many rules are additionally validated against a live Ubuntu 24.04 host over SSH,
which is also the false-positive tuning loop (it has so far caught and fixed: legit `.pth`,
group-only docker.sock, the `bpf` kallsyms pseudo-module).

## Snapshot data sources (~22)

`processes`, `listening_sockets`, `persistence.*` (cron, systemd_units, authorized_keys,
ld_preload), `kernel_modules`, `suspicious_files` (suid/hidden), `accounts`, `kernel_log`
(dmesg via /dev/kmsg), `pam_modules`, `pth_files`, `immutable_files`, `hidden_modules`,
`udev_rules`, `binfmt_entries`, `startup_scripts`, `shell_init`, `supervisor`, `hidden_pids`,
`at_jobs`, `suspicious_ksyms` (kallsyms), `sudo_rules`, `nfs_exports`, `world_writable_sensitive`,
`facts.*` (core_pattern, docker_sock, kernel_taint_chars, sshd_*).

## Tactic coverage (summary)

- **TA0003 Persistence** — strongest area: LKM rootkits ✅, LD_PRELOAD ✅, cron/at ✅, systemd ✅,
  systemd timers ✅, supervisor ✅, udev ✅, PAM ✅, SSHD config ✅, authorized_keys ✅, .pth ✅,
  binfmt ✅, shell-rc ✅, core_pattern ✅, dnf-plugin ✅. eBPF backdoors (BPFDoor, eBPF rootkits) 🔬.
- **TA0004 Privilege Escalation** — sudoers ✅, NFS no_root_squash ✅, SUID-in-writable ✅,
  docker.sock ✅, world-writable sensitive ✅, PATH hijack ✅, file capabilities (getcap) ✅,
  kernel lockdown ✅ (opt-in). CVE exploits (DirtyPipe/pkexec/UAF) 🔬 (`shield-*`).
- **TA0005 Defense Evasion** — memfd ✅, masquerade-state ✅, chattr immutable ✅, hidden exec ✅,
  SELinux-disabled ✅, sysctl/yama hardening-off ✅. Injection/runtime (ptrace, /proc/PID/mem) 🔬.
- **Rootkits** — hidden processes ✅, hidden modules (sysfs + kallsyms) ✅, kallsyms symbols ✅,
  taint ✅, dmesg module-load ✅.
- **TA0001 Initial Access / TA0011 C2 / TA0008 Lateral / TA0010 Exfil / TA0006 Cred / TA0007 Discovery**
  — mostly 🔬 (runtime exploits, network traffic, syscall behaviour). Agentless captures the
  *artifact* (listener, dropped tool, segfault in dmesg), eBPF captures the *act*.

## Agentless: the artifact vs the act

Agentless catches the **artifact** a technique leaves at rest; eBPF (Phase 2) catches the
**act** in real time. Example: file creation is an eBPF event, but the created hidden/SUID
file, modified config, or added key is an agentless artifact.

## Baseline / drift engine (anomaly detection)

In addition to the signature rules, a per-host **baseline** captures stable state
(listening ports, kernel modules, accounts, authorized keys, cron, systemd units).
The first scan establishes it; later scans emit a medium `baseline-new-*`
observation for anything new — covering novel/unknown threats that no signature
rule watches for. This is the explainable, deterministic anomaly layer.

**Fleet rarity scoring** is the second anomaly layer: across all hosts' baselines,
an item (kernel module / listener / key / cron) present on a very small fraction of
the fleet (≤5%, or unique to one host when the fleet is small) is a hunting lead —
a `fleet-rare-*` observation (low severity). E.g. a rootkit module unique to one
compromised box stands out against the fleet. Needs ≥4 hosts to score.

## Next agentless candidates

shadow/group manipulation, GRUB script (`/etc/grub.d`) cradle, `/proc/kallsyms` syscall-hook
diff, authorized_keys baseline-diff, rpm/dnf scriptlet scan, key-library `.so` hash check,
initramfs/`/boot` hash drift via baseline. (Done: PATH hijack, file capabilities, kernel
lockdown, systemd timers, GTFOBins in cron/sudo, initramfs hooks, SELinux-disabled, dnf-plugin.)

## Phase 2 (eBPF)

`bladedr-sensor` = a thin Tetragon wrapper loading `linux-probe-shield` policies 1:1, streaming
events into the same `observations` table / tagging / export. That covers the runtime half of
the matrix (exec/injection/fileless/C2/credential-access).
