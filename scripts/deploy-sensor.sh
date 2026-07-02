#!/usr/bin/env bash
# Deploy the bladedr eBPF sensor (Tetragon wrapper) onto a Linux host.
#
#   scripts/deploy-sensor.sh <ssh-user@host> <bladedr-host-id>
#
# It copies the linux-probe-shield TracingPolicies + the cross-built sensor to the
# host, runs Tetragon as a privileged container loading those policies, and starts
# bladedr-sensor following Tetragon's export and posting events to the control plane.
# Requires on the target: Docker, a BTF-capable kernel (/sys/kernel/btf/vmlinux),
# and sudo for the SSH user. Env:
#   BLADEDR_SERVER       control-plane URL reachable from the host (default http://<this-ip>:8080)
#   BLADEDR_POLICY_DIR   TracingPolicy bundle (default ./linux-probe-shield)
#   BLADEDR_TETRAGON     tetragon image (default quay.io/cilium/tetragon:v1.7.0)
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET="${1:?usage: deploy-sensor.sh <ssh-user@host> <bladedr-host-id>}"
HOST_ID="${2:?bladedr host id required}"
POLICY_DIR="${BLADEDR_POLICY_DIR:-linux-probe-shield}"
TETRAGON="${BLADEDR_TETRAGON:-quay.io/cilium/tetragon:v1.7.0}"
SERVER="${BLADEDR_SERVER:-http://$(ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}'):8080}"

[ -d "$POLICY_DIR" ] || { echo "policy dir not found: $POLICY_DIR" >&2; exit 1; }

echo "==> cross-building bladedr-sensor (linux/amd64)"
GOOS=linux GOARCH=amd64 go build -o /tmp/bladedr-sensor.linux ./cmd/bladedr-sensor

echo "==> copying policies + sensor to $TARGET"
ssh "$TARGET" 'rm -rf /tmp/bladedr-shield /tmp/bladedr-tetra && mkdir -p /tmp/bladedr-shield /tmp/bladedr-tetra'
scp -q "$POLICY_DIR"/shield-*.y*ml "$TARGET":/tmp/bladedr-shield/
scp -q /tmp/bladedr-sensor.linux "$TARGET":/tmp/bladedr-sensor

# Tetragon validates ALL policies at load and aborts on any failure, so a large
# bundle must be curated per kernel: drop policies whose non-syscall kprobe symbol
# is absent from /proc/kallsyms, plus a denylist of policies that fail validation
# for other kernel-version reasons. (For full-bundle robustness, load policies
# individually via `tetra tracingpolicy add` instead — left as a follow-up.)
echo "==> filtering policies for the target kernel"
ssh "$TARGET" 'cd /tmp/bladedr-shield; rm -f *.backup
for f in *.yml *.yaml; do [ -f "$f" ] || continue
  case "$f" in *cve-*|*dirtyfrag*|*iouring*|*userfaultfd*) mv "$f" "$f.off"; continue;; esac
  for s in $(grep -E "^[[:space:]]*-?[[:space:]]*call:" "$f" | sed -E "s/.*call:[[:space:]]*\"?([^\"]+)\"?.*/\1/"); do
    case "$s" in sys_*|__*) continue;; esac
    grep -qw "$s" /proc/kallsyms || { mv "$f" "$f.off"; break; }
  done
done
echo "    loadable: $(ls *.yml *.yaml 2>/dev/null | wc -l), skipped: $(ls *.off 2>/dev/null | wc -l)"'

echo "==> starting Tetragon ($TETRAGON) with the shield policies"
ssh "$TARGET" "sudo docker rm -f tetragon >/dev/null 2>&1 || true; sudo docker run -d --name tetragon \
  --privileged --pid=host --cgroupns=host \
  -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf:ro \
  -v /sys/fs/bpf:/sys/fs/bpf:rw \
  -v /tmp/bladedr-shield:/etc/tetragon/tetragon.tp.d:ro \
  -v /tmp/bladedr-tetra:/var/log/tetragon:rw \
  $TETRAGON --export-filename /var/log/tetragon/tetragon.log \
  --tracing-policy-dir /etc/tetragon/tetragon.tp.d >/dev/null"

echo "==> starting bladedr-sensor -> $SERVER (host $HOST_ID)"
ssh "$TARGET" "chmod +x /tmp/bladedr-sensor; sudo setsid sh -c \
  'nohup /tmp/bladedr-sensor --export-file /tmp/bladedr-tetra/tetragon.log \
     --policy-dir /tmp/bladedr-shield --server $SERVER --host-id $HOST_ID \
     >/tmp/bladedr-sensor.log 2>&1 &'"

echo "==> done. Tetragon + sensor running on $TARGET (mode scan_plus_sensor)."
echo "    sensor log: ssh $TARGET 'tail -f /tmp/bladedr-sensor.log'"
echo "    stop:       ssh $TARGET 'sudo docker rm -f tetragon; sudo pkill -f bladedr-sensor'"
