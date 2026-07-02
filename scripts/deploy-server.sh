#!/usr/bin/env bash
# Deploy the bladedr control plane on any Docker host (Linux or macOS).
#
#   - build server + the Linux probe binaries (amd64 + arm64)
#   - bring up ParadeDB (PostgreSQL + pg_search/BM25) and apply the schema
#   - mint & persist a node key in .bladedr.env (seals SSH credentials)
#   - (re)start bladedr-server with the Postgres backend + scheduler
#
# Idempotent: re-running reuses the persisted key and the Postgres data volume.
# After it prints "up", add Linux hosts with scripts/add-host.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

ENVFILE=.bladedr.env
DB_URL="postgres://bladedr:bladedr@localhost:5432/bladedr"
ADDR="${BLADEDR_ADDR:-:8080}"

echo "==> building server + linux probes + eBPF sensor"
make build build-probe-linux sensor >/dev/null

echo "==> starting ParadeDB (docker compose)"
docker compose up -d >/dev/null
printf "    waiting for db"
for _ in $(seq 1 30); do
  if docker compose exec -T db pg_isready -U bladedr >/dev/null 2>&1; then printf " ok\n"; break; fi
  printf "."; sleep 1
done

echo "==> schema: applied automatically by the server on startup (auto-migrate)"

echo "==> node key"
if [ -f "$ENVFILE" ] && grep -q BLADEDR_NODE_KEY "$ENVFILE"; then
  echo "    reusing key from $ENVFILE"
else
  out=$(./bin/bladedr-server -keygen)
  key=$(printf '%s\n' "$out" | sed -n 's/^BLADEDR_NODE_KEY=\([^ ]*\).*/\1/p')
  pub=$(printf '%s\n' "$out" | sed -n 's/^public_key=\([^ ]*\).*/\1/p')
  cat > "$ENVFILE" <<EOF
# bladedr deployment config — gitignored. Keep BLADEDR_NODE_KEY secret.
# Public key (seals credentials): $pub
BLADEDR_NODE_KEY=$key
BLADEDR_DATABASE_URL=$DB_URL
BLADEDR_PROBE_LINUX_AMD64=bin/bladedr-probe.linux-amd64
BLADEDR_PROBE_LINUX_ARM64=bin/bladedr-probe.linux-arm64
BLADEDR_ADDR=$ADDR
BLADEDR_SCHEDULER_TICK=30s
EOF
  echo "    minted a new node key → $ENVFILE (public=$pub)"
fi

# Sensor-deploy config (idempotent): how hosts reach the control plane, the policy
# bundle to push, and the cross-built sensor binaries. Appended if missing.
SERVER_URL="${BLADEDR_SERVER_URL:-http://$(ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}'):8080}"
POLICY_DIR="${BLADEDR_POLICY_DIR:-linux-probe-shield}"
gen() { openssl rand -hex "${1:-24}" 2>/dev/null || head -c "${1:-24}" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ensure_var() { grep -q "^$1=" "$ENVFILE" || printf '%s=%s\n' "$1" "$2" >> "$ENVFILE"; }
ensure_var BLADEDR_SENSOR_LINUX_AMD64 bin/bladedr-sensor.linux-amd64
ensure_var BLADEDR_SENSOR_LINUX_ARM64 bin/bladedr-sensor.linux-arm64
ensure_var BLADEDR_POLICY_DIR "$POLICY_DIR"
ensure_var BLADEDR_SERVER_URL "$SERVER_URL"
# Auth: machine-to-machine ingest token (sensors) + the initial admin password.
# Generated once and persisted so re-deploys and scripts (add-host) can reuse them.
ensure_var BLADEDR_INGEST_TOKEN "$(gen 24)"
ensure_var BLADEDR_ADMIN_PASSWORD "$(gen 12)"

echo "==> (re)starting bladedr-server"
pkill -f 'bin/bladedr-server' 2>/dev/null || true
sleep 0.3
set -a; . "./$ENVFILE"; set +a
nohup ./bin/bladedr-server > bladedr-server.log 2>&1 &
for _ in $(seq 1 20); do
  curl -fsS "localhost${ADDR}/healthz" >/dev/null 2>&1 && break
  sleep 0.3
done

echo
echo "bladedr-server is up:"
echo "  UI    : http://localhost${ADDR}/ui"
echo "  API   : http://localhost${ADDR}/api/v1"
echo "  login : admin / ${BLADEDR_ADMIN_PASSWORD:-(see $ENVFILE)}"
echo "  log   : bladedr-server.log   (config: $ENVFILE)"
echo
echo "Add a Linux host:"
echo "  BLADEDR_HOST_PASSWORD=… scripts/add-host.sh <ip> <ssh-user> --scan"
echo "  scripts/add-host.sh <ip> <ssh-user> --key ~/.ssh/id_ed25519 --scan"
