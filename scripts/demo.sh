#!/usr/bin/env bash
# bladedr demo — used by assets/demo.tape to produce the README GIF.
# Starts an isolated server on :19090, runs through login → rules → scan →
# observations → risk stats, then cleans up.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ADDR="localhost:19090"
PASS="demopass"
LOG="/tmp/bladedr-demo.log"

_red()    { printf '\033[31m%s\033[0m\n' "$*"; }
_green()  { printf '\033[32m%s\033[0m\n' "$*"; }
_yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
_cyan()   { printf '\033[36m%s\033[0m\n' "$*"; }
_bold()   { printf '\033[1m%s\033[0m\n' "$*"; }
_dim()    { printf '\033[2m%s\033[0m\n' "$*"; }

hr() { printf '\033[2m%s\033[0m\n' "────────────────────────────────────────────────────────────────"; }

cleanup() { pkill -f "bladedr-server.*19090" 2>/dev/null || true; }
trap cleanup EXIT

# ── start server ────────────────────────────────────────────────────────────
_bold "starting bladedr-server (in-memory, malicious snapshot mode)…"
BLADEDR_ADDR=":19090" \
BLADEDR_ADMIN_PASSWORD="$PASS" \
BLADEDR_PROBE_BIN="$ROOT/bin/bladedr-probe" \
BLADEDR_PROBE_EXTRA="--snapshot-file $ROOT/testdata/malicious-snapshot.json" \
  "$ROOT/bin/bladedr-server" >"$LOG" 2>&1 &

# wait until healthy
for i in $(seq 1 20); do
  if curl -sf "http://$ADDR/api/v1/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.3
done

# ── login ────────────────────────────────────────────────────────────────────
hr
_cyan "# 1 · login"
hr
TOKEN=$(curl -sf -X POST "http://$ADDR/api/v1/login" \
  -H 'content-type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$PASS\"}" | jq -r .token)
_green "✓ authenticated"
_dim "  token: ${TOKEN:0:24}…"
sleep 1

# ── active rules ─────────────────────────────────────────────────────────────
hr
_cyan "# 2 · active detection rules"
hr
RULES=$(curl -sf "http://$ADDR/api/v1/rules/active" \
  -H "Authorization: Bearer $TOKEN")
COUNT=$(echo "$RULES" | jq 'length')
_green "✓ $COUNT rules loaded"
echo "$RULES" | jq -r '.[] | select(.severity=="critical") | "  \(.severity | ascii_upcase)  \(.id)"' | head -6
_dim "  … and more"
sleep 1.5

# ── add host + scan ──────────────────────────────────────────────────────────
hr
_cyan "# 3 · add host and run scan"
hr
HID=$(curl -sf -X POST "http://$ADDR/api/v1/hosts" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' \
  -d '{"hostname":"web-01","primary_ip":"10.0.0.5","arch":"amd64"}' | jq -r .id)
_dim "  host id: $HID"
_dim "  running scan…"
SCAN=$(curl -sf -X POST "http://$ADDR/api/v1/hosts/$HID/scans" \
  -H "Authorization: Bearer $TOKEN")
echo "$SCAN" | jq '{status,duration_ms}'
sleep 1.5

# ── observations ─────────────────────────────────────────────────────────────
hr
_cyan "# 4 · findings (top by score)"
hr
curl -sf "http://$ADDR/api/v1/observations?host=$HID&limit=8" \
  -H "Authorization: Bearer $TOKEN" | \
  jq -r 'sort_by(-.score) | .[] |
    "\(if .severity=="critical" then "\u001b[31m" elif .severity=="high" then "\u001b[33m" else "\u001b[36m" end)\(.severity | ascii_upcase)\u001b[0m  score=\(.score)  \(.rule_id)"'
sleep 2

# ── risk stats ───────────────────────────────────────────────────────────────
hr
_cyan "# 5 · ML risk model"
hr
curl -sf "http://$ADDR/api/v1/risk/stats" \
  -H "Authorization: Bearer $TOKEN" | \
  jq '{trustworthy,labeled,positives,negatives,cv_accuracy,reason}'
sleep 2

hr
_green "demo complete — see http://localhost:8080 for the full web console"
hr
