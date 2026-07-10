#!/usr/bin/env bash
# End-to-end smoke test: boot the server against the bundled snapshot, authenticate,
# run a scan, and assert it produces observations. Also checks readyz/metrics.
# Runnable locally (./scripts/smoke.sh) and in CI.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PORT=18099
BASE="http://localhost:$PORT"
PASS="smoke-$(date +%s)"
LOG=/tmp/smoke-server.log

echo "==> building server + probe"
go build -o /tmp/smoke-server ./cmd/bladedr-server
go build -o /tmp/smoke-probe ./cmd/bladedr-probe

echo "==> starting server on $PORT"
BLADEDR_ADDR=":$PORT" \
BLADEDR_PROBE_BIN=/tmp/smoke-probe \
BLADEDR_PROBE_EXTRA="--snapshot-file testdata/malicious-snapshot.json" \
BLADEDR_ADMIN_PASSWORD="$PASS" \
	/tmp/smoke-server >"$LOG" 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true' EXIT

fail() { echo "SMOKE FAIL: $1"; echo "--- server log ---"; cat "$LOG"; exit 1; }

echo "==> waiting for /healthz"
for i in $(seq 1 40); do
	curl -fsS "$BASE/healthz" >/dev/null 2>&1 && break
	[ "$i" = 40 ] && fail "server did not come up"
	sleep 0.5
done

echo "==> /readyz"
curl -fsS "$BASE/readyz" >/dev/null || fail "readyz not ok"

echo "==> login"
TOKEN=$(curl -fsS -X POST "$BASE/api/v1/login" -H 'content-type: application/json' \
	-d "{\"Username\":\"admin\",\"Password\":\"$PASS\"}" \
	| python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])') || fail "login failed"

echo "==> create host"
HID=$(curl -fsS -H "Authorization: Bearer $TOKEN" -X POST "$BASE/api/v1/hosts" \
	-H 'content-type: application/json' -d '{"hostname":"smoke-01","primary_ip":"10.0.0.5"}' \
	| python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])') || fail "create host failed"

echo "==> scan"
curl -fsS -H "Authorization: Bearer $TOKEN" -X POST "$BASE/api/v1/hosts/$HID/scans" >/dev/null \
	|| fail "scan request failed"

echo "==> observations"
N=$(curl -fsS -H "Authorization: Bearer $TOKEN" "$BASE/api/v1/observations?host=$HID" \
	| python3 -c 'import sys,json;print(len(json.load(sys.stdin) or []))')
[ "$N" -gt 0 ] || fail "scan produced no observations"

echo "==> /metrics"
curl -fsS "$BASE/metrics" | grep -q bladedr_http_requests_total || fail "metrics missing counter"

echo "SMOKE OK ($N observations from the bundled snapshot)"
