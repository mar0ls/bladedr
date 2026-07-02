#!/usr/bin/env bash
# Register a Linux host with the running bladedr control plane (and optionally scan it).
#
#   BLADEDR_HOST_PASSWORD=secret scripts/add-host.sh <ip> <ssh-user> [--scan]
#   scripts/add-host.sh <ip> <ssh-user> --key ~/.ssh/id_ed25519 [--scan]
#
# The secret (password or private key) is sent to the local server, which seals it
# with the node key (split-trust); it is never stored in plaintext or echoed back.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .bladedr.env ] && { set -a; . ./.bladedr.env; set +a; }
ADDR="${BLADEDR_ADDR:-:8080}"
BASE="http://localhost${ADDR}/api/v1"

# Authenticate: reuse BLADEDR_API_TOKEN if given, else log in with the admin account
# (BLADEDR_ADMIN_USER/PASSWORD, persisted in .bladedr.env by deploy-server.sh).
TOKEN="${BLADEDR_API_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -n "${BLADEDR_ADMIN_PASSWORD:-}" ]; then
  TOKEN=$(curl -fsS -X POST "$BASE/login" -H 'content-type: application/json' \
    -d "{\"Username\":\"${BLADEDR_ADMIN_USER:-admin}\",\"Password\":\"$BLADEDR_ADMIN_PASSWORD\"}" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])') || true
fi
[ -z "$TOKEN" ] && { echo "not authenticated: set BLADEDR_API_TOKEN or BLADEDR_ADMIN_PASSWORD" >&2; exit 1; }
AUTH_HDR="Authorization: Bearer $TOKEN"

IP="${1:?usage: add-host.sh <ip> <ssh-user> [--key file] [--scan]}"
SSH_USER="${2:?ssh user required}"
shift 2
KEYFILE=""; DOSCAN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --key) KEYFILE="${2:?--key needs a file}"; shift 2;;
    --scan) DOSCAN=1; shift;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done

if [ -n "$KEYFILE" ]; then
  AUTH=ssh_key; SECRET="$(cat "$KEYFILE")"
else
  AUTH=password; SECRET="${BLADEDR_HOST_PASSWORD:?set BLADEDR_HOST_PASSWORD or pass --key <file>}"
fi

post() { # post <path> <json-on-stdin> -> response body
  curl -fsS -X POST "$BASE$1" -H 'content-type: application/json' -H "$AUTH_HDR" -d @-
}

# Build JSON safely (secret may contain quotes/newlines) via python, then POST.
CRED=$(SECRET="$SECRET" U="$SSH_USER" A="$AUTH" IP="$IP" python3 -c '
import json,os,sys
json.dump({"name":os.environ["U"]+"@"+os.environ["IP"],"username":os.environ["U"],
           "auth_type":os.environ["A"],"secret":os.environ["SECRET"]}, sys.stdout)' \
  | post /credentials | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')

HID=$(IP="$IP" CRED="$CRED" python3 -c '
import json,os,sys
json.dump({"primary_ip":os.environ["IP"],"ssh_port":22,
           "credential_id":os.environ["CRED"],"arch":"amd64"}, sys.stdout)' \
  | post /hosts | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')

echo "host registered: $HID  ($IP, $AUTH)"

if [ "$DOSCAN" = 1 ]; then
  curl -fsS -X POST "$BASE/hosts/$HID/scans" -H "$AUTH_HDR" \
    | python3 -c 'import sys,json;s=json.load(sys.stdin);print("scan:",s["status"],"| risk:",s["risk_score"])'
fi
echo "UI: http://localhost${ADDR}/ui"
