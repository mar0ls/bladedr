#!/usr/bin/env bash
# False-positive baseline: run the real probe and the real rules against stock distro
# images and require that nothing fires.
#
# The attack-emulation range answers "do the detections catch things". This answers the
# other half, which is just as easy to break and much easier to miss: a rule that fires on
# an untouched system produces noise on every host in the fleet, and no amount of technique
# coverage tells you that is happening.
#
# It doubles as the distro matrix. A rule can be correct on Debian and wrong on RHEL —
# `yama-runtime` is exactly that shape, where ptrace_scope=0 is a weakening on Debian and
# the vendor default on RHEL.
#
# Scope, honestly: containers under-represent a real host. There is no /dev/kmsg, so
# kernel-log rules cannot fire here at all, and the persistence surface is thin. This
# catches rules that fire on stock packages and stock accounts, not everything a real
# machine would surface. The real-host baseline is an out-of-band scan of a clean VM.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGES="${BLADEDR_BASELINE_IMAGES:-debian:stable-slim ubuntu:24.04 rockylinux/rockylinux:9 alpine:3.20}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "==> building probe and rule bundle"
CGO_ENABLED=0 GOOS=linux go build -o "$WORK/probe" ./cmd/bladedr-probe
go run ./cmd/bladedr-lab --dump-bundle > "$WORK/rules.json"

# Positive control. If the probe or the bundle is broken, every image reports zero
# findings and this script congratulates you on a clean fleet. Prove the pipeline can
# still see something before trusting the zeros.
echo "==> positive control: known-malicious snapshot"
CONTROL=$(CGO_ENABLED=0 go run ./cmd/bladedr-probe --rules "$WORK/rules.json" \
    --snapshot-file testdata/malicious-snapshot.json |
    python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("findings") or []))')
if [ "$CONTROL" -lt 1 ]; then
    echo "    the malicious snapshot produced $CONTROL findings — the probe or bundle is broken," >&2
    echo "    so a clean result below would mean nothing" >&2
    exit 1
fi
echo "    $CONTROL findings — pipeline is live"

FAILED=0
BROKEN=0
for image in $IMAGES; do
    echo "==> $image"
    # No --pull always: it makes every run depend on the network and refuses any
    # locally built image, which is how you test this script's own failure path.
    out=$(docker run --rm \
        -v "$WORK/probe:/probe:ro" -v "$WORK/rules.json:/rules.json:ro" \
        "$image" /probe --rules /rules.json 2>/dev/null || true)
    if [ -z "$out" ]; then
        echo "    probe produced no output — could not run in this image" >&2
        BROKEN=1
        continue
    fi
    printf '%s' "$out" > "$WORK/result.json"
    python3 - "$WORK/result.json" "$image" <<'PY' || FAILED=1
import json, sys
d = json.load(open(sys.argv[1]))
findings = d.get("findings") or []
host = d.get("host") or {}
digest = d.get("state_digest") or {}
print("    kernel %s, %d accounts, %d systemd units, %d modules" % (
    host.get("kernel", "?"), len(digest.get("accounts") or []),
    len(digest.get("systemd_units") or []), len(digest.get("kernel_modules") or [])))
if not findings:
    print("    clean")
    sys.exit(0)
# The probe emits rule_id and evidence; severity and title are joined server-side from
# the rule, so they are not available here. Print the evidence instead — it is what tells
# you whether the rule is wrong or the image genuinely ships that state.
print("    %d finding(s) on a stock image — these fire on every untouched host:" % len(findings))
for f in findings:
    print("      %-34s %s" % (f.get("rule_id"), json.dumps(f.get("evidence") or {})[:90]))
sys.exit(1)
PY
done

if [ "$BROKEN" -ne 0 ]; then
    echo
    echo "BASELINE ERROR: the probe could not run in one of the images, so this run proves" >&2
    echo "nothing either way. Not the same as a clean result." >&2
    exit 1
fi
if [ "$FAILED" -ne 0 ]; then
    echo
    echo "BASELINE FAIL: a rule fires on a stock image. Either the rule is wrong, or the" >&2
    echo "distro genuinely ships that state and the rule needs to know the vendor default" >&2
    echo "— see the Yama handling in internal/probe/collect_linux.go for the pattern." >&2
    exit 1
fi
echo
echo "BASELINE OK: no rule fires on any stock image"
