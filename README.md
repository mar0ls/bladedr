<p align="center">
  <img src="assets/logo.png" alt="bladedr" width="460">
</p>

<p align="center">
  <a href="https://github.com/mar0ls/bladedr/actions/workflows/ci.yml"><img src="https://github.com/mar0ls/bladedr/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/mar0ls/bladedr"><img src="https://codecov.io/gh/mar0ls/bladedr/graph/badge.svg" alt="Coverage"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/go-1.26-00ADD8" alt="Go">
</p>

Agentless threat detection and response for Linux, with an optional eBPF tier.
The agentless scanner is an independent implementation. The eBPF sensor uses
Tetragon for runtime telemetry.

<p align="center">
  <img src="assets/demo1_opt.gif" alt="bladedr web console" width="820">
</p>

See [DESIGN.md](DESIGN.md) for architecture and trust-boundary details.

<p align="center">
  <img src="assets/architecture.png" alt="bladedr architecture" width="820">
</p>

## Components

- **bladedr-probe** — static, ephemeral collector run on the target. Carries a CEL
  engine, evaluates rules against a `/proc` snapshot, returns findings. Linux-only;
  `--snapshot-file` replays a captured snapshot on any platform (tests, dev).
- **bladedr-server** — inventory, scan orchestration, rule engine, REST API, web
  console (auth + RBAC). In-memory store by default; Postgres + pg_search (BM25) for
  production (`internal/store/migrations/`).
- **bladedr-sensor** — the eBPF tier (Phase 2). Thin Tetragon wrapper: loads the
  policies, maps hits to observations, posts them to the server. Deployed over SSH,
  runs as a systemd unit.
- **bladectl** — script-friendly API client: `login`, `hosts`, `scans`, `findings`,
  `responses`. Reads `BLADEDR_SERVER_URL` and `BLADEDR_TOKEN`.

Scanning runs over SSH: sealed credential store, `SSHTransport` in
`internal/scan/ssh.go`, host keys pinned on first use. Rules are YAML + CEL
(`internal/rules/builtin/`), overridable via `BLADEDR_RULES_DIR` or the API/UI.
Baseline/drift, fleet-rarity and a risk model sit on top of the raw observations;
ECS/JSON export feeds a SIEM.

## Quick start

<p align="center">
  <img src="assets/demo.gif" alt="bladedr CLI demo" width="820">
</p>

```sh
make build               # server, probe and CLI
make demo                # scan against the bundled malicious snapshot
make build-probe-linux   # cross-compile the static probe for Linux
```

Manual startup:

```sh
BLADEDR_ADMIN_PASSWORD=dev-password \
BLADEDR_PROBE_BIN=./bin/bladedr-probe \
BLADEDR_PROBE_EXTRA="--snapshot-file testdata/malicious-snapshot.json" \
  ./bin/bladedr-server
```

In another shell:

```sh
TOKEN=$(curl -fsS -X POST localhost:8080/api/v1/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"dev-password"}' |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
AUTH="Authorization: Bearer $TOKEN"

HOST_ID=$(curl -fsS -H "$AUTH" -H 'content-type: application/json' \
  -X POST localhost:8080/api/v1/hosts \
  -d '{"hostname":"web-01","primary_ip":"10.0.0.5"}' |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
curl -H "$AUTH" -X POST "localhost:8080/api/v1/hosts/$HOST_ID/scans"
curl -H "$AUTH" "localhost:8080/api/v1/observations?host=$HOST_ID"
curl -H "$AUTH" "localhost:8080/api/v1/observations?q=rootkit"
```

## Storage

In-memory by default. For Postgres, point `BLADEDR_DATABASE_URL` at a ParadeDB
instance — the server applies the embedded, versioned migrations on startup (tracked
in `schema_migrations`, so each runs once):

```sh
docker compose up -d
BLADEDR_DATABASE_URL=postgres://bladedr:bladedr@localhost:5432/bladedr ./bin/bladedr-server
```

Both backends implement `store.Store`. Keyset pagination completeness, exclusive job
claims, lease reclamation, the response-action state machine and retention are
asserted once in `internal/store/contract_test.go` and run against both, so the
production backend is not the least-tested one. The Postgres pass needs a live
database; CI runs it and fails if it skips.

```sh
docker compose up -d
BLADEDR_TEST_DATABASE_URL=postgres://bladedr:bladedr@localhost:5432/bladedr \
  go test ./internal/store/
```

A case that fails on exactly one backend means that backend is wrong.

## Config

| var | default | meaning |
|-----|---------|---------|
| `BLADEDR_ADDR` | `:8080` | listen address |
| `BLADEDR_PROBE_BIN` | `bladedr-probe` | probe binary for LocalTransport |
| `BLADEDR_RULES_DIR` | (builtin) | load rules from a dir instead of embedded |
| `BLADEDR_PROBE_EXTRA` | – | extra probe args (dev/testing) |
| `BLADEDR_DATABASE_URL` | – | Postgres DSN; unset = in-memory |
| `BLADEDR_NODE_KEY` | (ephemeral) | base64 node key for credential sealing (`-keygen` mints one) |
| `BLADEDR_PROBE_LINUX_AMD64` | – | linux/amd64 probe path (SSH scanning) |
| `BLADEDR_PROBE_LINUX_ARM64` | – | linux/arm64 probe path (SSH scanning) |
| `BLADEDR_SENSOR_LINUX_AMD64` | – | linux/amd64 sensor path for server-side deployment |
| `BLADEDR_SENSOR_LINUX_ARM64` | – | linux/arm64 sensor path for server-side deployment |
| `BLADEDR_POLICY_DIR` | – | Tetragon policy directory used for sensor deployment |
| `BLADEDR_SERVER_URL` | – | control-plane URL reachable from deployed sensors |
| `BLADEDR_ADMIN_USER` | `admin` | initial administrator username |
| `BLADEDR_ADMIN_PASSWORD` | (generated) | initial admin password |
| `BLADEDR_RESPONSE_ALLOW_SELF_APPROVAL` | `false` | let one admin both request and approve a response action (see [Response actions](#response-actions)) |
| `BLADEDR_TLS_CERT` | – | PEM cert path; with `_KEY` serves HTTPS and auto-sets Secure cookies |
| `BLADEDR_TLS_KEY` | – | PEM private key path (pairs with `BLADEDR_TLS_CERT`) |
| `BLADEDR_SECURE_COOKIES` | `false` | force the `Secure` flag on session cookies (implied by TLS) |
| `BLADEDR_TRUSTED_PROXY_CIDRS` | – | comma-separated proxy networks allowed to supply forwarding headers |
| `BLADEDR_LOG_FORMAT` | `text` | `json` for structured logs (log aggregators) |
| `BLADEDR_LOG_LEVEL` | `info` | `debug` to include health/metrics scrapes and detail |
| `BLADEDR_SCAN_WORKERS` | `4` | concurrent scan workers, range 1–128 |
| `BLADEDR_SCAN_TIMEOUT` | `5m` | deadline for one queued scan |
| `BLADEDR_SCHEDULER_TICK` | `30s` | schedule polling interval |
| `BLADEDR_EXPORT_WORKERS` | `2` | concurrent export workers, range 1–32 |
| `BLADEDR_RISK_DATASET` | `poligon/dataset.jsonl` | labelled JSONL dataset; missing file disables lab samples |
| `BLADEDR_RISK_AUGMENT` | `false` | enable deterministic class balancing for model training |
| `BLADEDR_RETENTION_OBSERVATIONS` | disabled | observation archive age; minimum `1h` |
| `BLADEDR_RETENTION_SCANS` | disabled | scan archive age; minimum `1h` |
| `BLADEDR_RETENTION_AUDIT` | disabled | audit archive age; minimum `1h` |
| `BLADEDR_RETENTION_ARCHIVE` | disabled | archive deletion age; minimum `1h` |

## Deploy

The server runs anywhere; scan targets are always Linux (over SSH).

```sh
docker build -t bladedr-server .
docker run -p 8080:8080 -e BLADEDR_DATABASE_URL=... -e BLADEDR_NODE_KEY=... bladedr-server
```

Running it for real (TLS, systemd, Postgres, backups, hardening): see
[docs/deployment.md](docs/deployment.md).

Operational endpoints (unauthenticated, for probes/scrapers): `GET /healthz`
(liveness), `GET /readyz` (readiness — checks the store is reachable), `GET /metrics`
(Prometheus text: request counts by method/status + a latency summary).
The HTTP listener applies a 10-second header timeout, 30-second request-read timeout,
5-minute response-write timeout and 2-minute idle timeout.

Detection coverage vs the Linux ATT&CK / EDR-T matrix: [COVERAGE.md](COVERAGE.md).

## Rules

Rules are data (YAML + CEL), not code — author detections without recompiling. The
active set merges three layers, later wins (a user rule can override or, with
`enabled: false`, disable a builtin of the same id):

1. Builtin — embedded in the binary (`internal/rules/builtin/`).
2. Filesystem — `BLADEDR_RULES_DIR=/path` for versioned rule packs.
3. Database — POST a rule via API/UI; CEL-validated, active on the next scan.

```sh
curl -H "$AUTH" -X POST :8080/api/v1/rules --data-binary '
id: my-loader-watch
title: "Process named loader"
category: process
severity: medium
foreach: processes
when: '\''item.comm == "loader"'\''
evidence: { pid: item.pid, comm: item.comm }'

curl -H "$AUTH" :8080/api/v1/rules
curl -H "$AUTH" :8080/api/v1/rules/active
curl -H "$AUTH" -X PATCH :8080/api/v1/rules/my-loader-watch -d '{"enabled":false}'
curl -H "$AUTH" -X DELETE :8080/api/v1/rules/my-loader-watch
```

A rule is an optional `foreach` collection (dotted paths like
`persistence.systemd_units` work), a CEL `when`, and `evidence`/`dedup` expressions.
Snapshot fields: `processes`, `listening_sockets`, `persistence.*` (cron,
systemd_units, authorized_keys, ld_preload), `kernel_modules`, `suspicious_files`,
`accounts`, `kernel_log`, `pam_modules`, `pth_files`, `immutable_files`,
`hidden_modules`, `facts.*`.

## Baseline and drift

bladedr keeps a per-host baseline of stable state (listening ports, kernel modules,
accounts, authorized keys, cron, systemd units). The first scan sets it; later scans
diff against it and raise `baseline-new-*` for anything new — a new UID-0 account, a
new listener, a new key.

Fleet-rarity scoring complements it: an item present on a tiny fraction of the fleet
raises a low-severity `fleet-rare-*` lead. Both are deterministic, no training data.

```sh
curl -H "$AUTH" ":8080/api/v1/hosts/$HOST_ID/baseline"
curl -H "$AUTH" -X DELETE ":8080/api/v1/hosts/$HOST_ID/baseline"   # reset; next scan re-establishes it
```

## Risk scoring

A multinomial Naive Bayes model (`internal/risk`, pure Go) ranks open findings by how
likely you are to treat them as real. It trains on triage — `acknowledged` = real,
`false_positive` = noise (`resolved` is excluded, it's ambiguous) — using structural
features only (rule, category, severity, source, MITRE technique/tactic) plus coarse
evidence classes (`path:tmp` vs `path:home`, `uid:root`), never attacker-controlled
paths. So it learns techniques, not literal IOCs. It ranks; it does not detect.

`/risk/stats` cross-validates (stratified 5-fold, deterministic) and reports ROC AUC,
balanced accuracy, precision, recall and Brier score — enough to tell you whether the
labelled set is big/balanced/separable enough to trust. Each class is loaded
independently, up to 5k recent observations, so a backlog of untriaged alerts can't
crowd out the labels. Until both classes exist, scoring falls back to the rule's static
score.

`BLADEDR_RISK_AUGMENT` oversamples the minority class, but only when fitting the
scorer — the CV folds stay on real observations. Augmenting before the split would put
synthetic near-duplicates of a held-out row into training and quietly inflate every
number on that page.

Worth being honest about what the metrics mean: the labels are analyst decisions, and
the analyst was looking at this model's ranking when they made them. So the numbers
measure agreement with past triage, not ground truth, and a rule nobody ever triages
contributes nothing either way. That's the reason ranking and detection stay separate —
a badly calibrated model reorders your queue, it never makes a finding disappear.

A clean fleet yields few positives, so the model can also train on the attack-emulation
range ([poligon/](poligon/)): `make lab` plants known techniques and writes
`poligon/dataset.jsonl`. Set `BLADEDR_RISK_DATASET` to mix them in; `/risk/stats`
reports the prod-vs-lab split.

```sh
curl -H "$AUTH" :8080/api/v1/risk/stats
curl -H "$AUTH" :8080/api/v1/risk/observations
```

## Response actions

Containment runs over the host's existing pinned SSH transport. There is no generic
command endpoint: a request names one of four playbooks, and the server builds the
command from validated parameters.

| Playbook | Effect | Parameters |
|---|---|---|
| `kill_process` | `SIGTERM` after confirming `/proc/<pid>/exe` still resolves to `expected_exe` | `pid`, `expected_exe` (absolute) |
| `disable_systemd_unit` | `systemctl disable --now <unit>` | `unit` (matching `[A-Za-z0-9_.@-]{1,200}`) |
| `isolate_host` | nftables table `inet bladedr_response` with a default-drop policy, keeping SSH and the control plane reachable | `control_plane_ip` (literal), `control_plane_port` — either may be omitted and is taken from `BLADEDR_SERVER_URL` |
| `restore_network` | drops only the `bladedr_response` table | – |

Actions are created `pending`, and `dry_run` unless `dry_run:false` is passed. Nothing
reaches the host until a second administrator approves: an approval whose approver
equals the requester is refused with `409` and recorded in the audit log. Rejection is
terminal and does not contact the host; the requester may withdraw their own request.

`BLADEDR_RESPONSE_ALLOW_SELF_APPROVAL=true` relaxes this for deployments with one
administrator, at the cost of making a single admin session sufficient to run
root-level commands fleet-wide. The server logs a warning at startup when it is set.

The `expected_exe` check is re-evaluated on the host at execution time, so a PID
recycled between triage and approval is not killed. `isolate_host` refuses a DNS name
for the control plane — from either the parameter or the server URL — because
resolution is the first thing to break under a default-drop policy, and a host that
can't reach the control plane is a host you've lost.

```sh
ACTION=$(curl -fsS -H "$AUTH" -H 'content-type: application/json' \
  -X POST :8080/api/v1/responses \
  -d "{\"host_id\":\"$HOST_ID\",\"playbook\":\"kill_process\",
       \"params\":{\"pid\":\"4242\",\"expected_exe\":\"/usr/bin/xmrig\"},\"dry_run\":false}" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

# From a different admin account:
curl -H "$AUTH2" -X POST ":8080/api/v1/responses/$ACTION/approve"
curl -H "$AUTH2" -X POST ":8080/api/v1/responses/$ACTION/reject" \
  -H 'content-type: application/json' -d '{"reason":"wrong host"}'
curl -H "$AUTH" ":8080/api/v1/responses/$ACTION"
```

The same flow through `bladectl`:

```sh
bladectl responses request --host "$HOST_ID" --playbook kill_process \
  --param pid=4242 --param expected_exe=/usr/bin/xmrig --execute
bladectl responses approve "$ACTION"          # must be a different admin
bladectl responses reject --reason "wrong host" "$ACTION"
```

## eBPF tier

Agentless scans see the artifact at rest; the sensor sees the act in real time (exec,
injection, container escape, fileless, C2). `bladedr-sensor` wraps
[Tetragon](https://github.com/cilium/tetragon): it loads the `linux-probe-shield`
TracingPolicies, consumes Tetragon's JSON stream, maps each hit to an observation
(severity/MITRE from the policy annotations) and posts batches. These land in the same
`observations` table (`source=ebpf_sensor`), so they flow through triage, the risk
model, the UI and export unchanged. A host is `scan_only` or `scan_plus_sensor`.

```sh
make sensor
BLADEDR_TOKEN="$TOKEN" \
BLADEDR_SERVER=https://bladedr.example \
  scripts/deploy-sensor.sh user@host "$HOST_ID"
curl -H "$AUTH" ':8080/api/v1/observations?source=ebpf_sensor'
```

Needs Docker and a BTF-capable kernel (Tetragon runs as a privileged container). All
detection logic lives in the policies; the sensor only forwards events. The
server-push path installs to `/opt/bladedr` and runs the sensor as a systemd unit
(`Restart=always`, token in a mode-0600 `EnvironmentFile`, never in argv).

## Auth and roles

Console and API require auth. A fresh install creates an admin account (password from
`BLADEDR_ADMIN_PASSWORD`, or generated and printed once). Sign in at `/ui/login`; the
session works as a cookie (UI) or `Authorization: Bearer <token>` (API).

Roles: admin (everything + users/credentials/response decisions), operator (read +
triage/scan/rules/sensor), viewer (read-only). Only admins create users and assign
roles. eBPF sensors authenticate machine-to-machine with a per-host token minted at
`/api/v1/hosts/{id}/sensor-tokens` — the server keeps only the digest, so the table is
useless to anyone who reads it. Security events (logins, user/role changes, sensor
deploys, RBAC denials, blocked self-approvals) go to an audit log — `GET
/api/v1/audit` or the admin Audit page.

TOTP is optional per account, enrolled from the console (`/api/v1/me/mfa/setup`, then
`/confirm` with a code). The shared secret is sealed with the node key, so MFA only
works where `BLADEDR_NODE_KEY` is set. Turning MFA off needs the password *and* a
current code, so a hijacked session can't quietly strip it.

```sh
curl -X POST :8080/api/v1/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"…"}'
curl -H "Authorization: Bearer <token>" :8080/api/v1/hosts
```

Cookies are `HttpOnly` + `SameSite=Lax`, and `Secure` once TLS is on. Failed logins
are rate-limited per source IP (a short lockout that backs off on repeated failures),
so online password guessing is bounded. An unknown username still costs a full bcrypt
verification, otherwise login timing would tell an attacker which accounts exist. Keep
`.bladedr.env` private (gitignored) — it holds the deployment's secrets.

## Credentials and SSH

Credentials are sealed with a Curve25519 key (NaCl sealed box); only the node key
(`BLADEDR_NODE_KEY`) decrypts them, so the DB never holds usable secrets. Secrets are
write-only via the API. SSH host keys are pinned on first use.

### Agentless execution model

A scan opens an SSH session, drops a static probe in `/tmp/.bladedr/` at mode 0700,
runs it, and leaves nothing behind. The probe reads a `/proc` snapshot, evaluates the
rules locally and prints JSON. Root widens what it can collect but isn't required.
Tetragon is the only thing that stays resident, and only on hosts you opt in.

The probe is cached under its sha256 so repeat scans skip the upload, which makes that
cache path worth guarding: `/tmp` is world-writable, so the staging dir is required to
be 0700 and owned by the scan account (checked without following symlinks), and a
cached binary is re-hashed before it runs. Anything that doesn't verify gets
re-uploaded instead of trusted.

The probe is cached under its content hash so scheduled scans skip the multi-MB
upload. On a host that may already be compromised that cache is a code-execution
path, and `/tmp` is world-writable, so two checks gate it:

- the staging directory must be mode `0700` and owned by the scan account, checked
  with a non-dereferencing `ls -ld` so a symlink at the path is rejected;
- the cached binary is verified by SHA-256, not by size — a same-length substitute
  passes a size check. An entry that cannot be verified is re-uploaded, not trusted.

Without both, a local unprivileged user could pre-create `/tmp/.bladedr`, plant a
binary at the predictable path and have the next scan run it as the scan account.

The control plane holds SSH access to monitored hosts and must be treated as a
privileged system. Stored credentials are sealed with `BLADEDR_NODE_KEY`, which is
kept outside the database, and SSH host keys are pinned on first use. Use a
least-privilege SSH account when full `/proc` visibility is not required.

```sh
./bin/bladedr-server -keygen           # mint BLADEDR_NODE_KEY
CREDENTIAL_ID=$(curl -fsS -H "$AUTH" -H 'content-type: application/json' \
  -X POST :8080/api/v1/credentials \
  -d '{"username":"root","auth_type":"ssh_key","secret":"<PEM>"}' |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
HOST_ID=$(curl -fsS -H "$AUTH" -H 'content-type: application/json' \
  -X POST :8080/api/v1/hosts \
  -d "{\"primary_ip\":\"10.0.0.5\",\"ssh_port\":22,\"credential_id\":\"$CREDENTIAL_ID\",\"arch\":\"amd64\"}" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
curl -H "$AUTH" -X POST ":8080/api/v1/hosts/$HOST_ID/scans"
```
