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
The agentless model is Sandfly-style; the eBPF tier wraps Tetragon. Independent
implementation, not a fork.

<p align="center">
  <img src="assets/demo1_opt.gif" alt="bladedr web console" width="820">
</p>

See [DESIGN.md](DESIGN.md) for the design notes.

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
make build               # server + probe
make demo                # scan against the bundled malicious snapshot
make build-probe-linux   # cross-compile the static probe for Linux
```

Manual:

```sh
BLADEDR_PROBE_BIN=./bin/bladedr-probe \
BLADEDR_PROBE_EXTRA="--snapshot-file testdata/malicious-snapshot.json" \
  ./bin/bladedr-server

curl -X POST localhost:8080/api/v1/hosts -d '{"hostname":"web-01","primary_ip":"10.0.0.5"}'
curl -X POST localhost:8080/api/v1/hosts/<id>/scans
curl "localhost:8080/api/v1/observations?host=<id>"
curl "localhost:8080/api/v1/observations?q=rootkit"   # BM25 text search on Postgres
```

## Storage

In-memory by default. For Postgres:

```sh
docker compose up -d
psql "postgres://bladedr:bladedr@localhost:5432/bladedr" -f internal/store/migrations/0001_init.sql
```

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
| `BLADEDR_ADMIN_PASSWORD` | (generated) | initial admin password |
| `BLADEDR_INGEST_TOKEN` | – | shared bearer token sensors use to post events |
| `BLADEDR_SECURE_COOKIES` | `false` | set the `Secure` flag on session cookies (needs TLS) |

## Deploy

The server runs anywhere; scan targets are always Linux (over SSH).

```sh
docker build -t bladedr-server .
docker run -p 8080:8080 -e BLADEDR_DATABASE_URL=... -e BLADEDR_NODE_KEY=... bladedr-server
```

Detection coverage vs the Linux ATT&CK / EDR-T matrix: [COVERAGE.md](COVERAGE.md).

## Rules

Rules are data (YAML + CEL), not code — author detections without recompiling. The
active set merges three layers, later wins (a user rule can override or, with
`enabled: false`, disable a builtin of the same id):

1. Builtin — embedded in the binary (`internal/rules/builtin/`).
2. Filesystem — `BLADEDR_RULES_DIR=/path` for versioned rule packs.
3. Database — POST a rule via API/UI; CEL-validated, active on the next scan.

```sh
curl -X POST :8080/api/v1/rules --data-binary '
id: my-loader-watch
title: "Process named loader"
category: process
severity: medium
foreach: processes
when: '\''item.comm == "loader"'\''
evidence: { pid: item.pid, comm: item.comm }'

curl :8080/api/v1/rules          # user/DB rules
curl :8080/api/v1/rules/active   # merged active set
curl -X PATCH :8080/api/v1/rules/my-loader-watch -d '{"enabled":false}'
curl -X DELETE :8080/api/v1/rules/my-loader-watch
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
curl :8080/api/v1/hosts/<id>/baseline
curl -X DELETE :8080/api/v1/hosts/<id>/baseline   # reset; next scan re-establishes it
```

## Risk scoring

A multinomial Naive Bayes model (`internal/risk`, pure Go) ranks open findings by how
likely you are to treat them as real. It trains on triage — `acknowledged` = real,
`false_positive` = noise (`resolved` is excluded, it's ambiguous) — using structural
features only (rule, category, severity, source, MITRE technique/tactic) plus coarse
evidence classes (`path:tmp` vs `path:home`, `uid:root`), never attacker-controlled
paths. So it learns techniques, not literal IOCs. It ranks; it does not detect.

`/risk/stats` cross-validates (leave-one-out) and reports whether the labelled set is
big/balanced/separable enough to trust. Until both classes exist, scoring falls back
to the rule's static score. A clean fleet yields few positives, so the model can also
train on the attack-emulation range ([poligon/](poligon/)): `make lab` plants known
techniques and writes `poligon/dataset.jsonl`. Set `BLADEDR_RISK_DATASET` to mix them
in; `/risk/stats` reports the prod-vs-lab split.

```sh
curl :8080/api/v1/risk/stats          # is there enough labelled data to trust it?
curl :8080/api/v1/risk/observations   # open findings ranked, with the driving features
```

## eBPF tier (Phase 2)

Agentless scans see the artifact at rest; the sensor sees the act in real time (exec,
injection, container escape, fileless, C2). `bladedr-sensor` wraps
[Tetragon](https://github.com/cilium/tetragon): it loads the `linux-probe-shield`
TracingPolicies, consumes Tetragon's JSON stream, maps each hit to an observation
(severity/MITRE from the policy annotations) and posts batches. These land in the same
`observations` table (`source=ebpf_sensor`), so they flow through triage, the risk
model, the UI and export unchanged. A host is `scan_only` or `scan_plus_sensor`.

```sh
make sensor                                   # cross-build the Linux sensor
scripts/deploy-sensor.sh user@host <host-id>  # run Tetragon + sensor on a host
curl ':8080/api/v1/observations?source=ebpf_sensor'
```

Needs Docker and a BTF-capable kernel (Tetragon runs as a privileged container). All
detection logic lives in the policies; the sensor only forwards events. The
server-push path installs to `/opt/bladedr` and runs the sensor as a systemd unit
(`Restart=always`, ingest token in a mode-0600 `EnvironmentFile`).

## Auth and roles

Console and API require auth. A fresh install creates an admin account (password from
`BLADEDR_ADMIN_PASSWORD`, or generated and printed once). Sign in at `/ui/login`; the
session works as a cookie (UI) or `Authorization: Bearer <token>` (API).

Roles: admin (everything + users/credentials), operator (read + triage/scan/rules/
sensor), viewer (read-only). Only admins create users and assign roles. eBPF sensors
authenticate machine-to-machine with `BLADEDR_INGEST_TOKEN`. Security events (logins,
user/role changes, sensor deploys, RBAC denials) go to an audit log — `GET
/api/v1/audit` or the admin Audit page.

```sh
curl -X POST :8080/api/v1/login -d '{"Username":"admin","Password":"…"}'   # -> {token}
curl :8080/api/v1/hosts -H "Authorization: Bearer <token>"
```

Cookies are `HttpOnly` + `SameSite=Lax`. Behind TLS, set `BLADEDR_SECURE_COOKIES=1`.
Keep `.bladedr.env` private (gitignored) — it holds the deployment's secrets.

## Credentials and SSH

Credentials are sealed with a Curve25519 key (NaCl sealed box); only the node key
(`BLADEDR_NODE_KEY`) decrypts them, so the DB never holds usable secrets. Secrets are
write-only via the API. SSH host keys are pinned on first use.

```sh
./bin/bladedr-server -keygen           # mint BLADEDR_NODE_KEY
curl -X POST :8080/api/v1/credentials -d '{"username":"root","auth_type":"ssh_key","secret":"<PEM>"}'
curl -X POST :8080/api/v1/hosts -d '{"primary_ip":"10.0.0.5","ssh_port":22,"credential_id":"<id>","arch":"amd64"}'
curl -X POST :8080/api/v1/hosts/<id>/scans
```
