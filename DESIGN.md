# bladedr — technical design

Agentless threat hunting / DR for Linux, with an optional eBPF tier.
Inspiration: Sandfly (agentless model) + Tetragon/Kunai (eBPF telemetry).
**This is an independent implementation, not a clone** — our own code, our own data
model, with the eBPF engine drawn from open source (Tetragon, Apache-2.0).

---

## 1. Design principles

1. **Agentless is the default posture.** Every host is onboarded with
   SSH alone — zero install.
2. **eBPF is a per-host option** (`scan_only` vs `scan_plus_sensor`), enabled where
   you want hunting depth — not a global philosophy.
3. **One data model for both sources.** Findings (agentless) and events (eBPF) land
   in the same `observations` table — same tagging, scoring, dashboard and export.
   That lets the eBPF tier arrive without reworking the core.
4. **Rules are data, not code.** Agentless: YAML + CEL expressions. eBPF: native
   Tetragon TracingPolicies loaded 1:1. Add detections without recompiling.
5. **The probe is ephemeral and evaluates on-host.** It carries an embedded CEL engine; the
   server uploads it together with the current **rule bundle**, the probe evaluates
   detections on the host and returns findings (+ an optional compact snapshot for
   forensics), then deletes itself. Rules are still data (the bundle is uploaded at
   launch) → iterate without recompiling the probe. Less data on the wire; works in
   restricted environments.
6. **PostgreSQL + pg_search (BM25) underneath.** One backend: relational config and
   secrets (transactions, encryption) plus `observations` with full-text BM25
   (pg_search/tantivy) and SQL aggregations for the dashboard. Everything sits behind
   a `store` interface → if Phase 2 (eBPF) floods the system with events, the
   data-plane can be swapped to OpenSearch/ClickHouse without touching the rest.
   Secrets are never plaintext (envelope encryption), with a path to Vault. The
   hunting dashboard is our own (search + filters + timeline); ECS export to an
   external Kibana is optional.

---

## 2. Architecture

```
                      ┌──────────────────────────────────────────────┐
                      │                bladedr-server (Go)            │
                      │                                              │
  operator ──HTTP──►  │  REST API  ─┬─ inventory (hosts/creds)        │
   / web UI           │            ├─ scheduler (cron/interval)       │
                      │            ├─ rule bundle builder (CEL)        │
                      │            ├─ scoring + dedup + enrich          │
                      │            ├─ collections + tags              │
                      │            ├─ hunting UI (search/filter/timeline)│
                      │            └─ exporters (ECS→Kibana, webhook) │
                      │                  │                            │
                      │            ┌─────┴─────┐                      │
                      │            │  store    │  PostgreSQL          │
                      │            │  (iface)  │  + pg_search (BM25)  │
                      │            └───────────┘  → OpenSearch (P2)   │
                      └───────┬──────────────────────────┬───────────┘
                              │ SSH (pull, scheduled)     │ gRPC/mTLS (push, Phase 2)
                              ▼                           ▼
                   ┌────────────────────┐     ┌──────────────────────────┐
                   │ host [scan_only]   │     │ host [scan_plus_sensor]   │
                   │                    │     │                          │
                   │ bladedr-probe      │     │ bladedr-probe (scans)    │
                   │  • static binary   │     │       +                  │
                   │  • CEL + rule      │     │ bladedr-sensor           │
                   │    bundle (smart)  │     │  • Tetragon wrapper       │
                   │  • findings(+snap) │     │  • loads linux-probe-     │
                   │  • self-delete     │     │    shield 1:1             │
                   │  AGENTLESS         │     │  • event stream           │
                   └────────────────────┘     └──────────────────────────┘
```

Three binaries in a mono-repo:
- **bladedr-server** — API, scheduler, rule engine, storage, export, web UI.
- **bladedr-probe** — static, smart collector (CGO_ENABLED=0, cross-compiled for
  amd64/arm64). No runtime dependencies. It carries the embedded CEL engine; the
  server uploads it over SSH with the current **rule bundle**, the probe collects
  state, evaluates rules on the host and returns findings (+ optional compact
  snapshot), then deletes itself.
- **bladedr-sensor** — Phase 2 (IMPLEMENTED). A thin Tetragon wrapper: loads the
  linux-probe-shield TracingPolicies 1:1, consumes Tetragon's JSON event stream, maps
  each policy hit to an observation (severity/MITRE from the policy annotations) and
  posts batches to `POST /api/v1/hosts/{id}/events` (the existing REST API — pragmatic
  vs. the originally-sketched gRPC/mTLS). Optional, only for `scan_plus_sensor` hosts.
  Validated live (Tetragon container on a real host → sensor → observations). See `internal/sensor`, `cmd/bladedr-sensor`, `scripts/deploy-sensor.sh`, and the
  dashboard "Enable sensor" toggle (server-push deploy over SSH via `POST /hosts/{id}/sensor`).

---

## 3. Data model (PostgreSQL + pg_search)

Backend: **PostgreSQL**. Keys as `uuid`, time as `timestamptz` (UTC), structures as
`jsonb`. Config (host, credential, collection, tag, rule, schedule, export_target) is
relational and transactional. `scan` and `observation` are time-series; over the
`observation` text fields there is a **BM25 (pg_search / tantivy)** index for
full-text hunting, alongside ordinary B-tree indexes for structured filters and SQL
aggregations. Everything sits behind the `store` interface — the data-plane
(`scan`/`observation`) is swappable to OpenSearch/ClickHouse in Phase 2.

### 3.1 host
| column | type | description |
|---|---|---|
| id | uuid PK | |
| hostname | text | reported by the host or assigned |
| primary_ip | text | address to connect to |
| ssh_port | int | default 22 |
| credential_id | uuid FK→credential | how to connect |
| ssh_host_key | text | pinned host key (TOFU) |
| os_name / os_version / kernel | text | detected on first scan |
| arch | text | amd64 / arm64 |
| mode | text enum | `scan_only` \| `scan_plus_sensor` |
| status | text enum | `pending` \| `online` \| `unreachable` \| `disabled` |
| last_seen | datetime | last successful contact |
| created_at | datetime | |

### 3.2 credential
SSH key/password, **reusable** across hosts (one key → many machines).
| column | type | description |
|---|---|---|
| id | uuid PK | |
| name | text | label |
| username | text | SSH user |
| auth_type | text enum | `ssh_key` \| `password` \| `ssh_agent` |
| secret_ref | text | path to key / vault reference; **no plaintext stored** |
| secret_enc | blob | secret sealed to the node public key; never plaintext |
| created_at | datetime | |

> Secret protection: secrets are sealed with a Curve25519 public key (NaCl sealed
> box, `internal/secrets`); only the node private key (`BLADEDR_NODE_KEY`) decrypts
> them, so the server database holds only ciphertext (Sandfly-style split trust).
> The API is write-only for secrets. Future: Vault/SSM via `secret_ref`.

### 3.3 collection — taggable sets
A set of hosts: **static** (a list) or **dynamic** (membership rule by hostname / IP
/ tag). Implements "tagged by user, or by hostname or ip".
| column | type | description |
|---|---|---|
| id | uuid PK | |
| name | text | |
| description | text | |
| membership_type | text enum | `static` \| `dynamic` |
| membership_rule | json | for `dynamic`: `{hostname_glob, ip_cidr[], tags[]}` |
| created_at | datetime | |

`collection_member` (for static): `(collection_id, host_id)`.
Dynamic membership is resolved on the fly from `membership_rule`.

### 3.4 tag + host_tag
Key-value tags attached to hosts (and to observations).
- `tag(id, key, value)`
- `host_tag(host_id, tag_id, set_by)` — `set_by`: `user` \| `auto`

### 3.5 scan
A single agentless run against a host.
| column | type | description |
|---|---|---|
| id | uuid PK | |
| host_id | uuid FK | |
| trigger | text enum | `scheduled` \| `manual` \| `api` |
| status | text enum | `running` \| `ok` \| `partial` \| `failed` |
| probe_version | text | |
| started_at / finished_at | datetime | |
| duration_ms | int | |
| error | text | when `failed` |
| risk_score | int | aggregated 0–100 for this scan |

### 3.6 observation — **shared findings + events table**
The key decision. An agentless finding and an eBPF event are the same record; they
differ in the `source` field.
| column | type | description |
|---|---|---|
| id | uuid PK | |
| host_id | uuid FK | |
| scan_id | uuid FK nullable | set for agentless; NULL for the eBPF stream |
| source | text enum | `agentless_probe` \| `ebpf_sensor` |
| rule_id | text | which rule fired |
| category | text | `process` \| `persistence` \| `network` \| `file` \| `kernel` \| `credential` |
| title | text | |
| severity | text enum | `info` \| `low` \| `medium` \| `high` \| `critical` |
| score | int | contribution to risk_score |
| mitre | json | `["T1620","T1059.004"]` |
| evidence | json | the proof: snapshot fragment / event payload |
| dedup_key | text | stable key — collapses repeats |
| status | text enum | `open` \| `acknowledged` \| `resolved` \| `false_positive` |
| first_seen / last_seen | datetime | |
| count | int | how many times deduplicated |

B-tree indexes: `(host_id, status)`, `(dedup_key)`, `(severity, last_seen)`, `(rule_id)`.
A **BM25 (pg_search)** index over `title` + serialized `evidence` + `rule_id` powers
full-text hunting (`GET /observations?q=...`).

### 3.7 rule
| column | type | description |
|---|---|---|
| id | text PK | e.g. `deleted-running-binary` |
| source | text enum | `builtin` \| `yaml` \| `user` \| `tetragon` |
| category | text | |
| severity | text | |
| mitre | json | |
| enabled | bool | |
| definition | json/yaml | agentless: match+CEL; tetragon: raw policy YAML |

### 3.8 schedule
| column | type | description |
|---|---|---|
| id | uuid PK | |
| scope_type | text enum | `host` \| `collection` |
| scope_id | uuid | |
| interval | text | cron (`0 */6 * * *`) or duration (`15m`) |
| scan_profile | text | which rule set (e.g. `full`, `quick`) |
| enabled | bool | |
| next_run | datetime | |

Implements "scan frequency" — per host or per collection.

### 3.9 export_target
| column | type | description |
|---|---|---|
| id | uuid PK | |
| type | text enum | `elasticsearch` \| `kibana` \| `webhook` \| `syslog` |
| config | json | `{url, index, api_key, ...}` |
| filter | json | e.g. min severity, only selected collections |
| enabled | bool | |

---

## 4. Probe ↔ server contract

The probe is **smart**: it evaluates rules on the host. Communication is bidirectional.

**Flow:**
1. The server uploads the probe binary + the **rule bundle** (`rules.json`) to a
   temporary directory on the host.
2. It runs the probe with a session: `bladedr-probe --session <id> --rules rules.json
   [--emit-snapshot]`.
3. The probe collects state, evaluates the CEL rules locally, writes the **result**
   (findings, optionally a snapshot) to stdout.
4. The server reads the result; the probe deletes itself and the bundle, disconnects.

### 4.1 Input — rule bundle (server → probe)
```json
{
  "schema": "bladedr.rulebundle/v1",
  "bundle_version": "2026-06-10T11:00:00Z",
  "rules": [
    { "id": "deleted-running-binary", "foreach": "processes",
      "when": "item.exe_deleted == true && !item.exe.startsWith(\"/memfd:\")",
      "evidence": { "pid": "item.pid", "exe": "item.exe", "comm": "item.comm" },
      "dedup": ["item.pid", "item.exe"] }
  ]
}
```
The probe knows only the match logic (CEL); metadata (severity, score, mitre) stays
on the server and is attached during enrichment — so scoring can be re-tuned without
re-scanning.

### 4.2 Output — scan result (probe → server)
```json
{
  "schema": "bladedr.scanresult/v1",
  "probe_version": "0.1.0",
  "bundle_version": "2026-06-10T11:00:00Z",
  "collected_at": "2026-06-10T12:00:00Z",
  "host": {
    "hostname": "web-01", "kernel": "6.8.0-31-generic",
    "os": "Ubuntu 24.04", "arch": "amd64", "uptime_s": 812340
  },
  "findings": [
    { "rule_id": "deleted-running-binary",
      "evidence": { "pid": 4711, "exe": "/tmp/.x/payload", "comm": "kworker/u8:2" },
      "dedup_key": "4711|/tmp/.x/payload",
      "observed_at": "2026-06-10T12:00:00Z" }
  ],
  "collector_errors": [],
  "snapshot": null
}
```
`findings[]` → the server enriches them (severity/score/mitre from the rule registry,
host context, tags) and stores them as `observations`. `collector_errors[]` allows a
partial scan (`scan.status=partial`).

### 4.3 Optional snapshot (`--emit-snapshot`) for forensics / re-evaluation
When enabled, `snapshot` holds the raw state — letting you later run NEW rules over
OLD state without re-entering the host:

```json
{
  "schema": "bladedr.snapshot/v1",
  "probe_version": "0.1.0",
  "collected_at": "2026-06-10T12:00:00Z",
  "host": { "hostname": "web-01", "kernel": "6.8.0-31-generic", "os": "Ubuntu 24.04", "arch": "amd64", "uptime_s": 812340 },
  "processes": [
    { "pid": 4711, "ppid": 1, "uid": 0, "comm": "kworker/u8:2", "exe": "/tmp/.x/payload", "exe_deleted": true }
  ],
  "persistence": {
    "cron": [{"path":"/etc/cron.d/x","line":"* * * * * curl ..."}],
    "ld_preload": {"ld_so_preload":"/etc/ld.so.preload","entries":["/tmp/evil.so"]}
  },
  "kernel_modules": [{"name":"hideproc","out_of_tree":true,"signed":false}],
  "facts": { "core_pattern": "|/usr/lib/systemd/systemd-coredump" },
  "collector_errors": []
}
```

All three contracts are versioned by the `schema` field — new collectors add fields,
they do not break older servers.

---

## 5. Agentless rule format (YAML + CEL)

Rules are evaluated by the **probe on the host** (the CEL engine is embedded in the
binary; the bundle is uploaded at launch — section 4.1). Expressions are in **CEL**
(Google Common Expression Language — a mature Go library, safe, no arbitrary code
execution). Severity/score/mitre are not in the bundle — the server attaches them at
enrichment, so scoring is re-tunable without re-scanning. Rules live in three layers,
merged by `id` (later wins): builtin (`internal/rules/builtin/`, embedded),
filesystem (`BLADEDR_RULES_DIR`), and the database (added via the API, CEL-validated).

```yaml
id: deleted-running-binary
title: "Running process whose binary was deleted from disk"
category: process
severity: high
score: 70
mitre: ["T1055", "T1620"]
# iterates a snapshot collection; 'item' is the current element. Dotted paths
# (e.g. persistence.systemd_units) are supported. Omit foreach for host-level rules.
foreach: processes
when: 'item.exe_deleted == true && !item.exe.startsWith("/memfd:")'
evidence:
  pid: item.pid
  exe: item.exe
  comm: item.comm
dedup: ["item.pid", "item.exe"]
```

Tetragon rule mapping (Phase 2): we do NOT translate them to CEL — we load them
natively into the sensor. The `linux-probe-shield` policies stay as-is; `bladedr` only
manages them, tags the resulting `observations`, and exports them.

---

## 6. REST API (`/api/v1`)

All JSON. Auth: Bearer token (MVP), per-operator later. Endpoints marked (P2)/(planned)
are designed but not yet implemented.

### Hosts and credentials
```
POST   /hosts                      # add host {hostname, ip, ssh_port, credential_id, arch, mode}
GET    /hosts                      # ?collection=&tag=&status=
GET    /hosts/{id}
DELETE /hosts/{id}
POST   /credentials                # {name, username, auth_type, secret}  (write-only secret)
GET    /credentials                # no secrets in the response
DELETE /credentials/{id}
```

### Scans
```
POST   /hosts/{id}/scans           # manual trigger; returns the scan
GET    /hosts/{id}/scans           # history
GET    /scans/{id}                 # status + risk_score
```

### Observations (findings + events — shared)
```
GET    /observations               # ?host=&severity=&status=&source=&rule=&q=  (q = BM25)
GET    /observations/{id}
PATCH  /observations/{id}          # {status: acknowledged|resolved|false_positive}
```

### Rules (user/DB-managed; merged with builtin at scan time)
```
GET    /rules                      # user/DB rules
GET    /rules/active               # merged active set actually running
POST   /rules                      # add a rule (YAML or JSON); CEL-validated
PATCH  /rules/{id}                 # {enabled}
DELETE /rules/{id}
```

### Schedules (recurring scans)
```
GET  /schedules     POST /schedules     GET/PATCH/DELETE /schedules/{id}
POST /schedules/{id}/run                 (fire now, don't wait for the tick)
```
A schedule has an interval (duration string "15m" or interval_s) and a target:
host_id (one host), collection_id (the collection's hosts), or neither (all hosts).
A background scheduler fires due schedules every BLADEDR_SCHEDULER_TICK (default
30s) and advances next_run.

### Collections & tags
```
GET/POST /collections     GET/PATCH/DELETE /collections/{id}
GET  /collections/{id}/hosts                          (resolved membership)
PUT/DELETE /collections/{id}/members/{host}           (static membership)
PATCH /hosts/{id}                                     (merge tags; ""=delete key)
GET  /hosts?tag=env=prod&tag=team=sec                 (filter, all must match)
```
A collection is **static** (explicit member list) or **dynamic** (`match_tags`:
a host is a member iff its tags are a superset). Used for scoped scheduling and
filtering.

### Hunting web UI
```
GET /ui  →  /ui/dashboard       (server-rendered, embedded templates, no JS build)
GET /ui/dashboard               overview: KPI cards + severity/MITRE/rule/host bar charts
GET /ui/observations           filters: q (BM25), severity, status, host; inline triage
GET /ui/hosts                  hosts + tags + open-finding counts; tag filter
POST /ui/hosts                 "+ Add host" form (seals secret, creates cred+host)
                               per-row "Scan now" button → POST /hosts/{id}/scans
```
Triage buttons (Ack / Resolve / False-Positive) PATCH the JSON API; these status
changes are the human labels that will feed the future ML risk-scoring tier.

### Export — ECS / SIEM
```
GET /api/v1/export/ecs?host=&severity=&status=&rule=&q=&limit=
    → ECS NDJSON (application/x-ndjson), one JSON doc per observation
```
Maps each observation to an Elastic Common Schema alert document (event.*, rule.*,
host.*, threat.technique.id from MITRE, labels.status/source, bladedr.evidence).
Ingest directly with Elasticsearch `_bulk`, Filebeat, Logstash or any SIEM. Push
targets (POST /exports to Elasticsearch/webhook/syslog) remain planned.

### Ingest (Phase 2 — eBPF sensor)
```
POST   /ingest/events              # gRPC/mTLS or HTTP; event batch → observations
```

### Operational
```
GET    /healthz                    # /readyz /metrics (planned)
```

---

## 7. Export to Kibana (ECS)

The hunting dashboard is **our own** (Postgres + BM25). Export is an **option** for
those who want to ship data to an existing stack (Kibana/Elasticsearch, Splunk, SIEM).
`observations` are mapped to the **Elastic Common Schema** and sent via the Bulk API or
a data stream. Example document:

```json
{
  "@timestamp": "2026-06-10T12:00:00Z",
  "event": { "kind": "alert", "category": ["process"], "severity": 73,
             "provider": "bladedr", "module": "agentless_probe" },
  "host": { "hostname": "web-01", "ip": ["10.0.0.5"], "os": { "kernel": "6.8.0" } },
  "rule": { "id": "deleted-running-binary", "name": "..." },
  "threat": { "technique": { "id": ["T1055"] } },
  "process": { "pid": 4711, "executable": "/tmp/.x/payload" },
  "labels": { "collection": "prod-web", "team": "infra" },
  "bladedr": { "observation_id": "...", "score": 70, "status": "open" }
}
```

The exporter is one of the `export_target`s; it pushes (batched every N seconds) with a
filter (e.g. only `severity >= medium`). Webhook and syslog are analogous.

---

## 8. Repository layout

```
bladedr/
├── cmd/
│   ├── bladedr-server/main.go
│   ├── bladedr-probe/main.go
│   └── bladedr-sensor/main.go        # Phase 2 (planned)
├── internal/
│   ├── api/            # REST handlers, routing, auth
│   ├── store/          # store interface + PostgreSQL impl (pg_search/BM25) + memory
│   ├── secrets/        # NaCl sealed-box credential protection
│   ├── ssh/  → scan/   # SSH transport, probe transfer+exec (in internal/scan)
│   ├── probe/          # shared snapshot/bundle/result types + Linux collector
│   ├── rules/          # YAML loading, CEL engine, builtin/*.yaml
│   └── scan/           # scan orchestration, transports, scoring, dedup
├── internal/store/migrations/  # PostgreSQL schema (pg_search / BM25), embedded & auto-applied
├── policies/           # imported TracingPolicy (linux-probe-shield) — Phase 2 (planned)
├── Dockerfile          # server image (bundles linux probes)
├── COVERAGE.md  README.md  DESIGN.md
└── go.mod
```

---

## 9. Phased plan

- **Phase 1 — agentless core** (done): inventory, SSH+probe, snapshot, CEL engine,
  builtin rule set, credentials (sealed-box) + password/key SSH auth, host-key TOFU,
  rule management API, observations, REST API, Postgres store. Remaining Phase 1:
  scheduler, collections/tags in the API, ECS→Kibana exporter, hunting web UI.
- **Phase 2 — eBPF tier**: `bladedr-sensor` (Tetragon wrapper) loading
  `linux-probe-shield` 1:1, `/ingest/events`, the same observations/tags/export.
- **Phase 3 — optional**: transient eBPF over SSH; snapshot↔event correlation.

---

## 10. Open decisions

1. eBPF model: persistent sensor (A) vs transient-over-SSH (B). The core is shared —
   deferred until after Phase 1.
2. Secret storage: node key (MVP) vs Vault/SSM (prod).
3. Hunting web UI: htmx + Go templates (light) vs a separate React frontend (richer).
4. Data-plane swap (`scan`/`observation`) to OpenSearch/ClickHouse — the event-volume
   threshold that justifies it (most likely only with eBPF in Phase 2).

**Resolved:** storage = PostgreSQL + pg_search (BM25); probe = smart (CEL on host);
credential protection = NaCl sealed-box (split trust); SSH auth = key + password;
host key = TOFU pinning; eBPF tier = Tetragon wrapper (Phase 2).
```
