# Changelog

Notable changes. Format loosely follows [Keep a Changelog](https://keepachangelog.com);
versions follow [SemVer](https://semver.org).

## [0.9.0] - 2026-07-25

### Added
- Response actions: four allowlisted playbooks (`kill_process`, `disable_systemd_unit`,
  `isolate_host`, `restore_network`) run over the host's existing pinned SSH transport.
  No endpoint takes a command string — the server builds each command from validated
  parameters. Actions are dry-run unless asked otherwise.
- Two-person control on response actions. The store refuses an approval whose approver
  is the requester, in the same statement as the state transition, and audits the
  refusal. `BLADEDR_RESPONSE_ALLOW_SELF_APPROVAL=true` opts out for single-admin
  deployments; the server warns about it at startup.
- Durable scan queue: jobs are claimed with leases and renewed by a heartbeat, so
  multiple server processes can share the work and a dead worker's job is reclaimed
  rather than lost. A partial unique index keeps one active job per host, which makes
  API retries and overlapping schedules idempotent.
- Export outbox with at-least-once delivery to webhook, Elasticsearch and syslog
  targets. HTTP targets get a stable `Idempotency-Key`. Permanent failures (4xx other
  than 429) stop immediately instead of burning the retry budget; the dead-letter queue
  is readable and retryable through the API.
- Per-host sensor tokens (`/api/v1/hosts/{id}/sensor-tokens`), stored as SHA-256
  digests, individually revocable and expiring. Replaces the shared ingest token.
- Optional TOTP MFA per account. The secret is sealed with the node key; disabling MFA
  needs the password *and* a current code.
- Retention: observations, scans and audit rows can be archived after a configurable
  age, and archived rows deleted after a second one.
- `bladectl`, a script-friendly API client (`login`, `hosts`, `scans`, `findings`,
  `responses`).
- OpenAPI 3.1 spec served at `GET /openapi.yaml`, covering every `/api/v1` route.
- Store contract suite: pagination completeness, exclusive claims, lease reclamation,
  the response state machine and retention are asserted once and run against both the
  in-memory and Postgres backends. CI fails if the Postgres pass is skipped, so a
  broken service can't silently reduce coverage to the in-memory store.
- `BLADEDR_TRUSTED_PROXY_CIDRS`: forwarding headers are honoured only from listed proxy
  networks. Without it `X-Forwarded-For` is ignored, so a spoofed header can't dodge the
  login lockout or misattribute an audit entry.
- Keyset pagination on observations, so paging a large fleet can't skip or repeat rows.

### Changed
- Sensors authenticate per host instead of with a shared `BLADEDR_INGEST_TOKEN`. The
  server no longer reads that variable; it survives only as the sensor-side env var the
  deploy script writes into a mode-0600 `EnvironmentFile`.
- The sensor deploy no longer passes the token in argv, where it was visible in `ps` on
  the target for the length of the deployment. It arrives over SSH stdin in a 0600 file
  that the script reads and unlinks.
- The cached probe is verified by SHA-256 before execution, not by file size — any
  same-length substitute passed the old check. The staging directory must be mode 0700
  and owned by the scan account, checked without following symlinks.
- An unknown username now costs the same bcrypt verification as a known one, so login
  latency no longer reveals which accounts exist.
- Lab dataset records must carry an explicit label. An unlabelled record used to default
  to `true_positive`, which quietly taught the model that benign-but-flagged scenarios
  were real findings.

### Upgrade notes
- **Everyone is logged out once.** Sessions used to be stored as the bearer token
  itself; they are digests now, and a plaintext token can't be converted into its own
  hash, so migration `0002` empties the session table. Sign in again after the upgrade.
  API clients holding a token need a fresh one.
- Sensor tokens are per host now. A sensor still configured with the old shared
  `BLADEDR_INGEST_TOKEN` will be rejected — mint one per host
  (`POST /api/v1/hosts/{id}/sensor-tokens`) or redeploy, which does it for you.
- Nothing else is dropped or rewritten. Hosts, scans, observations, triage state, rules,
  baselines, credentials and audit history all carry across; there is a test that seeds a
  0.1.0-era schema, upgrades it and asserts exactly that.

### Fixed
- `isolate_host` accepted `control_plane_ip` without `control_plane_port` at request
  time but refused it at execution — after a second admin had already approved the
  action. Both fields now fall back to `BLADEDR_SERVER_URL` independently.
- The store contract suite `TRUNCATE`s every table but accepted any DSN, and the README
  handed you the same one it uses for the dev server — so following the docs wiped your
  own database. It now refuses a database whose name doesn't mark it as disposable.
- The probe cache guard compared the directory mode literally against `drwx------`,
  which fails closed on every SELinux or ACL-bearing host (`ls` appends `.` or `+`), so
  no scan would run on RHEL-derived distros. The mode is now matched as a prefix.

## [0.8.0] - 2026-07-10

### Added
- TLS: serve HTTPS from `BLADEDR_TLS_CERT`/`BLADEDR_TLS_KEY` (min TLS 1.2); the session
  cookie's `Secure` flag turns on automatically when TLS is enabled.
- Per-IP login rate limiting with exponential backoff, so online password guessing is
  bounded.
- eBPF policy catalog in the UI (`/ui/policies`) and API (`GET /api/v1/policies`).
- Versioned database migrations: applied files are tracked in `schema_migrations` and
  each runs once, inside its own transaction.
- Sensor event buffering: transient control-plane outages no longer drop events. The
  buffer is bounded, drains in chunks, and backs off between retries.
- Observability: `GET /readyz` (readiness, checks the store), `GET /metrics`
  (Prometheus text), and structured logging (`BLADEDR_LOG_FORMAT=json`,
  `BLADEDR_LOG_LEVEL`).
- Ingest-token rotation: `BLADEDR_INGEST_TOKEN` accepts a comma-separated list so a
  token can be rolled with no downtime. Expired sessions are pruned in the background.

### Changed
- Storage docs: the server auto-applies migrations on startup; the manual `psql` step
  is no longer needed.

## [0.1.0] - 2026-07-03

Initial release: agentless probe (CEL rules over a `/proc` snapshot), control-plane
server with REST API and web console, auth + RBAC + audit log, Postgres/pg_search
backend, baseline/drift and fleet-rarity scoring, a Naive-Bayes risk prioritiser, and
the Phase-2 eBPF sensor (Tetragon wrapper) with server-push deploy.
