# Changelog

Notable changes. Format loosely follows [Keep a Changelog](https://keepachangelog.com);
versions follow [SemVer](https://semver.org).

## [0.9.1] - 2026-07-29

Response actions did not work on any host where sudo asks for a password, which is most
of them. Upgrade if you use them.

### Fixed
- Every response playbook failed on a password-sudo host. The command was pasted straight
  after `sudo -S`, so the remote shell split it on the first `;` and sudo received only
  the fragment before it; the rest ran unprivileged with its variables unset. The failure
  surfaced as `executable mismatch; refusing` — a guard message from a guard that never
  ran, which is the worst way for a safety check to fail.
- `isolate_host` cut the SSH session it was installed over, every time, leaving the host
  filtering everything with nothing allowed and the action stuck reporting `running`. Two
  causes: rules were applied one at a time so the drop policy landed before any accept
  rule, and `ct state established` never matched a connection that predated the table.
  The ruleset now loads in a single `nft -f` transaction and carries stateless port rules
  in both directions.
- `/risk/stats` reported a figure that depended on the order rows came back from the
  database. It now averages seven seeded cross-validation passes and publishes the spread;
  a ROC AUC standard deviation above 0.10 marks the result untrustworthy whatever the
  mean. On the poligon dataset that figure ranged 0.48 to 0.82 across seeds.
- GitHub releases and Docker Hub disagreed about what a prerelease is: `v*-rc*` tags
  published as normal releases on one and prereleases on the other.

### Added
- CI gates the detections themselves: the attack-emulation range must fire every expected
  rule, and no rule may fire on a stock Debian, Ubuntu, Rocky or Alpine image. Releases
  depend on both.
- `SECURITY.md` documents the build and release trust boundary, including a third-party
  CI agent that fetches an unverified binary. That agent no longer runs in the jobs
  holding publishing credentials.

### Verified
All four response playbooks now run end to end on Rocky Linux 10.2 and Ubuntu 24.04 —
request, second-admin approval, execution, and a verified `restore_network` after
`isolate_host`. They remain Beta: two lab hosts are not a fleet.

## [0.9.0] - 2026-07-27

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
- Forced password change (`POST /api/v1/me/password`, `/ui/password`). A password the
  account holder didn't choose — a generated bootstrap password, which the startup log
  keeps, or one an admin set or reset — has to be replaced before anything else works.
  Every other route returns `403` until then and the console redirects to the form.
  Self-service password change is available to every role, which also means a viewer can
  finally enrol MFA on their own account.

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
- Existing accounts are **not** forced to change their passwords on upgrade. Migration
  `0009` defaults the flag to false: those operators chose their passwords, and locking a
  running deployment out of its own console would be a worse failure than the one this
  prevents. It applies to accounts created or reset from 0.9.0 onward.
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
  but `ls` appends `.` for an SELinux context, so on a RHEL-derived host the staging
  directory reads `drwx------.` and the guard refused it — **no agentless scan could run
  on that family at all**. The mode is matched as a prefix now. Confirmed end to end on
  Rocky Linux 10.2 with SELinux Enforcing: a scan completes, the probe caches under its
  content hash, and a second scan reuses it. Permissive modes are still refused with the
  suffix present.

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
