# Changelog

Notable changes. Format loosely follows [Keep a Changelog](https://keepachangelog.com);
versions follow [SemVer](https://semver.org).

## [Unreleased]

### Known limitations

- Process-level rules that dedup on `item.exe` (`exec-from-world-writable`,
  `process-ld-preload-env`, and siblings) can merge two distinct processes that happen to
  share an executable path into one observation, keeping only the last-evaluated instance's
  evidence. Detection still fires; only the evidence of one contributing process survives.
  See [COVERAGE.md](COVERAGE.md#known-limitations). Not fixed here — it touches every rule
  using that dedup pattern, wider than a patch.

## [0.9.2] - 2026-10-10

Adds detection of credential paths between hosts and of libraries loaded into running
processes, tracks analyst verdicts separately from workflow status, and makes scans through
sudo complete instead of partial. Back up the database before upgrading: this release adds
migrations 0010–0012, which are forward-only, so a downgrade needs the backup. After
upgrading, enter a sudo password on hosts whose account needs one (Hosts → edit); every host
needs one scan before cross-host findings appear. Earlier status-based triage no longer
counts as training data — assess findings with Confirm finding / Close as FP.

### Added
- Credential tracking across the fleet, for the paths an intruder uses to move between
  machines. The probe now reads password-hash schemes from `/etc/shadow` and finds SSH
  private keys under home directories; the server keeps a current per-host inventory and
  reports a key authorized on several hosts (`fleet-shared-ssh-key`), a private key stored
  on one host that opens others (`ssh-private-key-grants-access`), a private key copied
  between hosts, and a password hash shared across hosts or accounts. Two host-level rules
  join them: `weak-password-hash-scheme` and `unprotected-ssh-private-key`. Only
  fingerprints leave a host — a SHA-256 of each key, a truncated SHA-256 of each hash —
  never a key or a hash. Needs root for `/etc/shadow` and other users' homes; an
  unprivileged scan reports that it could not read them. Password-hash and private-key
  identifiers are kept out of the baseline, so a changed password is not drift. The probe
  binary grows by about 2 MB (the SSH library used to read key files).
- Three rules for libraries loaded into running processes, which the file-level checks
  (ld.so.preload, units, profiles) cannot see: `process-library-from-writable-path`,
  `process-library-deleted` and `process-ld-preload-env`. The probe reads
  `/proc/PID/maps` and `/proc/PID/environ`; only executable mappings count, the process's
  own binary and routine package-upgrade deletions are skipped, and a preload of a
  distribution library (jemalloc, libgtk3-nocsd) is not reported. Unprivileged scans see
  only their own account's processes and now say so.
- Closed findings (false positive or resolved) reopen when they vanish and come back: the
  host's previous completed scan did not see them and they were last seen at least 24 hours
  ago (`BLADEDR_REOPEN_AFTER`, `off` to disable). A finding present on every scan stays
  closed, and so does everything on a host that was merely unreachable for a while, since
  the scan before the gap saw it. The verdict is kept, so the earlier assessment can be
  confirmed or overturned.
- A partial scan now records what the collectors could not read in the scan's `error`
  field, instead of only saying it was partial.
- Optional sudo password on a host's credential (add/edit host form and API
  `sudo_password`), sealed with the node key like the SSH secret and never returned. A
  key-authenticated account has no password to escalate with, so its scans stayed
  `partial`; the stored sudo password is used by the scan and the sensor deploy, and
  falls back to the login password of a password account when absent.
- Isolated `bladedr-atomic` artifact capture for reviewed SetUID and cap_setuid
  tests, with benign controls, exact-rule/path checks, cleanup checks and source
  provenance. Captures remain separate from the deployed training dataset.

### Fixed
- `packet-sniffer-process` was keyed by PID, so every run of the same tool opened a new
  alert (ten for one tcpdump habit). It is keyed by program; the PID stays in the evidence.
- Scans finished `partial` for reasons that said nothing about the host. The BPF evidence
  collector counted a process or fd that vanished between listing and reading as an
  incomplete collection, which on a live system is routine, and treated a missing optional
  `bpftool` as a failed scan on every host that has BPF programs. A vanished file is no
  longer an error and a missing `bpftool` is reported on each program's evidence only; a
  permission failure still makes the scan partial.
- The probe cache on scanned hosts grew by about 16 MB per released version and was never
  cleaned, contradicting "leaves nothing behind". Each scan now removes probe binaries of
  other versions and leftover rule bundles older than an hour; the sensor staging files
  that share the directory are not touched.
- File-loaded ML examples cannot count as fleet labels by supplying a production
  source name. Reviewed external imports require provenance and scenario grouping.
- Findings now expose atomic disposition actions with English labels. Closing as
  FP also writes the negative verdict; inconclusive closure excludes the finding
  from training. Remediation closure requires a confirmed positive verdict.
- ML supervision uses a separate explicit analyst verdict instead of workflow
  status. Legacy false_positive requests now explicitly write a negative verdict;
  legacy resolution requires a positive verdict, including bulk requests. The console
  provides independent assessments, audited by the API; historical verdicts default
  to unknown rather than being guessed from old status values.
- Risk scores were dominated by where a finding came from, not what it was. The rule's
  category, severity and MITRE tags were emitted as separate features on top of the
  rule itself, so a rule counted five times in a model that treats features as
  independent, and lab plants taught every finding sharing a tactic to score as an
  attack (BPF baseline drift scored 80 because of kernel-module plants). Lab rows
  also carried a `lab` source token that no real finding has, the class prior was
  the lab's own 141:54 attack-heavy ratio, and running-process executables were
  mixed into the same path class as tampered files. The model now uses the rule as
  one feature, treats lab rows as probe findings, uses a flat prior (a finding with
  no learned evidence scores 50), and separates executable and artifact path
  classes. Lab cross-validated ROC AUC rose from 0.652 to 0.740 on `dataset.jsonl`
  and from 0.685 to 0.756 on a second capture. Scores on real findings changed too:
  a long-running system daemon after a package upgrade fell from 80 to 35.
- Risk-model validation now keeps variants of each lab technique and findings from
  each fleet host in one fold. Trust also requires at least 30 confirmed fleet labels
  per class and a passing fleet-only evaluation; one fleet label can no longer unlock
  a model validated mainly on attack-range data. Historical row-split metrics are
  documented separately from the current validation protocol.
- Every IPv4 address read from `/proc/net/tcp` was reversed: 127.0.0.1 was reported as
  1.0.0.127, a Cloudflare address, in `miner-c2-outbound-connection` evidence and in
  listening sockets. The hex was decoded as bytes and then read little-endian, reversing
  it twice. IPv6 from `/proc/net/tcp6` was wrong too, being taken as a byte string
  rather than four host-order words. Detection was unaffected, since no rule matches on
  the address, but the evidence an analyst works from was not the real address.
- A non-root scan account never ran the probe as root, so every scan of a host reached
  as `ubuntu`, `dev` or similar came back `partial`, blind to `/dev/kmsg` and other users'
  processes. The poligon meanwhile ran the probe under sudo, so the risk model trained
  on what a root probe sees and scored hosts it could not see that way. The probe now
  escalates through passwordless sudo or the stored password when the account is
  allowed to, and falls back to the unprivileged scan when it is not.
- `bladedr-lab --target` deleted files it had overwritten instead of restoring them:
  a full run removed `sshd_config`, `nsswitch.conf`, `/etc/profile`, root's
  `authorized_keys`, `/var/log/auth.log` and `/run/docker.sock` from the host it ran on.
  Those plants now save the original and put it back, and a full run over SSH requires
  `--disposable`.

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
