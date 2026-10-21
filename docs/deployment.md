# Deploying bladedr

Notes for running the control plane in something more permanent than a dev shell. The
[README](../README.md) covers what the pieces are; this is about wiring them up.

## Layout

One control-plane host runs `bladedr-server` and talks to Postgres. It reaches the
fleet over SSH to scan, and (optionally) pushes the eBPF sensor to hosts you want
runtime coverage on. Nothing but the server needs inbound access.

## Scan locking and process evidence (unreleased)

Builds containing these unreleased changes require `flock` on scanned Linux hosts. The launcher acquires an
exclusive lock before launching the probe and waits up to 30 seconds; timeout or
missing `flock` fails the attempt without launching an unlocked collector. The
normal queue retry policy applies. No service or audit rule is installed.

Root and sudo scans share `/run/bladedr-probe/scan.lock`. Unprivileged scans use
`/tmp/.bladedr/scan-lock/scan.lock` under the existing scan-account cache. The lock
directory must be owned by the executing UID and mode `0700`; symlink directories,
symlink lock files and non-regular lock files are rejected. Lock files remain in
place between scans; do not remove them while a scan or waiter is running. The
kernel releases the lock when its last holding descriptor closes. Root and
unprivileged scans use separate locks; separate mount namespaces or older servers
that do not use this protocol are not coordinated.

After a remote command returns, the queue worker checks cancellation and renews
its ownership before ingesting the result. A superseded attempt records a failed
scan with `discarded scan result`, without ingesting findings or changing host
reachability. This is an ingestion-boundary check, not a transaction spanning
every subsequent observation write.

For executables under `/tmp`, `/var/tmp` and `/dev/shm`, and deleted file-backed
executables outside those directories, the new probe collects
`execution_evidence`: SHA-256 via `/proc/PID/exe`, process start ticks, PPID,
session ID, parent executable, cgroup, and executable/ancestor UID, GID and mode.
Modes include file-type bits. Ancestors are sampled through the target's mount
namespace; ACLs and effective access are not evaluated. Raw command arguments
and environment variables are not added to this evidence.

Both categories share a limit of eight candidate processes per scan and 64 MiB
per hash. Anonymous memfd executables are not added to this evidence collection.
Exceeded limits, missing permissions and vanished processes produce evidence
errors, not a benign verdict. `stable` records agreement of the sampled process
identity and executable metadata before/after collection; it does not establish
trust or provide an atomic snapshot. A detected identity change clears the hash.
The existing rule ID `exec-from-world-writable` still means a temporary-path
match, not proof that the executable or its immediate directory is writable by
everyone. Its matching logic and analyst verdicts are unchanged.

For a deleted executable, the hash describes the running inode opened through
`/proc/PID/exe`, not a replacement now installed at the original path. Package
history and a trusted reference binary are still needed to attribute an update;
an executable name or a stable hash alone does not establish a benign verdict.

Deploy both server and probes for the complete change. External rule files or
stored overrides of `exec-from-world-writable` and `deleted-running-binary` need
the new `execution` evidence expression to expose these details. Older probes
still match the rule without the new fields.
Existing historical findings cannot acquire evidence for processes already gone.

## Database

Use ParadeDB (Postgres + pg_search) — the free-text search relies on the BM25 index.

```sh
docker compose up -d          # brings up ParadeDB on :5432
```

Point the server at it with `BLADEDR_DATABASE_URL`. Migrations apply on startup and
are tracked in `schema_migrations`, so upgrades are just "deploy the new binary and
restart". Without `BLADEDR_DATABASE_URL` the server keeps everything in memory and
loses it on restart — fine for a demo, not for production.

## Upgrade with observation verdicts (migration 0010)

Back up Postgres and keep the previous server image before upgrading. Migration
0010 adds `observations.verdict` and defaults historical rows to `unknown`.
Workflow statuses and alert IDs are unchanged. Legacy status and bulk updates use
the same transitions as the console: false_positive writes a negative verdict,
resolved requires a positive verdict, open/acknowledged preserve assessment.
Bulk requests return an updated count; rejected rows remain unchanged.
The console's `Close as FP` and `Confirm
finding` actions update status and verdict atomically. `Close inconclusive` closes
without a training label. `Resolved after remediation` requires a positive verdict.
These actions use the existing columns; no migration beyond 0010 is needed.

## Upgrade notes (migrations 0011, 0012)

Both are additive. 0011 adds `credentials.sudo_secret_enc` (null until you enter a sudo
password for a host); 0012 adds `host_inventory`, which fills in as hosts are scanned, so
cross-host findings (a key or password hash shared between hosts) appear after every host
has had one scan on the new version. `BLADEDR_REOPEN_AFTER` (default `24h`, `off` disables)
controls when a closed finding that vanished and returned reopens.

If previous decisions have been independently verified, export their exact IDs
and assessments before the upgrade. Restore only those IDs after migration, in a
transaction with an expected-row-count check. Record this administrative backfill
in `audit_log`. Do not map all acknowledged findings to true positives.

After startup, check `/readyz`, the migration ledger, verdict counts and a sample
of both classes. Verify that a workflow-only change leaves the verdict unchanged.
Run a scan and check that deduplication preserves the verdict. Keep the backup
outside the repository; it contains credentials and host inventory.

## Secrets

Generate the node key once and keep it:

```sh
./bladedr-server -keygen            # prints BLADEDR_NODE_KEY
```

`BLADEDR_NODE_KEY` decrypts sealed SSH credentials. **If you lose it, every stored
credential is unrecoverable** (by design — the database alone can't decrypt them). Back
it up separately from the database, or you'll restore a dump into a server that can't
log into anything.

Sensor tokens need no such care: they're per-host, the server stores only digests, and
deployment mints and rotates them for you. Revoke and redeploy if one leaks.

Keep the server's secrets in the unit's `EnvironmentFile` (mode 0600), not on the
command line.

## TLS

Either give the server a cert directly:

```sh
BLADEDR_TLS_CERT=/etc/bladedr/tls.crt BLADEDR_TLS_KEY=/etc/bladedr/tls.key ./bladedr-server
```

or terminate TLS at a reverse proxy (nginx/Caddy) and set `BLADEDR_SECURE_COOKIES=1`
so the session cookie still gets the `Secure` flag. Behind a proxy, forward the client
IP as `X-Forwarded-For` — the login rate-limiter and audit log key off it. Set
`BLADEDR_TRUSTED_PROXY_CIDRS` to your proxy's network first: without it the header is
ignored, which is the right default, since anyone who can reach the server directly
could otherwise spoof a source IP and dodge the login lockout.

Don't put the console on plaintext outside a trusted network.

## systemd unit

Run the server as a dedicated non-root user:

```ini
# /etc/systemd/system/bladedr-server.service
[Unit]
Description=bladedr control plane
After=network-online.target docker.service
Wants=network-online.target

[Service]
User=bladedr
EnvironmentFile=/etc/bladedr/server.env
ExecStart=/usr/local/bin/bladedr-server
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

State is stored in Postgres, so the service needs no writable filesystem path.
`ProtectSystem=strict` can be used without `ReadWritePaths`.

`/etc/bladedr/server.env` holds `BLADEDR_DATABASE_URL`, `BLADEDR_NODE_KEY`,
`BLADEDR_TLS_*`, `BLADEDR_ADMIN_PASSWORD`, and `BLADEDR_LOG_FORMAT=json`.

## Health and metrics

- `GET /healthz` — liveness.
- `GET /readyz` — readiness; returns 503 until the database is reachable.
- `GET /metrics` — Prometheus text (request counts by method/status, latency summary).

These are unauthenticated; keep them on an internal interface or restrict them at the
proxy.

## Backup and restore

```sh
pg_dump "$BLADEDR_DATABASE_URL" > bladedr-$(date +%F).sql   # data
```

The dump and `BLADEDR_NODE_KEY` form a complete backup. Restore the dump into a fresh
Postgres instance and start the server with the same node key. Startup migrations
reconcile the schema.

## Upgrades

Replace the binary and restart. Migrations run once and are recorded; a downgrade that
predates a migration is not supported, so snapshot the DB before a major bump.
