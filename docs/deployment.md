# Deploying bladedr

Notes for running the control plane in something more permanent than a dev shell. The
[README](../README.md) covers what the pieces are; this is about wiring them up.

## Layout

One control-plane host runs `bladedr-server` and talks to Postgres. It reaches the
fleet over SSH to scan, and (optionally) pushes the eBPF sensor to hosts you want
runtime coverage on. Nothing but the server needs inbound access.

## Database

Use ParadeDB (Postgres + pg_search) — the free-text search relies on the BM25 index.

```sh
docker compose up -d          # brings up ParadeDB on :5432
```

Point the server at it with `BLADEDR_DATABASE_URL`. Migrations apply on startup and
are tracked in `schema_migrations`, so upgrades are just "deploy the new binary and
restart". Without `BLADEDR_DATABASE_URL` the server keeps everything in memory and
loses it on restart — fine for a demo, not for production.

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
