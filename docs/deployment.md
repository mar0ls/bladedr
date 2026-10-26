# Deploying bladedr

How to run the control plane for real. The [README](../README.md) covers what the
pieces are; this is about wiring them up. Current release: **0.9.5**.

- [Layout](#layout)
- [Requirements](#requirements)
- [Option A: Docker Compose (recommended)](#option-a-docker-compose-recommended)
- [Option B: release binaries + systemd](#option-b-release-binaries--systemd)
- [First steps after install](#first-steps-after-install)
- [Secrets](#secrets) · [TLS](#tls) · [Health and metrics](#health-and-metrics)
- [Backup and restore](#backup-and-restore) · [Upgrades](#upgrades)

## Layout

One control-plane host runs `bladedr-server` and talks to Postgres (ParadeDB). It
reaches the fleet over SSH to scan, and (optionally) pushes the eBPF sensor to hosts you
want runtime coverage on. Only operators' browsers and, if you run the sensor tier,
the sensors need inbound access to the server. Nothing needs inbound access to the
database.

```
operators ──HTTPS──▶ bladedr-server ──SSH──▶ monitored Linux hosts
                         │   ▲                       │
                         ▼   └──── sensor events ────┘ (optional eBPF tier)
                     ParadeDB
```

## Requirements

**Control plane**

- Docker with the Compose plugin (option A), or any linux/amd64 or linux/arm64 host
  (option B). The server itself runs anywhere; scan targets are always Linux.
- ParadeDB, not stock Postgres — free-text search uses its BM25 index. Both options
  below use `paradedb/paradedb:0.23.5`.
- Outbound SSH (default port 22) to every host you want to scan.

**Each monitored host**

- Linux, amd64 or arm64, reachable over SSH with an account you give bladedr
  (key or password).
- `flock` (util-linux; present on every mainstream distro). Since 0.9.4 a scan takes a
  host-side lock before starting the probe, and fails without `flock` rather than
  running unlocked — see [scan locking](#scan-locking-and-process-evidence-094).
- A writable `/tmp`. The probe is staged in `/tmp/.bladedr/` (mode 0700) and runs
  from there; nothing is installed.
- Optional: root, or sudo for the scan account (passwordless, or with a sudo password
  stored on the credential). Without it scans still run but come back `partial` — the
  probe cannot read `/dev/kmsg` or other users' processes.
- Optional: `bpftool`, for richer [BPF evidence](bpf-evidence.md).

**Hosts with the eBPF sensor (optional)**

- Docker and a BTF-capable kernel (`/sys/kernel/btf/vmlinux`), sudo for the SSH account,
  and network access to the server at `BLADEDR_SERVER_URL`.
- Your own Tetragon TracingPolicy bundle. bladedr does not ship one yet; without it the
  sensor tier stays off and agentless scanning is unaffected.

## Option A: Docker Compose (recommended)

The image `mar0ls/bladedr` (linux/amd64 + linux/arm64) carries the server, the CLI,
and the probe and sensor binaries for both architectures; the ~90 builtin rules are
compiled in. You need no checkout of this repository.

**1. Get the compose file**

```sh
mkdir -p /opt/bladedr && cd /opt/bladedr
curl -fsSLo compose.yml \
  https://raw.githubusercontent.com/mar0ls/bladedr/v0.9.5/docs/compose.example.yml
```

**2. Create `.env`**

```sh
docker run --rm mar0ls/bladedr:0.9.5 -keygen
# BLADEDR_NODE_KEY=…   # private (node) — keep secret
# public_key=…         # seals credentials

cat > .env <<EOF
BLADEDR_NODE_KEY=<the private key printed above>
POSTGRES_PASSWORD=$(openssl rand -hex 24)
# Optional — see the comments in compose.yml:
# BLADEDR_ADMIN_PASSWORD=<choose one, or leave unset to have one generated>
# BLADEDR_SERVER_URL=http://<this host's IP>:8080
EOF
chmod 600 .env
```

Back up `BLADEDR_NODE_KEY` somewhere other than this machine **now**. It is the only
thing that decrypts the stored SSH credentials; see [Secrets](#secrets).

**3. Start it**

```sh
docker compose up -d
docker compose ps                 # db healthy, server healthy after ~10 s
docker compose logs server | grep -E 'listening|GENERATED password'
```

Compose refuses to start if `BLADEDR_NODE_KEY` or `POSTGRES_PASSWORD` is missing — on
purpose, so it never comes up with an example password guarding your credentials.
The server applies its database migrations on startup.

**4. Make it reachable**

The compose file publishes `127.0.0.1:8080` only, because it serves plaintext HTTP.
Either put a reverse proxy in front (recommended; see [TLS](#tls)), or give the server
a certificate and publish 8080 on a real interface. For a quick look from your laptop:

```sh
ssh -L 8080:127.0.0.1:8080 you@control-plane   # then open http://localhost:8080/ui
```

Continue with [First steps after install](#first-steps-after-install).

### Optional additions

- **eBPF policies:** create `./policies/` with your `*.yml`/`*.yaml` TracingPolicies,
  add `- ./policies:/etc/bladedr/policies:ro` under the server's `volumes:`, set
  `BLADEDR_SERVER_URL` in `.env`, and `docker compose up -d`. The server reads the
  bundle at startup, so restart it after changing policies.
- **TLS on the container:** see the commented lines in `compose.yml`. Key and
  certificate must be readable by uid 10001, and the image's healthcheck must be
  swapped for the HTTPS one shown there.
- **Other settings** (scan workers, retention, …): add them to the server's
  `environment:`. The full list is in the README's [Config](../README.md#config) table.

## Option B: release binaries + systemd

Each [GitHub release](https://github.com/mar0ls/bladedr/releases) has static
linux/amd64 and linux/arm64 binaries, an SPDX SBOM and `SHA256SUMS`.

**1. Database.** Run ParadeDB somewhere the server can reach — the `db` service from
[compose.example.yml](compose.example.yml) on its own is fine. Don't use the
repository's `docker-compose.yml` for this: it is a development database with a fixed
password.

**2. Binaries**

```sh
V=v0.9.5; ARCH=amd64     # or arm64 — the control plane's own architecture
base=https://github.com/mar0ls/bladedr/releases/download/$V
cd "$(mktemp -d)"
for f in bladedr-server.linux-$ARCH bladectl.linux-$ARCH \
         bladedr-probe.linux-amd64 bladedr-probe.linux-arm64 \
         bladedr-sensor.linux-amd64 bladedr-sensor.linux-arm64 SHA256SUMS; do
  curl -fsSLO "$base/$f"
done
sha256sum --check --ignore-missing SHA256SUMS

sudo install -m 0755 bladedr-server.linux-$ARCH /usr/local/bin/bladedr-server
sudo install -m 0755 bladectl.linux-$ARCH      /usr/local/bin/bladectl
sudo install -d /usr/local/lib/bladedr
sudo install -m 0755 bladedr-probe.linux-* bladedr-sensor.linux-* /usr/local/lib/bladedr/
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin bladedr
```

Keep both probe architectures even if the control plane is amd64: the server uploads
the one matching each target.

**3. Configuration** — `/etc/bladedr/server.env`, mode 0600, owned by root:

```sh
BLADEDR_DATABASE_URL=postgres://bladedr:<password>@<db-host>:5432/bladedr
BLADEDR_NODE_KEY=<from: bladedr-server -keygen>
# Without these, SSH scans fail with "no probe binary configured for arch …".
BLADEDR_PROBE_LINUX_AMD64=/usr/local/lib/bladedr/bladedr-probe.linux-amd64
BLADEDR_PROBE_LINUX_ARM64=/usr/local/lib/bladedr/bladedr-probe.linux-arm64
BLADEDR_LOG_FORMAT=json
# Optional:
# BLADEDR_ADMIN_PASSWORD=…
# BLADEDR_TLS_CERT=/etc/bladedr/tls.crt
# BLADEDR_TLS_KEY=/etc/bladedr/tls.key
# eBPF tier:
# BLADEDR_SERVER_URL=https://10.0.0.2:8080
# BLADEDR_SENSOR_LINUX_AMD64=/usr/local/lib/bladedr/bladedr-sensor.linux-amd64
# BLADEDR_SENSOR_LINUX_ARM64=/usr/local/lib/bladedr/bladedr-sensor.linux-arm64
# BLADEDR_POLICY_DIR=/etc/bladedr/policies
```

**4. systemd unit** — run as the dedicated non-root user:

```ini
# /etc/systemd/system/bladedr-server.service
[Unit]
Description=bladedr control plane
After=network-online.target
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

If ParadeDB runs in Docker on the same machine, add `docker.service` to `After=`.
State lives in Postgres, so the service needs no writable path and
`ProtectSystem=strict` works without `ReadWritePaths`. TLS key files must be readable
by the `bladedr` user.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now bladedr-server
journalctl -u bladedr-server | grep -E 'listening|GENERATED password'
```

> `scripts/deploy-server.sh` (`make deploy`) is a different thing: a one-machine
> developer setup that builds from source, uses the development database and runs the
> server with `nohup`. Don't use it for production.

## First steps after install

1. **Sign in** at `/ui/login` as `admin`. If the password was generated, it is in the
   startup log and must be changed at first sign-in. With TOTP enrolled (optional, per
   account) the account is protected by more than that password.
2. **Create accounts** for the other people (Users page). Response actions need a
   *second* admin to approve; see the README's
   [Response actions](../README.md#response-actions).
3. **Add a credential and a host.** In the console (Hosts), or from a shell:

   ```sh
   export BLADEDR_SERVER_URL=https://bladedr.example
   BLADEDR_PASSWORD=… bladectl login --username admin   # prints JSON with "token"
   export BLADEDR_TOKEN=<that token>
   ```

   then create the credential through the API (`POST /api/v1/credentials`, as in the
   README's [Credentials and SSH](../README.md#credentials-and-ssh)) and the host with
   `bladectl hosts add --ip 10.0.0.5 --credential <id> --arch amd64`. Use a dedicated,
   least-privilege scan account; give it sudo only if you want full `/proc` visibility.
   The SSH host key is pinned on the first connection, so make that first scan over a
   network path you trust.
4. **Run a scan** and look at Findings. The first scan of each host sets its baseline;
   drift findings (`baseline-new-*`) appear from the second scan on.
5. **Schedule** recurring scans (Schedules page).

## Secrets

`BLADEDR_NODE_KEY` decrypts sealed SSH credentials and MFA secrets. **If you lose it,
every stored credential is unrecoverable** (by design — the database alone can't
decrypt them). Back it up separately from the database, or you'll restore a dump into a
server that can't log into anything. Without it set, the server mints an ephemeral key
and forgets every credential on restart.

```sh
bladedr-server -keygen                       # binary
docker run --rm mar0ls/bladedr:0.9.5 -keygen # image
```

Sensor tokens need no such care: they're per-host, the server stores only digests, and
deployment mints and rotates them for you. Revoke and redeploy if one leaks.

Keep the server's secrets in a mode-0600 file (`.env` for Compose, the unit's
`EnvironmentFile` for systemd), never on the command line.

## TLS

Don't put the console on plaintext outside a trusted network. Either give the server a
certificate directly:

```sh
BLADEDR_TLS_CERT=/etc/bladedr/tls.crt BLADEDR_TLS_KEY=/etc/bladedr/tls.key
```

or terminate TLS at a reverse proxy (nginx/Caddy) and set `BLADEDR_SECURE_COOKIES=1`
so the session cookie still gets the `Secure` flag. Behind a proxy, forward the client
IP as `X-Forwarded-For` — the login rate-limiter and audit log key off it. Set
`BLADEDR_TRUSTED_PROXY_CIDRS` to your proxy's network first: without it the header is
ignored, which is the right default, since anyone who can reach the server directly
could otherwise spoof a source IP and dodge the login lockout.

A minimal Caddy front for the Compose setup (Caddy on the same host):

```
bladedr.example {
    reverse_proxy 127.0.0.1:8080
}
```

with `BLADEDR_SECURE_COOKIES=1` and `BLADEDR_TRUSTED_PROXY_CIDRS=172.16.0.0/12` (the
Docker bridge networks Caddy's connections arrive from) in the server's environment.

## Health and metrics

- `GET /healthz` — liveness.
- `GET /readyz` — readiness; returns 503 until the database is reachable. The image's
  healthcheck uses it.
- `GET /metrics` — Prometheus text (request counts by method/status, latency summary,
  `bladedr_audit_append_failures_total`).

These are unauthenticated; keep them on an internal interface or restrict them at the
proxy.

## Backup and restore

The database dump and `BLADEDR_NODE_KEY` together form a complete backup. Neither alone
is enough.

```sh
# Compose
docker compose exec -T db pg_dump -U bladedr bladedr > bladedr-$(date +%F).sql
# Anything else
pg_dump "$BLADEDR_DATABASE_URL" > bladedr-$(date +%F).sql
```

To restore, load the dump into a fresh ParadeDB instance and start the server with the
same node key; startup migrations reconcile the schema. Keep dumps outside the
repository — they contain host inventory and (sealed) credentials.

## Upgrades

Back up first. Then:

```sh
# Compose: bump the image tag in compose.yml, then
docker compose pull && docker compose up -d
# systemd: replace the binaries (server and both probes), then
sudo systemctl restart bladedr-server
```

Migrations are forward-only, run once and are recorded in `schema_migrations`. A
downgrade past a migration is not supported, so keep the previous image or binary
*and* the pre-upgrade dump. After the restart check `/readyz` and run one scan.

Always upgrade server and probes together. With the image that is automatic; with
binaries, replace the probe files too.

### Scan locking and process evidence (0.9.4)

Scanned hosts need `flock`. The launcher acquires an exclusive lock before starting the
probe and waits up to 30 seconds; a timeout or missing `flock` fails the attempt
without launching an unlocked collector, and the normal queue retry policy applies. No
service or audit rule is installed.

Root and sudo scans share `/run/bladedr-probe/scan.lock`. Unprivileged scans use
`/tmp/.bladedr/scan-lock/scan.lock` under the existing scan-account cache. The lock
directory must be owned by the executing UID and mode `0700`; symlink directories,
symlink lock files and non-regular lock files are rejected. Lock files remain in place
between scans; do not remove them while a scan or waiter is running. Root and
unprivileged scans use separate locks; separate mount namespaces or older servers that
do not use this protocol are not coordinated.

After a remote command returns, the queue worker checks cancellation and renews its
ownership before ingesting the result. A superseded attempt records a failed scan with
`discarded scan result`, without ingesting findings or changing host reachability.

For executables under `/tmp`, `/var/tmp` and `/dev/shm`, and deleted file-backed
executables elsewhere, the probe collects `execution_evidence`: SHA-256 via
`/proc/PID/exe`, process start ticks, PPID, session ID, parent executable, cgroup, and
executable/ancestor UID, GID and mode. Both categories share a limit of eight candidate
processes per scan and 64 MiB per hash; exceeded limits, missing permissions and
vanished processes produce evidence errors, not a benign verdict. `stable` records
agreement of the sampled identity before and after collection; it does not establish
trust. For a deleted executable the hash describes the running inode, not whatever is
now installed at the original path.

External rule files or stored overrides of `exec-from-world-writable` and
`deleted-running-binary` need the new `execution` evidence expression to expose these
details. Older probes still match the rule without the new fields. Historical findings
cannot acquire evidence for processes already gone.

### Migrations 0011 and 0012 (0.9.2)

Both are additive. 0011 adds `credentials.sudo_secret_enc` (null until you enter a sudo
password for a host); 0012 adds `host_inventory`, which fills in as hosts are scanned,
so cross-host findings (a key or password hash shared between hosts) appear after every
host has had one scan on the new version. `BLADEDR_REOPEN_AFTER` (default `24h`, `off`
disables) controls when a closed finding that vanished and returned reopens.

### Observation verdicts — migration 0010 (0.9.2)

Migration 0010 adds `observations.verdict` and defaults historical rows to `unknown`.
Workflow statuses and alert IDs are unchanged. Legacy status and bulk updates use the
same transitions as the console: false_positive writes a negative verdict, resolved
requires a positive verdict, open/acknowledged preserve assessment. Bulk requests return
an updated count; rejected rows remain unchanged.

If previous decisions have been independently verified, export their exact IDs and
assessments before the upgrade. Restore only those IDs after migration, in a
transaction with an expected-row-count check, and record this administrative backfill in
`audit_log`. Do not map all acknowledged findings to true positives.

After startup, check `/readyz`, the migration ledger, verdict counts and a sample of
both classes. Verify that a workflow-only change leaves the verdict unchanged, and that
a scan's deduplication preserves it.
