

<p align="center">
  <img src="https://raw.githubusercontent.com/mar0ls/bladedr/main/assets/logo.png" alt="bladedr" width="360">
</p>

**Agentless threat detection and response for Linux, with an optional eBPF tier.**

bladedr scans your Linux fleet over SSH: it uploads a static probe, evaluates ~90
builtin YAML + CEL rules against a `/proc` snapshot, and removes the probe again, so
nothing stays installed. On top of the raw findings it adds per-host baseline drift,
fleet rarity, triage with an audit log, ECS/JSON export to a SIEM, and response actions
that need a second admin's approval. An optional sensor built on Cilium Tetragon adds
real-time runtime telemetry.

This image is the **control plane**: server, web console, REST API, `bladectl`, and the
probe and sensor binaries for both target architectures. Point it at a database, give it
a node key, and it is a working install.

- Source, docs, changelog: https://github.com/mar0ls/bladedr
- Deployment guide: https://github.com/mar0ls/bladedr/blob/main/docs/deployment.md
- License: GPL-3.0

## Tags

| Tag | Meaning |
|---|---|
| `0.9.5` | Exact release. **Use this.** |
| `0.9` | Newest 0.9.x patch release. |
| `latest` | Newest stable release. Moves without warning. |

Images are multi-arch (`linux/amd64`, `linux/arm64`) and published with build provenance
and an SBOM. Pin a version, or better a digest: this container holds SSH access to your
fleet.

## Quick start (Docker Compose)

```sh
mkdir -p /opt/bladedr && cd /opt/bladedr
curl -fsSLo compose.yml \
  https://raw.githubusercontent.com/mar0ls/bladedr/v0.9.5/docs/compose.example.yml

docker run --rm mar0ls/bladedr:0.9.5 -keygen      # prints BLADEDR_NODE_KEY=…
cat > .env <<EOF
BLADEDR_NODE_KEY=<the key it printed>
POSTGRES_PASSWORD=$(openssl rand -hex 24)
EOF
chmod 600 .env

docker compose up -d
docker compose logs server | grep 'GENERATED password'   # first admin password
```

Then open `http://127.0.0.1:8080/ui`, sign in as `admin` and set a new password. The
compose file publishes the console on loopback only, because it serves plaintext HTTP.
Put a TLS reverse proxy in front of it, or set `BLADEDR_TLS_CERT`/`BLADEDR_TLS_KEY`.

**Back up `BLADEDR_NODE_KEY` separately from the database.** It is the only key that
decrypts the stored SSH credentials. If you lose it, the credentials cannot be recovered.

## Plain `docker run`

```sh
docker run -d --name bladedr -p 127.0.0.1:8080:8080 \
  -e BLADEDR_DATABASE_URL=postgres://bladedr:…@db-host:5432/bladedr \
  -e BLADEDR_NODE_KEY=… \
  mar0ls/bladedr:0.9.5
```

The database must be **ParadeDB** (PostgreSQL + pg_search), e.g.
`paradedb/paradedb:0.23.5`. Stock PostgreSQL will not work, because full-text search
uses its BM25 index. The server applies its own migrations on startup. If
`BLADEDR_DATABASE_URL` is not set, all state is kept in memory and lost on restart.

## Configuration

| Variable | Required | Purpose |
|---|---|---|
| `BLADEDR_DATABASE_URL` | yes | ParadeDB DSN |
| `BLADEDR_NODE_KEY` | yes | Seals SSH credentials and MFA secrets; mint with `-keygen` |
| `BLADEDR_ADMIN_PASSWORD` | – | Initial admin password; if unset, one is generated, logged once and must be changed |
| `BLADEDR_SERVER_URL` | eBPF / isolation | Address monitored hosts use to reach the server (literal IP) |
| `BLADEDR_TLS_CERT`, `BLADEDR_TLS_KEY` | – | Serve HTTPS directly |
| `BLADEDR_SECURE_COOKIES` | behind a proxy | Set `1` when TLS terminates at a proxy |
| `BLADEDR_TRUSTED_PROXY_CIDRS` | behind a proxy | Proxy networks allowed to set `X-Forwarded-For` |
| `BLADEDR_LOG_FORMAT` | – | `json` for log aggregators |

Full list: [README → Config](https://github.com/mar0ls/bladedr#config).

## Image details

- Runs as non-root uid `10001` on Alpine; listens on `8080`.
- Healthcheck: `GET /readyz` over plaintext. If you enable TLS, override it (see the
  compose file). `/healthz` and `/metrics` (Prometheus) are also available and
  unauthenticated, so keep them on an internal network.
- `/etc/bladedr/policies` is empty on purpose. For the optional eBPF tier, mount your own
  Tetragon TracingPolicy bundle there read-only. bladedr does not ship policies yet.
- Nothing else needs to be mounted. All state is in the database.

## Monitored hosts need

Linux (amd64/arm64), SSH access, a writable `/tmp`, and `flock` (util-linux). Root or
sudo is optional; without it scans still run but are marked `partial`. The eBPF tier
also needs Docker and a BTF-capable kernel on the host.

## Stability

0.x. Agentless scanning, rules, triage, the API and storage are on the path to a stable
v1. Response actions and the eBPF tier are Beta, and risk scoring is experimental. See
[docs/stability.md](https://github.com/mar0ls/bladedr/blob/main/docs/stability.md).
Report security issues privately as described in
[SECURITY.md](https://github.com/mar0ls/bladedr/blob/main/SECURITY.md).
