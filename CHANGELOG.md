# Changelog

Notable changes. Format loosely follows [Keep a Changelog](https://keepachangelog.com);
versions follow [SemVer](https://semver.org).

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
