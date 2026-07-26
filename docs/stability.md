# Stability and v1 scope

What bladedr v1.0.0 promises, what it deliberately doesn't, and which parts you can
build on. This is the reference for "is it safe to depend on X" — if something isn't
listed here, treat it as unstable.

## The promise

> bladedr v1 provides stable agentless threat detection and response for supported Linux
> systems: SSH-based scans, deterministic CEL rules, baseline drift detection, triage,
> audit logging, and optional Tetragon-based runtime telemetry.

Two things that promise does *not* include, stated up front because they're the usual
misreading:

- **It is not a guarantee of detection coverage.** Rules find what they're written to
  find. [COVERAGE.md](../COVERAGE.md) maps what's implemented against the ATT&CK/EDR-T
  matrix, including the gaps.
- **It is not agent-grade visibility.** An agentless scan is a point-in-time look at
  state. Anything ephemeral — an exec, an injection, C2 traffic — is gone between scans
  unless you run the eBPF tier. That's a property of the model, not a bug to fix.

## Stability profiles

**GA** — stable in v1. Breaking changes need a major version.

| Component | Notes |
|---|---|
| `bladedr-server` | Config env vars, listen behaviour, TLS |
| `bladedr-probe` (linux/amd64, linux/arm64) | Snapshot schema consumed by rules |
| Agentless SSH scanning | Transport, host-key pinning, probe delivery |
| CEL rule engine | Rule schema, snapshot field paths, merge order |
| REST API `/api/v1` | See compatibility rules below |
| Postgres storage + migrations | Forward-only, data-preserving |
| Auth, RBAC, audit log | Roles, session and token handling |
| Observations, triage, baseline/drift | Statuses, dedup, `baseline-new-*` |
| ECS/JSON export | Field mapping |
| Web console | Behaviour, not markup |
| `/healthz`, `/readyz`, `/metrics` | Metric names |
| Backup and restore | `pg_dump` + node key |

**Beta** — works, tested, but the surface may change in a minor release.

| Component | Why it isn't GA |
|---|---|
| `bladedr-sensor` + Tetragon integration | Depends on an external policy engine and a BTF-capable kernel, and **you supply the TracingPolicies** — no bundle ships with bladedr yet, so the tier is off out of the box. A written and kernel-tested set is planned for a later release. The event→observation mapping is still settling |
| Server-push sensor deployment | Touches systemd and Docker on the target; too many host variations to call settled |
| **Response actions** | Landed in 0.9.0 and run root commands on production hosts. Unit- and API-tested, but not yet proven on a real fleet — `isolate_host` in particular can strand a host if the control-plane endpoint is wrong |
| `bladectl` | Flag names may change while the ergonomics settle |

**Experimental** — usable, no compatibility promise, may be removed.

| Component | Why |
|---|---|
| Learned risk scoring | Ranks findings; the model, features and reported metrics can all change |
| Training on attack-emulation datasets | `poligon/` dataset format is internal |
| Retention/archive | Archive table layout may change |

Risk scoring stays a **prioritiser**, never part of detection. A mis-calibrated model
reorders your queue; it must never be able to suppress a finding. That separation is a
design constraint, not an implementation detail.

## Compatibility rules for `/api/v1`

Within v1 we may:

- add endpoints, and add fields to responses
- add optional request fields and query parameters
- add new enum values to fields already documented as extensible (`rule_id`, `category`,
  `source`)

Within v1 we won't:

- remove or rename an endpoint, field, or query parameter
- change a field's type, or make an optional request field required
- change the meaning of an existing enum value
- tighten validation so a request that used to be accepted starts failing

Clients should ignore unknown fields. [internal/api/openapi.yaml](../internal/api/openapi.yaml)
is the contract and covers every route; a test fails if a route is missing from it.

## Migrations

Forward-only, applied automatically at startup, each in its own transaction and recorded
once in `schema_migrations`. Upgrading is "deploy the new binary and restart".

Downgrade is not supported: a binary that predates a migration will not run against a
database that has it. Snapshot the database before a major bump.

Migrations preserve data. The exception in the 0.9.0 line is the session table, which is
emptied because plaintext bearer tokens can't be converted into digests — see the upgrade
notes in [CHANGELOG.md](../CHANGELOG.md). `TestUpgradeFromInitialSchemaKeepsData` seeds a
0.1.0-era schema, upgrades to head and asserts everything else survives and stays
readable.

## Packaging for v1.0.0

The release is a tagged `v1.0.0` that produces:

- a container image on Docker Hub, multi-arch (linux/amd64, linux/arm64), tagged
  `v1.0.0`, `1.0`, `1` and `latest`
- static `linux/amd64` and `linux/arm64` binaries for server, probe, sensor and
  `bladectl`
- an SPDX SBOM and `SHA256SUMS`

The image is the primary artifact: `docker run` with `BLADEDR_DATABASE_URL` and
`BLADEDR_NODE_KEY` should be a working control plane. It already ships the
architecture-specific probe and sensor binaries, runs as uid 10001, and has a
`/readyz`-based healthcheck. Policies stay an operator-mounted bundle at
`/etc/bladedr/policies` so they can be versioned independently.

Current gap: the release workflow publishes binaries but not the image, and there is no
Docker Hub repository wired up yet.

## Scope freeze

From here to v1.0.0, changes are limited to:

bug fixes · security fixes · false-positive tuning · detection tests · upgrade and
restore tests · documentation · packaging and release automation · UX fixes · API
stabilisation

Not before v1, absent a specific reason:

another ML model · a new sensor type · Windows or macOS targets · multi-tenancy · new
large integrations · a UI rewrite · a storage rewrite · broader SOAR · automatic
remediation

The remaining work for v1 isn't features. It's evidence: that detections fire on real
compromises and stay quiet on clean hosts, that deployment is safe, and that upgrading
loses neither data nor access to the fleet.
