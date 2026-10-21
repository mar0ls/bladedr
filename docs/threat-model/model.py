"""bladedr threat model, as pytm (https://github.com/izar/pytm) code.

This is a structured, checkable companion to ../../SECURITY.md, not a replacement for
it: SECURITY.md is the prose explanation of why each boundary is drawn where it is;
this file is the versioned, diffable description of the same boundaries, so a change
to a trust assumption (e.g. a dataflow losing its encryption or authentication) shows
up as a code review comment on this file instead of only living in someone's head.

Usage (from this directory, with pytm installed -- see requirements.txt):

    python3 model.py --dfd | dot -Tsvg -o dfd.svg       # data-flow diagram
    python3 model.py --seq                              # sequence diagram (PlantUML)
    python3 model.py --json model.json                  # machine-readable dump
    python3 summarize.py model.json > summary.md         # human-readable summary
    python3 model.py --list                              # every threat rule pytm knows

pytm 1.4.0 quirk worth knowing before editing this file: `Dataflow.protocol`,
`.srcPort`/`.dstPort`, `.controls.isEncrypted` and `.controls.authenticatesDestination`
are NOT read back from what you pass into the Dataflow() constructor. During
`tm.check()`, `_apply_forward_defaults()` (pytm/pytm.py) unconditionally overwrites them
from the *endpoint elements*: protocol/dstPort/isEncrypted come from the flow's sink,
authenticatesDestination comes from the flow's source. So those five fields are set on
the Server/Datastore elements below, not on the Dataflow calls -- setting them on a
Dataflow is silently discarded. Every other Controls flag (implementsPOLP, isHardened,
providesIntegrity, validatesInput, handlesResourceConsumption, tracksExecutionFlow,
sanitizesInput, checksInputBounds, authenticatesSource, authorizesSource, usesMFA,
implementsAuthenticationScheme, handlesCrashes, ...) is NOT touched by that step and
does belong on the Dataflow, which is where the fixes below are set.
"""

from pytm import (
    TM,
    Actor,
    Boundary,
    Controls,
    Dataflow,
    Datastore,
    DatastoreType,
    Server,
)

tm = TM("bladedr")
tm.description = (
    "Agentless Linux EDR: a control plane (bladedr-server) that reaches a fleet over "
    "SSH to run a probe, optionally deploys an eBPF sensor (bladedr-sensor, a "
    "Tetragon wrapper) for runtime telemetry, and stores findings in Postgres. See "
    "docs/deployment.md for the deployment topology and SECURITY.md for the prose "
    "version of this model's trust boundaries."
)

# ---------------------------------------------------------------------------
# Boundaries
# ---------------------------------------------------------------------------

operator_zone = Boundary("Operator network")
control_plane = Boundary("Control plane")
# Deliberately a separate, lower-trust boundary: SECURITY.md is explicit that a scan
# target "may already be compromised" and that the probe cache guard exists because
# `/tmp` on it is attacker-reachable. Nothing in this boundary is assumed honest.
managed_fleet = Boundary("Managed fleet (scan targets / sensor hosts)")

# ---------------------------------------------------------------------------
# Actors, processes, datastore
#
# protocol/port/isEncrypted/authenticatesDestination live here (see module
# docstring): bladedr-server's own `controls.isEncrypted` is what every flow landing
# on it (login, probe output, sensor ingest) inherits as its encryption-in-transit
# flag, and its `controls.authenticatesDestination` is what every flow it *initiates*
# (probe launch, sensor deploy) inherits for "did we verify who we're talking to".
# ---------------------------------------------------------------------------

analyst = Actor(
    "Security analyst (browser)",
    inBoundary=operator_zone,
    controls=Controls(authenticatesDestination=True),  # browser TLS certificate validation
)

bladedr_server = Server(
    "bladedr-server",
    inBoundary=control_plane,
    OS="Linux",
    protocol="HTTPS",
    port=443,
    controls=Controls(
        isEncrypted=True,  # TLS, directly or via a fronting proxy -- see docs/deployment.md
        authenticatesDestination=True,  # SSH host-key pinning after TOFU, ssh.go hostKeyCallback
        implementsAuthenticationScheme=True,  # session cookie + bearer token, internal/api/auth.go
        hasAccessControl=True,  # RBAC: admin/operator/viewer, internal/auth
        validatesInput=True,
    ),
)

scan_target = Server(
    "Scan target host",
    inBoundary=managed_fleet,
    OS="Linux",
    protocol="SSH",
    port=22,
    controls=Controls(
        isEncrypted=True,  # the SSH transport itself
        isHardened=False,  # the fleet host is the thing being monitored, not vetted infra
    ),
)

sensor = Server(
    "bladedr-sensor (Tetragon wrapper)",
    inBoundary=managed_fleet,
    OS="Linux",
)

db = Datastore(
    "Postgres",
    inBoundary=control_plane,
    type=DatastoreType.SQL,
    storesSensitiveData=True,  # sealed credentials, password-hash fingerprints, audit log
    storesLogData=True,
    controls=Controls(
        isEncryptedAtRest=False,  # operator/infra responsibility, not handled by bladedr itself
        hasAccessControl=True,
    ),
)

# ---------------------------------------------------------------------------
# Dataflows -- each `note` cites the code (and, where one exists, the regression
# test) that the control flags are asserting against.
# ---------------------------------------------------------------------------

Dataflow(
    analyst,
    bladedr_server,
    "Operator login (username/password, optional TOTP) and session cookie",
    controls=Controls(
        usesMFA=True,  # supported, not mandatory -- see internal/auth
        handlesResourceConsumption=True,  # per-IP login throttle, internal/api/auth.go loginLimiter
    ),
    note=(
        "internal/api/auth.go (login, session cookie, per-IP throttle). Failed and "
        "throttled attempts are audited (auditAs)."
    ),
)

Dataflow(
    bladedr_server,
    scan_target,
    "Agentless probe launch over SSH, escalated via sudo when available",
    controls=Controls(
        implementsPOLP=True,  # escalation attempted, never required; probe runs unprivileged if sudo is refused
        isHardened=True,  # probe cache dir must be 0700 + scan-account-owned; cached binary sha256-verified
    ),
    note=(
        "internal/scan/ssh.go: probeCommand, privilegedProbeScript, cacheDirScript. "
        "Fixed 2026-10-20: the sudo password, when needed, used to be embedded as a "
        "shell-escaped literal in the command text sshd hands the remote shell as its "
        "argv -- readable by any local account via `ps` for as long as that process "
        "ran. It now travels only as real SSH stdin, read once into a shell variable "
        "(TestProbeCommandDoesNotLeakPasswordInCommandText)."
    ),
)

Dataflow(
    scan_target,
    bladedr_server,
    # The reported protocol/port on this flow will read HTTPS/443, inherited from
    # bladedr_server as sink (see module docstring): it's actually the same SSH
    # session flow 2 opened. One Controls object per element can't represent "this
    # process speaks two protocols on two ports" more precisely than that.
    "Probe result (JSON findings) over the same SSH session's stdout/stderr",
    controls=Controls(
        validatesInput=True,  # decoded into typed structs, not trusted as-is
        handlesResourceConsumption=True,
    ),
    note=(
        "internal/scan/ssh.go: run(), capturedOutput. The scan target is not fully "
        "trusted (compromised, or just misbehaving) and the control plane talks to "
        "many of them, so an unbounded stdout/stderr was a memory-exhaustion vector. "
        "Fixed 2026-10-20: output is capped at 64 MiB per stream; exceeding it fails "
        "the command instead of returning a partial result "
        "(TestRunRefusesOversizedRemoteOutput)."
    ),
)

Dataflow(
    bladedr_server,
    scan_target,
    "Sensor deployment (binary + Tetragon policy bundle), run as root via sudo",
    controls=Controls(
        providesIntegrity=True,  # sha256 digest check before either file is used as root
    ),
    note=(
        "internal/scan/ssh.go: DeploySensor, sensorDeployScript, verifyDigestScript. "
        "The binary and policy bundle are uploaded to the scan account's own "
        "(non-root) staging directory, then a later, separate step runs them as root "
        "-- the same upload-then-sudo-run gap the probe path's digest check exists to "
        "close, left open here until fixed 2026-10-20: deploy.sh now takes "
        "server-computed sha256 digests and refuses to proceed if either file changed "
        "after upload (TestSensorDeployScriptRejectsTamperedSensorBinary). This flow's "
        "own sudo escalation goes through wrapSudo, which had the same argv-visible "
        "password problem as probeCommand (see the probe-launch flow's note) until the "
        "same review pass fixed it there too -- caught by re-reading every wrapSudo "
        "call site, not limited to the one already fixed "
        "(TestWrapSudoDoesNotLeakPasswordInCommandText)."
    ),
)

Dataflow(
    sensor,
    bladedr_server,
    "Sensor event ingestion: POST /api/v1/hosts/{id}/events, bearer sensor token",
    controls=Controls(
        authenticatesSource=True,  # per-host bearer token; server keeps only its SHA-256 digest
        authorizesSource=True,  # token is scoped to its own host, nothing else -- SECURITY.md "Sensor credentials"
        checksInputBounds=True,
        sanitizesInput=True,
    ),
    note=(
        "internal/api/api.go: ingestEvents, sensorEvent. A per-host sensor token is "
        "deliberately the narrowest trust boundary in the system (it can only report "
        "detections for its own host) -- see SECURITY.md 'Sensor credentials'. Fixed "
        "2026-10-20: the handler used to decode the sensor's batch straight into "
        "store.Observation, so a leaked token could set its own verdict (poisoning "
        "the ML risk model and the fleet trust gate), id (colliding with an unrelated "
        "observation) or status (self-resolving its own finding). It now decodes into "
        "an allowlisted type carrying only detection metadata; HostID, Source, "
        "Status and Verdict stay server-assigned "
        "(TestIngestEventsIgnoresServerControlledFields)."
    ),
)

Dataflow(
    bladedr_server,
    db,
    # Reported authenticatesDestination=True on this flow is inherited from
    # bladedr_server's own controls (set for SSH host-key pinning, not Postgres
    # auth) -- same per-element-not-per-flow limitation as the note above.
    "Observation, audit and credential writes",
    controls=Controls(
        tracksExecutionFlow=True,  # audit-append failures are now logged and counted, not swallowed
        handlesCrashes=True,
    ),
    note=(
        "internal/api/auth.go: auditAs. internal/api/metrics.go: "
        "bladedr_audit_append_failures_total. Fixed 2026-10-20: a failed "
        "AppendAudit used to be discarded outright (`_ = a.Store.AppendAudit(...)`), "
        "so an audit backend outage (disk full, DB unreachable) left no trace that "
        "anything had gone unrecorded. Failures are now logged via slog and counted "
        "in a scrapeable metric; the triggering action still completes "
        "(TestAuditFailureIsCountedNotSwallowed)."
    ),
)

if __name__ == "__main__":
    tm.process()
