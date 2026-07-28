# Security policy

## Reporting a vulnerability

Please don't open a public issue for security problems.

Use GitHub's private reporting instead: the **Security** tab → **Report a
vulnerability**. That opens a private advisory only the maintainers can see.

Include what you'd expect — affected version/commit, how to reproduce, and the impact
you think it has. A proof of concept helps but isn't required. Strip node keys, bearer
tokens and real host data out of the report before you send it.

I'll try to acknowledge within a few days and keep you posted while it's being fixed.
Once there's a patch we'll coordinate on disclosure timing. Fixes land on `main` and in
the next tagged release; older releases don't get separate backports.

## Scope

bladedr holds SSH access to the hosts it scans and can run root commands on them, so
the parts most worth looking at:

- credential sealing / node-key handling (`internal/secrets`)
- the SSH transport and the shell it builds on remote hosts (`internal/scan/ssh.go`)
- auth, MFA, RBAC and session handling (`internal/api`, `internal/auth`)
- the sensor ingest path (`POST /hosts/{id}/events`) and its token check
- response-action approval and the commands the playbooks build (`internal/scan/response.go`)
- export-target secrets and where a webhook is allowed to send data (`internal/export`)
- rule parsing and CEL evaluation, which take operator-supplied input

A dependency bug counts if bladedr's use of it opens a real path in, not just because
the version string matches an advisory.

## Sensor credentials

Sensors get a 256-bit bearer token bound to one host, and the server keeps only the
SHA-256 digest. A token can ingest events for its own host and nothing else — no reads,
no other host, no operator API. It's still a secret: whoever holds it can inject or
replay observations for that host, which is a way to poison triage and the risk model.

Redeployment mints the new token before revoking the old one, so a failed deploy
doesn't leave the host unable to report.

## Response actions

Response actions run root commands on a monitored host, so they're deliberately narrow:
four fixed playbooks, commands built by the server from validated parameters. There is
no endpoint that takes a command string.

Approving needs a second admin. The check lives in the store, in the same statement as
the state transition — approver equals requester is refused there, not in a handler
where a second code path could miss it, and the refusal is audited.
`BLADEDR_RESPONSE_ALLOW_SELF_APPROVAL=true` turns that off for one-admin deployments,
and the server warns about it at startup. Anything that needs that opt-out to work
isn't a finding; the default configuration is what's in scope.

## Agentless probe delivery

The probe lands in `/tmp/.bladedr/` under its content hash, and the scan account is
usually root — so that cache is a way to get root code execution on a host that may
already be compromised. `/tmp` is world-writable, and the path is predictable, so
without a guard any local user could pre-create the directory and park a binary there.

Hence: the staging dir has to be mode 0700 and owned by the scan account, checked
without following symlinks, and a cached binary is verified by SHA-256 before it runs.
Anything unverifiable gets re-uploaded rather than trusted. If you find a way for an
unprivileged local account to influence which binary a scan executes, that's in scope.

## Build and release

The published image is the thing operators run with SSH access to their fleet, so what
can reach the release pipeline matters as much as what can reach a host.

Most of that chain is nailed down. All 24 GitHub Action references are pinned by commit
SHA, both Dockerfile base images are pinned by digest, and release images carry build
provenance and an SBOM. Nothing publishes until the tagged commit passes the store
contract against Postgres, the attack-emulation range and the false-positive baseline —
the release and image jobs depend on those gates rather than running beside them.

What that does *not* give you is review. A tag is accepted on the strength of its name
alone (`refs/tags/v*`), so anyone who can push a tag can publish any commit that passes
the gates, whether or not it ever went through a pull request. Branch and tag protection
is the place to fix that, not the workflow.

One gap is open and worth stating plainly rather than leaving for someone to find. CI runs
`cicd-sensor/cicd-sensor-action`, which downloads its agent binary from a GitHub release
with `curl` and unpacks it with `tar` — no checksum, no signature. Pinning the action by
SHA pins its *code*, and the agent version with it, but not the release asset that code
fetches: that asset can be replaced without the pinned SHA changing.

It is a third-party dependency: `cicd-sensor` is an organisation this project has no
control over and no write access to. The release it downloads from does publish
`checksums.txt` and a Sigstore bundle for it, so verification is possible today and simply
is not performed — but neither that decision nor the release channel is ours, so asking
for a fix is not a mitigation this project controls.

What this project controls is where the agent runs, so it no longer runs in the two jobs
that can publish on your behalf: `release`, which holds `contents: write`, and `image`,
which holds the Docker Hub token. It still runs in `build`, `semgrep`, `smoke` and
`detections`, where a compromise costs a false CI report rather than a substituted
artifact. This is not a claim that the action is hostile — there is no evidence of that.
It is the ordinary rule that a job able to ship something to users should carry as little
unverified code as it can.

Reports of a *different* way into the release path — an unpinned action, a workflow that
runs untrusted input with write permissions, a way to publish under a tag that never
passed the gates — are in scope.

## Not in scope

- Anything requiring an already-compromised control-plane host, or `BLADEDR_NODE_KEY`.
- Anything requiring arbitrary writes to the database — unless bladedr is what hands
  you that access, or turns a lesser database privilege into it.
- Evasion that just needs root on the monitored host. Agentless scanning can't win
  against full control of the thing it's scanning, and doesn't claim to.
- The disposable attack-emulation range under `poligon/` — it plants real techniques
  on throwaway hosts by design.

Read-only disclosure of the database *is* in scope. Sealed credentials, sessions and
sensor tokens are all built so that a database snapshot alone gives you nothing
replayable — if that turns out to be false somewhere, I want to know.
