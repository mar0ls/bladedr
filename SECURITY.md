# Security policy

## Reporting a vulnerability

Please don't open a public issue for security problems.

Use GitHub's private reporting instead: the **Security** tab → **Report a
vulnerability**. That opens a private advisory only the maintainers can see.

Include what you'd expect — affected version/commit, how to reproduce, and the impact
you think it has. A proof of concept helps but isn't required.

I'll try to acknowledge within a few days and keep you posted while it's being fixed.
Once there's a patch we'll coordinate on disclosure timing.

## Scope

bladedr holds SSH access to the hosts it scans, so the parts most worth looking at:

- the credential sealing / node-key handling (`internal/secrets`)
- the SSH transport and the shell it builds on remote hosts (`internal/scan/ssh.go`)
- auth, RBAC and session handling (`internal/api`, `internal/auth`)
- the sensor ingest path (`POST /hosts/{id}/events`) and its token check

## Not in scope

- Anything requiring an already-compromised control-plane host or database.
- The disposable attack-emulation range under `poligon/` — it plants real techniques
  on throwaway hosts by design.
