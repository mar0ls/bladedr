# bladedr attack-emulation range: a disposable Linux host we drop EDR-T techniques
# into, then scan with the real bladedr probe to produce LABELED training data for
# the ML risk model — and to validate that each rule actually fires on a live host.
#
# Techniques run in two variants: "obvious" (bright PoC names like /tmp/.x/evil) and
# "stealthy" (realistic names under /usr/local, /var/lib, ...). The model trains on
# both so it learns the STRUCTURAL signature of a compromise, not the bright names
# that never appear in a real intrusion.
FROM debian:stable-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        procps libcap2-bin passwd coreutils ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/lib/python3/dist-packages /usr/lib/python3.11/site-packages

# A realistic service account, so a planted SSH backdoor in a service account or a
# stealthy SUID under its home blends into a believable host surface.
RUN useradd -m -s /usr/sbin/nologin svc-metrics 2>/dev/null || true \
    && useradd -m -s /bin/bash deploy 2>/dev/null || true

COPY techniques.sh /lab/techniques.sh
RUN chmod +x /lab/techniques.sh

# Runs as root BY DESIGN: this is a disposable attack-emulation range — the technique
# scripts plant root-owned artifacts (/etc configs, SUID, accounts) and the probe reads
# /proc as root. It is never exposed and never runs production workloads.
# Idle; the orchestrator drives everything via `docker exec`.
# nosemgrep: dockerfile.security.missing-user.missing-user
CMD ["sleep", "infinity"]
