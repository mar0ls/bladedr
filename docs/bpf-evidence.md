# BPF evidence in scan alerts

The probe sends bounded BPF metadata independently of full snapshots. New
baseline BPF alerts retain matching programs in their existing JSON evidence:
ID, type, tag, name, creating UID, kernel monotonic load time, translated/JIT
sizes, observed process holders and attachment records. Multiple programs with
the same type/tag are retained together. Existing evidence rendering exposes
these fields; no database migration is needed.

Process holders are discovered read-only from `/proc/*/fdinfo`; executable and
cgroup identify the observed process, not necessarily the original loader.
Attachment enrichment uses optional `bpftool -j link show` and `bpftool -j cgroup
tree`. No programs are attached, pinned, modified or installed. Collection is
bounded by time, descriptor count and command output size. A missing bpftool,
permissions failure, disappearing descriptor or unobserved attachment is
reported, not interpreted as absence of risk. A missing bpftool is reported on each program's evidence and does not make the scan partial. Evidence is deliberately marked
partial: attachment coverage is not exhaustive, kernel identities may race,
and original loader attribution is not available from this scan.

The monotonic `load_time_ns` is not a UTC timestamp. `scan_started_at` is the
server scan start, not the exact BPF load time. No automatic FP or allowlist is
derived from names, UID or a systemd-looking cgroup.

Upserts retain the latest evidence for each deduplicated alert, not a timeline
of every occurrence. Durable occurrence history, systemd policy parsing and
sensor-level load/attach events are separate extensions. Old alerts cannot be
retroactively enriched unless the program appears in another scan. Programs
that disappear between scans are not captured.

Deploy a rebuilt server with the matching probe binaries to enable this wire
extension. Agentless scans upload the configured probe to the target; an existing
sensor does not need to be redeployed for this scan-only change.
