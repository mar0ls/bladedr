# poligon — attack-emulation range

A disposable Linux container we drop EDR-T techniques into, then scan with the
**real** bladedr probe to (a) validate that each rule actually fires on a live host
and (b) produce **labelled training data** for the ML risk model.

```sh
make lab          # build probes + image, run the full range, write poligon/dataset.jsonl
# or:
go run ./cmd/bladedr-lab [--variants obvious,stealthy] [--only id1,id2] [--append] [--keep]
```

Needs Docker. Nothing touches the live fleet or the server DB — the orchestrator
runs the probe locally inside the container, so production data stays clean.

### Privileged techniques on a real host (`--target`)

A few techniques (`chattr +i`, binfmt register, `/proc` bind-mount) need root and a
real kernel/filesystem a container can't provide; they carry `requires: privileged`
and are **skipped on the container**. Run them against a throwaway Linux VM over SSH:

```sh
BLADEDR_LAB_SSH_PASSWORD=… go run ./cmd/bladedr-lab \
    --target user@host --only immutable-file,binfmt-register --append
```

The password is used only for the SSH session and, transiently, for `sudo -S` on
the target's privileged plant/clean steps (nothing persistent is changed — no
sudoers edits). The probe itself runs non-root (the artifacts are world-readable).
`proc-bind-mount` additionally needs SELinux permissive/off — an enforcing policy
denies bind-mounting over `/proc/<pid>`, so it MISSes on a hardened RHEL box (the
emulation is blocked, not the detection). Regenerate the full set with a container
run (overwrites) followed by a `--target … --append` run for the privileged ones.

## How it works

For each technique in `manifest.yaml`, the orchestrator (`cmd/bladedr-lab`):

1. plants the technique's **artifact** in the container (`techniques.sh <id> plant <variant>`),
2. runs the real probe (`bladedr-probe --rules <builtin bundle>`),
3. diffs the findings against a clean baseline → the findings the technique introduced,
4. labels each new finding with the technique and writes it to `dataset.jsonl`,
5. cleans up and moves on.

It then prints a **detection-coverage** matrix (which rules fired vs. expected) and
the **dataset composition**.

## Two variants, one structure

Every technique runs in two naming variants that share the **same structural
trigger** and differ only in cosmetic names:

| variant  | example |
|----------|---------|
| obvious  | `/tmp/.x/payload`, `evil.service`, `toor` |
| stealthy | `/var/tmp/.cache/agent`, `node-metrics.service`, `svc-sync` |

This is the whole point: real intrusions don't use bright PoC names. The risk model
(`internal/risk`) keys on **structural** features (rule, category, severity, MITRE)
and deliberately ignores evidence strings (the names/paths), so training on both
variants teaches it the shape of a compromise, not the literal IOCs. You can see
this directly in `dataset.jsonl`: the obvious and stealthy rows of a technique have
identical `rule_id`/`category`/`mitre` and differ only in `evidence`.

## Positive and negative classes

Most techniques are **true positives** (real compromise artifacts). A few are
**benign-but-flagged negatives** (`label: false_positive` in the manifest): a
legitimate config that trips an *ambiguous* medium-severity rule — e.g. a dev box
loosening `ptrace_scope`, a CI service account in the `docker` group, `.` in a
dev's PATH. These share the rule/category features of the malicious version, so
they teach the model that those rules are **lower precision** (it should rank them
medium, not high). `/risk/stats` reports `lab_positives` vs `lab_negatives` so the
mix is visible.

## Safety / scope

Most techniques reproduce the **artifact at rest** (a file, config, account, key)
that an agentless scan detects — not working malware. **Runtime** techniques (a live
process / socket the probe must see during the scan — fileless memfd exec, a
backdoor listener, an AF_PACKET sniffer, a spoofed reverse-shell/ssh-tunnel cmdline,
a masquerading process, an established miner connection) are driven by a small
static helper (`helpers/runtime`) that holds the resource and sleeps; the
orchestrator starts it before the scan and kills it after. This is authorized
detection engineering on a throwaway container you own.

**Out of scope here** (need a real kernel artifact, a privileged container, or a
VM — these belong to a privileged lab or the eBPF tier): LKM/kernel rootkits
(hidden module/process, kallsyms, taint), dmesg ring-buffer events (segfault, oops,
out-of-tree load, promiscuous — the container shares the host kernel log), eBPF
program load, host-global sysctls (core_pattern, yama ptrace_scope — not
namespaced), `chattr +i` (needs CAP_LINUX_IMMUTABLE) and binfmt_misc (needs a
mount), and the opt-in-off rules. The lab covers ~80% of the builtin rules; the
rest are intentionally left to wave #2.

## Extending

Add a technique in three steps:

1. add a `case "<id>:plant"` / `"<id>:clean"` to `techniques.sh` (support both variants via `pick OBVIOUS STEALTHY`),
2. add an entry to `manifest.yaml` with the rule you expect it to trigger,
3. `make lab`.

A new technique that shows `MISS` is a real coverage gap — either the rule is too
narrow or the variant left the rule's trigger (both worth knowing).
