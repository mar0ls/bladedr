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

Only the privileged set is meant for a host. The rest is written for a container that
is deleted afterwards: while it runs the host carries a world-writable `/etc/passwd`,
SUID root shells, uid-0 accounts and a replaced `sshd_config`. So `--target` refuses
any non-privileged technique unless you pass `--disposable`, which says the host is a
throwaway VM. Plants that overwrite an existing file (sshd_config, nsswitch.conf,
root's authorized_keys, …) save the original to `/var/tmp/bladedr-lab-orig` and put it
back on clean; if a run dies mid-way, that is where to find them.

The password is used only for the SSH session and, transiently, for `sudo -S` on
the target's privileged plant/clean steps (nothing persistent is changed — no
sudoers edits). The probe runs under the same `sudo -S`, as a production scan of a
password-sudo account does, so the dataset sees what a root probe sees.
`proc-bind-mount` additionally needs SELinux permissive/off — an enforcing policy
denies bind-mounting over `/proc/<pid>`, so it MISSes on a hardened RHEL box (the
emulation is blocked, not the detection). Regenerate the full set with a container
run (overwrites) followed by a `--target … --append` run for the privileged ones.

Run them on both a RHEL-family and a Debian-family host, because two of the five
legitimately disagree between the two — and only seeing both tells you the difference is
correct rather than a broken rule. Measured on Rocky Linux 10.2 (SELinux enforcing) and
Ubuntu 24.04:

| technique | Rocky 10.2 | Ubuntu 24.04 |
|---|---|---|
| `immutable-file` | ok | ok |
| `binfmt-register` | ok | ok |
| `core-pattern` | ok | ok |
| `proc-bind-mount` | MISS | ok |
| `yama-runtime` | MISS | ok |

Both Rocky MISSes are the intended behaviour. SELinux blocks the `proc-bind-mount` plant,
so there is nothing to detect. And `yama-runtime` sets `ptrace_scope=0`, which *is*
RHEL's vendor default — the collector deliberately suppresses a runtime value matching the
vendor default, because flagging it there is noise. Debian and Ubuntu ship `1`, so the
same plant is a genuine weakening and the rule fires. A single-distro run would either
never exercise that path or report a permanent false MISS.

## How it works

For each technique in `manifest.yaml`, the orchestrator (`cmd/bladedr-lab`):

1. plants the technique's **artifact** in the container (`techniques.sh <id> plant <variant>`),
2. runs the real probe (`bladedr-probe --rules <builtin bundle>`),
3. diffs the findings against a clean baseline → the findings the technique introduced,
4. labels each new finding with the technique and writes it to `dataset.jsonl`,
5. cleans up and moves on.

It then prints a **detection-coverage** matrix (which rules fired vs. expected), the
**negative-class calibration** line (benign scenarios still tripping their ambiguous
rule — counted separately, so it can never inflate coverage), the **dataset
composition**, and the **feature ablation** described in the dataset sheet below.

## Two variants, one structure

Every technique runs in two naming variants that share the **same structural
trigger** and differ only in cosmetic names:

| variant  | example |
|----------|---------|
| obvious  | `/tmp/.x/payload`, `evil.service`, `toor` |
| stealthy | `/var/tmp/.cache/agent`, `node-metrics.service`, `svc-sync` |

This is the whole point: real intrusions don't use bright PoC names. The risk model
(`internal/risk`) keys on **structural** features (the rule, its source, and the shape of
the artifact) and deliberately ignores evidence strings (the names/paths), so training on
both variants teaches it the shape of a compromise, not the literal IOCs. You can see
this directly in `dataset.jsonl`: the obvious and stealthy rows of a technique have
identical `rule_id`/`category`/`mitre` and differ only in `evidence`.

## Positive and negative classes

Most techniques are **true positives** (real compromise artifacts). 26 are
**benign-but-flagged negatives** (`label: false_positive` in the manifest): a
legitimate config that trips an *ambiguous* rule — a dev box loosening
`ptrace_scope`, a CI service account in the `docker` group, a backup group granted
`sudo tar`, a daemon still running from a binary `apt upgrade` replaced, an APM agent
carrying `cap_sys_ptrace`. These share the rule/category features of the malicious
version, so they teach the model that those rules are **lower precision** rather than
letting it conclude that whatever a rule fires on is real. `/risk/stats` reports
`lab_positives` vs `lab_negatives` so the mix is visible.

A benign scenario is only worth having if its justification survives contact with a
reviewer. If you cannot say why a competent admin would ship that config, it is not a
negative — it is a mislabelled positive, and it teaches the model the opposite of the
point. Each entry in `techniques.sh` carries that justification as a comment.

## Dataset sheet

Current validation protocol: [ML validation](../docs/ml-validation.md). The measured
tables below describe earlier feature versions and row-based splits; they are
historical development measurements, not current independent acceptance results.
Current evaluation groups naming variants by technique and fleet findings by host,
and requires sufficient labels and a successful evaluation on fleet data alone.

**Provenance.** `dataset.jsonl` is generated, never committed — it is in `.gitignore`,
and `make lab` rewrites it. Every row is a finding the real probe produced on a live
container after a real plant, diffed against a clean baseline. No row is hand-written,
synthesised, or imported from an external corpus.

**Composition**, measured on a full container run (`go run ./cmd/bladedr-lab
--fail-on-miss --expect-techniques 102`, both variants, 0 MISS):

| | |
|---|---|
| rows | 215 |
| `true_positive` | 152 (71%) |
| `false_positive` | 63 (29%) |
| distinct `rule_id` | 74 |
| rules appearing under **both** labels | 29 |
| mean rows per rule | 2.9 |
| attack techniques / benign scenarios | 72 / 30 |
| `source` | `lab` (100%) |

The 29 mixed-label rules are the point of the negative class, and they are what the
within-rule diagnostic below is measured over. A rule that appears only under one label
is a lookup entry; a rule that appears under both forces the model to learn something
about the instance instead of about the rule.

**Why the negatives have to be planted.** They cannot be harvested from clean hosts.
`scripts/baseline.sh` requires that *no* rule fires on stock Debian, Ubuntu, Rocky or
Alpine, and CI enforces it — so a clean host produces zero observations and therefore
zero negatives. The only negative that exists in this model's world is a legitimate
config that trips an ambiguous rule, which is a function of *these* rules and cannot be
sourced from a public IDS corpus with a different feature space.

**These are not fleet priors.** The set is 72% positive because an attack range is
mostly attacks. A real fleet inverts that: most of what a rule raises is noise. Weights
fitted here encode the lab's prior, which is why bladedr ships **no pre-trained model** —
`/risk/stats` fits per deployment on explicit analyst verdicts, mixed with this set.
Workflow status does not supply labels. Imported records use their `label` as the
observation verdict; records with `verdict=unknown` are excluded from training.

That is enforced rather than advised. `Stats.Trustworthy` is false whenever *every*
labelled observation carries `source: lab`, no matter how well separated the figures look,
because a model that has only ever seen the range is calibrated to a fleet that does not
exist. This gate matters: with the instance-shape features the range data clears every
quality threshold on its own, and without the provenance check the report would read
`trustworthy: true` on a set no real host contributed a row to.

**Measured behaviour — size of the negative class.** Same run, same 141 positives;
only the negative class differs:

| negatives | ROC AUC | ±sd | balanced acc. | Brier | base rate | trustworthy |
|---|---|---|---|---|---|---|
| 10 (before) | 0.773 | 0.063 | 0.490 | 0.070 | 0.934 | *see below* |
| **54 (now)** | **0.575** | **0.026** | **0.498** | **0.280** | **0.723** | no |

1. **The old 0.773 was a better-looking number about a worse-understood model.** Its
   balanced accuracy was 0.490 — below a coin flip — against a base rate of 0.934. The
   model was ranking 10 negatives among 141 positives and being scored mostly on the
   prior. Under the pre-existing size gate (8 per class) that set evaluated as
   `trustworthy: true`, with the reason *"enough balanced, separable data to prioritise
   findings"*. That is the exact failure the gate existed to prevent, so the floor is
   now 30 per class (`minPerClass` in `internal/risk/model.go`), sized so five folds
   leave ~6 of the minority class in every held-out fold.
2. **The drop to 0.575 is the measurement becoming honest, not the model getting
   worse.** Balanced accuracy went *up* (0.490 → 0.498) and the spread across seeds
   halved (±0.063 → ±0.026). The figure is now stable enough to believe, and what it
   says is that the model is weak. The Brier rise (0.070 → 0.280) is the same effect:
   0.070 was cheap to achieve by predicting the 93% prior everywhere.

**Measured behaviour — what the model can and cannot separate.** The figure to read is
not the pooled ROC AUC. Pooling every observation mostly measures ranking one rule above
another, which the rule's own static score already does deterministically. The question
only a model can answer is the one *inside* a rule: this rule fires on both real findings
and noise, so is this instance real? A rule whose every instance gets the same score is
**tied** — the model has no feature that distinguishes them and is re-expressing the
rule's static score while looking like a second opinion.

| | tied ambiguous rules | pooled ROC AUC | balanced acc. |
|---|---|---|---|
| rule-derived features only (before) | **20 of 25** | 0.575 | 0.498 |
| with instance-shape features | 9 of 25 | 0.649 | 0.544 |
| + `writable_persistence` carrying *how* | 7 of 25 | 0.652 | 0.544 |
| + redundant rule tokens removed, library and credential techniques (now) | **8 of 29** | 0.718 | 0.691 |

The last row is a collector change, not a modelling one. `writable_persistence` used to be
a list of paths, so the rule could only say "a non-root principal can write this file".
It now carries `via` — `other` (every account on the host) or `group` (one named non-root
group) — and the model can finally tell a unit file group-owned by `deploy` from the same
file left world-writable. The rule still fires on both, because from a snapshot neither is
decidable; the evidence just stopped throwing the difference away.

The instance-shape features (`shape:` in `Features()`) describe the artifact rather than
the rule: whether it hides a path component under a transient root, which class of file
capability it carries, whether a sudo grant names a role or one account, whether it
reaches for the dynamic linker, whether it hands a string to a shell instead of an argv
list, whether a tunnel is a general-purpose pivot or a point-to-point forward, whether an
enforcement layer is off or merely permissive.

The line they hold is that **a feature must survive renaming**. An attacker picks the
filename, the port and the account name freely, so those stay excluded — which is the
whole reason the range runs an obvious and a stealthy variant of every technique. Of the
25 ambiguous rules measured when this was written, 22 had *some* evidence field that separates the classes, but for
most of them that field is the literal (`pid`, port `4444` vs `9001`, `evil.example` vs
`apt.internal.corp`). Featurising those would raise every number here and produce a worse
IOC matcher than the rules already are.

**Feature ablation**, identical folds, seeds and metrics on every row:

| features withheld | ROC AUC | reading |
|---|---|---|
| none | 0.718 | |
| `shape:` | 0.614 | the instance-shape features carry about 0.10 of the AUC |
| `rule:` (rule identity) | 0.760 | rule identity is *hurting* on this data |

Measured on the 215-example set from the 2026-10-10 range run (102 techniques, both
variants). The model no longer emits category, severity or MITRE tokens: the rule fixes
them, and Naive Bayes counts every token as independent evidence, so they counted the rule
five times over and carried verdicts between unrelated rules that happen to share a tactic
(kernel-module plants taught every T1547 finding, BPF baseline drift included, to look like
an attack). Removing them, together with giving a running process's executable its own
directory class, moved the full-model figure from 0.652 to 0.740 on the set this table was
first measured on. With them gone, `rule:` is the only rule-identity token,
so dropping it is a real ablation, which it was not while the metadata was still there.

The last row should not be read as "delete the rule feature". It says rule identity is noise
*here*, where a rule carries about two rows on average and its identity is close to a row id.
In a deployment where an operator has triaged one rule fifty times, that same token is the
per-rule precision the model should be learning. The lab cannot see that, which is a limit
of the lab, not a verdict on the feature.

**The seven that remain tied**, and why each one is honest:

- `docker-socket-exposed`, `service-account-in-privileged-group`, `sysctl-hardening-disabled`
  — the benign and malicious instances are genuinely indistinguishable from state. A
  world-readable docker socket is a world-readable docker socket. These are the cases the
  rule cannot resolve and neither can the model; they are the argument for two-person
  review, not for a better feature.
- `nsswitch-unusual-module`, `package-repo-unverified`, `suspicious-port-listener` — the
  only difference is the literal (module name, mirror hostname, port number). Correctly
  left tied, on purpose: featurising those is IOC matching, which the rules already do.
- `packet-sniffer-process` — an artifact of the range: both the flow exporter and the
  sniffer are the same `helpers/runtime` binary, so `comm` matches. A real fleet would
  differ here.

(`writable-persistence-file` and `ssh-config-localcommand` used to be on this list. Both
were fixed — the first by making the collector say *how* a file is writable, the second by
narrowing the hidden-path feature so `~/.ssh` stopped counting as concealment.)

**Scenes, and the co-occurrence hypothesis that did not survive them.** The per-technique
loop scans a host carrying exactly one plant, so every row it produces is a lone finding.
That made an obvious hypothesis untestable: an intrusion usually trips several rules at
once, a legitimate configuration trips one, so the number of findings sharing a scan
should itself be a feature. `manifest.yaml` grew a `scenes:` section to test it — five
attack chains and five legitimate host postures, each planted whole, scanned once and
cleaned in reverse (`poligon/scenes.jsonl`, generated, gitignored).

Measured over all ten scenes in both variants: **attack scenes produce 3.7 findings on
average, benign scenes 3.4**, with the counts almost entirely overlapping —
`[3,3,3,3,3,4,4,4,5,5]` against `[3,3,3,3,3,3,4,4,4,4]`.

No feature was built on that, and the reason matters more than the number: **a synthetic
range cannot test this hypothesis at all.** A scene produces as many findings as the
person writing the manifest put techniques in it. The measurement above says "when an
attack plants three artifacts and a CI box has three legitimate configs, both scans return
three findings", which is arithmetic, not evidence. Answering it properly needs scene sizes
drawn from real incidents and real hosts, which is production triage — the same data the
provenance gate is waiting for.

The scenes stay, for the value that does not depend on that hypothesis: they are the only
place two techniques are ever on the host at once, so they exercise the plant/clean
interactions the per-technique loop cannot (a technique that overwrites another's file, a
cleanup that removes a file a second technique still needs). `--fail-on-miss` treats a
failed scene plant as an error, because a scene short one plant reports a smaller finding
count for a reason that has nothing to do with detection.

**Known limitations.** Small (195 rows against 69 rule tokens). Single source — no
production triage in it, so nothing here exercises the observation fields that only exist
in a running deployment: `Count` and `FirstSeen`/`LastSeen` are not featurised, because
every row the range produces has a count of one and no history. Whether a benign config's
persistence across scans separates it from an intrusion artifact is still an open
hypothesis, and it is open for the same reason co-occurrence turned out to be (see
scenes, above): the range decides those values, so it cannot be the thing that tests them.

The two naming variants of a technique share every rule-derived feature and differ only
in `evidence`, so they are near-duplicates on that half of the vector; the folds are
stratified but not grouped by technique, so a technique's twin row can land across the
split. Per-rule counts are small enough (~2.8) that a *within-rule* cross-validated AUC
is not measurable at all — holding out one instance of a four-row rule shifts that rule's
class balance in the training fold against the held-out row's own label, and the figure
inverts (measured 0.159, below chance, from fold mechanics rather than from the model).
That is why the within-rule diagnostic above is a tie count and not an AUC.

Five techniques never run in the container (see above) and are absent unless a `--target`
run appends them.

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
