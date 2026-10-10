# Risk-model validation for 1.0

The task is to prioritise findings that deterministic rules already raised. A
label is an explicit analyst verdict: `true_positive` or `false_positive`.
The independent `verdict=unknown` is excluded. Workflow statuses (`open`,
`acknowledged`, `resolved`, `false_positive`) never supervise training. In particular,
acknowledging an alert merely to track investigation must not be confused with
confirming its ground truth. A confirmed unsafe configuration can be a positive
finding even when the owner installed it; the model is not a classifier of attacker
intent. Authorised, ordinary operation falsely presented as suspicious is negative.

## Workflow and migration

The console exposes combined disposition actions and ML-only controls under
`Change assessment`. `Close as FP` writes a negative label; `Confirm finding`
writes a positive label. `Close inconclusive` clears the label to unknown.
Legacy status requests map to the same actions: false_positive writes a negative
verdict, resolved requires a positive verdict, open/acknowledged preserve verdicts.
Repeated scans preserve both.
Explicit verdict and disposition changes are audited and
require operator/admin permissions. Resolving a confirmed finding preserves its
positive training label. Lab records carry their own ground-truth verdict.

Migration 0010 initializes historical verdicts to unknown; it deliberately does
not infer ground truth from old statuses. Before upgrading, back up the database
and record the IDs and verdicts of independently reviewed findings. Restore those
assessments by ID after migration; check affected-row counts and record the change
in the audit log. Do not run a generic status-to-verdict backfill.

## Current evaluation

The loader preserves the technique or scene identifier in the in-memory ScanID
of imported lab observations. This field is validation metadata, never a feature.
Every variant and incidental finding from that technique stays in one fold.
Fleet observations are grouped by HostID, holding out the entire host. Records
without group identifiers fall back to row splits; those legacy records do not
establish independence and should be replaced with identified records.

Repeated seeded folds are exploratory cross-validation. They do not become an
independent test simply because features were ablated or the seed was changed.
The historical figures in poligon/README.md used row splits and earlier feature
versions; they must not be compared directly with the grouped results.

Trust requires at least 30 confirmed fleet labels per class, in addition to the
existing size and quality gates. These are minimum operational floors, not a
sample-size or statistical-power guarantee. The fleet-only evaluation must also
pass: lab examples cannot supply missing fleet negatives or positives. Insufficient
independent groups or a training fold missing a class makes evaluation unavailable.
The API reports fleet counts, fleet-only ROC AUC and its validation reason.

## Independent acceptance test

All file-loaded examples are lab data; source fields cannot promote external examples
into fleet validation.

Before gathering new acceptance data, freeze the feature extractor, model settings,
label definitions and decision thresholds. Reserve newly collected scenarios and
hosts that have never informed feature design. Keep related incident artifacts,
host clones and repeated scans together. Document collection dates and provenance.

Compare against the rule's static score and a per-rule label-frequency baseline
fitted only on training data. Report ranking, balanced accuracy, precision/recall,
calibration and uncertainty; report results separately for lab and fleet data.
The tied-rule count describes scoring capacity on a fitted model, not held-out
accuracy. A lower tie count alone cannot establish better predictions.

Do not describe confirmed configuration exposures as intrusions, or label safe
operation positive simply to balance the data. If confirmed positives are scarce,
keep the trust claim unavailable
while collecting legitimate negative feedback and separately labelled emulations.

## Triage evidence

- Deleted system executables: check package upgrade history, file ownership and
  process start time before confirming an upgrade-related false positive.
- BPF baseline drift: establish loader/program provenance and expected systemd,
  container or observability activity; a program type or hash alone is insufficient.
- SSH key rarity or change: confirm fingerprints against the owner's approved keys.
- Broad sudo grants: confirm intended administration and record the security
  exposure even when the configuration is authorised.
- CI runner service: confirm that the named runner, executable and installation
  belong to the owner before recording a legitimate-service negative.

Changing an analyst verdict supplies feedback when the running server next computes
risk scores. Code changes require rebuilding and restarting that server separately.
