package main

import (
	"bladedr/internal/probe"
	"bladedr/internal/rules"
	"bladedr/internal/store"
)

// technique is one manifest entry: an id (the dispatcher key), its tactic, and the
// rule the planted artifact is expected to trigger (the coverage assertion).
type technique struct {
	ID     string `yaml:"id"`
	Tactic string `yaml:"tactic"`
	Expect string `yaml:"expect"`
	// Label is the training class for what this technique plants. Empty defaults to
	// "true_positive" (a real compromise artifact). "false_positive" marks a
	// benign-but-flagged scenario — a legitimate config that trips an ambiguous
	// rule — so the model learns that rule's lower precision (the negative class).
	Label string `yaml:"label"`
	// Requires gates where a technique can run. "privileged" needs root + a real
	// host (chattr/mount/binfmt), so it is skipped on the disposable container and
	// only runs against an SSH target.
	Requires string `yaml:"requires"`
}

func (t technique) label() string {
	if t.Label == "false_positive" {
		return "false_positive"
	}
	return "true_positive"
}

type manifest struct {
	Techniques []technique `yaml:"techniques"`
}

// covKey identifies one technique+variant scenario in the coverage map.
type covKey struct{ tech, variant string }

// example is one labelled training record: a finding produced by a planted
// technique, joined with the rule's metadata. Both naming variants emit the same
// structural features (rule/category/severity/mitre); only Evidence (the cosmetic
// names/paths) differs — which is exactly what teaches the model to generalise.
type example struct {
	Technique string         `json:"technique"`
	Variant   string         `json:"variant"`
	Expect    string         `json:"expect_rule"`
	Detected  bool           `json:"detected"` // the expected rule fired for this technique+variant
	RuleID    string         `json:"rule_id"`
	Category  string         `json:"category"`
	Severity  string         `json:"severity"`
	Mitre     []string       `json:"mitre,omitempty"`
	Source    string         `json:"source"` // always "lab"
	Label     string         `json:"label"`  // always "true_positive"
	Evidence  map[string]any `json:"evidence,omitempty"`
}

// observation projects an example onto a store.Observation so the risk model can
// train on it directly: true_positive => acknowledged (positive class),
// false_positive => the negative class.
func (e example) observation() *store.Observation {
	status := store.ObsAcknowledged
	if e.Label == "false_positive" {
		status = store.ObsFalsePositive
	}
	return &store.Observation{
		RuleID:   e.RuleID,
		Category: e.Category,
		Severity: e.Severity,
		Mitre:    e.Mitre,
		Source:   e.Source,
		Status:   status,
		Evidence: e.Evidence,
	}
}

// dedupSet indexes findings by their dedup key (the stable per-finding identity).
func dedupSet(fs []probe.Finding) map[string]bool {
	m := make(map[string]bool, len(fs))
	for _, f := range fs {
		m[f.DedupKey] = true
	}
	return m
}

// newFindings returns the findings absent from the clean baseline — i.e. those the
// just-planted technique introduced.
func newFindings(baseline map[string]bool, fs []probe.Finding) []probe.Finding {
	var out []probe.Finding
	for _, f := range fs {
		if !baseline[f.DedupKey] {
			out = append(out, f)
		}
	}
	return out
}

// labelFindings turns a technique's new findings into labelled examples, joining
// each finding's rule id to its server-side metadata. Detected reflects whether the
// expected rule fired (a technique-level fact, denormalised onto each row).
func labelFindings(t technique, variant string, newF []probe.Finding, meta map[string]rules.Rule) []example {
	detected := false
	for _, f := range newF {
		if f.RuleID == t.Expect {
			detected = true
			break
		}
	}
	out := make([]example, 0, len(newF))
	for _, f := range newF {
		r := meta[f.RuleID]
		out = append(out, example{
			Technique: t.ID, Variant: variant, Expect: t.Expect, Detected: detected,
			RuleID: f.RuleID, Category: r.Category, Severity: r.Severity, Mitre: r.Mitre,
			Source: "lab", Label: t.label(), Evidence: f.Evidence,
		})
	}
	return out
}

// buildBundle compiles the enabled builtin rules into a probe bundle and returns it
// alongside an id->rule metadata map for labelling.
func buildBundle() (probe.RuleBundle, map[string]rules.Rule, error) {
	rs, err := rules.Builtin()
	if err != nil {
		return probe.RuleBundle{}, nil, err
	}
	meta := make(map[string]rules.Rule, len(rs))
	var br []probe.BundleRule
	for _, r := range rs {
		meta[r.ID] = r
		if r.IsEnabled() {
			br = append(br, r.ToBundleRule())
		}
	}
	return probe.RuleBundle{Schema: probe.SchemaRuleBundle, BundleVersion: "lab", Rules: br}, meta, nil
}
