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

// scene is a set of techniques planted together and scanned once, so their findings
// share a host the way they would in production. The per-technique loop deliberately
// scans a host carrying exactly one plant; that answers "does the rule fire" and nothing
// about what else was true at the time. A scene is how the range produces a row that has
// siblings — and therefore the only way to find out whether an intrusion tripping four
// rules is distinguishable from a CI box tripping four.
type scene struct {
	ID         string   `yaml:"id"`
	Label      string   `yaml:"label"`
	Techniques []string `yaml:"techniques"`
}

func (s scene) label() string {
	if s.Label == "false_positive" {
		return "false_positive"
	}
	return "true_positive"
}

type manifest struct {
	Techniques []technique `yaml:"techniques"`
	Scenes     []scene     `yaml:"scenes"`
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
	Label     string         `json:"label"`  // "true_positive" or "false_positive"
	Evidence  map[string]any `json:"evidence,omitempty"`
	// Scene and SceneFindings are set only for rows produced by a scene: the scene's id
	// and how many findings that single scan produced in total. Together they are the
	// co-occurrence context a one-plant row cannot have.
	Scene         string `json:"scene,omitempty"`
	SceneFindings int    `json:"scene_findings,omitempty"`
}

// observation projects an example onto a store.Observation so the risk model can
// train on its explicit ground-truth verdict independently of workflow status.
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
		Verdict:  e.Label,
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

// sceneFindingStats summarises how many findings each class of scene produced. It is the
// measurement scenes exist for: if an intrusion and a busy-but-legitimate host both trip
// four rules, then finding density carries no signal and no feature should be built on
// it. Reporting it every run is the cheapest way to keep that honest.
func sceneFindingStats(rows []example) (attackMean, benignMean float64, attackScenes, benignScenes int) {
	type key struct{ scene, variant string }
	size := map[key]int{}
	label := map[key]string{}
	for _, e := range rows {
		k := key{e.Scene, e.Variant}
		size[k] = e.SceneFindings
		label[k] = e.Label
	}
	var aSum, bSum int
	for k, n := range size {
		if label[k] == "false_positive" {
			benignScenes++
			bSum += n
			continue
		}
		attackScenes++
		aSum += n
	}
	if attackScenes > 0 {
		attackMean = float64(aSum) / float64(attackScenes)
	}
	if benignScenes > 0 {
		benignMean = float64(bSum) / float64(benignScenes)
	}
	return attackMean, benignMean, attackScenes, benignScenes
}

// distinctRules counts how many different rules a set of findings covers.
func distinctRules(fs []probe.Finding) int {
	seen := map[string]bool{}
	for _, f := range fs {
		seen[f.RuleID] = true
	}
	return len(seen)
}
