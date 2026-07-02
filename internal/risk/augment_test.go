package risk

import (
	"testing"

	"bladedr/internal/store"
)

func TestFeaturesStructuralClasses(t *testing.T) {
	o := &store.Observation{
		RuleID: "systemd-suspicious-execstart", Category: "persistence", Severity: "high",
		Source: store.SourceEBPFSensor, Mitre: []string{"T1543.002"},
		Evidence: map[string]any{"exec_start": "/tmp/.x/agent --daemon", "uid": float64(0), "parent": "/usr/sbin/apache2"},
	}
	feats := map[string]bool{}
	for _, f := range Features(o) {
		feats[f] = true
	}
	for _, want := range []string{"rule:systemd-suspicious-execstart", "path:tmp", "uid:root", "parent:web", "tac:T1543"} {
		if !feats[want] {
			t.Errorf("missing feature %q in %v", want, feats)
		}
	}
	// path:home vs path:tmp must differ — the whole point (separable within a rule).
	home := &store.Observation{RuleID: "systemd-suspicious-execstart", Evidence: map[string]any{"exec_start": "/home/ci/run.sh"}}
	hf := map[string]bool{}
	for _, f := range Features(home) {
		hf[f] = true
	}
	if hf["path:tmp"] || !hf["path:home"] {
		t.Errorf("home exec should be path:home, got %v", hf)
	}
}

func TestAugmentBalancesMinority(t *testing.T) {
	var data []*store.Observation
	for i := 0; i < 20; i++ {
		data = append(data, obs("r-pos", "c", "high", store.ObsAcknowledged))
	}
	for i := 0; i < 4; i++ {
		data = append(data, obs("r-neg", "c", "medium", store.ObsFalsePositive))
	}
	aug := Augment(data, 42)
	pos, neg := 0, 0
	for _, o := range aug {
		switch LabelOf(o.Status) {
		case Positive:
			pos++
		case Negative:
			neg++
		}
	}
	if pos != 20 || neg != 20 {
		t.Errorf("expected balanced 20/20, got pos=%d neg=%d", pos, neg)
	}
	// Deterministic for a given seed.
	if len(Augment(data, 42)) != len(aug) {
		t.Error("Augment should be deterministic for a fixed seed")
	}
	// No-op when a class is empty (nothing to balance against).
	onlyPos := data[:20]
	if len(Augment(onlyPos, 1)) != 20 {
		t.Error("Augment with one class should return the input unchanged")
	}
}
