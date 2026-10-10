package risk

import (
	"testing"

	"bladedr/internal/store"
)

// TestAblationRemovesTheRuleSignal builds the pathological case the ablation exists to
// detect: a dataset where rule identity alone decides the label and every other feature
// is constant. The full model must rank it perfectly, and withholding "rule:" must leave
// nothing to rank on. If ablation stopped actually withholding the feature, the second
// figure would stay high and the diagnostic the lab prints would quietly become a lie.
func TestAblationRemovesTheRuleSignal(t *testing.T) {
	var data []*store.Observation
	for i := 0; i < minPerClass; i++ {
		data = append(data, obs("always-real", "persistence", "high", store.ObsAcknowledged, "T1543.002"))
		data = append(data, obs("always-noise", "persistence", "high", store.ObsFalsePositive, "T1543.002"))
	}

	full := Evaluate(data)
	if full.CVROCAUC != 1 {
		t.Fatalf("rule identity alone separates this set; expected ROC AUC 1, got %.3f", full.CVROCAUC)
	}

	ablated := EvaluateWithout(data, "rule:")
	// Every remaining feature is identical across both classes, so the model can only
	// return the class prior and ranking is a coin flip.
	if ablated.CVROCAUC != 0.5 {
		t.Errorf("with rule identity withheld nothing separates the classes; expected ROC AUC 0.5, got %.3f", ablated.CVROCAUC)
	}
	if ablated.Trustworthy {
		t.Errorf("a set with no separating feature must not be called trustworthy: %+v", ablated)
	}
}

// TestAblationKeepsTheOtherFeatures guards the other half: the prefix filter must strip
// only what it was asked to. Here the separating signal is where the artifact lives, not
// the rule, so withholding "rule:" must not disturb the ranking at all.
func TestAblationKeepsTheOtherFeatures(t *testing.T) {
	var data []*store.Observation
	for i := 0; i < minPerClass; i++ {
		real := obs("shared-rule", "persistence", "high", store.ObsAcknowledged, "T1543.002")
		real.Evidence = map[string]any{"path": "/tmp/payload"}
		noise := obs("shared-rule", "persistence", "high", store.ObsFalsePositive, "T1543.002")
		noise.Evidence = map[string]any{"path": "/home/ci/run.sh"}
		data = append(data, real, noise)
	}

	full := Evaluate(data)
	ablated := EvaluateWithout(data, "rule:")
	if full.CVROCAUC != 1 || ablated.CVROCAUC != 1 {
		t.Errorf("the path class carries the signal; withholding rule identity must not change it: full %.3f, ablated %.3f",
			full.CVROCAUC, ablated.CVROCAUC)
	}
}
