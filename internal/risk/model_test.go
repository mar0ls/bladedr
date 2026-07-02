package risk

import (
	"testing"

	"bladedr/internal/store"
)

func obs(rule, cat, sev, status string, mitre ...string) *store.Observation {
	return &store.Observation{RuleID: rule, Category: cat, Severity: sev, Source: store.SourceAgentlessProbe, Mitre: mitre, Status: status, Score: 50}
}

func TestLabelOf(t *testing.T) {
	cases := map[string]Label{
		store.ObsFalsePositive: Negative,
		store.ObsAcknowledged:  Positive,
		store.ObsResolved:      Unlabeled, // ambiguous (remediated-real vs benign-reviewed) -> excluded
		store.ObsOpen:          Unlabeled,
		"":                     Unlabeled,
	}
	for status, want := range cases {
		if got := LabelOf(status); got != want {
			t.Errorf("LabelOf(%q)=%v want %v", status, got, want)
		}
	}
}

func TestFeaturesStructuralOnly(t *testing.T) {
	o := obs("systemd-timer-suspicious", "persistence", "high", store.ObsAcknowledged, "T1053.006")
	feats := map[string]bool{}
	for _, f := range Features(o) {
		feats[f] = true
	}
	for _, want := range []string{"rule:systemd-timer-suspicious", "cat:persistence", "sev:high", "src:agentless_probe", "tech:T1053.006", "tac:T1053"} {
		if !feats[want] {
			t.Errorf("missing feature %q in %v", want, feats)
		}
	}
}

func TestUntrainedFallsBackToStaticScore(t *testing.T) {
	m := Train(nil) // no labelled data
	if m.Trained() {
		t.Fatal("model with no data should report Trained()=false")
	}
	r := m.Score(&store.Observation{Score: 73})
	if r.Trained || r.Priority != 73 {
		t.Errorf("untrained Score = %+v, want Priority=73 Trained=false", r)
	}
}

func TestScoreSeparatesRealFromFalsePositive(t *testing.T) {
	// A rule consistently triaged real, and one consistently a false positive.
	var train []*store.Observation
	for i := 0; i < 10; i++ {
		train = append(train, obs("hidden-kernel-module", "kernel", "critical", store.ObsAcknowledged, "T1014"))
		train = append(train, obs("kernel-promiscuous-mode", "network", "medium", store.ObsFalsePositive, "T1040"))
	}
	m := Train(train)
	if !m.Trained() {
		t.Fatal("model should be trained")
	}
	real := m.Score(obs("hidden-kernel-module", "kernel", "critical", store.ObsOpen, "T1014"))
	fp := m.Score(obs("kernel-promiscuous-mode", "network", "medium", store.ObsOpen, "T1040"))
	if real.Priority <= fp.Priority {
		t.Errorf("real finding (%d) should outrank the noisy one (%d)", real.Priority, fp.Priority)
	}
	if real.Priority < 60 {
		t.Errorf("consistently-real rule should score high, got %d", real.Priority)
	}
	if fp.Priority > 40 {
		t.Errorf("consistently-FP rule should score low, got %d", fp.Priority)
	}
	// Top contribution of the real finding should be its rule, pulling positive.
	if len(real.Top) == 0 || real.Top[0].Weight <= 0 {
		t.Errorf("expected a positive top contribution, got %+v", real.Top)
	}
}

func TestEvaluateReportsInsufficientData(t *testing.T) {
	st := Evaluate(nil)
	if st.Trustworthy || st.Labeled != 0 {
		t.Errorf("empty set should be untrustworthy, got %+v", st)
	}

	// A handful of one-sided labels: not trustworthy, and the reason should call it out.
	var few []*store.Observation
	for i := 0; i < 5; i++ {
		few = append(few, obs("r", "c", "low", store.ObsFalsePositive))
	}
	st = Evaluate(few)
	if st.Trustworthy {
		t.Errorf("tiny one-sided set must not be trustworthy: %+v", st)
	}
	if st.Negatives != 5 || st.Positives != 0 {
		t.Errorf("counts wrong: %+v", st)
	}
}

func TestEvaluateTrustworthyOnSeparableData(t *testing.T) {
	var data []*store.Observation
	for i := 0; i < 20; i++ {
		data = append(data, obs("real-rule", "persistence", "high", store.ObsAcknowledged, "T1543.002"))
		data = append(data, obs("noisy-rule", "network", "medium", store.ObsFalsePositive, "T1040"))
	}
	st := Evaluate(data)
	if !st.Trustworthy {
		t.Errorf("clean separable balanced data should be trustworthy: %+v", st)
	}
	if st.CVAccuracy <= st.BaseRate {
		t.Errorf("CV accuracy (%.2f) should beat base rate (%.2f)", st.CVAccuracy, st.BaseRate)
	}
}
