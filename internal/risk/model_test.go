package risk

import (
	"reflect"
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
	o := obs("systemd-timer-suspicious", "persistence", "high", store.ObsAcknowledged, "T1053.006", "T1053.006")
	feats := map[string]bool{}
	techniqueCount := 0
	for _, f := range Features(o) {
		feats[f] = true
		if f == "tech:T1053.006" {
			techniqueCount++
		}
	}
	for _, want := range []string{"rule:systemd-timer-suspicious", "cat:persistence", "sev:high", "src:agentless_probe", "tech:T1053.006", "tac:T1053"} {
		if !feats[want] {
			t.Errorf("missing feature %q in %v", want, feats)
		}
	}
	if techniqueCount != 1 {
		t.Fatalf("duplicate MITRE values produced %d identical features, want 1", techniqueCount)
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

func TestScoreIgnoresUnknownFeatures(t *testing.T) {
	var train []*store.Observation
	for i := 0; i < 10; i++ {
		train = append(train, obs("real-rule", "persistence", "high", store.ObsAcknowledged))
		train = append(train, obs("noisy-rule", "network", "low", store.ObsFalsePositive))
	}
	model := Train(train)
	base := obs("real-rule", "persistence", "high", store.ObsOpen)
	withUnknown := obs("real-rule", "persistence", "high", store.ObsOpen, "T9999.999")

	baseScore := model.Score(base)
	unknownScore := model.Score(withUnknown)
	if baseScore.Prob != unknownScore.Prob {
		t.Fatalf("unknown features changed probability from %v to %v", baseScore.Prob, unknownScore.Prob)
	}
	for _, contribution := range unknownScore.Top {
		if contribution.Feature == "tech:T9999.999" || contribution.Feature == "tac:T9999" {
			t.Fatalf("unknown feature included in explanation: %+v", contribution)
		}
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
	if st.CVROCAUC != 1 || st.CVBalancedAccuracy != 1 {
		t.Errorf("separable data should have perfect ranking metrics: %+v", st)
	}
	if st.CVBrierScore <= 0 || st.CVBrierScore >= 0.25 {
		t.Errorf("unexpected Brier score for separable data: %+v", st)
	}
}

func TestEvaluateIsDeterministic(t *testing.T) {
	var data []*store.Observation
	for i := 0; i < 20; i++ {
		data = append(data, obs("real-rule", "persistence", "high", store.ObsAcknowledged, "T1543.002"))
		data = append(data, obs("noisy-rule", "network", "medium", store.ObsFalsePositive, "T1040"))
	}
	first := Evaluate(data)
	second := Evaluate(data)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("Evaluate is not deterministic:\nfirst:  %+v\nsecond: %+v", first, second)
	}
}

// Fold assignment used to follow the order rows arrived in, so the reported metrics were
// a property of insertion order. Two stores holding the same observations could disagree,
// and nothing in the output hinted the number was movable at all.
func TestEvaluateDoesNotDependOnInputOrder(t *testing.T) {
	var data []*store.Observation
	for i := 0; i < 20; i++ {
		data = append(data, obs("real-rule", "persistence", "high", store.ObsAcknowledged, "T1543.002"))
		data = append(data, obs("noisy-rule", "network", "medium", store.ObsFalsePositive, "T1040"))
	}
	reversed := make([]*store.Observation, len(data))
	for i := range data {
		reversed[i] = data[len(data)-1-i]
	}
	forward, backward := Evaluate(data), Evaluate(reversed)
	if forward.CVROCAUC != backward.CVROCAUC {
		t.Errorf("ROC AUC depends on input order: %.4f forward vs %.4f reversed",
			forward.CVROCAUC, backward.CVROCAUC)
	}
	if forward.CVRepeats != cvRepeats {
		t.Errorf("CVRepeats = %d, want %d — the report must say how many passes it averages",
			forward.CVRepeats, cvRepeats)
	}
}

// A mean is not a result on its own. On a small, lopsided label set the same model scores
// anywhere from below chance to strong depending only on how the folds fall, and reporting
// the average of that as a single figure invites acting on it. Measured on the poligon
// dataset (157 positives, 10 negatives), ROC AUC ranged 0.48–0.82 across seven seeds.
func TestUnstableRankingIsNotCalledTrustworthy(t *testing.T) {
	var data []*store.Observation
	// Enough labels to clear the size gates, deliberately overlapping so no feature
	// separates the classes cleanly and the fold split decides the outcome.
	for i := 0; i < 30; i++ {
		status := store.ObsAcknowledged
		if i%3 == 0 {
			status = store.ObsFalsePositive
		}
		data = append(data, obs("ambiguous-rule", "persistence", "medium", status, "T1543.002"))
	}
	st := Evaluate(data)
	if st.CVROCAUCStdDev == 0 && st.Trustworthy {
		t.Skip("this data happened to be stable; the guard is exercised by the assertion below")
	}
	if st.CVROCAUCStdDev > 0.10 && st.Trustworthy {
		t.Errorf("ROC AUC swings ±%.2f between resamplings but the model was called trustworthy: %s",
			st.CVROCAUCStdDev, st.Reason)
	}
}

func TestPredictionMetrics(t *testing.T) {
	predictions := []prediction{
		{prob: 0.9, positive: true},
		{prob: 0.8, positive: true},
		{prob: 0.2, positive: false},
		{prob: 0.1, positive: false},
	}
	accuracy, balanced, precision, recall, auc, brier := predictionMetrics(predictions)
	if accuracy != 1 || balanced != 1 || precision != 1 || recall != 1 || auc != 1 {
		t.Fatalf("perfect predictions produced incorrect metrics: accuracy=%v balanced=%v precision=%v recall=%v auc=%v",
			accuracy, balanced, precision, recall, auc)
	}
	if brier <= 0 || brier >= 0.05 {
		t.Fatalf("unexpected Brier score: %v", brier)
	}

	tied := []prediction{{prob: 0.5, positive: true}, {prob: 0.5, positive: false}}
	_, _, _, _, auc, _ = predictionMetrics(tied)
	if auc != 0.5 {
		t.Fatalf("tied positive and negative should have AUC 0.5, got %v", auc)
	}
}

func BenchmarkEvaluate(b *testing.B) {
	data := make([]*store.Observation, 0, 10_000)
	for i := 0; i < 5_000; i++ {
		data = append(data, obs("real-rule", "persistence", "high", store.ObsAcknowledged, "T1543.002"))
		data = append(data, obs("noisy-rule", "network", "medium", store.ObsFalsePositive, "T1040"))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Evaluate(data)
	}
}
