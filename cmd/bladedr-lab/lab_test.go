package main

import (
	"testing"

	"bladedr/internal/probe"
	"bladedr/internal/rules"
	"bladedr/internal/store"
)

func TestNewFindingsSubtractsBaseline(t *testing.T) {
	base := dedupSet([]probe.Finding{{RuleID: "a", DedupKey: "a"}})
	got := newFindings(base, []probe.Finding{
		{RuleID: "a", DedupKey: "a"},        // pre-existing -> dropped
		{RuleID: "b", DedupKey: "b|/tmp/x"}, // new -> kept
	})
	if len(got) != 1 || got[0].RuleID != "b" {
		t.Fatalf("expected only the new finding, got %+v", got)
	}
}

func TestLabelFindingsJoinsMetaAndDetection(t *testing.T) {
	meta := map[string]rules.Rule{
		"suid-in-writable-path":    {ID: "suid-in-writable-path", Category: "privilege", Severity: "high", Mitre: []string{"T1548.001"}},
		"exec-from-world-writable": {ID: "exec-from-world-writable", Category: "process", Severity: "medium"},
	}
	tch := technique{ID: "suid-writable", Tactic: "privilege", Expect: "suid-in-writable-path"}
	newF := []probe.Finding{
		{RuleID: "suid-in-writable-path", DedupKey: "k1", Evidence: map[string]any{"path": "/var/tmp/.fontcache/upd"}},
		{RuleID: "exec-from-world-writable", DedupKey: "k2"}, // incidental
	}
	exs := labelFindings(tch, "stealthy", newF, meta)
	if len(exs) != 2 {
		t.Fatalf("want 2 examples, got %d", len(exs))
	}
	for _, e := range exs {
		if !e.Detected {
			t.Errorf("expected rule fired, so Detected must be true: %+v", e)
		}
		if e.Source != "lab" || e.Label != "true_positive" || e.Variant != "stealthy" {
			t.Errorf("bad labelling: %+v", e)
		}
	}
	// Metadata is joined from the rule.
	if exs[0].Category != "privilege" || exs[0].Severity != "high" || len(exs[0].Mitre) != 1 {
		t.Errorf("metadata not joined: %+v", exs[0])
	}
	// Projects to a positive-class observation for the risk model.
	if exs[0].observation().Status != store.ObsAcknowledged {
		t.Errorf("lab example should map to an acknowledged (positive) observation")
	}
}

func TestLabelFindingsMissWhenExpectAbsent(t *testing.T) {
	tch := technique{ID: "x", Expect: "wanted-rule"}
	exs := labelFindings(tch, "obvious", []probe.Finding{{RuleID: "other", DedupKey: "k"}}, map[string]rules.Rule{})
	if len(exs) != 1 || exs[0].Detected {
		t.Fatalf("expected a non-detection (Detected=false), got %+v", exs)
	}
}
