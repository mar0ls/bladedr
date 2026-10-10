package api

import (
	"context"
	"net/http"
	"testing"

	"bladedr/internal/store"
)

// A verdict is a training label for the risk model and a disposition closes a finding, so
// both must be operator actions: a read-only account that could change them could quietly
// poison what the model learns or hide a real finding.
func TestViewerCannotChangeVerdictOrCloseFindings(t *testing.T) {
	a, tokens := newTestAPI(t)
	ctx := context.Background()
	h := &store.Host{Hostname: "h"}
	if err := a.Store.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	o, err := a.Store.UpsertObservation(ctx, &store.Observation{
		HostID: h.ID, Source: store.SourceAgentlessProbe,
		RuleID: "r", Category: "c", Severity: "low", DedupKey: "k",
	})
	if err != nil {
		t.Fatal(err)
	}
	viewer := tokens[store.RoleViewer]
	for _, tc := range []struct {
		name, path string
		body       any
	}{
		{"verdict", "/api/v1/observations/" + o.ID, map[string]string{"verdict": "false_positive"}},
		{"disposition", "/api/v1/observations/" + o.ID, map[string]string{"action": "close_false_positive"}},
		{"legacy status", "/api/v1/observations/" + o.ID, map[string]string{"status": "false_positive"}},
	} {
		if w := do(a, "PATCH", tc.path, viewer, tc.body); w.Code != http.StatusForbidden {
			t.Errorf("viewer %s = %d, want 403", tc.name, w.Code)
		}
	}
	if w := do(a, "POST", "/api/v1/observations/bulk", viewer, map[string]any{"ids": []string{o.ID}, "action": "close_false_positive"}); w.Code != http.StatusForbidden {
		t.Errorf("viewer bulk = %d, want 403", w.Code)
	}
	got, _ := a.Store.GetObservation(ctx, o.ID)
	if got.Status != store.ObsOpen || got.Verdict != "unknown" {
		t.Fatalf("a refused request must change nothing: %s/%s", got.Status, got.Verdict)
	}
	// The operator can, and it is recorded.
	if w := do(a, "PATCH", "/api/v1/observations/"+o.ID, tokens[store.RoleOperator], map[string]string{"verdict": "true_positive"}); w.Code != http.StatusNoContent {
		t.Fatalf("operator verdict = %d, want 204", w.Code)
	}
	if got, _ := a.Store.GetObservation(ctx, o.ID); got.Verdict != "true_positive" {
		t.Fatalf("operator's verdict not applied: %s", got.Verdict)
	}
}
