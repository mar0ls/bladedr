package api

import (
	"bladedr/internal/store"
	"context"
	"net/http"
	"testing"
)

func TestVerdictIndependentOfWorkflow(t *testing.T) {
	a, tokens := newTestAPI(t)
	ctx := context.Background()
	o, err := a.Store.UpsertObservation(ctx, &store.Observation{RuleID: "test", DedupKey: "verdict-test", Status: store.ObsOpen})
	if err != nil {
		t.Fatal(err)
	}
	url := "/api/v1/observations/" + o.ID
	res := do(a, http.MethodPatch, url, tokens[store.RoleOperator], map[string]any{"status": "acknowledged"})
	if res.Code != 204 {
		t.Fatalf("ack: %d", res.Code)
	}
	labels, _ := a.productionRiskLabels(ctx)
	if len(labels) != 0 {
		t.Fatal("ack must not train ML")
	}
	res = do(a, http.MethodPatch, url, tokens[store.RoleOperator], map[string]any{"verdict": "true_positive"})
	if res.Code != 204 {
		t.Fatalf("verdict: %d", res.Code)
	}
	labels, _ = a.productionRiskLabels(ctx)
	if len(labels) != 1 {
		t.Fatal("explicit assessment must train ML")
	}
	res = do(a, http.MethodPatch, url, tokens[store.RoleOperator], map[string]any{"status": "resolved"})
	if res.Code != 204 {
		t.Fatal(res.Code)
	}
	got, _ := a.Store.GetObservation(ctx, o.ID)
	if got.Verdict != "true_positive" {
		t.Fatal("resolution erased assessment")
	}
	_, _ = a.Store.UpsertObservation(ctx, &store.Observation{RuleID: "test", DedupKey: "verdict-test", Status: store.ObsOpen})
	got, _ = a.Store.GetObservation(ctx, o.ID)
	if got.Verdict != "true_positive" {
		t.Fatal("scan erased assessment")
	}
	res = do(a, http.MethodPatch, url, tokens[store.RoleOperator], map[string]any{"verdict": "unknown"})
	if res.Code != 204 {
		t.Fatal(res.Code)
	}
	labels, _ = a.productionRiskLabels(ctx)
	if len(labels) != 0 {
		t.Fatal("unknown must not train ML")
	}
	res = do(a, http.MethodPatch, url, tokens[store.RoleViewer], map[string]any{"verdict": "false_positive"})
	if res.Code != 403 {
		t.Fatalf("viewer: %d", res.Code)
	}
	res = do(a, http.MethodPatch, url, tokens[store.RoleOperator], map[string]any{"verdict": "bad"})
	if res.Code != 400 {
		t.Fatal(res.Code)
	}
}
