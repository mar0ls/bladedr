package api

import (
	"bladedr/internal/store"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyStatusTransitions(t *testing.T) {
	a, tokens := newTestAPI(t)
	ctx := context.Background()
	o, err := a.Store.UpsertObservation(ctx, &store.Observation{RuleID: "legacy", DedupKey: "legacy", Status: store.ObsOpen})
	if err != nil {
		t.Fatal(err)
	}
	url := "/api/v1/observations/" + o.ID
	res := do(a, "PATCH", url, tokens[store.RoleOperator], map[string]any{"status": "resolved"})
	if res.Code != 409 {
		t.Fatalf("unconfirmed resolution: %d", res.Code)
	}
	res = do(a, "POST", "/api/v1/observations/bulk", tokens[store.RoleOperator], map[string]any{"ids": []string{o.ID}, "status": "resolved"})
	if res.Code != 200 || res.Body.String() != "{\"updated\":0}\n" {
		t.Fatalf("bulk: %d %s", res.Code, res.Body)
	}
	got, _ := a.Store.GetObservation(ctx, o.ID)
	if got.Status != store.ObsOpen || got.Verdict != "unknown" {
		t.Fatalf("rejected update mutated finding: %+v", got)
	}
	for _, bulk := range []bool{false, true} {
		if bulk {
			res = do(a, "POST", "/api/v1/observations/bulk", tokens[store.RoleOperator], map[string]any{"ids": []string{o.ID}, "status": "false_positive"})
		} else {
			res = do(a, "PATCH", url, tokens[store.RoleOperator], map[string]any{"status": "false_positive"})
		}
		if res.Code != 200 && res.Code != 204 {
			t.Fatal(res.Code)
		}
		got, _ = a.Store.GetObservation(ctx, o.ID)
		if got.Status != store.ObsFalsePositive || got.Verdict != "false_positive" {
			t.Fatalf("FP pair: %+v", got)
		}
	}
}

func TestRiskStatsCountsLabVerdicts(t *testing.T) {
	a, tokens := newTestAPI(t)
	a.RiskDataset = filepath.Join(t.TempDir(), "dataset.jsonl")
	data := "{\"rule_id\":\"r\",\"category\":\"test\",\"severity\":\"high\",\"label\":\"true_positive\"}\n{\"rule_id\":\"r\",\"category\":\"test\",\"severity\":\"high\",\"label\":\"false_positive\"}\n"
	if err := os.WriteFile(a.RiskDataset, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	res := do(a, "GET", "/api/v1/risk/stats", tokens[store.RoleViewer], nil)
	if res.Code != 200 {
		t.Fatalf("stats: %d %s", res.Code, res.Body)
	}
	var got struct {
		Pos int `json:"lab_positives"`
		Neg int `json:"lab_negatives"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Pos != 1 || got.Neg != 1 {
		t.Fatalf("counts: %+v", got)
	}
}

func TestObservationActions(t *testing.T) {
	a, tokens := newTestAPI(t)
	ctx := context.Background()
	o, err := a.Store.UpsertObservation(ctx, &store.Observation{RuleID: "test", DedupKey: "actions", Status: store.ObsOpen})
	if err != nil {
		t.Fatal(err)
	}
	url := "/api/v1/observations/" + o.ID
	for _, tc := range []struct {
		action, status, verdict string
		code                    int
	}{
		{"resolve", "open", "unknown", 409},
		{"take_ownership", "acknowledged", "unknown", 204},
		{"confirm_finding", "acknowledged", "true_positive", 204},
		{"resolve", "resolved", "true_positive", 204},
		{"reopen", "open", "true_positive", 204},
		{"close_false_positive", "false_positive", "false_positive", 204},
		{"close_inconclusive", "resolved", "unknown", 204},
		{"bad", "resolved", "unknown", 400},
	} {
		res := do(a, http.MethodPatch, url, tokens[store.RoleOperator], map[string]any{"action": tc.action})
		if res.Code != tc.code {
			t.Fatalf("%s: %d: %s", tc.action, res.Code, res.Body.String())
		}
		got, err := a.Store.GetObservation(ctx, o.ID)
		if err != nil || got.Status != tc.status || got.Verdict != tc.verdict {
			t.Fatalf("%s: %+v %v", tc.action, got, err)
		}
	}
	for _, tc := range []struct {
		role string
		body map[string]any
		code int
	}{
		{store.RoleViewer, map[string]any{"action": "close_false_positive"}, 403},
		{store.RoleOperator, map[string]any{"action": "close_false_positive", "status": "open"}, 400},
		{store.RoleOperator, map[string]any{"action": "close_false_positive", "verdict": "unknown"}, 400},
	} {
		res := do(a, http.MethodPatch, url, tokens[tc.role], tc.body)
		if res.Code != tc.code {
			t.Fatal(res.Code)
		}
	}
}
