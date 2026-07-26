package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"bladedr/internal/scan"
	"bladedr/internal/store"
)

func TestResponseRequiresAdminApproval(t *testing.T) {
	a, tokens := newTestAPI(t)
	host := &store.Host{Hostname: "web"}
	_ = a.Store.CreateHost(t.Context(), host)
	body := map[string]any{
		"host_id": host.ID, "playbook": scan.PlaybookKillProcess,
		"params": map[string]string{"pid": "42", "expected_exe": "/usr/bin/suspicious"},
	}
	created := do(a, http.MethodPost, "/api/v1/responses", tokens[store.RoleOperator], body)
	if created.Code != http.StatusCreated {
		t.Fatalf("create response = %d: %s", created.Code, created.Body.String())
	}
	var action store.ResponseAction
	_ = json.Unmarshal(created.Body.Bytes(), &action)
	if !action.DryRun || action.Status != store.ResponsePending {
		t.Fatalf("unsafe response defaults: %+v", action)
	}
	denied := do(a, http.MethodPost, "/api/v1/responses/"+action.ID+"/approve", tokens[store.RoleOperator], nil)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("operator approve = %d, want 403", denied.Code)
	}
	approved := do(a, http.MethodPost, "/api/v1/responses/"+action.ID+"/approve", tokens[store.RoleAdmin], nil)
	if approved.Code != http.StatusAccepted {
		t.Fatalf("admin approve = %d: %s", approved.Code, approved.Body.String())
	}
}
