package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"bladedr/internal/auth"
	"bladedr/internal/store"
)

// secondAdmin adds another admin account so the two-person control path has an
// actor distinct from the one seeded by newTestAPI.
func secondAdmin(t *testing.T, a *API, username string) string {
	t.Helper()
	ctx := context.Background()
	hash, err := auth.HashPassword("password123")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	u := &store.User{Username: username, PasswordHash: hash, Role: store.RoleAdmin}
	if err := a.Store.CreateUser(ctx, u); err != nil {
		t.Fatalf("create %s: %v", username, err)
	}
	tok := auth.NewToken()
	if err := a.Store.CreateSession(ctx, &store.Session{
		TokenHash: auth.TokenDigest(tok), UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("session %s: %v", username, err)
	}
	return tok
}

func newResponseHost(t *testing.T, a *API) string {
	t.Helper()
	h := &store.Host{Hostname: "response-host", PrimaryIP: "10.0.0.7", SSHPort: 22,
		Mode: store.ModeScanOnly, Status: store.StatusPending}
	if err := a.Store.CreateHost(context.Background(), h); err != nil {
		t.Fatalf("create host: %v", err)
	}
	return h.ID
}

func createResponseAction(t *testing.T, a *API, token, hostID string) string {
	t.Helper()
	w := do(a, http.MethodPost, "/api/v1/responses", token, map[string]any{
		"host_id":  hostID,
		"playbook": "kill_process",
		"params":   map[string]string{"pid": "4242", "expected_exe": "/usr/bin/evil"},
		"dry_run":  true,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create response = %d: %s", w.Code, w.Body.String())
	}
	var action store.ResponseAction
	if err := json.Unmarshal(w.Body.Bytes(), &action); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return action.ID
}

func TestApproveOwnResponseActionIsRejected(t *testing.T) {
	a, tokens := newTestAPI(t)
	hostID := newResponseHost(t, a)
	id := createResponseAction(t, a, tokens[store.RoleAdmin], hostID)

	w := do(a, http.MethodPost, "/api/v1/responses/"+id+"/approve", tokens[store.RoleAdmin], nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("self-approval = %d, want 409: %s", w.Code, w.Body.String())
	}

	got, err := a.Store.GetResponseAction(context.Background(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != store.ResponsePending {
		t.Errorf("status = %q, want %q", got.Status, store.ResponsePending)
	}
}

// A blocked self-approval is a security-relevant event: it is the signature of both
// an operator mistake and a single compromised admin account attempting containment.
func TestBlockedSelfApprovalIsAudited(t *testing.T) {
	a, tokens := newTestAPI(t)
	hostID := newResponseHost(t, a)
	id := createResponseAction(t, a, tokens[store.RoleAdmin], hostID)

	do(a, http.MethodPost, "/api/v1/responses/"+id+"/approve", tokens[store.RoleAdmin], nil)

	events, err := a.Store.ListAudit(context.Background(), 50)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	for _, e := range events {
		if e.Action == "response.approve" && e.Result == "denied" && e.Target == id {
			return
		}
	}
	t.Fatalf("no denied response.approve audit event for %s: %+v", id, events)
}

func TestSecondAdminCanApproveResponseAction(t *testing.T) {
	a, tokens := newTestAPI(t)
	hostID := newResponseHost(t, a)
	id := createResponseAction(t, a, tokens[store.RoleAdmin], hostID)
	other := secondAdmin(t, a, "second-admin")

	w := do(a, http.MethodPost, "/api/v1/responses/"+id+"/approve", other, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("approve by a second admin = %d, want 202: %s", w.Code, w.Body.String())
	}

	got, err := a.Store.GetResponseAction(context.Background(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != store.ResponseApproved || got.ApprovedBy != "second-admin" {
		t.Fatalf("status=%q approved_by=%q", got.Status, got.ApprovedBy)
	}
}

func TestRejectResponseActionIsTerminal(t *testing.T) {
	a, tokens := newTestAPI(t)
	hostID := newResponseHost(t, a)
	id := createResponseAction(t, a, tokens[store.RoleAdmin], hostID)

	w := do(a, http.MethodPost, "/api/v1/responses/"+id+"/reject", tokens[store.RoleAdmin],
		map[string]string{"reason": "wrong host"})
	if w.Code != http.StatusOK {
		t.Fatalf("reject = %d, want 200: %s", w.Code, w.Body.String())
	}

	got, err := a.Store.GetResponseAction(context.Background(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != store.ResponseRejected || got.RejectReason != "wrong host" {
		t.Fatalf("status=%q reason=%q", got.Status, got.RejectReason)
	}

	other := secondAdmin(t, a, "third-admin")
	if w := do(a, http.MethodPost, "/api/v1/responses/"+id+"/approve", other, nil); w.Code == http.StatusAccepted {
		t.Error("a rejected action was approved afterwards")
	}
}

// Deciding a containment action is admin-only in both directions.
func TestResponseDecisionsRequireAdmin(t *testing.T) {
	a, tokens := newTestAPI(t)
	hostID := newResponseHost(t, a)
	id := createResponseAction(t, a, tokens[store.RoleAdmin], hostID)

	for _, role := range []string{store.RoleOperator, store.RoleViewer} {
		for _, verb := range []string{"approve", "reject"} {
			w := do(a, http.MethodPost, "/api/v1/responses/"+id+"/"+verb, tokens[role], nil)
			if w.Code != http.StatusForbidden {
				t.Errorf("%s as %s = %d, want 403", verb, role, w.Code)
			}
		}
	}
}
