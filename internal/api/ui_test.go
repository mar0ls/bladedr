package api

import (
	"context"
	"net/http"
	"testing"

	"bladedr/internal/rules"
	"bladedr/internal/store"
)

func TestUIPagesRender(t *testing.T) {
	a, tok := newTestAPI(t)
	a.ActiveRules = func(context.Context) ([]rules.Rule, error) { return nil, nil }
	admin := tok[store.RoleAdmin]

	// Seed a little data so the pages exercise their row-rendering paths.
	ctx := context.Background()
	_ = a.Store.CreateHost(ctx, &store.Host{Hostname: "web-01", PrimaryIP: "10.0.0.5"})
	_, _ = a.Store.UpsertObservation(ctx, &store.Observation{HostID: "h1", RuleID: "r", DedupKey: "k", Severity: "high", Source: "probe", Title: "finding"})

	for _, p := range []string{
		"/ui/dashboard", "/ui/observations", "/ui/hosts", "/ui/schedules",
		"/ui/rules", "/ui/policies", "/ui/users", "/ui/audit",
	} {
		if w := do(a, "GET", p, admin, nil); w.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", p, w.Code)
		}
	}
}

func TestUIRootRedirectsToDashboard(t *testing.T) {
	a, tok := newTestAPI(t)
	w := do(a, "GET", "/ui", tok[store.RoleAdmin], nil)
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Fatalf("GET /ui = %d, want a redirect", w.Code)
	}
}

func TestUILoginPageIsPublic(t *testing.T) {
	a, _ := newTestAPI(t)
	if w := do(a, "GET", "/ui/login", "", nil); w.Code != http.StatusOK {
		t.Fatalf("GET /ui/login = %d, want 200", w.Code)
	}
}

func TestUIAdminPagesRejectViewer(t *testing.T) {
	a, tok := newTestAPI(t)
	for _, p := range []string{"/ui/users", "/ui/audit"} {
		if w := do(a, "GET", p, tok[store.RoleViewer], nil); w.Code == http.StatusOK {
			t.Errorf("viewer GET %s = 200, want denied", p)
		}
	}
}

func TestUIEditHostForm(t *testing.T) {
	a, tok := newTestAPI(t)
	h := &store.Host{Hostname: "edit-me", PrimaryIP: "10.0.0.7"}
	if err := a.Store.CreateHost(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if w := do(a, "GET", "/ui/hosts/"+h.ID+"/edit", tok[store.RoleAdmin], nil); w.Code != http.StatusOK {
		t.Fatalf("GET edit-host form = %d, want 200", w.Code)
	}
}
