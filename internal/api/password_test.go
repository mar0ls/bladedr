package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"bladedr/internal/auth"
	"bladedr/internal/store"
)

// flagForcedChange marks a role's account as needing a password change and returns its
// user record.
func flagForcedChange(t *testing.T, a *API, role string) *store.User {
	t.Helper()
	ctx := context.Background()
	u, err := a.Store.GetUserByName(ctx, role+"-user")
	if err != nil {
		t.Fatal(err)
	}
	u.MustChangePassword = true
	if err := a.Store.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	return u
}

// The point of the flag is that a password someone else has seen buys nothing but the
// chance to replace it. If any ordinary route still answers, it bought more than that.
func TestForcedChangeBlocksEverythingButThePasswordChange(t *testing.T) {
	a, tokens := newTestAPI(t)
	flagForcedChange(t, a, store.RoleAdmin)
	tok := tokens[store.RoleAdmin]

	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/hosts"},
		{"POST", "/api/v1/hosts"},
		{"GET", "/api/v1/observations"},
		{"GET", "/api/v1/users"},
		{"GET", "/api/v1/audit"},
		{"GET", "/api/v1/rules"},
		{"POST", "/api/v1/responses"},
	} {
		w := do(a, c.method, c.path, tok, json.RawMessage("{}"))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s = %d, want 403 while a password change is pending", c.method, c.path, w.Code)
		}
		if !strings.Contains(w.Body.String(), "password change required") {
			t.Errorf("%s %s: body does not say why: %s", c.method, c.path, w.Body.String())
		}
	}
}

// The escape hatches have to keep working, or the account is bricked rather than fenced.
func TestForcedChangeLeavesAWayOut(t *testing.T) {
	a, tokens := newTestAPI(t)
	flagForcedChange(t, a, store.RoleAdmin)
	tok := tokens[store.RoleAdmin]

	if w := do(a, "GET", "/api/v1/me", tok, nil); w.Code != http.StatusOK {
		t.Errorf("GET /api/v1/me = %d, want 200 so a client can see why it is blocked", w.Code)
	}
	if w := do(a, "GET", "/ui/password", tok, nil); w.Code != http.StatusOK {
		t.Errorf("GET /ui/password = %d, want the form to render", w.Code)
	}
	if w := do(a, "POST", "/api/v1/logout", tok, nil); w.Code >= 400 {
		t.Errorf("POST /api/v1/logout = %d, want the account able to sign out", w.Code)
	}
}

// UI routes redirect instead of returning JSON, so a browser lands on the form rather
// than a raw error page.
func TestForcedChangeRedirectsTheConsole(t *testing.T) {
	a, tokens := newTestAPI(t)
	flagForcedChange(t, a, store.RoleAdmin)
	w := do(a, "GET", "/ui/hosts", tokens[store.RoleAdmin], nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("GET /ui/hosts = %d, want 303", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/ui/password" {
		t.Errorf("redirected to %q, want /ui/password", loc)
	}
}

func TestChangingThePasswordClearsTheFlagAndRestoresAccess(t *testing.T) {
	a, tokens := newTestAPI(t)
	u := flagForcedChange(t, a, store.RoleAdmin)
	tok := tokens[store.RoleAdmin]

	w := do(a, "POST", "/api/v1/me/password", tok, json.RawMessage(`{"current_password":"password123","new_password":"a-much-better-secret"}`))
	if w.Code != http.StatusNoContent {
		t.Fatalf("change password = %d (%s)", w.Code, w.Body.String())
	}
	if w := do(a, "GET", "/api/v1/hosts", tok, nil); w.Code != http.StatusOK {
		t.Errorf("GET /api/v1/hosts = %d after the change, want 200", w.Code)
	}
	got, err := a.Store.GetUser(context.Background(), u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.MustChangePassword {
		t.Error("flag still set after a successful change")
	}
	if !auth.CheckPassword(got.PasswordHash, "a-much-better-secret") {
		t.Error("new password does not verify")
	}
	if auth.CheckPassword(got.PasswordHash, "password123") {
		t.Error("old password still verifies")
	}
}

func TestChangePasswordRejectsBadInput(t *testing.T) {
	a, tokens := newTestAPI(t)
	tok := tokens[store.RoleAdmin]
	for _, c := range []struct {
		name, body string
		want       int
	}{
		{"wrong current password", `{"current_password":"nope","new_password":"a-much-better-secret"}`, http.StatusUnauthorized},
		{"too short", `{"current_password":"password123","new_password":"short"}`, http.StatusBadRequest},
		{"unchanged", `{"current_password":"password123","new_password":"password123"}`, http.StatusBadRequest},
	} {
		t.Run(c.name, func(t *testing.T) {
			if w := do(a, "POST", "/api/v1/me/password", tok, json.RawMessage(c.body)); w.Code != c.want {
				t.Errorf("= %d, want %d (%s)", w.Code, c.want, w.Body.String())
			}
		})
	}
}

// A viewer is read-only everywhere else, which would make a forced change inescapable
// for exactly the role least able to ask for help. Their own account is the one thing
// they must be able to write to.
func TestEveryRoleCanChangeItsOwnPassword(t *testing.T) {
	for _, role := range []string{store.RoleAdmin, store.RoleOperator, store.RoleViewer} {
		t.Run(role, func(t *testing.T) {
			a, tokens := newTestAPI(t)
			flagForcedChange(t, a, role)
			w := do(a, "POST", "/api/v1/me/password", tokens[role], json.RawMessage(`{"current_password":"password123","new_password":"a-much-better-secret"}`))
			if w.Code != http.StatusNoContent {
				t.Fatalf("%s could not change its own password: %d (%s)", role, w.Code, w.Body.String())
			}
		})
	}
}

// An admin resetting someone's password knows it, so the account must not keep it.
func TestAdminResetForcesTheUserToChangeIt(t *testing.T) {
	a, tokens := newTestAPI(t)
	ctx := context.Background()
	target, err := a.Store.GetUserByName(ctx, store.RoleViewer+"-user")
	if err != nil {
		t.Fatal(err)
	}
	w := do(a, "PATCH", "/api/v1/users/"+target.ID, tokens[store.RoleAdmin], json.RawMessage(`{"password":"reset-by-an-admin"}`))
	if w.Code >= 400 {
		t.Fatalf("admin reset = %d (%s)", w.Code, w.Body.String())
	}
	got, err := a.Store.GetUser(ctx, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.MustChangePassword {
		t.Error("an admin-set password was left in place permanently")
	}
}

// Accounts created by an admin start with a password that admin chose.
func TestCreatedUsersMustChangeTheirPassword(t *testing.T) {
	a, tokens := newTestAPI(t)
	w := do(a, "POST", "/api/v1/users", tokens[store.RoleAdmin], json.RawMessage(`{"username":"newcomer","password":"chosen-by-admin","role":"operator"}`))
	if w.Code >= 400 {
		t.Fatalf("create user = %d (%s)", w.Code, w.Body.String())
	}
	got, err := a.Store.GetUserByName(context.Background(), "newcomer")
	if err != nil {
		t.Fatal(err)
	}
	if !got.MustChangePassword {
		t.Error("a new account kept the password its creator chose")
	}
}

// Sensor ingest authenticates with its own host-bound token and has nothing to do with
// operator passwords; a pending change must not take the fleet's telemetry down with it.
func TestForcedChangeDoesNotBlockSensorIngest(t *testing.T) {
	a, _ := newTestAPI(t)
	flagForcedChange(t, a, store.RoleAdmin)
	ctx := context.Background()
	host := &store.Host{Hostname: "sensor-host"}
	if err := a.Store.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}
	tok := auth.NewToken()
	expiry := time.Now().Add(time.Hour)
	if err := a.Store.CreateSensorToken(ctx, &store.SensorToken{
		HostID: host.ID, TokenHash: auth.TokenDigest(tok), ExpiresAt: &expiry,
	}); err != nil {
		t.Fatal(err)
	}
	w := do(a, "POST", "/api/v1/hosts/"+host.ID+"/events", tok, json.RawMessage(`{"events":[]}`))
	if w.Code == http.StatusForbidden && strings.Contains(w.Body.String(), "password change required") {
		t.Error("a pending operator password change blocked sensor ingest")
	}
}
