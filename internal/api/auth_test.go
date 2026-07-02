package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bladedr/internal/auth"
	"bladedr/internal/store"
)

// newTestAPI builds an API backed by an in-memory store, seeded with one user per
// role, and returns the API plus a bearer token for each role.
func newTestAPI(t *testing.T) (*API, map[string]string) {
	t.Helper()
	st := store.NewMemory()
	ctx := context.Background()
	tokens := map[string]string{}
	for _, role := range []string{store.RoleAdmin, store.RoleOperator, store.RoleViewer} {
		hash, err := auth.HashPassword("password123")
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		u := &store.User{Username: role + "-user", PasswordHash: hash, Role: role}
		if err := st.CreateUser(ctx, u); err != nil {
			t.Fatalf("create %s: %v", role, err)
		}
		tok := auth.NewToken()
		if err := st.CreateSession(ctx, &store.Session{Token: tok, UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatalf("session %s: %v", role, err)
		}
		tokens[role] = tok
	}
	return &API{Store: st}, tokens
}

// do runs a request through the full router (auth middleware included).
func do(a *API, method, path, token string, body any) *httptest.ResponseRecorder {
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	a.Routes().ServeHTTP(w, r)
	return w
}

func TestHealthzIsPublic(t *testing.T) {
	a, _ := newTestAPI(t)
	w := do(a, http.MethodGet, "/healthz", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200", w.Code)
	}
}

func TestUnauthenticatedAPIReturns401(t *testing.T) {
	a, _ := newTestAPI(t)
	w := do(a, http.MethodGet, "/api/v1/hosts", "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth /api/v1/hosts = %d, want 401", w.Code)
	}
}

func TestUnauthenticatedUIRedirects(t *testing.T) {
	a, _ := newTestAPI(t)
	w := do(a, http.MethodGet, "/ui/dashboard", "", nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("no-auth /ui/dashboard = %d, want 303 redirect", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/ui/login" {
		t.Errorf("redirect Location = %q, want /ui/login", loc)
	}
}

func TestInvalidTokenReturns401(t *testing.T) {
	a, _ := newTestAPI(t)
	w := do(a, http.MethodGet, "/api/v1/hosts", "not-a-real-token", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad-token = %d, want 401", w.Code)
	}
}

func TestLoginSuccess(t *testing.T) {
	a, _ := newTestAPI(t)
	w := do(a, http.MethodPost, "/api/v1/login", "", map[string]string{
		"username": "admin-user", "password": "password123",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("login = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct{ Token, Username, Role string }
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token == "" {
		t.Error("login returned an empty token")
	}
	if resp.Role != store.RoleAdmin {
		t.Errorf("role = %q, want admin", resp.Role)
	}
	// A session cookie must be set, HttpOnly.
	var found bool
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			found = true
			if !c.HttpOnly {
				t.Error("session cookie is not HttpOnly")
			}
			if c.SameSite != http.SameSiteLaxMode {
				t.Error("session cookie is not SameSite=Lax")
			}
		}
	}
	if !found {
		t.Error("no session cookie set on login")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	a, _ := newTestAPI(t)
	w := do(a, http.MethodPost, "/api/v1/login", "", map[string]string{
		"username": "admin-user", "password": "wrong",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-password login = %d, want 401", w.Code)
	}
}

func TestLoginUnknownUser(t *testing.T) {
	a, _ := newTestAPI(t)
	w := do(a, http.MethodPost, "/api/v1/login", "", map[string]string{
		"username": "ghost", "password": "password123",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown-user login = %d, want 401", w.Code)
	}
}

func TestLoginDisabledUser(t *testing.T) {
	a, tokens := newTestAPI(t)
	// disable the viewer via the store directly
	ctx := context.Background()
	u, _ := a.Store.GetUserByName(ctx, "viewer-user")
	u.Disabled = true
	if err := a.Store.UpdateUser(ctx, u); err != nil {
		t.Fatalf("disable: %v", err)
	}
	// login refused
	w := do(a, http.MethodPost, "/api/v1/login", "", map[string]string{
		"username": "viewer-user", "password": "password123",
	})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("disabled login = %d, want 401", w.Code)
	}
	// existing session also refused
	w = do(a, http.MethodGet, "/api/v1/hosts", tokens[store.RoleViewer], nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("disabled session = %d, want 401", w.Code)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	a, tokens := newTestAPI(t)
	tok := tokens[store.RoleAdmin]
	if w := do(a, http.MethodPost, "/api/v1/logout", tok, nil); w.Code != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", w.Code)
	}
	if w := do(a, http.MethodGet, "/api/v1/me", tok, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("post-logout /me = %d, want 401", w.Code)
	}
}

func TestMeReturnsUser(t *testing.T) {
	a, tokens := newTestAPI(t)
	w := do(a, http.MethodGet, "/api/v1/me", tokens[store.RoleOperator], nil)
	if w.Code != http.StatusOK {
		t.Fatalf("/me = %d, want 200", w.Code)
	}
	var u store.User
	if err := json.Unmarshal(w.Body.Bytes(), &u); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if u.Username != "operator-user" {
		t.Errorf("username = %q, want operator-user", u.Username)
	}
	if strings.Contains(w.Body.String(), "password") {
		t.Error("/me response leaks a password field")
	}
}

func TestRBACViewerCannotWrite(t *testing.T) {
	a, tokens := newTestAPI(t)
	w := do(a, http.MethodPost, "/api/v1/hosts", tokens[store.RoleViewer], map[string]string{
		"hostname": "web-01", "primary_ip": "10.0.0.5",
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer POST /hosts = %d, want 403", w.Code)
	}
}

func TestRBACOperatorCannotAccessAdminAreas(t *testing.T) {
	a, tokens := newTestAPI(t)
	for _, path := range []string{"/api/v1/users", "/api/v1/audit"} {
		w := do(a, http.MethodGet, path, tokens[store.RoleOperator], nil)
		if w.Code != http.StatusForbidden {
			t.Errorf("operator GET %s = %d, want 403", path, w.Code)
		}
	}
}

func TestRBACAdminCanManageUsers(t *testing.T) {
	a, tokens := newTestAPI(t)
	w := do(a, http.MethodGet, "/api/v1/users", tokens[store.RoleAdmin], nil)
	if w.Code != http.StatusOK {
		t.Fatalf("admin GET /users = %d, want 200", w.Code)
	}
}

func TestCreateUserValidation(t *testing.T) {
	a, tokens := newTestAPI(t)
	admin := tokens[store.RoleAdmin]
	cases := []struct {
		name string
		body map[string]string
		want int
	}{
		{"short password", map[string]string{"username": "bob", "password": "short", "role": "viewer"}, http.StatusBadRequest},
		{"missing username", map[string]string{"username": "", "password": "password123", "role": "viewer"}, http.StatusBadRequest},
		{"invalid role", map[string]string{"username": "bob", "password": "password123", "role": "superuser"}, http.StatusBadRequest},
		{"valid", map[string]string{"username": "bob", "password": "password123", "role": "viewer"}, http.StatusCreated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := do(a, http.MethodPost, "/api/v1/users", admin, tc.body)
			if w.Code != tc.want {
				t.Errorf("create user = %d, want %d; body=%s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestCreateDuplicateUserConflicts(t *testing.T) {
	a, tokens := newTestAPI(t)
	admin := tokens[store.RoleAdmin]
	body := map[string]string{"username": "admin-user", "password": "password123", "role": "viewer"}
	w := do(a, http.MethodPost, "/api/v1/users", admin, body)
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate user = %d, want 409", w.Code)
	}
}

func TestCannotDeleteOwnAccount(t *testing.T) {
	a, tokens := newTestAPI(t)
	ctx := context.Background()
	admin, _ := a.Store.GetUserByName(ctx, "admin-user")
	w := do(a, http.MethodDelete, "/api/v1/users/"+admin.ID, tokens[store.RoleAdmin], nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("self-delete = %d, want 400", w.Code)
	}
}

func TestIngestTokenAuthorizesEventsOnly(t *testing.T) {
	a, _ := newTestAPI(t)
	a.IngestToken = "ingest-secret"
	// seed a host so the events route resolves
	ctx := context.Background()
	h := &store.Host{Hostname: "web-01"}
	if err := a.Store.CreateHost(ctx, h); err != nil {
		t.Fatalf("create host: %v", err)
	}

	// A valid ingest token on a non-events route must NOT authenticate.
	w := do(a, http.MethodGet, "/api/v1/hosts", "ingest-secret", nil)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("ingest token on /hosts = %d, want 401", w.Code)
	}

	// A wrong ingest token on the events route is rejected.
	w = do(a, http.MethodPost, "/api/v1/hosts/"+h.ID+"/events", "wrong-token", []any{})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("wrong ingest token on /events = %d, want 401", w.Code)
	}
}
