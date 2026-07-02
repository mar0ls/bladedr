package auth

import (
	"net/http"
	"testing"

	"bladedr/internal/store"
)

func TestHashAndCheckPassword(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "correct horse battery staple" {
		t.Fatal("password stored in cleartext")
	}
	if !CheckPassword(hash, "correct horse battery staple") {
		t.Error("CheckPassword rejected the correct password")
	}
	if CheckPassword(hash, "wrong password") {
		t.Error("CheckPassword accepted a wrong password")
	}
}

func TestHashPasswordIsSalted(t *testing.T) {
	h1, _ := HashPassword("same")
	h2, _ := HashPassword("same")
	if h1 == h2 {
		t.Error("two hashes of the same password are identical (unsalted)")
	}
}

func TestNewToken(t *testing.T) {
	t1 := NewToken()
	t2 := NewToken()
	if len(t1) != 64 { // 32 bytes hex-encoded
		t.Errorf("token length = %d, want 64 hex chars", len(t1))
	}
	if t1 == t2 {
		t.Error("two tokens are identical")
	}
}

func TestAllowed(t *testing.T) {
	cases := []struct {
		name   string
		role   string
		method string
		path   string
		want   bool
	}{
		// admin: everything
		{"admin reads", store.RoleAdmin, http.MethodGet, "/api/v1/hosts", true},
		{"admin writes", store.RoleAdmin, http.MethodPost, "/api/v1/hosts", true},
		{"admin users", store.RoleAdmin, http.MethodPost, "/api/v1/users", true},
		{"admin audit", store.RoleAdmin, http.MethodGet, "/api/v1/audit", true},

		// operator: read + non-admin mutations, but not admin areas
		{"operator reads", store.RoleOperator, http.MethodGet, "/api/v1/hosts", true},
		{"operator scans", store.RoleOperator, http.MethodPost, "/api/v1/hosts/x/scans", true},
		{"operator rules", store.RoleOperator, http.MethodPost, "/api/v1/rules", true},
		{"operator denied users", store.RoleOperator, http.MethodGet, "/api/v1/users", false},
		{"operator denied credentials", store.RoleOperator, http.MethodPost, "/api/v1/credentials", false},
		{"operator denied audit", store.RoleOperator, http.MethodGet, "/api/v1/audit", false},
		{"operator denied ui users", store.RoleOperator, http.MethodGet, "/ui/users", false},

		// viewer: read-only, no admin areas
		{"viewer reads", store.RoleViewer, http.MethodGet, "/api/v1/hosts", true},
		{"viewer head", store.RoleViewer, http.MethodHead, "/api/v1/hosts", true},
		{"viewer denied write", store.RoleViewer, http.MethodPost, "/api/v1/hosts", false},
		{"viewer denied patch", store.RoleViewer, http.MethodPatch, "/api/v1/observations/x", false},
		{"viewer denied users", store.RoleViewer, http.MethodGet, "/api/v1/users", false},

		// unknown role: nothing
		{"unknown role", "superuser", http.MethodGet, "/api/v1/hosts", false},
		{"empty role", "", http.MethodGet, "/api/v1/hosts", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Allowed(tc.role, tc.method, tc.path); got != tc.want {
				t.Errorf("Allowed(%q, %q, %q) = %v, want %v", tc.role, tc.method, tc.path, got, tc.want)
			}
		})
	}
}

func TestAdminOnly(t *testing.T) {
	adminPaths := []string{
		"/api/v1/users",
		"/api/v1/users/abc",
		"/api/v1/credentials",
		"/api/v1/credentials/abc",
		"/api/v1/audit",
		"/ui/users",
		"/ui/audit",
	}
	for _, p := range adminPaths {
		if !adminOnly(p) {
			t.Errorf("adminOnly(%q) = false, want true", p)
		}
	}
	openPaths := []string{
		"/api/v1/hosts",
		"/api/v1/rules",
		"/ui/dashboard",
		"/healthz",
	}
	for _, p := range openPaths {
		if adminOnly(p) {
			t.Errorf("adminOnly(%q) = true, want false", p)
		}
	}
}
