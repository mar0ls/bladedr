// Package auth provides password hashing, session tokens, and the RBAC policy for
// the bladedr console. Roles: admin (everything + user/credential management),
// operator (read + non-admin mutations: triage, scan, rules, sensor), viewer
// (read-only). Detection logic lives elsewhere; this is just access control.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"bladedr/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// HashPassword returns a bcrypt hash for storage.
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

// CheckPassword reports whether pw matches the stored hash.
func CheckPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// NewToken returns a 256-bit random session token (hex).
func NewToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// adminOnly paths: user management and credential handling (sealed SSH secrets).
func adminOnly(path string) bool {
	return strings.HasPrefix(path, "/api/v1/users") ||
		strings.HasPrefix(path, "/api/v1/credentials") ||
		strings.HasPrefix(path, "/api/v1/audit") ||
		strings.HasPrefix(path, "/ui/users") ||
		strings.HasPrefix(path, "/ui/audit")
}

// Allowed reports whether a role may perform method on path. Public routes are
// handled by the caller before this is consulted.
func Allowed(role, method, path string) bool {
	switch role {
	case store.RoleAdmin:
		return true
	case store.RoleOperator:
		return !adminOnly(path) // read + non-admin mutations
	case store.RoleViewer:
		return !adminOnly(path) && (method == http.MethodGet || method == http.MethodHead)
	default:
		return false
	}
}
