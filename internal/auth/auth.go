// Package auth provides password hashing, session tokens, and the RBAC policy for
// the bladedr console. Roles: admin (everything + user/credential management),
// operator (read + non-admin mutations: triage, scan, rules, sensor), viewer
// (read-only). Detection logic lives elsewhere; this is just access control.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // SHA-1 is required by RFC 6238's interoperable default, not used for password hashing.
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

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

// decoyHash is a valid bcrypt digest at DefaultCost over an unguessable value. It
// exists solely so DummyCheckPassword performs real work; nothing verifies against it.
var decoyHash = mustDecoyHash()

func mustDecoyHash() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("auth: no entropy for decoy hash: " + err.Error())
	}
	h, err := bcrypt.GenerateFromPassword([]byte(hex.EncodeToString(b)), bcrypt.DefaultCost)
	if err != nil {
		panic("auth: decoy hash: " + err.Error())
	}
	return h
}

// DummyCheckPassword burns one bcrypt verification and always fails. Callers use it
// on the "no such user" branch so an unknown username costs the same as a known one.
// bcrypt at DefaultCost runs for tens of milliseconds, which is measurable over the
// network; skipping it would make login a user enumeration oracle.
func DummyCheckPassword(pw string) bool {
	bcrypt.CompareHashAndPassword(decoyHash, []byte(pw)) //nolint:errcheck // result is discarded by design
	return false
}

// NewToken returns a 256-bit random session token (hex).
func NewToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// TokenDigest returns the non-reversible lookup key persisted for bearer
// credentials. A database leak therefore does not disclose live session or sensor
// tokens. Tokens contain 256 random bits, so a plain SHA-256 digest is sufficient;
// slow password hashing would add cost without improving resistance to guessing.
func TokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// NewTOTPSecret returns a 160-bit base32 secret compatible with RFC 6238
// authenticator applications.
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// VerifyTOTP accepts the current 30-second window and one adjacent window on each
// side to tolerate modest clock skew. Codes are compared in constant time.
func VerifyTOTP(secret, code string, now time.Time) bool {
	if len(code) != 6 {
		return false
	}
	if _, err := strconv.Atoi(code); err != nil {
		return false
	}
	for delta := int64(-1); delta <= 1; delta++ {
		want, err := totpCode(secret, now.Unix()/30+delta)
		if err == nil && hmac.Equal([]byte(want), []byte(code)) {
			return true
		}
	}
	return false
}

func totpCode(secret string, counter int64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1_000_000), nil
}

// adminOnly paths: user management and credential handling (sealed SSH secrets).
func adminOnly(path string) bool {
	// Deciding a containment action is an admin call in both directions: approving
	// releases root-level commands onto a host, and rejecting silently discards a
	// containment request an operator may be relying on.
	if strings.HasPrefix(path, "/api/v1/responses/") &&
		(strings.HasSuffix(path, "/approve") || strings.HasSuffix(path, "/reject")) {
		return true
	}
	if strings.Contains(path, "/sensor-tokens") {
		return true
	}
	return strings.HasPrefix(path, "/api/v1/users") ||
		strings.HasPrefix(path, "/api/v1/credentials") ||
		strings.HasPrefix(path, "/api/v1/export-targets") ||
		strings.HasPrefix(path, "/api/v1/export-dlq") ||
		strings.HasPrefix(path, "/api/v1/archive") ||
		strings.HasPrefix(path, "/api/v1/retention") ||
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
