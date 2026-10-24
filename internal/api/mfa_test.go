package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"bladedr/internal/auth"
	"bladedr/internal/store"
)

// currentTOTP independently computes the RFC 6238 code for secret at the current
// moment (the same algorithm internal/auth.totpCode uses, reimplemented here since
// it is unexported), so the test has a way to produce a valid code without calling
// into the thing it is testing. auth.VerifyTOTP -- the real code under test -- is
// still what every assertion below goes through.
func currentTOTP(t *testing.T, secret string) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	code := fmt.Sprintf("%06d", n%1_000_000)
	if !auth.VerifyTOTP(secret, code, time.Now()) {
		t.Fatal("computed code does not verify; TOTP reimplementation diverged from auth.VerifyTOTP")
	}
	return code
}

// TestSetupMFARequiresCurrentCodeWhenAlreadyEnabled is the regression test for a
// second-factor bypass: setupMFA used to accept only the password, even for an
// account that already had MFA enabled, and would silently replace the secret and
// reset MFAEnabled to false. Anyone who obtained just the password (the exact
// scenario MFA exists to contain) could call it to disable or take over MFA
// without ever proving the current factor -- which disableMFA has always
// required. setupMFA must hold the same bar once MFA is on.
func TestSetupMFARequiresCurrentCodeWhenAlreadyEnabled(t *testing.T) {
	a, tok := newTestAPI(t)
	withCrypto(t, a)
	operator := tok[store.RoleOperator]

	// Enroll and confirm the first secret.
	w := do(a, "POST", "/api/v1/me/mfa/setup", operator, map[string]string{"password": "password123"})
	if w.Code != http.StatusOK {
		t.Fatalf("initial setup = %d (%s)", w.Code, w.Body)
	}
	var setup struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &setup); err != nil {
		t.Fatal(err)
	}
	code := currentTOTP(t, setup.Secret)
	if w := do(a, "POST", "/api/v1/me/mfa/confirm", operator, map[string]string{"code": code}); w.Code != http.StatusNoContent {
		t.Fatalf("confirm = %d (%s)", w.Code, w.Body)
	}

	// Password alone must no longer be enough to re-enroll.
	w = do(a, "POST", "/api/v1/me/mfa/setup", operator, map[string]string{"password": "password123"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("password-only re-enroll = %d, want 401 (%s)", w.Code, w.Body)
	}

	// Nor does a wrong code help.
	w = do(a, "POST", "/api/v1/me/mfa/setup", operator, map[string]string{"password": "password123", "code": "000000"})
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-code re-enroll = %d, want 401 (%s)", w.Code, w.Body)
	}

	// The account must still be protected by the original secret after both
	// rejected attempts -- not left in some half-reset state.
	u, err := a.Store.GetUserByName(context.Background(), "operator-user")
	if err != nil {
		t.Fatal(err)
	}
	if !u.MFAEnabled {
		t.Fatal("a rejected re-enroll attempt disabled MFA")
	}
	if got := currentTOTP(t, setup.Secret); !auth.VerifyTOTP(setup.Secret, got, time.Now()) {
		t.Fatal("original secret no longer verifies")
	}

	// The current code, alongside the password, is accepted and rotates the secret.
	code = currentTOTP(t, setup.Secret)
	w = do(a, "POST", "/api/v1/me/mfa/setup", operator, map[string]string{"password": "password123", "code": code})
	if w.Code != http.StatusOK {
		t.Fatalf("re-enroll with current code = %d (%s)", w.Code, w.Body)
	}
	var rotated struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Secret == setup.Secret {
		t.Fatal("re-enroll did not rotate the secret")
	}
}
