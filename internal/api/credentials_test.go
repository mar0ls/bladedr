package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"bladedr/internal/secrets"
	"bladedr/internal/store"
)

func withCrypto(t *testing.T, a *API) {
	t.Helper()
	_, priv, err := secrets.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	c, err := secrets.FromNodeKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	a.Crypto = c
}

func TestCredentialsCRUD(t *testing.T) {
	a, tok := newTestAPI(t)
	withCrypto(t, a)
	admin := tok[store.RoleAdmin]

	w := do(a, "POST", "/api/v1/credentials", admin, map[string]any{
		"name": "root-key", "username": "root", "auth_type": "password", "secret": "hunter2",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create credential = %d, want 201 (%s)", w.Code, w.Body)
	}
	var cred store.Credential
	if err := json.Unmarshal(w.Body.Bytes(), &cred); err != nil || cred.ID == "" {
		t.Fatalf("create credential response: %v (%s)", err, w.Body)
	}
	// The plaintext secret must never be echoed back.
	if len(cred.SecretEnc) != 0 {
		t.Error("credential response leaked the sealed secret")
	}

	if w := do(a, "GET", "/api/v1/credentials", admin, nil); w.Code != http.StatusOK {
		t.Fatalf("list credentials = %d", w.Code)
	}
	if w := do(a, "DELETE", "/api/v1/credentials/"+cred.ID, admin, nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete credential = %d", w.Code)
	}
}

func TestCreateCredentialDisabledWithoutCrypto(t *testing.T) {
	a, tok := newTestAPI(t) // no Crypto configured
	w := do(a, "POST", "/api/v1/credentials", tok[store.RoleAdmin], map[string]any{
		"username": "root", "secret": "x",
	})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("create credential without node key = %d, want 503", w.Code)
	}
}

func TestCreateCredentialRejectsBadAuthType(t *testing.T) {
	a, tok := newTestAPI(t)
	withCrypto(t, a)
	w := do(a, "POST", "/api/v1/credentials", tok[store.RoleAdmin], map[string]any{
		"username": "root", "secret": "x", "auth_type": "nonsense",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid auth_type = %d, want 400", w.Code)
	}
}

func TestViewerCannotCreateCredential(t *testing.T) {
	a, tok := newTestAPI(t)
	withCrypto(t, a)
	w := do(a, "POST", "/api/v1/credentials", tok[store.RoleViewer], map[string]any{
		"username": "root", "secret": "x",
	})
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer create credential = %d, want 403", w.Code)
	}
}

func TestCreateCredentialRejectsSSHAgent(t *testing.T) {
	// ssh_agent is a real auth_type value (the DB schema and OpenAPI accept it), but
	// scan.AuthFor has no case for it, so a credential created with it would seal fine
	// and then fail every scan with "unsupported auth type" — discovered only at scan
	// time, not at creation. It must be rejected here instead, with a message that says
	// why, not just "invalid auth_type" (it isn't invalid input, it's unimplemented).
	a, tok := newTestAPI(t)
	withCrypto(t, a)
	w := do(a, "POST", "/api/v1/credentials", tok[store.RoleAdmin], map[string]any{
		"username": "root", "secret": "x", "auth_type": "ssh_agent",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("ssh_agent auth_type = %d, want 400 (%s)", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "not implemented") {
		t.Errorf("rejection should say ssh_agent isn't implemented, not just reject it: %s", w.Body)
	}
}
