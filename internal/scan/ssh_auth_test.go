package scan

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

func TestAuthForSSHKey(t *testing.T) {
	pem, err := os.ReadFile("testdata/ed25519_key")
	if err != nil {
		t.Fatal(err)
	}
	methods, err := AuthFor("ssh_key", string(pem))
	if err != nil || len(methods) != 1 {
		t.Fatalf("AuthFor(ssh_key) = %v, %v", methods, err)
	}
}

func TestAuthForSSHKeyRejectsGarbage(t *testing.T) {
	if _, err := AuthFor("ssh_key", "not a key"); err == nil {
		t.Fatal("a malformed key must fail to parse, not silently produce no auth methods")
	}
}

func TestAuthForPasswordOffersBothMethods(t *testing.T) {
	// Password alone fails against many PAM-backed sshd configs that only accept
	// keyboard-interactive; both must be offered so the handshake can use either.
	methods, err := AuthFor("password", "hunter2")
	if err != nil || len(methods) != 2 {
		t.Fatalf("AuthFor(password) = %v, %v, want 2 methods", methods, err)
	}
}

func TestAuthForRejectsUnsupportedType(t *testing.T) {
	// ssh_agent is a valid auth_type at the API/schema level (see
	// TestCreateCredentialRejectsSSHAgent) but has no transport implementation; this is
	// the second half of that guarantee — even if one slipped through, the transport
	// itself refuses it rather than silently connecting with no auth method at all.
	for _, bad := range []string{"ssh_agent", "", "nonsense"} {
		if _, err := AuthFor(bad, "x"); err == nil {
			t.Errorf("AuthFor(%q) should be rejected, not silently accepted", bad)
		}
	}
}

func TestDecodeExecErrorExtractsStderr(t *testing.T) {
	cmd := exec.Command("sh", "-c", "echo details >&2; exit 1")
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatal("expected an *exec.ExitError from the shell command")
	}
	exitErr.Stderr = []byte("probe lock unavailable\n")
	got := decodeExecError(exitErr)
	if got.Error() != "probe failed: probe lock unavailable\n" {
		t.Errorf("decodeExecError = %q", got.Error())
	}
}

func TestDecodeExecErrorPassesThroughOtherErrors(t *testing.T) {
	plain := errors.New("dial tcp: connection refused")
	if got := decodeExecError(plain); got != plain {
		t.Errorf("a non-exec error must pass through unchanged, got %v", got)
	}
}
