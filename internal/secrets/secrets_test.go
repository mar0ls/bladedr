package secrets

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	node, err := FromNodeKey(priv)
	if err != nil {
		t.Fatalf("FromNodeKey: %v", err)
	}
	// Server seals with only the public key (cannot open).
	server, err := FromPublicKey(pub)
	if err != nil {
		t.Fatalf("FromPublicKey: %v", err)
	}
	if server.CanOpen() {
		t.Fatal("seal-only Crypto must not be able to open")
	}

	secret := []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n...")
	ct, err := server.Seal(secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(ct, secret) {
		t.Fatal("ciphertext leaks plaintext")
	}

	got, err := node.Open(ct)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round-trip mismatch: got %q", got)
	}

	// Server (no private key) must not be able to open.
	if _, err := server.Open(ct); err == nil {
		t.Fatal("seal-only Crypto should not open ciphertext")
	}

	// A different node key must fail to open.
	_, otherPriv, _ := GenerateKeyPair()
	other, _ := FromNodeKey(otherPriv)
	if _, err := other.Open(ct); err == nil {
		t.Fatal("wrong key opened ciphertext")
	}
}

func TestPublicKeyDerivationMatches(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	node, err := FromNodeKey(priv)
	if err != nil {
		t.Fatalf("FromNodeKey: %v", err)
	}
	if node.PublicKey() != pub {
		t.Fatalf("derived public key %q != generated %q", node.PublicKey(), pub)
	}
}
