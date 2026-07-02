// Package secrets implements Sandfly-style split-trust credential protection:
// secrets are sealed to a Curve25519 *public* key (anyone/the server can seal),
// and can only be opened with the corresponding *private* key, which is held by
// the scanning node. A compromised server database therefore yields only
// ciphertext. In the single-binary MVP the server also holds the private key,
// but the split is preserved so the private key can later move to dedicated nodes.
package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// Crypto seals and (if a private key is present) opens credential secrets.
type Crypto struct {
	pub  *[32]byte
	priv *[32]byte // nil when this process can only seal
}

// GenerateKeyPair returns a new (publicB64, privateB64) Curve25519 pair.
func GenerateKeyPair() (string, string, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return b64(pub[:]), b64(priv[:]), nil
}

// FromNodeKey builds a Crypto from a base64 private key (node mode): it derives
// the public key and can both seal and open. Use this in the single-binary MVP.
func FromNodeKey(privB64 string) (*Crypto, error) {
	priv, err := decodeKey(privB64)
	if err != nil {
		return nil, fmt.Errorf("node key: %w", err)
	}
	pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	var pub [32]byte
	copy(pub[:], pubBytes)
	return &Crypto{pub: &pub, priv: priv}, nil
}

// FromPublicKey builds a seal-only Crypto (server-without-node mode).
func FromPublicKey(pubB64 string) (*Crypto, error) {
	pub, err := decodeKey(pubB64)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	return &Crypto{pub: pub}, nil
}

// PublicKey returns the base64 public key this Crypto seals to.
func (c *Crypto) PublicKey() string { return b64(c.pub[:]) }

// CanOpen reports whether this process holds the private key.
func (c *Crypto) CanOpen() bool { return c.priv != nil }

// Seal encrypts plaintext to the public key (anonymous sealed box).
func (c *Crypto) Seal(plaintext []byte) ([]byte, error) {
	return box.SealAnonymous(nil, plaintext, c.pub, rand.Reader)
}

// Open decrypts a sealed box. Requires the private key.
func (c *Crypto) Open(ciphertext []byte) ([]byte, error) {
	if c.priv == nil {
		return nil, fmt.Errorf("cannot open: no private key loaded")
	}
	out, ok := box.OpenAnonymous(nil, ciphertext, c.pub, c.priv)
	if !ok {
		return nil, fmt.Errorf("decrypt failed (wrong key or corrupt ciphertext)")
	}
	return out, nil
}

func decodeKey(s string) (*[32]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("expected 32-byte key, got %d", len(raw))
	}
	var k [32]byte
	copy(k[:], raw)
	return &k, nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
