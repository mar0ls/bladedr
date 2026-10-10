package probe

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestPasswordScheme(t *testing.T) {
	cases := map[string]string{
		"":                              SchemeNone,
		"!":                             SchemeLocked,
		"*":                             SchemeLocked,
		"!$6$salt$hash":                 SchemeLocked,
		"$1$abcdefgh$xxxxxxxxxxxxxxxx":  SchemeMD5,
		"$5$salt$hash":                  SchemeSHA256,
		"$6$salt$hash":                  SchemeSHA512,
		"$y$j9T$salt$hash":              SchemeYescrypt,
		"$2b$12$saltsaltsaltsaltsaltsu": SchemeBcrypt,
		"abJnggxhB/yWI":                 SchemeDES,
		"$weird$":                       SchemeOther,
	}
	for hash, want := range cases {
		if got := passwordScheme(hash); got != want {
			t.Errorf("passwordScheme(%q) = %q, want %q", hash, got, want)
		}
	}
}

func TestPasswordFingerprint(t *testing.T) {
	a, b := passwordFingerprint("$6$s$one"), passwordFingerprint("$6$s$two")
	if a == "" || a == b || len(a) != 16 {
		t.Fatalf("fingerprints must be 16 hex chars and differ per hash: %q %q", a, b)
	}
	if a != passwordFingerprint("$6$s$one") {
		t.Fatal("fingerprint must be stable")
	}
	for _, unusable := range []string{"", "!", "*", "!$6$s$one"} {
		if passwordFingerprint(unusable) != "" {
			t.Errorf("%q is not a usable credential and must have no fingerprint", unusable)
		}
	}
	for _, leaked := range []string{"one", "$6$s"} {
		if strings.Contains(a, leaked) {
			t.Errorf("fingerprint %q reveals part of the hash", a)
		}
	}
}

func TestShadowHashes(t *testing.T) {
	got := shadowHashes("root:$6$s$h:19000:0:99999:7:::\n#comment\ndaemon:*:19000:::::\n\nbad\n")
	if got["root"] != "$6$s$h" || got["daemon"] != "*" || len(got) != 2 {
		t.Fatalf("shadowHashes = %v", got)
	}
}

func TestPrivateKeyInfo(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sshPub, _ := ssh.NewPublicKey(pub)
	want := pubKeySHA(sshPub.Marshal())

	plain, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	typ, enc, sha, ok := privateKeyInfo(pem.EncodeToMemory(plain))
	if !ok || enc || typ != "ssh-ed25519" || sha != want {
		t.Errorf("unencrypted openssh key: %q enc=%v sha-match=%v ok=%v", typ, enc, sha == want, ok)
	}

	locked, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	_, enc, sha, ok = privateKeyInfo(pem.EncodeToMemory(locked))
	if !ok || !enc || sha != want {
		t.Errorf("a passphrase-protected openssh key still exposes its public half: enc=%v sha-match=%v ok=%v", enc, sha == want, ok)
	}

	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)})
	rpub, _ := ssh.NewPublicKey(&rk.PublicKey)
	typ, enc, sha, ok = privateKeyInfo(rsaPEM)
	if !ok || enc || typ != "rsa" || sha != pubKeySHA(rpub.Marshal()) {
		t.Errorf("unencrypted PEM rsa: %q enc=%v ok=%v", typ, enc, ok)
	}

	encPEM := []byte("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n")
	if typ, enc, sha, ok = privateKeyInfo(encPEM); !ok || !enc || sha != "" {
		t.Errorf("encrypted PEM: %q enc=%v sha=%q ok=%v", typ, enc, sha, ok)
	}

	for _, notKey := range []string{
		"", "ssh-ed25519 AAAA comment\n", "just a text file\n", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nbm90IGEga2V5\n-----END OPENSSH PRIVATE KEY-----\n",
	} {
		if _, _, _, ok := privateKeyInfo([]byte(notKey)); ok {
			t.Errorf("%q is not a private key", notKey)
		}
	}
}
