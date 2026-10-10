package probe

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Password schemes reported for an /etc/shadow hash field. Only the scheme and a
// fingerprint leave the host — never the hash, which is enough to attack offline.
const (
	SchemeNone     = "none"     // empty field: login without a password
	SchemeLocked   = "locked"   // "!" or "*": password login disabled
	SchemeMD5      = "md5crypt" // $1$
	SchemeSHA256   = "sha256crypt"
	SchemeSHA512   = "sha512crypt"
	SchemeYescrypt = "yescrypt"
	SchemeBcrypt   = "bcrypt"
	SchemeScrypt   = "scrypt"
	SchemeDES      = "des" // 13 characters, no $ prefix: 1970s crypt(3)
	SchemeOther    = "other"
)

// shadowHashes returns account name -> hash field from /etc/shadow contents.
func shadowHashes(content string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 2 && f[0] != "" && !strings.HasPrefix(f[0], "#") {
			out[f[0]] = f[1]
		}
	}
	return out
}

// passwordScheme classifies a hash field. A leading "!" locks the account but keeps the
// hash behind it ("!$6$…"); that is still a locked account, not a usable credential.
func passwordScheme(hash string) string {
	switch {
	case hash == "":
		return SchemeNone
	case hash[0] == '!' || hash[0] == '*':
		return SchemeLocked
	case strings.HasPrefix(hash, "$1$"):
		return SchemeMD5
	case strings.HasPrefix(hash, "$5$"):
		return SchemeSHA256
	case strings.HasPrefix(hash, "$6$"):
		return SchemeSHA512
	case strings.HasPrefix(hash, "$y$") || strings.HasPrefix(hash, "$gy$"):
		return SchemeYescrypt
	case strings.HasPrefix(hash, "$2"):
		return SchemeBcrypt
	case strings.HasPrefix(hash, "$7$"):
		return SchemeScrypt
	case !strings.HasPrefix(hash, "$") && len(hash) == 13:
		return SchemeDES
	}
	return SchemeOther
}

// passwordFingerprint identifies a usable hash without revealing it. The same string on
// two hosts means one password was set the same way on both — a provisioning template, a
// cloned image, or a reused credential — so cracking one account opens the others. Salts
// make independently chosen identical passwords differ, so a match is a copied hash.
func passwordFingerprint(hash string) string {
	switch passwordScheme(hash) {
	case SchemeNone, SchemeLocked:
		return ""
	}
	sum := sha256.Sum256([]byte(hash))
	return hex.EncodeToString(sum[:])[:16]
}

// privateKeyInfo reads what can be learned from a file that may be an SSH private key:
// its type, whether the secret part is passphrase-protected, and the SHA-256 of the public
// key in the same form authorized_keys entries are hashed, so a key on this host can be
// matched with the hosts that authorize it. ok is false for anything that is not a private
// key. The secret material itself is never retained.
func privateKeyInfo(data []byte) (keyType string, encrypted bool, pubSHA string, ok bool) {
	text := string(data)
	i := strings.Index(text, "-----BEGIN ")
	if i < 0 {
		return "", false, "", false
	}
	text = text[i:]
	header, _, _ := strings.Cut(text, "\n")
	header = strings.TrimSpace(header)
	switch {
	case header == "-----BEGIN OPENSSH PRIVATE KEY-----":
		return openSSHPrivateKey(text)
	case header == "-----BEGIN ENCRYPTED PRIVATE KEY-----":
		return "pkcs8", true, "", true
	case strings.HasPrefix(header, "-----BEGIN ") && strings.HasSuffix(header, "PRIVATE KEY-----"):
		typ := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(header, "-----BEGIN "), "PRIVATE KEY-----")))
		if typ == "" {
			typ = "pkcs8"
		}
		if strings.Contains(text, "ENCRYPTED") {
			return typ, true, "", true // Proc-Type: 4,ENCRYPTED — the public half is not recoverable
		}
		raw, err := ssh.ParseRawPrivateKey(data)
		if err != nil {
			return typ, false, "", true
		}
		signer, err := ssh.NewSignerFromKey(raw)
		if err != nil {
			return typ, false, "", true
		}
		return typ, false, pubKeySHA(signer.PublicKey().Marshal()), true
	}
	return "", false, "", false
}

// openSSHPrivateKey parses the openssh-key-v1 container. Its public key is stored in the
// clear even when the private part is encrypted, so an encrypted key can still be matched.
func openSSHPrivateKey(text string) (string, bool, string, bool) {
	var body strings.Builder
	for _, line := range strings.Split(text, "\n")[1:] {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-----END") {
			break
		}
		body.WriteString(line)
	}
	raw, err := base64.StdEncoding.DecodeString(body.String())
	const magic = "openssh-key-v1\x00"
	if err != nil || len(raw) < len(magic) || string(raw[:len(magic)]) != magic {
		return "", false, "", false
	}
	rest := raw[len(magic):]
	next := func() ([]byte, bool) {
		if len(rest) < 4 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(rest)
		if uint64(n) > uint64(len(rest)-4) {
			return nil, false
		}
		field := rest[4 : 4+n]
		rest = rest[4+n:]
		return field, true
	}
	cipher, ok1 := next()
	_, ok2 := next() // kdfname
	_, ok3 := next() // kdfoptions
	if !ok1 || !ok2 || !ok3 || len(rest) < 4 {
		return "", false, "", false
	}
	rest = rest[4:] // number of keys
	blob, ok := next()
	if !ok {
		return "", false, "", false
	}
	keyType := "openssh"
	if pk, err := ssh.ParsePublicKey(blob); err == nil {
		keyType = pk.Type()
	}
	return keyType, string(cipher) != "none", pubKeySHA(blob), true
}

// pubKeySHA hashes a public key blob exactly as parseAuthKey hashes an authorized_keys
// field: SHA-256 of the base64 text.
func pubKeySHA(blob []byte) string {
	sum := sha256.Sum256([]byte(base64.StdEncoding.EncodeToString(blob)))
	return hex.EncodeToString(sum[:])
}
