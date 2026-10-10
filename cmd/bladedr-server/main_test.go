package main

import (
	"net/http"
	"testing"
	"time"

	"bladedr/internal/secrets"
	"bladedr/internal/store"
)

func TestNewHTTPServerLimits(t *testing.T) {
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	server := newHTTPServer(":8080", handler)

	if server.Addr != ":8080" || server.Handler == nil {
		t.Fatalf("server address or handler not configured: %+v", server)
	}
	if server.ReadHeaderTimeout != 10*time.Second {
		t.Errorf("ReadHeaderTimeout = %s, want 10s", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout = %s, want 30s", server.ReadTimeout)
	}
	if server.WriteTimeout != 5*time.Minute {
		t.Errorf("WriteTimeout = %s, want 5m", server.WriteTimeout)
	}
	if server.IdleTimeout != 2*time.Minute {
		t.Errorf("IdleTimeout = %s, want 2m", server.IdleTimeout)
	}
	if server.MaxHeaderBytes != 1<<20 {
		t.Errorf("MaxHeaderBytes = %d, want %d", server.MaxHeaderBytes, 1<<20)
	}
}

func TestSudoPasswordFor(t *testing.T) {
	_, priv, err := secrets.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := secrets.FromNodeKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := crypto.Seal([]byte("dedicated"))
	cases := []struct {
		name string
		cred store.Credential
		want string
	}{
		{"dedicated sudo password wins", store.Credential{AuthType: "password", SudoSecretEnc: sealed}, "dedicated"},
		{"key account with a sudo password", store.Credential{AuthType: "ssh_key", SudoSecretEnc: sealed}, "dedicated"},
		{"password account falls back to its login password", store.Credential{AuthType: "password"}, "login-pw"},
		{"key account with none uses passwordless sudo only", store.Credential{AuthType: "ssh_key"}, ""},
		{"undecryptable sudo secret falls back, not fails", store.Credential{AuthType: "password", SudoSecretEnc: []byte("garbage")}, "login-pw"},
	}
	for _, tc := range cases {
		if got := sudoPasswordFor(crypto, &tc.cred, []byte("login-pw")); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
