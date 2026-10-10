package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"bladedr/internal/secrets"
	"bladedr/internal/store"
)

func sealingAPI(t *testing.T) (*API, map[string]string, *secrets.Crypto) {
	t.Helper()
	a, tokens := newTestAPI(t)
	_, priv, err := secrets.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if a.Crypto, err = secrets.FromNodeKey(priv); err != nil {
		t.Fatal(err)
	}
	return a, tokens, a.Crypto
}

func onlyCredential(t *testing.T, a *API) *store.Credential {
	t.Helper()
	list, err := a.Store.ListCredentials(context.Background())
	if err != nil || len(list) == 0 {
		t.Fatalf("no credential stored: %v", err)
	}
	return list[len(list)-1]
}

func TestAPICredentialSealsSudoPasswordAndNeverEchoesIt(t *testing.T) {
	a, tokens, crypto := sealingAPI(t)
	w := do(a, "POST", "/api/v1/credentials", tokens[store.RoleAdmin], map[string]string{
		"username": "master", "auth_type": "ssh_key", "secret": "PEM", "sudo_password": "hunter2-sudo",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "hunter2") {
		t.Fatalf("response echoed the sudo password: %s", w.Body)
	}
	c := onlyCredential(t, a)
	if bytes.Contains(c.SudoSecretEnc, []byte("hunter2")) {
		t.Fatal("sudo password stored in plaintext")
	}
	if pw, err := crypto.Open(c.SudoSecretEnc); err != nil || string(pw) != "hunter2-sudo" {
		t.Fatalf("sealed sudo password does not open to the input: %q %v", pw, err)
	}
	if login, _ := crypto.Open(c.SecretEnc); string(login) != "PEM" {
		t.Fatalf("login secret changed: %q", login)
	}
}

func postForm(h http.HandlerFunc, path string, id string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if id != "" {
		r.SetPathValue("id", id)
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestUIAddHostStoresSealedSudoPassword(t *testing.T) {
	a, _, crypto := sealingAPI(t)
	w := postForm(a.uiAddHost, "/ui/hosts", "", url.Values{
		"primary_ip": {"192.0.2.10"}, "username": {"master"}, "auth_type": {"ssh_key"},
		"secret": {"PEM"}, "sudo_password": {"s-pw"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	c := onlyCredential(t, a)
	if pw, err := crypto.Open(c.SudoSecretEnc); err != nil || string(pw) != "s-pw" {
		t.Fatalf("sudo password not stored sealed: %q %v", pw, err)
	}
	// Left blank, nothing is stored: sudo then falls back to the login password.
	postForm(a.uiAddHost, "/ui/hosts", "", url.Values{
		"primary_ip": {"192.0.2.11"}, "username": {"dev"}, "auth_type": {"password"}, "secret": {"pw"},
	})
	if c := onlyCredential(t, a); len(c.SudoSecretEnc) != 0 {
		t.Fatalf("blank sudo password stored something: %q", c.SudoSecretEnc)
	}
}

func TestUIEditHostSudoPasswordIsKeptAndChangedIndependently(t *testing.T) {
	a, _, crypto := sealingAPI(t)
	postForm(a.uiAddHost, "/ui/hosts", "", url.Values{
		"primary_ip": {"192.0.2.12"}, "username": {"master"}, "auth_type": {"ssh_key"},
		"secret": {"PEM"}, "sudo_password": {"first"},
	})
	hosts, _ := a.Store.ListHosts(context.Background())
	id := hosts[0].ID
	open := func() (login, sudo string) {
		h, _ := a.Store.GetHost(context.Background(), id)
		c, _ := a.Store.GetCredential(context.Background(), h.CredentialID)
		l, _ := crypto.Open(c.SecretEnc)
		s, _ := crypto.Open(c.SudoSecretEnc)
		return string(l), string(s)
	}
	// New login secret, sudo field blank: the stored sudo password must survive.
	postForm(a.uiEditHost, "/ui/hosts/"+id+"/edit", id, url.Values{
		"hostname": {"h"}, "username": {"master"}, "auth_type": {"ssh_key"}, "secret": {"PEM2"},
	})
	if l, s := open(); l != "PEM2" || s != "first" {
		t.Fatalf("replacing the login secret lost the sudo password: login=%q sudo=%q", l, s)
	}
	// Only the sudo password: the login secret must survive.
	postForm(a.uiEditHost, "/ui/hosts/"+id+"/edit", id, url.Values{
		"hostname": {"h"}, "sudo_password": {"second"},
	})
	if l, s := open(); l != "PEM2" || s != "second" {
		t.Fatalf("changing only the sudo password: login=%q sudo=%q", l, s)
	}
}
