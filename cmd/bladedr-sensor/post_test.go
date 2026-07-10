package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"bladedr/internal/store"
)

func TestPostSendsBatchWithBearer(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody []*store.Observation
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := post(srv.URL, "host-1", "tok", []*store.Observation{{RuleID: "r"}}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("Authorization = %q, want \"Bearer tok\"", gotAuth)
	}
	if gotPath != "/api/v1/hosts/host-1/events" {
		t.Fatalf("path = %q", gotPath)
	}
	if len(gotBody) != 1 || gotBody[0].RuleID != "r" {
		t.Fatalf("posted body = %v", gotBody)
	}
}

func TestPostOmitsAuthWithoutToken(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := post(srv.URL, "h", "", []*store.Observation{{RuleID: "r"}}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" {
		t.Fatalf("no token should omit the Authorization header, got %q", gotAuth)
	}
}

func TestPostErrorsOnServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := post(srv.URL, "h", "", []*store.Observation{{RuleID: "r"}}); err == nil {
		t.Fatal("post should return an error on a 5xx response")
	}
}
