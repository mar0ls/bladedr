package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"bladedr/internal/store"
)

type postRoundTripFunc func(*http.Request) (*http.Response, error)

func (f postRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func withDefaultTransport(t *testing.T, fn postRoundTripFunc) {
	t.Helper()
	original := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: fn}
	t.Cleanup(func() { http.DefaultClient = original })
}

func response(status int) *http.Response {
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}
}

func TestPostSendsBatchWithBearer(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody []*store.Observation
	withDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		return response(http.StatusOK), nil
	})

	if err := post("https://control.example", "host-1", "tok", []*store.Observation{{RuleID: "r"}}); err != nil {
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
	withDefaultTransport(t, func(r *http.Request) (*http.Response, error) {
		gotAuth = r.Header.Get("Authorization")
		return response(http.StatusOK), nil
	})
	if err := post("https://control.example", "h", "", []*store.Observation{{RuleID: "r"}}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "" {
		t.Fatalf("no token should omit the Authorization header, got %q", gotAuth)
	}
}

func TestPostErrorsOnServerError(t *testing.T) {
	withDefaultTransport(t, func(*http.Request) (*http.Response, error) {
		return response(http.StatusInternalServerError), nil
	})
	if err := post("https://control.example", "h", "", []*store.Observation{{RuleID: "r"}}); err == nil {
		t.Fatal("post should return an error on a 5xx response")
	}
}
