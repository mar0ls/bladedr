package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClientAddsBearerAndFormatsJSON(t *testing.T) {
	c := &client{base: "https://control.example", token: "secret", http: &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.Header.Get("Authorization") != "Bearer secret" {
				t.Errorf("authorization = %q", r.Header.Get("Authorization"))
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Header: make(http.Header)}, nil
		}),
	}}
	var out bytes.Buffer
	if err := c.request(http.MethodGet, "/api/v1/hosts", nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"ok": true`) {
		t.Fatalf("output = %q", out.String())
	}
}

func TestResponsesRequestDefaultsToDryRunAndParsesParams(t *testing.T) {
	var request map[string]any
	c := &client{base: "https://control.example", token: "secret", http: &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path != "/api/v1/responses" || r.Method != http.MethodPost {
				t.Errorf("request = %s %s", r.Method, r.URL.Path)
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader(`{"id":"action-1"}`)), Header: make(http.Header)}, nil
		}),
	}}
	var out bytes.Buffer
	if err := responses(c, []string{"request", "--host", "host-1", "--playbook", "kill_process", "--param", "pid=42", "--param", "expected_exe=/usr/bin/test"}, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if request["dry_run"] != true {
		t.Fatalf("dry_run = %#v", request["dry_run"])
	}
	params, ok := request["params"].(map[string]any)
	if !ok || params["pid"] != "42" || params["expected_exe"] != "/usr/bin/test" {
		t.Fatalf("params = %#v", request["params"])
	}
}
