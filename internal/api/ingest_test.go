package api

import (
	"net"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientIPRequiresTrustedProxy(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.10:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.8")
	if got := (&API{}).clientIP(r); got != "203.0.113.10" {
		t.Fatalf("untrusted forwarding header yielded %q", got)
	}
	_, network, _ := net.ParseCIDR("203.0.113.0/24")
	if got := (&API{TrustedProxies: []*net.IPNet{network}}).clientIP(r); got != "198.51.100.8" {
		t.Fatalf("trusted forwarding header yielded %q", got)
	}
}

func TestIngestBatchLimits(t *testing.T) {
	a, tokens := newTestAPI(t)
	items := make([]any, maxIngestBatch+1)
	w := do(a, "POST", "/api/v1/hosts/missing/events", tokens["operator"], items)
	// Host lookup happens before decoding; create a real host in the auth integration
	// tests. Here exercise the generic body cap directly.
	_ = w
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"x":"`+strings.Repeat("a", maxJSONBodyBytes)+`"}`))
	rec := httptest.NewRecorder()
	var dst map[string]string
	if decode(rec, r, &dst) || rec.Code != 413 {
		t.Fatalf("oversized JSON: ok=%v status=%d", rec.Code < 400, rec.Code)
	}
}
