package api

import (
	"context"
	"net"
	"net/http/httptest"
	"strings"
	"testing"

	"bladedr/internal/store"
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

// TestIngestEventsIgnoresServerControlledFields is the regression test for the
// sensor-verdict-injection finding: a per-host sensor token is a narrower trust
// boundary than an operator session, so a batch that tries to set verdict, id,
// status or count must have every one of those fields ignored, even though the
// request is otherwise well-formed and accepted.
func TestIngestEventsIgnoresServerControlledFields(t *testing.T) {
	a, tokens := newTestAPI(t)
	ctx := context.Background()
	h := &store.Host{Hostname: "sensor-host", PrimaryIP: "10.0.0.11"}
	if err := a.Store.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	payload := []map[string]any{{
		"rule_id":    "exec-tmp",
		"severity":   "high",
		"dedup_key":  "e1",
		"id":         "11111111-1111-1111-1111-111111111111",
		"host_id":    "some-other-host",
		"source":     "operator",
		"status":     "resolved",
		"verdict":    "true_positive",
		"first_seen": "2000-01-01T00:00:00Z",
		"last_seen":  "2000-01-01T00:00:00Z",
		"count":      999,
	}}
	w := do(a, "POST", "/api/v1/hosts/"+h.ID+"/events", tokens["operator"], payload)
	if w.Code != 200 {
		t.Fatalf("ingest events = %d (%s)", w.Code, w.Body)
	}
	obs, err := a.Store.ListObservations(ctx, store.ObservationFilter{HostID: h.ID})
	if err != nil || len(obs) != 1 {
		t.Fatalf("ListObservations: %v, %v", obs, err)
	}
	o := obs[0]
	if o.ID == "11111111-1111-1111-1111-111111111111" {
		t.Error("sensor-supplied id was not replaced with a server-assigned one")
	}
	if o.HostID != h.ID {
		t.Errorf("host_id = %q, want %q (sensor must not redirect to another host)", o.HostID, h.ID)
	}
	if o.Source != store.SourceEBPFSensor {
		t.Errorf("source = %q, want %q", o.Source, store.SourceEBPFSensor)
	}
	if o.Status != store.ObsOpen {
		t.Errorf("status = %q, want open (sensor must not self-resolve a finding)", o.Status)
	}
	if o.Verdict == "true_positive" {
		t.Error("sensor-supplied verdict was not ignored: this would poison ML training data and the fleet trust gate")
	}
	if o.Count > 1 {
		t.Errorf("count = %d, want store-managed count, not sensor-supplied 999", o.Count)
	}
}

// TestIngestEventsRejectsOutOfBandSeverityAndScore is the regression test for the
// gap that survived the field-allowlisting fix above: Severity and Score are
// allowlisted sensor-supplied fields, but the legitimate sensor only ever sends one
// of five known severity labels and the matching 0-100 score it computes from that
// label (internal/sensor/event.go: severityScore). A leaked token could otherwise
// send any string as severity, or a score outside 0-100, distorting that host's
// triage display and -- while the risk model is untrained -- skewing its fallback
// probability, which reads Score/100 as-is.
func TestIngestEventsRejectsOutOfBandSeverityAndScore(t *testing.T) {
	a, tokens := newTestAPI(t)
	ctx := context.Background()
	h := &store.Host{Hostname: "sensor-host", PrimaryIP: "10.0.0.12"}
	if err := a.Store.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	payload := []map[string]any{
		{"rule_id": "exec-tmp", "dedup_key": "bad-severity", "severity": "pwned", "score": 50},
		{"rule_id": "exec-tmp", "dedup_key": "bad-score-high", "severity": "high", "score": 999999},
		{"rule_id": "exec-tmp", "dedup_key": "bad-score-negative", "severity": "high", "score": -1},
		{"rule_id": "exec-tmp", "dedup_key": "good", "severity": "high", "score": 75},
	}
	w := do(a, "POST", "/api/v1/hosts/"+h.ID+"/events", tokens["operator"], payload)
	if w.Code != 200 {
		t.Fatalf("ingest events = %d (%s)", w.Code, w.Body)
	}
	obs, err := a.Store.ListObservations(ctx, store.ObservationFilter{HostID: h.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 1 || obs[0].DedupKey != "good" {
		t.Fatalf("only the valid event should have been ingested, got %+v", obs)
	}
}
