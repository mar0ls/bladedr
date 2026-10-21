package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bladedr/internal/store"
)

func TestMetricsObserveAndWrite(t *testing.T) {
	m := newMetrics()
	m.observe("GET", 200, 10*time.Millisecond)
	m.observe("GET", 200, 20*time.Millisecond)
	m.observe("POST", 500, 5*time.Millisecond)

	var sb strings.Builder
	m.write(&sb)
	out := sb.String()

	if !strings.Contains(out, `bladedr_http_requests_total{method="GET",code="200"} 2`) {
		t.Errorf("missing/incorrect GET 200 counter:\n%s", out)
	}
	if !strings.Contains(out, `bladedr_http_requests_total{method="POST",code="500"} 1`) {
		t.Errorf("missing/incorrect POST 500 counter:\n%s", out)
	}
	if !strings.Contains(out, "bladedr_http_request_duration_seconds_count 3") {
		t.Errorf("duration count should be 3:\n%s", out)
	}
}

func TestStatusRecorderCapturesCode(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}
	rec.WriteHeader(http.StatusTeapot)
	if rec.status != http.StatusTeapot {
		t.Fatalf("statusRecorder.status = %d, want %d", rec.status, http.StatusTeapot)
	}
}

func TestStatusRecorderKeepsFirstStatus(t *testing.T) {
	underlying := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: underlying, status: http.StatusOK}
	rec.WriteHeader(http.StatusAccepted)
	rec.WriteHeader(http.StatusInternalServerError)

	if rec.status != http.StatusAccepted || underlying.Code != http.StatusAccepted {
		t.Fatalf("status = %d, underlying = %d; want first status %d",
			rec.status, underlying.Code, http.StatusAccepted)
	}
}

func TestStatusRecorderWriteCommitsOK(t *testing.T) {
	underlying := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: underlying, status: http.StatusOK}
	if _, err := rec.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	rec.WriteHeader(http.StatusInternalServerError)

	if rec.status != http.StatusOK || underlying.Code != http.StatusOK {
		t.Fatalf("status = %d, underlying = %d; want 200", rec.status, underlying.Code)
	}
}

func TestReadyzOK(t *testing.T) {
	a := &API{Store: store.NewMemory()}
	w := httptest.NewRecorder()
	a.readyz(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("readyz with healthy store = %d, want 200", w.Code)
	}
}

// pingFailStore is a store whose Ping always fails, for the readiness-down path.
type pingFailStore struct{ *store.Memory }

func (pingFailStore) Ping(context.Context) error { return errors.New("db down") }

// auditFailStore is a store whose AppendAudit always fails, for the
// audit-append-failure regression test: a disk-full or unreachable audit backend
// must not vanish silently.
type auditFailStore struct{ *store.Memory }

func (auditFailStore) AppendAudit(context.Context, *store.AuditEvent) error {
	return errors.New("audit backend unavailable")
}

// TestAuditFailureIsCountedNotSwallowed is the regression test for the
// repudiation finding: AppendAudit's error used to be discarded outright
// (`_ = a.Store.AppendAudit(...)`), so an audit backend that was down left
// zero trace that anything had gone unrecorded. A failed write must now surface
// through the metrics counter, so it can be scraped and alerted on.
func TestAuditFailureIsCountedNotSwallowed(t *testing.T) {
	a := &API{Store: auditFailStore{store.NewMemory()}, metrics: newMetrics()}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	a.auditAs(r, "someone", "test.action", "target", "ok", "")

	var sb strings.Builder
	a.metrics.write(&sb)
	if !strings.Contains(sb.String(), "bladedr_audit_append_failures_total 1") {
		t.Fatalf("audit failure was not counted:\n%s", sb.String())
	}
}

func TestAuditSuccessDoesNotCountAsFailure(t *testing.T) {
	a := &API{Store: store.NewMemory(), metrics: newMetrics()}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	a.auditAs(r, "someone", "test.action", "target", "ok", "")

	var sb strings.Builder
	a.metrics.write(&sb)
	if !strings.Contains(sb.String(), "bladedr_audit_append_failures_total 0") {
		t.Fatalf("a successful append must not be counted as a failure:\n%s", sb.String())
	}
}

func TestReadyzUnavailableWhenStoreDown(t *testing.T) {
	a := &API{Store: pingFailStore{store.NewMemory()}}
	w := httptest.NewRecorder()
	a.readyz(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz with store down = %d, want 503", w.Code)
	}
}
