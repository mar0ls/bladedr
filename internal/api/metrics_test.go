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

func TestReadyzUnavailableWhenStoreDown(t *testing.T) {
	a := &API{Store: pingFailStore{store.NewMemory()}}
	w := httptest.NewRecorder()
	a.readyz(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz with store down = %d, want 503", w.Code)
	}
}
