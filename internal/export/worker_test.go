package export

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"bladedr/internal/store"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWorkerDeliversWebhookFromOutbox(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		if r.Header.Get("Idempotency-Key") == "" {
			t.Error("missing Idempotency-Key")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type = %q", r.Header.Get("Content-Type"))
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}

	ctx := context.Background()
	st := store.NewMemory()
	target := &store.ExportTarget{Name: "test", Type: store.ExportWebhook,
		Config: map[string]string{"url": "https://siem.example/ingest"}, Enabled: true}
	if err := st.CreateExportTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	host := &store.Host{Hostname: "web"}
	_ = st.CreateHost(ctx, host)
	_, err := st.UpsertObservation(ctx, &store.Observation{
		HostID: host.ID, Source: store.SourceAgentlessProbe, RuleID: "r1", Title: "alert",
		Severity: "high", DedupKey: "d1",
	})
	if err != nil {
		t.Fatal(err)
	}
	worker := &Worker{Store: st, HTTPClient: client}
	worked, err := worker.RunOne(ctx)
	if err != nil || !worked {
		t.Fatalf("RunOne = %v, %v", worked, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("webhook calls = %d, want 1", calls.Load())
	}
	if worked, err := worker.RunOne(ctx); err != nil || worked {
		t.Fatalf("completed delivery was claimed again: %v, %v", worked, err)
	}
}

func TestDisabledTargetDoesNotCreateDelivery(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.CreateExportTarget(ctx, &store.ExportTarget{Name: "off", Type: store.ExportWebhook,
		Config: map[string]string{"url": "https://example.invalid"}, Enabled: false})
	host := &store.Host{Hostname: "web"}
	_ = st.CreateHost(ctx, host)
	_, _ = st.UpsertObservation(ctx, &store.Observation{HostID: host.ID, RuleID: "r", Severity: "low", DedupKey: "d"})
	worked, err := (&Worker{Store: st}).RunOne(ctx)
	if err != nil || worked {
		t.Fatalf("disabled target produced work: %v, %v", worked, err)
	}
}
