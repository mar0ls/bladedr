package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"bladedr/internal/scan"
	"bladedr/internal/store"
)

// TestWriteErrSensorNotConfiguredIs503 is a direct unit test on the dispatcher: a missing
// local setup (no sensor binary/policy bundle/SSH wiring) must answer 503, the same code
// every other "this install isn't set up for that" error in the API already uses — not
// 502, which claims the host was unreachable when it was never contacted.
func TestWriteErrSensorNotConfiguredIs503(t *testing.T) {
	w := httptest.NewRecorder()
	writeErr(w, scan.ErrSensorNotConfigured("no policy bundle configured (set BLADEDR_POLICY_DIR)"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

// TestHostSensorEnableUnconfiguredIs503 drives the real route: clicking "Enable" on a
// host when the server has no policy bundle used to answer 502 (discovered 2026-10-11 in
// the console: enable, 502, the operator deleted the host assuming it was broken).
func TestHostSensorEnableUnconfiguredIs503(t *testing.T) {
	a, tokens := newTestAPI(t)
	// No SensorBins/PolicyTar configured: the first EnableSensor precondition it hits.
	a.Runner = &scan.Runner{Store: a.Store}
	host := &store.Host{Hostname: "h"}
	if err := a.Store.CreateHost(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	w := do(a, "POST", "/api/v1/hosts/"+host.ID+"/sensor", tokens[store.RoleAdmin], map[string]string{"action": "enable"})
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusServiceUnavailable, w.Body)
	}
}
