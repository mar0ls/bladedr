package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"bladedr/internal/store"
)

func TestSchedulesCRUDAndRun(t *testing.T) {
	a, tok := newTestAPI(t)
	admin := tok[store.RoleAdmin]

	w := do(a, "POST", "/api/v1/schedules", admin, map[string]any{"name": "nightly", "interval_s": 900})
	if w.Code != http.StatusCreated {
		t.Fatalf("create schedule = %d (%s)", w.Code, w.Body)
	}
	var s store.Schedule
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil || s.ID == "" {
		t.Fatalf("create schedule response: %v (%s)", err, w.Body)
	}

	if w := do(a, "GET", "/api/v1/schedules", admin, nil); w.Code != http.StatusOK {
		t.Fatalf("list schedules = %d", w.Code)
	}
	if w := do(a, "GET", "/api/v1/schedules/"+s.ID, admin, nil); w.Code != http.StatusOK {
		t.Fatalf("get schedule = %d", w.Code)
	}
	if w := do(a, "PATCH", "/api/v1/schedules/"+s.ID, admin, map[string]any{"enabled": false}); w.Code != http.StatusOK {
		t.Fatalf("patch schedule = %d", w.Code)
	}
	if g, _ := a.Store.GetSchedule(context.Background(), s.ID); g != nil && g.Enabled {
		t.Fatal("patch enabled=false did not persist")
	}
	// Run with no hosts in the fleet: triggers zero scans but exercises the handler.
	if w := do(a, "POST", "/api/v1/schedules/"+s.ID+"/run", admin, nil); w.Code != http.StatusOK {
		t.Fatalf("run schedule = %d", w.Code)
	}
	if w := do(a, "DELETE", "/api/v1/schedules/"+s.ID, admin, nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete schedule = %d", w.Code)
	}
}

func TestCreateScheduleRejectsTooFrequent(t *testing.T) {
	a, tok := newTestAPI(t)
	w := do(a, "POST", "/api/v1/schedules", tok[store.RoleAdmin], map[string]any{"name": "x", "interval_s": 60})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("sub-5m interval = %d, want 400", w.Code)
	}
}

func TestCreateScheduleRejectsBadDuration(t *testing.T) {
	a, tok := newTestAPI(t)
	w := do(a, "POST", "/api/v1/schedules", tok[store.RoleAdmin], map[string]any{"name": "x", "interval": "banana"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid duration = %d, want 400", w.Code)
	}
}
