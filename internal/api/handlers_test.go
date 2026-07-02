package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bladedr/internal/store"
)

// seedObs plants a store.Observation directly and returns it.
func seedObs(t *testing.T, st store.Store, hostID, ruleID, severity string) *store.Observation {
	t.Helper()
	o := &store.Observation{
		HostID:    hostID,
		Source:    store.SourceAgentlessProbe,
		RuleID:    ruleID,
		Category:  "process",
		Title:     ruleID + " finding",
		Severity:  severity,
		Score:     70,
		DedupKey:  ruleID + "|" + hostID,
		Status:    store.ObsOpen,
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
		Count:     1,
	}
	_, err := st.UpsertObservation(context.Background(), o)
	if err != nil {
		t.Fatalf("seed observation: %v", err)
	}
	return o
}

// --- hosts ---

func TestCreateHostMinimal(t *testing.T) {
	a, tokens := newTestAPI(t)
	w := do(a, http.MethodPost, "/api/v1/hosts", tokens[store.RoleOperator],
		map[string]string{"hostname": "web-01", "primary_ip": "10.0.0.5"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create host = %d; body=%s", w.Code, w.Body.String())
	}
	var h store.Host
	if err := json.Unmarshal(w.Body.Bytes(), &h); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if h.ID == "" {
		t.Error("host ID not assigned")
	}
	if h.SSHPort != 22 {
		t.Errorf("default SSH port = %d, want 22", h.SSHPort)
	}
	if h.Mode != store.ModeScanOnly {
		t.Errorf("default mode = %q, want %q", h.Mode, store.ModeScanOnly)
	}
	if h.Status != store.StatusPending {
		t.Errorf("initial status = %q, want %q", h.Status, store.StatusPending)
	}
}

func TestCreateHostMissingIPAndHostname(t *testing.T) {
	a, tokens := newTestAPI(t)
	w := do(a, http.MethodPost, "/api/v1/hosts", tokens[store.RoleOperator],
		map[string]string{"ssh_port": "22"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("no-ip-no-hostname = %d, want 400", w.Code)
	}
}

func TestGetHost(t *testing.T) {
	a, tokens := newTestAPI(t)
	// create
	w := do(a, http.MethodPost, "/api/v1/hosts", tokens[store.RoleOperator],
		map[string]string{"hostname": "db-01", "primary_ip": "10.0.0.6"})
	var h store.Host
	json.Unmarshal(w.Body.Bytes(), &h)

	w = do(a, http.MethodGet, "/api/v1/hosts/"+h.ID, tokens[store.RoleViewer], nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get host = %d", w.Code)
	}
	var got store.Host
	json.Unmarshal(w.Body.Bytes(), &got)
	if got.Hostname != "db-01" {
		t.Errorf("hostname = %q, want db-01", got.Hostname)
	}
}

func TestGetHostNotFound(t *testing.T) {
	a, tokens := newTestAPI(t)
	w := do(a, http.MethodGet, "/api/v1/hosts/does-not-exist", tokens[store.RoleViewer], nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing host = %d, want 404", w.Code)
	}
}

func TestListHosts(t *testing.T) {
	a, tokens := newTestAPI(t)
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		do(a, http.MethodPost, "/api/v1/hosts", tokens[store.RoleOperator],
			map[string]string{"primary_ip": ip})
	}
	w := do(a, http.MethodGet, "/api/v1/hosts", tokens[store.RoleViewer], nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list hosts = %d", w.Code)
	}
	var hosts []store.Host
	json.Unmarshal(w.Body.Bytes(), &hosts)
	if len(hosts) < 3 {
		t.Errorf("got %d hosts, want ≥3", len(hosts))
	}
}

func TestDeleteHost(t *testing.T) {
	a, tokens := newTestAPI(t)
	w := do(a, http.MethodPost, "/api/v1/hosts", tokens[store.RoleOperator],
		map[string]string{"hostname": "temp", "primary_ip": "10.1.1.1"})
	var h store.Host
	json.Unmarshal(w.Body.Bytes(), &h)

	w = do(a, http.MethodDelete, "/api/v1/hosts/"+h.ID, tokens[store.RoleOperator], nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204", w.Code)
	}
	w = do(a, http.MethodGet, "/api/v1/hosts/"+h.ID, tokens[store.RoleViewer], nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("get-after-delete = %d, want 404", w.Code)
	}
}

func TestViewerCannotDeleteHost(t *testing.T) {
	a, tokens := newTestAPI(t)
	w := do(a, http.MethodPost, "/api/v1/hosts", tokens[store.RoleOperator],
		map[string]string{"hostname": "keep", "primary_ip": "10.1.1.2"})
	var h store.Host
	json.Unmarshal(w.Body.Bytes(), &h)

	w = do(a, http.MethodDelete, "/api/v1/hosts/"+h.ID, tokens[store.RoleViewer], nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer delete = %d, want 403", w.Code)
	}
}

// --- observations ---

func TestListObservationsEmpty(t *testing.T) {
	a, tokens := newTestAPI(t)
	w := do(a, http.MethodGet, "/api/v1/observations", tokens[store.RoleViewer], nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list obs = %d", w.Code)
	}
	// empty list is null or [] — both are fine
	body := strings.TrimSpace(w.Body.String())
	if body != "null\n" && body != "[]\n" && body != "null" && body != "[]" {
		t.Errorf("empty list body = %q", body)
	}
}

func TestListObservationsFilterBySeverity(t *testing.T) {
	a, tokens := newTestAPI(t)
	w := do(a, http.MethodPost, "/api/v1/hosts", tokens[store.RoleOperator],
		map[string]string{"hostname": "h1", "primary_ip": "10.0.1.1"})
	var h store.Host
	json.Unmarshal(w.Body.Bytes(), &h)

	seedObs(t, a.Store, h.ID, "rule-critical", "critical")
	seedObs(t, a.Store, h.ID, "rule-low", "low")

	// filter by host
	w = do(a, http.MethodGet, "/api/v1/observations?host="+h.ID, tokens[store.RoleViewer], nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list obs by host = %d", w.Code)
	}
	var obs []store.Observation
	json.Unmarshal(w.Body.Bytes(), &obs)
	if len(obs) != 2 {
		t.Errorf("got %d obs for host, want 2", len(obs))
	}

	// filter by severity
	w = do(a, http.MethodGet, "/api/v1/observations?host="+h.ID+"&severity=critical",
		tokens[store.RoleViewer], nil)
	json.Unmarshal(w.Body.Bytes(), &obs)
	if len(obs) != 1 || obs[0].RuleID != "rule-critical" {
		t.Errorf("severity filter: got %d obs", len(obs))
	}
}

func TestPatchObservationTriage(t *testing.T) {
	a, tokens := newTestAPI(t)
	w := do(a, http.MethodPost, "/api/v1/hosts", tokens[store.RoleOperator],
		map[string]string{"hostname": "triage-host", "primary_ip": "10.0.2.1"})
	var h store.Host
	json.Unmarshal(w.Body.Bytes(), &h)

	o := seedObs(t, a.Store, h.ID, "suspicious-port-listener", "high")

	// acknowledge
	w = do(a, http.MethodPatch, "/api/v1/observations/"+o.ID, tokens[store.RoleOperator],
		map[string]string{"status": store.ObsAcknowledged})
	if w.Code != http.StatusNoContent {
		t.Fatalf("acknowledge = %d; body=%s", w.Code, w.Body.String())
	}
	updated, _ := a.Store.GetObservation(context.Background(), o.ID)
	if updated.Status != store.ObsAcknowledged {
		t.Errorf("status = %q, want acknowledged", updated.Status)
	}

	// false positive
	w = do(a, http.MethodPatch, "/api/v1/observations/"+o.ID, tokens[store.RoleOperator],
		map[string]string{"status": store.ObsFalsePositive})
	if w.Code != http.StatusNoContent {
		t.Fatalf("false_positive = %d", w.Code)
	}

	// invalid status
	w = do(a, http.MethodPatch, "/api/v1/observations/"+o.ID, tokens[store.RoleOperator],
		map[string]string{"status": "irrelevant"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid status = %d, want 400", w.Code)
	}
}

func TestBulkObservationsTriage(t *testing.T) {
	a, tokens := newTestAPI(t)
	w := do(a, http.MethodPost, "/api/v1/hosts", tokens[store.RoleOperator],
		map[string]string{"hostname": "bulk-host", "primary_ip": "10.0.3.1"})
	var h store.Host
	json.Unmarshal(w.Body.Bytes(), &h)

	o1 := seedObs(t, a.Store, h.ID, "rule-a", "high")
	o2 := seedObs(t, a.Store, h.ID, "rule-b", "medium")
	o3 := seedObs(t, a.Store, h.ID, "rule-c", "low")

	w = do(a, http.MethodPost, "/api/v1/observations/bulk", tokens[store.RoleOperator],
		map[string]any{"ids": []string{o1.ID, o2.ID, o3.ID}, "status": store.ObsResolved})
	if w.Code != http.StatusOK {
		t.Fatalf("bulk = %d; body=%s", w.Code, w.Body.String())
	}
	var result map[string]int
	json.Unmarshal(w.Body.Bytes(), &result)
	if result["updated"] != 3 {
		t.Errorf("bulk updated = %d, want 3", result["updated"])
	}
	// verify one
	got, _ := a.Store.GetObservation(context.Background(), o1.ID)
	if got.Status != store.ObsResolved {
		t.Errorf("o1 status = %q, want resolved", got.Status)
	}
}

func TestBulkObservationsInvalidStatus(t *testing.T) {
	a, tokens := newTestAPI(t)
	w := do(a, http.MethodPost, "/api/v1/observations/bulk", tokens[store.RoleOperator],
		map[string]any{"ids": []string{"x"}, "status": "deleted"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid bulk status = %d, want 400", w.Code)
	}
}

// --- rules ---

const testRule = `id: test-loader
title: "Process named loader"
category: process
severity: medium
foreach: processes
when: 'item.comm == "loader"'
evidence:
  pid: item.pid
  comm: item.comm
`

func TestCreateAndListRule(t *testing.T) {
	a, tokens := newTestAPI(t)
	// create
	req, _ := newTextRequest(http.MethodPost, "/api/v1/rules", tokens[store.RoleOperator], testRule)
	w := doReq(a, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create rule = %d; body=%s", w.Code, w.Body.String())
	}
	var rec store.RuleRecord
	json.Unmarshal(w.Body.Bytes(), &rec)
	if rec.ID != "test-loader" {
		t.Errorf("rule id = %q", rec.ID)
	}

	// list
	w = do(a, http.MethodGet, "/api/v1/rules", tokens[store.RoleViewer], nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list rules = %d", w.Code)
	}
	var rules []store.RuleRecord
	json.Unmarshal(w.Body.Bytes(), &rules)
	found := false
	for _, r := range rules {
		if r.ID == "test-loader" {
			found = true
		}
	}
	if !found {
		t.Error("created rule not in list")
	}
}

func TestCreateRuleInvalidCEL(t *testing.T) {
	a, tokens := newTestAPI(t)
	bad := `id: bad-rule
title: "bad"
category: process
severity: medium
foreach: processes
when: 'item.comm ==== broken syntax'
`
	req, _ := newTextRequest(http.MethodPost, "/api/v1/rules", tokens[store.RoleOperator], bad)
	w := doReq(a, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid CEL rule = %d, want 400", w.Code)
	}
}

func TestPatchAndDeleteRule(t *testing.T) {
	a, tokens := newTestAPI(t)
	req, _ := newTextRequest(http.MethodPost, "/api/v1/rules", tokens[store.RoleOperator], testRule)
	doReq(a, req)

	// disable
	w := do(a, http.MethodPatch, "/api/v1/rules/test-loader", tokens[store.RoleOperator],
		map[string]bool{"enabled": false})
	if w.Code != http.StatusNoContent {
		t.Fatalf("patch rule = %d; body=%s", w.Code, w.Body.String())
	}

	// delete
	w = do(a, http.MethodDelete, "/api/v1/rules/test-loader", tokens[store.RoleOperator], nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete rule = %d", w.Code)
	}
	// verify gone
	w = do(a, http.MethodGet, "/api/v1/rules", tokens[store.RoleViewer], nil)
	var rs []store.RuleRecord
	json.Unmarshal(w.Body.Bytes(), &rs)
	for _, r := range rs {
		if r.ID == "test-loader" {
			t.Error("rule still present after delete")
		}
	}
}

func TestViewerCannotCreateRule(t *testing.T) {
	a, tokens := newTestAPI(t)
	req, _ := newTextRequest(http.MethodPost, "/api/v1/rules", tokens[store.RoleViewer], testRule)
	w := doReq(a, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer create rule = %d, want 403", w.Code)
	}
}

// --- schedules ---

func TestCreateAndListSchedule(t *testing.T) {
	a, tokens := newTestAPI(t)
	// create host first
	wh := do(a, http.MethodPost, "/api/v1/hosts", tokens[store.RoleOperator],
		map[string]string{"hostname": "sched-host", "primary_ip": "10.0.5.1"})
	var h store.Host
	json.Unmarshal(wh.Body.Bytes(), &h)

	body := map[string]any{"name": "nightly", "host_id": h.ID, "interval_s": 3600, "enabled": true}
	w := do(a, http.MethodPost, "/api/v1/schedules", tokens[store.RoleOperator], body)
	if w.Code != http.StatusCreated {
		t.Fatalf("create schedule = %d; body=%s", w.Code, w.Body.String())
	}
	var sc store.Schedule
	json.Unmarshal(w.Body.Bytes(), &sc)
	if sc.ID == "" {
		t.Error("schedule id not assigned")
	}
	if sc.IntervalS != 3600 {
		t.Errorf("interval = %d, want 3600", sc.IntervalS)
	}

	// list
	w = do(a, http.MethodGet, "/api/v1/schedules", tokens[store.RoleViewer], nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list schedules = %d", w.Code)
	}
}

// --- helpers used in this file ---

func newTextRequest(method, path, token, body string) (*http.Request, *httptest.ResponseRecorder) {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "text/plain")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r, httptest.NewRecorder()
}

func doReq(a *API, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.Routes().ServeHTTP(w, r)
	return w
}
