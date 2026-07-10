package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"bladedr/internal/store"
)

func TestCollectionsCRUDAndMembers(t *testing.T) {
	a, tok := newTestAPI(t)
	admin := tok[store.RoleAdmin]
	ctx := context.Background()

	h := &store.Host{Hostname: "c-host", PrimaryIP: "10.0.0.9"}
	if err := a.Store.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	w := do(a, "POST", "/api/v1/collections", admin, map[string]any{"name": "prod"})
	if w.Code != http.StatusCreated {
		t.Fatalf("create collection = %d, want 201", w.Code)
	}
	var col store.Collection
	if err := json.Unmarshal(w.Body.Bytes(), &col); err != nil || col.ID == "" {
		t.Fatalf("create collection response: %v (%s)", err, w.Body)
	}

	if w := do(a, "GET", "/api/v1/collections", admin, nil); w.Code != http.StatusOK {
		t.Fatalf("list collections = %d", w.Code)
	}
	if w := do(a, "GET", "/api/v1/collections/"+col.ID, admin, nil); w.Code != http.StatusOK {
		t.Fatalf("get collection = %d", w.Code)
	}
	if w := do(a, "PUT", "/api/v1/collections/"+col.ID+"/members/"+h.ID, admin, nil); w.Code != http.StatusNoContent {
		t.Fatalf("add member = %d", w.Code)
	}
	w = do(a, "GET", "/api/v1/collections/"+col.ID+"/hosts", admin, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("collection hosts = %d", w.Code)
	}
	var hosts []*store.Host
	_ = json.Unmarshal(w.Body.Bytes(), &hosts)
	if len(hosts) != 1 || hosts[0].ID != h.ID {
		t.Fatalf("resolved members = %v, want [%s]", hosts, h.ID)
	}
	if w := do(a, "DELETE", "/api/v1/collections/"+col.ID+"/members/"+h.ID, admin, nil); w.Code != http.StatusNoContent {
		t.Fatalf("remove member = %d", w.Code)
	}
	if w := do(a, "PATCH", "/api/v1/collections/"+col.ID, admin, map[string]any{"name": "prod2"}); w.Code != http.StatusOK {
		t.Fatalf("patch collection = %d", w.Code)
	}
	if w := do(a, "DELETE", "/api/v1/collections/"+col.ID, admin, nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete collection = %d", w.Code)
	}
	if w := do(a, "GET", "/api/v1/collections/"+col.ID, admin, nil); w.Code != http.StatusNotFound {
		t.Fatalf("get deleted collection = %d, want 404", w.Code)
	}
}

func TestCreateDynamicCollectionRequiresMatchTags(t *testing.T) {
	a, tok := newTestAPI(t)
	w := do(a, "POST", "/api/v1/collections", tok[store.RoleAdmin], map[string]any{"name": "dyn", "dynamic": true})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("dynamic collection without match_tags = %d, want 400", w.Code)
	}
}

func TestExportECS(t *testing.T) {
	a, tok := newTestAPI(t)
	ctx := context.Background()
	if _, err := a.Store.UpsertObservation(ctx, &store.Observation{
		HostID: "h1", RuleID: "rootkit-x", DedupKey: "d1", Severity: "critical", Source: "probe", Title: "rootkit",
	}); err != nil {
		t.Fatal(err)
	}
	w := do(a, "GET", "/api/v1/export/ecs", tok[store.RoleViewer], nil)
	if w.Code != http.StatusOK {
		t.Fatalf("export ecs = %d, want 200", w.Code)
	}
	if w.Body.Len() == 0 {
		t.Fatal("export ecs returned an empty body")
	}
}

func TestRiskEndpoints(t *testing.T) {
	a, tok := newTestAPI(t)
	for _, path := range []string{"/api/v1/risk/stats", "/api/v1/risk/observations"} {
		if w := do(a, "GET", path, tok[store.RoleViewer], nil); w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, w.Code)
		}
	}
}

func TestBaselineGetAndReset(t *testing.T) {
	a, tok := newTestAPI(t)
	admin := tok[store.RoleAdmin]
	// No baseline yet -> not found.
	if w := do(a, "GET", "/api/v1/hosts/h1/baseline", admin, nil); w.Code != http.StatusNotFound {
		t.Fatalf("missing baseline = %d, want 404", w.Code)
	}
	if err := a.Store.SaveBaseline(context.Background(), &store.Baseline{HostID: "h1", Digest: map[string][]string{"ports": {"22"}}}); err != nil {
		t.Fatal(err)
	}
	if w := do(a, "GET", "/api/v1/hosts/h1/baseline", admin, nil); w.Code != http.StatusOK {
		t.Fatalf("existing baseline = %d, want 200", w.Code)
	}
	if w := do(a, "DELETE", "/api/v1/hosts/h1/baseline", admin, nil); w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Fatalf("reset baseline = %d", w.Code)
	}
}

func TestGetScanNotFound(t *testing.T) {
	a, tok := newTestAPI(t)
	if w := do(a, "GET", "/api/v1/scans/does-not-exist", tok[store.RoleViewer], nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown scan = %d, want 404", w.Code)
	}
}

func TestIngestEventsViaSession(t *testing.T) {
	a, tok := newTestAPI(t)
	ctx := context.Background()
	h := &store.Host{Hostname: "sensor-host", PrimaryIP: "10.0.0.10"}
	if err := a.Store.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	events := []map[string]any{{"rule_id": "exec-tmp", "severity": "high", "dedup_key": "e1", "source": "ebpf_sensor"}}
	w := do(a, "POST", "/api/v1/hosts/"+h.ID+"/events", tok[store.RoleOperator], events)
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("ingest events = %d (%s)", w.Code, w.Body)
	}
	obs, _ := a.Store.ListObservations(ctx, store.ObservationFilter{HostID: h.ID})
	if len(obs) != 1 || obs[0].Source != "ebpf_sensor" {
		t.Fatalf("ingested observations = %v", obs)
	}
}
