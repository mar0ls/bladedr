package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"bladedr/internal/store"
)

func TestObservationCursorPagination(t *testing.T) {
	a, tokens := newTestAPI(t)
	ctx := context.Background()
	h := &store.Host{Hostname: "h"}
	_ = a.Store.CreateHost(ctx, h)
	for _, id := range []string{"a", "b", "c"} {
		_, err := a.Store.UpsertObservation(ctx, &store.Observation{
			HostID: h.ID, RuleID: id, Severity: "low", Source: store.SourceAgentlessProbe, DedupKey: id,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	first := do(a, http.MethodGet, "/api/v1/observations?limit=2", tokens[store.RoleViewer], nil)
	if first.Code != http.StatusOK {
		t.Fatalf("first page = %d", first.Code)
	}
	cursor := first.Header().Get("X-Next-Cursor")
	if cursor == "" {
		t.Fatal("first page did not return a cursor")
	}
	var page1 []store.Observation
	_ = json.Unmarshal(first.Body.Bytes(), &page1)
	second := do(a, http.MethodGet, "/api/v1/observations?limit=2&cursor="+cursor, tokens[store.RoleViewer], nil)
	var page2 []store.Observation
	_ = json.Unmarshal(second.Body.Bytes(), &page2)
	if len(page1) != 2 || len(page2) != 1 {
		t.Fatalf("page sizes = %d, %d", len(page1), len(page2))
	}
	if page1[0].ID == page2[0].ID || page1[1].ID == page2[0].ID {
		t.Fatal("cursor repeated an observation")
	}
}
