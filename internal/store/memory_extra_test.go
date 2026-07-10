package store

import (
	"context"
	"testing"
	"time"
)

func TestMemoryHostCRUD(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	h := &Host{Hostname: "web-01", PrimaryIP: "10.0.0.5"}
	if err := m.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if h.ID == "" {
		t.Fatal("CreateHost should assign an ID")
	}
	got, err := m.GetHost(ctx, h.ID)
	if err != nil || got.Hostname != "web-01" {
		t.Fatalf("GetHost = %v, %v", got, err)
	}
	h.Hostname = "web-01-renamed"
	if err := m.UpdateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if got, _ = m.GetHost(ctx, h.ID); got.Hostname != "web-01-renamed" {
		t.Fatalf("UpdateHost did not persist: %q", got.Hostname)
	}
	if err := m.DeleteHost(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetHost(ctx, h.ID); err == nil {
		t.Fatal("GetHost after delete should error")
	}
}

func TestMemoryUsersAndSessions(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	if n, _ := m.CountUsers(ctx); n != 0 {
		t.Fatalf("fresh store should have 0 users, got %d", n)
	}
	u := &User{Username: "alice", PasswordHash: "hash", Role: RoleAdmin}
	if err := m.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if n, _ := m.CountUsers(ctx); n != 1 {
		t.Fatalf("CountUsers = %d, want 1", n)
	}
	byName, err := m.GetUserByName(ctx, "alice")
	if err != nil || byName.ID != u.ID {
		t.Fatalf("GetUserByName = %v, %v", byName, err)
	}
	if _, err := m.GetUserByName(ctx, "nobody"); err == nil {
		t.Fatal("GetUserByName for unknown user should error")
	}

	// A live session resolves to its user; an expired one does not.
	live := &Session{Token: "live", UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)}
	expired := &Session{Token: "expired", UserID: u.ID, ExpiresAt: time.Now().Add(-time.Minute)}
	_ = m.CreateSession(ctx, live)
	_ = m.CreateSession(ctx, expired)
	if su, err := m.SessionUser(ctx, "live"); err != nil || su.Username != "alice" {
		t.Fatalf("SessionUser(live) = %v, %v", su, err)
	}
	if _, err := m.SessionUser(ctx, "expired"); err == nil {
		t.Fatal("SessionUser(expired) should error")
	}
	if _, err := m.SessionUser(ctx, "nonexistent"); err == nil {
		t.Fatal("SessionUser(unknown) should error")
	}
	if err := m.DeleteSession(ctx, "live"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SessionUser(ctx, "live"); err == nil {
		t.Fatal("SessionUser after DeleteSession should error")
	}
}

func TestMemoryDeleteExpiredSessions(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	u := &User{Username: "u", Role: RoleViewer}
	if err := m.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	_ = m.CreateSession(ctx, &Session{Token: "live", UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)})
	_ = m.CreateSession(ctx, &Session{Token: "dead", UserID: u.ID, ExpiresAt: time.Now().Add(-time.Hour)})

	n, err := m.DeleteExpiredSessions(ctx)
	if err != nil || n != 1 {
		t.Fatalf("DeleteExpiredSessions = %d, %v; want 1, nil", n, err)
	}
	if _, err := m.SessionUser(ctx, "live"); err != nil {
		t.Fatalf("live session should survive the prune: %v", err)
	}
	if again, _ := m.DeleteExpiredSessions(ctx); again != 0 {
		t.Fatalf("second prune should remove nothing, got %d", again)
	}
}

func TestMemoryObservationDedup(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	hostID := "host-1"

	first := &Observation{HostID: hostID, RuleID: "r1", DedupKey: "k1", Severity: "high", Score: 50, Source: "probe"}
	saved, err := m.UpsertObservation(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Count != 1 || saved.ID == "" || saved.Status != ObsOpen {
		t.Fatalf("first upsert: count=%d id=%q status=%q", saved.Count, saved.ID, saved.Status)
	}

	// Same host + dedup key collapses onto the same row and bumps Count/Score.
	dup := &Observation{HostID: hostID, RuleID: "r1", DedupKey: "k1", Severity: "critical", Score: 80, Source: "probe"}
	saved2, err := m.UpsertObservation(ctx, dup)
	if err != nil {
		t.Fatal(err)
	}
	if saved2.ID != saved.ID {
		t.Fatalf("dedup should reuse the row: %q != %q", saved2.ID, saved.ID)
	}
	if saved2.Count != 2 {
		t.Fatalf("dedup Count = %d, want 2", saved2.Count)
	}
	if saved2.Score != 80 || saved2.Severity != "critical" {
		t.Fatalf("dedup should refresh score/severity: score=%d sev=%q", saved2.Score, saved2.Severity)
	}

	// A different dedup key is a distinct observation.
	other := &Observation{HostID: hostID, RuleID: "r2", DedupKey: "k2", Severity: "low", Source: "probe"}
	if _, err := m.UpsertObservation(ctx, other); err != nil {
		t.Fatal(err)
	}
	all, _ := m.ListObservations(ctx, ObservationFilter{HostID: hostID})
	if len(all) != 2 {
		t.Fatalf("expected 2 distinct observations, got %d", len(all))
	}
}

func TestMemoryObservationFilterAndStatus(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	seed := []*Observation{
		{HostID: "h1", RuleID: "rootkit-x", DedupKey: "a", Severity: "critical", Source: "probe", Title: "rootkit found"},
		{HostID: "h1", RuleID: "cron-y", DedupKey: "b", Severity: "low", Source: "probe", Title: "odd cron"},
		{HostID: "h2", RuleID: "exec-z", DedupKey: "c", Severity: "critical", Source: "ebpf_sensor", Title: "exec from tmp"},
	}
	for _, o := range seed {
		if _, err := m.UpsertObservation(ctx, o); err != nil {
			t.Fatal(err)
		}
	}

	if got, _ := m.ListObservations(ctx, ObservationFilter{Severity: "critical"}); len(got) != 2 {
		t.Fatalf("severity=critical -> %d, want 2", len(got))
	}
	if got, _ := m.ListObservations(ctx, ObservationFilter{Source: "ebpf_sensor"}); len(got) != 1 {
		t.Fatalf("source=ebpf_sensor -> %d, want 1", len(got))
	}
	if got, _ := m.ListObservations(ctx, ObservationFilter{HostID: "h1"}); len(got) != 2 {
		t.Fatalf("host=h1 -> %d, want 2", len(got))
	}
	if got, _ := m.ListObservations(ctx, ObservationFilter{Query: "rootkit"}); len(got) != 1 {
		t.Fatalf("query=rootkit -> %d, want 1", len(got))
	}

	// SetObservationStatus flips the row and is filterable.
	target, _ := m.ListObservations(ctx, ObservationFilter{Query: "rootkit"})
	if err := m.SetObservationStatus(ctx, target[0].ID, ObsFalsePositive); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.ListObservations(ctx, ObservationFilter{Status: ObsFalsePositive}); len(got) != 1 {
		t.Fatalf("status=false_positive -> %d, want 1", len(got))
	}
	if err := m.SetObservationStatus(ctx, "no-such-id", ObsResolved); err == nil {
		t.Fatal("SetObservationStatus on unknown id should error")
	}
}

func TestMemoryAuditAppendAndList(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	for i, act := range []string{"login", "user.create", "logout"} {
		e := &AuditEvent{Actor: "alice", Action: act, Result: "ok", Time: time.Now().Add(time.Duration(i) * time.Second)}
		if err := m.AppendAudit(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	all, err := m.ListAudit(ctx, 0) // 0 = no limit
	if err != nil || len(all) != 3 {
		t.Fatalf("ListAudit(0) = %d events, %v", len(all), err)
	}
	if all[0].Action != "logout" {
		t.Fatalf("ListAudit should be newest-first, got %q first", all[0].Action)
	}
	if limited, _ := m.ListAudit(ctx, 2); len(limited) != 2 {
		t.Fatalf("ListAudit(2) = %d, want 2", len(limited))
	}
}

func TestMemoryBaselineLifecycle(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	if _, err := m.GetBaseline(ctx, "h1"); err == nil {
		t.Fatal("GetBaseline before save should error")
	}
	b := &Baseline{HostID: "h1", Digest: map[string][]string{"ports": {"22", "443"}}}
	if err := m.SaveBaseline(ctx, b); err != nil {
		t.Fatal(err)
	}
	got, err := m.GetBaseline(ctx, "h1")
	if err != nil || len(got.Digest["ports"]) != 2 {
		t.Fatalf("GetBaseline = %v, %v", got, err)
	}
	if err := m.DeleteBaseline(ctx, "h1"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetBaseline(ctx, "h1"); err == nil {
		t.Fatal("GetBaseline after delete should error")
	}
}

func TestMemoryRuleRecords(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	r := &RuleRecord{ID: "my-rule", Source: "user", Category: "process", Severity: "high", Enabled: true, Definition: []byte(`{"id":"my-rule"}`)}
	if err := m.UpsertRule(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, err := m.GetRule(ctx, "my-rule")
	if err != nil || got.Severity != "high" {
		t.Fatalf("GetRule = %v, %v", got, err)
	}
	if err := m.SetRuleEnabled(ctx, "my-rule", false); err != nil {
		t.Fatal(err)
	}
	if got, _ = m.GetRule(ctx, "my-rule"); got.Enabled {
		t.Fatal("SetRuleEnabled(false) did not persist")
	}
	if list, _ := m.ListRules(ctx); len(list) != 1 {
		t.Fatalf("ListRules = %d, want 1", len(list))
	}
	if err := m.DeleteRule(ctx, "my-rule"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetRule(ctx, "my-rule"); err == nil {
		t.Fatal("GetRule after delete should error")
	}
}
