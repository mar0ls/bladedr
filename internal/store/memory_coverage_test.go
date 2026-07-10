package store

import (
	"context"
	"testing"
	"time"
)

func TestMemorySchedules(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	s := &Schedule{Name: "nightly", IntervalS: 3600, Enabled: true, NextRun: time.Now()}
	if err := m.CreateSchedule(ctx, s); err != nil {
		t.Fatal(err)
	}
	if s.ID == "" {
		t.Fatal("CreateSchedule should assign an ID")
	}
	got, err := m.GetSchedule(ctx, s.ID)
	if err != nil || got.Name != "nightly" {
		t.Fatalf("GetSchedule = %v, %v", got, err)
	}
	s.Enabled = false
	if err := m.UpdateSchedule(ctx, s); err != nil {
		t.Fatal(err)
	}
	if g, _ := m.GetSchedule(ctx, s.ID); g.Enabled {
		t.Fatal("UpdateSchedule did not persist")
	}
	if list, _ := m.ListSchedules(ctx); len(list) != 1 {
		t.Fatalf("ListSchedules = %d, want 1", len(list))
	}
	if err := m.DeleteSchedule(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetSchedule(ctx, s.ID); err == nil {
		t.Fatal("GetSchedule after delete should error")
	}
}

func TestMemoryCredentials(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	c := &Credential{Name: "root-key", Username: "root", AuthType: "ssh_key", SecretEnc: []byte("sealed")}
	if err := m.CreateCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	if c.ID == "" {
		t.Fatal("CreateCredential should assign an ID")
	}
	got, err := m.GetCredential(ctx, c.ID)
	if err != nil || got.Username != "root" {
		t.Fatalf("GetCredential = %v, %v", got, err)
	}
	if list, _ := m.ListCredentials(ctx); len(list) != 1 {
		t.Fatalf("ListCredentials = %d, want 1", len(list))
	}
	if err := m.DeleteCredential(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetCredential(ctx, c.ID); err == nil {
		t.Fatal("GetCredential after delete should error")
	}
}

func TestMemoryScans(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	sc := &Scan{HostID: "h1", Trigger: "manual", Status: ScanRunning, StartedAt: time.Now()}
	if err := m.CreateScan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	if sc.ID == "" {
		t.Fatal("CreateScan should assign an ID")
	}
	sc.Status = ScanOK
	if err := m.UpdateScan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	got, err := m.GetScan(ctx, sc.ID)
	if err != nil || got.Status != ScanOK {
		t.Fatalf("GetScan = %v, %v", got, err)
	}
	if list, _ := m.ListScansByHost(ctx, "h1"); len(list) != 1 {
		t.Fatalf("ListScansByHost = %d, want 1", len(list))
	}
}

func TestMemoryUserUpdateDelete(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	u := &User{Username: "bob", Role: RoleOperator}
	if err := m.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	got, err := m.GetUser(ctx, u.ID)
	if err != nil || got.Username != "bob" {
		t.Fatalf("GetUser = %v, %v", got, err)
	}
	u.Role = RoleViewer
	u.Disabled = true
	if err := m.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if g, _ := m.GetUser(ctx, u.ID); g.Role != RoleViewer || !g.Disabled {
		t.Fatalf("UpdateUser did not persist: %+v", g)
	}
	if list, _ := m.ListUsers(ctx); len(list) != 1 {
		t.Fatalf("ListUsers = %d, want 1", len(list))
	}
	if err := m.DeleteUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetUser(ctx, u.ID); err == nil {
		t.Fatal("GetUser after delete should error")
	}
}

func TestMemoryGetObservationHostsBaselinesPing(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	o, err := m.UpsertObservation(ctx, &Observation{HostID: "h1", RuleID: "r", DedupKey: "k", Severity: "low", Source: "probe"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.GetObservation(ctx, o.ID)
	if err != nil || got.RuleID != "r" {
		t.Fatalf("GetObservation = %v, %v", got, err)
	}
	if _, err := m.GetObservation(ctx, "nope"); err == nil {
		t.Fatal("GetObservation(unknown) should error")
	}
	_ = m.CreateHost(ctx, &Host{Hostname: "a"})
	_ = m.CreateHost(ctx, &Host{Hostname: "b"})
	if hs, _ := m.ListHosts(ctx); len(hs) != 2 {
		t.Fatalf("ListHosts = %d, want 2", len(hs))
	}
	_ = m.SaveBaseline(ctx, &Baseline{HostID: "h1", Digest: map[string][]string{"x": {"1"}}})
	if bs, _ := m.ListBaselines(ctx); len(bs) != 1 {
		t.Fatalf("ListBaselines = %d, want 1", len(bs))
	}
	if err := m.Ping(ctx); err != nil {
		t.Fatalf("Ping = %v, want nil", err)
	}
}

func TestMemoryCollectionUpdateDelete(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	c := &Collection{Name: "x"}
	if err := m.CreateCollection(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := m.GetCollection(ctx, c.ID)
	if err != nil || got.Name != "x" {
		t.Fatalf("GetCollection = %v, %v", got, err)
	}
	c.Name = "y"
	if err := m.UpdateCollection(ctx, c); err != nil {
		t.Fatal(err)
	}
	if g, _ := m.GetCollection(ctx, c.ID); g.Name != "y" {
		t.Fatal("UpdateCollection did not persist")
	}
	if list, _ := m.ListCollections(ctx); len(list) != 1 {
		t.Fatalf("ListCollections = %d, want 1", len(list))
	}
	if err := m.DeleteCollection(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.GetCollection(ctx, c.ID); err == nil {
		t.Fatal("GetCollection after delete should error")
	}
}
