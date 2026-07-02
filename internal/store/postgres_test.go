package store

import (
	"context"
	"os"
	"testing"
)

// Integration test against a real PostgreSQL + pg_search (ParadeDB). Skipped
// unless BLADEDR_TEST_DATABASE_URL is set, e.g.:
//
//	docker compose up -d
//	psql "$DSN" -f internal/store/migrations/0001_init.sql
//	BLADEDR_TEST_DATABASE_URL="postgres://bladedr:bladedr@localhost:5432/bladedr" go test ./internal/store/
func TestPostgresRoundTrip(t *testing.T) {
	dsn := os.Getenv("BLADEDR_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set BLADEDR_TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	p, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer p.Close()

	// Credential (sealed bytes are opaque here).
	cred := &Credential{Name: "test", Username: "sandfly", AuthType: AuthSSHKey, SecretEnc: []byte("sealed-blob")}
	if err := p.CreateCredential(ctx, cred); err != nil {
		t.Fatalf("create credential: %v", err)
	}
	t.Cleanup(func() { _ = p.DeleteCredential(ctx, cred.ID) })

	// Host referencing the credential + a pinned host key.
	host := &Host{Hostname: "pg-host", PrimaryIP: "10.9.9.9", SSHPort: 22, CredentialID: cred.ID,
		SSHHostKey: "ssh-ed25519 AAAATESTKEY", Mode: ModeScanOnly, Status: StatusPending}
	if err := p.CreateHost(ctx, host); err != nil {
		t.Fatalf("create host: %v", err)
	}
	t.Cleanup(func() { _ = p.DeleteHost(ctx, host.ID) })

	got, err := p.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}
	if got.CredentialID != cred.ID || got.SSHHostKey != "ssh-ed25519 AAAATESTKEY" {
		t.Fatalf("host round-trip lost fields: %+v", got)
	}

	// Scan.
	sc := &Scan{HostID: host.ID, Trigger: "manual", Status: ScanRunning}
	if err := p.CreateScan(ctx, sc); err != nil {
		t.Fatalf("create scan: %v", err)
	}
	sc.Status = ScanOK
	sc.RiskScore = 90
	if err := p.UpdateScan(ctx, sc); err != nil {
		t.Fatalf("update scan: %v", err)
	}

	// Observation upsert dedup: insert twice, expect count == 2.
	mkObs := func() *Observation {
		return &Observation{HostID: host.ID, ScanID: sc.ID, Source: SourceAgentlessProbe,
			RuleID: "ld-so-preload-rootkit", Category: "kernel", Title: "rootkit ld.so.preload",
			Severity: "critical", Score: 90, Mitre: []string{"T1574.006"},
			Evidence: map[string]any{"entries": []any{"/tmp/evil.so"}}, DedupKey: "pgtest-key"}
	}
	o1, err := p.UpsertObservation(ctx, mkObs())
	if err != nil {
		t.Fatalf("upsert 1: %v", err)
	}
	t.Cleanup(func() { _, _ = p.pool.Exec(ctx, `DELETE FROM observations WHERE id=$1`, o1.ID) })
	o2, err := p.UpsertObservation(ctx, mkObs())
	if err != nil {
		t.Fatalf("upsert 2: %v", err)
	}
	if o2.Count != 2 {
		t.Fatalf("dedup count = %d, want 2", o2.Count)
	}
	if o2.ID != o1.ID {
		t.Fatalf("dedup created a new row (%s != %s)", o2.ID, o1.ID)
	}

	// Structured filter.
	list, err := p.ListObservations(ctx, ObservationFilter{HostID: host.ID, Severity: "critical"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].RuleID != "ld-so-preload-rootkit" {
		t.Fatalf("filter returned %d rows: %+v", len(list), list)
	}
	if list[0].Evidence["entries"] == nil {
		t.Fatalf("evidence jsonb not round-tripped: %+v", list[0].Evidence)
	}

	// BM25 full-text query.
	hits, err := p.ListObservations(ctx, ObservationFilter{HostID: host.ID, Query: "rootkit"})
	if err != nil {
		t.Fatalf("bm25 query: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("BM25 q=rootkit returned %d rows, want 1", len(hits))
	}

	// Status transition.
	if err := p.SetObservationStatus(ctx, o1.ID, ObsResolved); err != nil {
		t.Fatalf("set status: %v", err)
	}
	after, _ := p.GetObservation(ctx, o1.ID)
	if after.Status != ObsResolved {
		t.Fatalf("status = %q, want resolved", after.Status)
	}
}
