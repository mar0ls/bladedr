package store

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Store invariants asserted once and run against both implementations. Memory backs
// development and the unit tests; Postgres backs production. Tested separately, the
// production backend gets the least coverage and any drift in cursor ordering, claim
// atomicity or legal state transitions shows up as an incident rather than a failure.
//
// The Postgres pass needs BLADEDR_TEST_DATABASE_URL and is skipped without it:
//
//	docker compose up -d
//	BLADEDR_TEST_DATABASE_URL="postgres://bladedr:bladedr@localhost:5432/bladedr" go test ./internal/store/
//
// A case failing on exactly one backend means that backend is wrong; the assertions
// describe the contract, not either implementation's current behaviour.

// newStore returns an empty Store. Postgres reuses one pool and truncates between
// cases; a pool per case is slow and leaks connections on failure.
type newStore func(t *testing.T) Store

func TestStoreContract(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		runStoreContract(t, func(*testing.T) Store { return NewMemory() })
	})

	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("BLADEDR_TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("set BLADEDR_TEST_DATABASE_URL to run the contract suite against Postgres")
		}
		pg, err := OpenPostgres(context.Background(), dsn)
		if err != nil {
			t.Fatalf("open postgres: %v", err)
		}
		t.Cleanup(pg.Close)
		runStoreContract(t, func(t *testing.T) Store {
			truncateAll(t, pg)
			return pg
		})
	})
}

// truncateAll resets the database between cases. The table list comes from the
// catalog so a table added by a future migration is cleaned up too. schema_migrations
// is the migration ledger and spatial_ref_sys belongs to PostGIS in the ParadeDB
// image; neither is ours to truncate.
func truncateAll(t *testing.T, p *Postgres) {
	t.Helper()
	ctx := context.Background()
	rows, err := p.pool.Query(ctx, `SELECT quote_ident(tablename) FROM pg_tables
		WHERE schemaname='public' AND tablename NOT IN ('schema_migrations','spatial_ref_sys')`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			t.Fatalf("scan table name: %v", err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("list tables: %v", err)
	}
	if len(tables) == 0 {
		t.Fatal("no application tables found; did the migrations run?")
	}
	if _, err := p.pool.Exec(ctx, `TRUNCATE `+strings.Join(tables, ", ")+` RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

func runStoreContract(t *testing.T, open newStore) {
	cases := []struct {
		name string
		run  func(*testing.T, context.Context, Store)
	}{
		{"HostRoundTrip", contractHostRoundTrip},
		{"ObservationDedup", contractObservationDedup},
		{"ObservationCursorPagination", contractObservationCursor},
		{"ScanJobClaimIsExclusive", contractScanJobClaimExclusive},
		{"ScanJobLeaseReclaim", contractScanJobLeaseReclaim},
		{"ScanJobRetryThenTerminal", contractScanJobRetry},
		{"ResponseTwoPersonControl", contractResponseTwoPersonControl},
		{"ResponseSelfApprovalOptOut", contractResponseSelfApprovalOptOut},
		{"ResponseRejectIsTerminal", contractResponseReject},
		{"ResponseClaimSkipsUnapproved", contractResponseClaimSkipsUnapproved},
		{"ResponseCompleteRequiresLease", contractResponseCompleteRequiresLease},
		{"SessionExpiry", contractSessionExpiry},
		{"SensorTokenScope", contractSensorTokenScope},
		{"RetentionArchives", contractRetention},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t, context.Background(), open(t))
		})
	}
}

// --- helpers ---

func mustHost(t *testing.T, ctx context.Context, s Store) *Host {
	t.Helper()
	h := &Host{Hostname: "contract-host", PrimaryIP: "10.0.0.1", SSHPort: 22,
		Mode: ModeScanOnly, Status: StatusPending}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatalf("create host: %v", err)
	}
	return h
}

func mustObs(t *testing.T, ctx context.Context, s Store, hostID, dedup string, lastSeen time.Time) *Observation {
	t.Helper()
	o := &Observation{HostID: hostID, Source: SourceAgentlessProbe, RuleID: "contract-rule",
		Category: "process", Title: "contract finding", Severity: "high", Score: 70,
		DedupKey: dedup, Status: ObsOpen, FirstSeen: lastSeen, LastSeen: lastSeen}
	got, err := s.UpsertObservation(ctx, o)
	if err != nil {
		t.Fatalf("upsert observation: %v", err)
	}
	return got
}

func mustResponse(t *testing.T, ctx context.Context, s Store, hostID, requester string) *ResponseAction {
	t.Helper()
	a := &ResponseAction{HostID: hostID, Playbook: "kill_process",
		Params: map[string]string{"pid": "4242", "expected_exe": "/usr/bin/evil"},
		DryRun: true, Status: ResponsePending, RequestedBy: requester}
	if err := s.CreateResponseAction(ctx, a); err != nil {
		t.Fatalf("create response action: %v", err)
	}
	return a
}

// --- contract cases ---

func contractHostRoundTrip(t *testing.T, ctx context.Context, s Store) {
	h := mustHost(t, ctx, s)
	h.SSHHostKey = "ssh-ed25519 AAAACONTRACT"
	h.Tags = map[string]string{"env": "prod"}
	h.Mode = ModeScanPlusSensor
	if err := s.UpdateHost(ctx, h); err != nil {
		t.Fatalf("update host: %v", err)
	}
	got, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}
	if got.SSHHostKey != h.SSHHostKey {
		t.Errorf("pinned host key = %q, want %q", got.SSHHostKey, h.SSHHostKey)
	}
	if got.Tags["env"] != "prod" {
		t.Errorf("tags = %v, want env=prod", got.Tags)
	}
	if got.Mode != ModeScanPlusSensor {
		t.Errorf("mode = %q, want %q", got.Mode, ModeScanPlusSensor)
	}

	if err := s.DeleteHost(ctx, h.ID); err != nil {
		t.Fatalf("delete host: %v", err)
	}
	if _, err := s.GetHost(ctx, h.ID); err == nil {
		t.Fatal("get after delete returned no error")
	} else if _, ok := err.(ErrNotFound); !ok {
		t.Errorf("get after delete = %T (%v), want ErrNotFound", err, err)
	}
}

// Dedup keeps one row per (host, dedup_key) and increments Count. A backend that
// inserted a second row instead would multiply every recurring finding on every
// scheduled scan.
func contractObservationDedup(t *testing.T, ctx context.Context, s Store) {
	h := mustHost(t, ctx, s)
	now := time.Now().UTC().Truncate(time.Millisecond)

	first := mustObs(t, ctx, s, h.ID, "same-key", now)
	second := mustObs(t, ctx, s, h.ID, "same-key", now.Add(time.Minute))
	if first.ID != second.ID {
		t.Fatalf("dedup created a second row: %s != %s", first.ID, second.ID)
	}
	if second.Count != 2 {
		t.Errorf("count after re-upsert = %d, want 2", second.Count)
	}

	// A different key on the same host is a distinct finding.
	other := mustObs(t, ctx, s, h.ID, "other-key", now)
	if other.ID == first.ID {
		t.Fatal("distinct dedup keys collapsed into one observation")
	}

	list, err := s.ListObservations(ctx, ObservationFilter{HostID: h.ID})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("host has %d observations, want 2", len(list))
	}
}

// Walking (last_seen, id) pages must return every row exactly once. One scan writes
// its observations in a burst, so last_seen values are dense and can collide; the id
// tiebreaker is what makes the ordering a strict total order. Without it, rows on a
// page boundary are skipped or repeated.
func contractObservationCursor(t *testing.T, ctx context.Context, s Store) {
	h := mustHost(t, ctx, s)
	now := time.Now().UTC()

	const total = 25
	for i := range total {
		mustObs(t, ctx, s, h.ID, fmt.Sprintf("key-%02d", i), now)
	}

	seen := map[string]int{}
	filter := ObservationFilter{HostID: h.ID, Limit: 7}
	var prev *Observation
	for page := 0; ; page++ {
		if page > total {
			t.Fatal("pagination did not terminate")
		}
		rows, err := s.ListObservations(ctx, filter)
		if err != nil {
			t.Fatalf("page %d: %v", page, err)
		}
		if len(rows) == 0 {
			break
		}
		for _, o := range rows {
			seen[o.ID]++
			if prev != nil {
				// Strictly descending on (last_seen, id).
				if o.LastSeen.After(prev.LastSeen) {
					t.Fatalf("ordering broke: %v came after %v", o.LastSeen, prev.LastSeen)
				}
				if o.LastSeen.Equal(prev.LastSeen) && o.ID >= prev.ID {
					t.Fatalf("tie not broken by descending id: %q after %q", o.ID, prev.ID)
				}
			}
			prev = o
		}
		last := rows[len(rows)-1]
		filter.BeforeTime, filter.BeforeID = last.LastSeen, last.ID
	}

	if len(seen) != total {
		t.Errorf("walked %d distinct rows, want %d", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("row %s returned %d times, want 1", id, n)
		}
	}
}

// Two workers racing for the queue must not both receive the same job; a duplicate
// claim means the same host is scanned twice concurrently over one SSH credential.
func contractScanJobClaimExclusive(t *testing.T, ctx context.Context, s Store) {
	h := mustHost(t, ctx, s)
	if _, err := s.EnqueueScanJob(ctx, &ScanJob{HostID: h.ID, Trigger: TriggerAPI, MaxAttempts: 3}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	now := time.Now().UTC()
	const workers = 8
	var (
		mu      sync.Mutex
		claimed []string
		wg      sync.WaitGroup
	)
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			job, err := s.ClaimScanJob(ctx, fmt.Sprintf("worker-%d", i), now, time.Minute)
			if err != nil {
				return // ErrNotFound: nothing claimable, which is the expected outcome for 7 of 8
			}
			mu.Lock()
			claimed = append(claimed, job.ID)
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	if len(claimed) != 1 {
		t.Fatalf("%d workers claimed the same job, want exactly 1", len(claimed))
	}
}

// A worker that dies mid-scan leaves a running job with a lease. Once the lease
// lapses another worker must be able to reclaim it, or the job is stuck forever.
func contractScanJobLeaseReclaim(t *testing.T, ctx context.Context, s Store) {
	h := mustHost(t, ctx, s)
	if _, err := s.EnqueueScanJob(ctx, &ScanJob{HostID: h.ID, Trigger: TriggerAPI, MaxAttempts: 3}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	now := time.Now().UTC()

	first, err := s.ClaimScanJob(ctx, "worker-a", now, time.Minute)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	// Still leased: no other worker may take it.
	if _, err := s.ClaimScanJob(ctx, "worker-b", now.Add(30*time.Second), time.Minute); err == nil {
		t.Fatal("job was claimed while its lease was still valid")
	}
	// Lease lapsed: reclaimable.
	second, err := s.ClaimScanJob(ctx, "worker-b", now.Add(2*time.Minute), time.Minute)
	if err != nil {
		t.Fatalf("reclaim after lease expiry: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("reclaimed a different job: %s != %s", second.ID, first.ID)
	}
	if second.Attempts != 2 {
		t.Errorf("attempts = %d after reclaim, want 2", second.Attempts)
	}

	// The stale owner must not be able to complete a job it no longer holds.
	if err := s.CompleteScanJob(ctx, first.ID, "worker-a", "scan-id"); err == nil {
		t.Error("stale worker completed a job whose lease it lost")
	}
}

// A retryable failure returns the job to the queue with a backoff; a terminal one
// closes it. Getting this wrong either loses scans or retries them forever.
func contractScanJobRetry(t *testing.T, ctx context.Context, s Store) {
	h := mustHost(t, ctx, s)
	if _, err := s.EnqueueScanJob(ctx, &ScanJob{HostID: h.ID, Trigger: TriggerAPI, MaxAttempts: 3}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	now := time.Now().UTC()

	job, err := s.ClaimScanJob(ctx, "worker-a", now, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	retryAt := now.Add(10 * time.Minute)
	if err := s.FailScanJob(ctx, job.ID, "worker-a", "ssh timeout", retryAt, false); err != nil {
		t.Fatalf("fail (retryable): %v", err)
	}
	after, err := s.GetScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if after.Status != ScanJobQueued {
		t.Fatalf("status after retryable failure = %q, want %q", after.Status, ScanJobQueued)
	}
	// The backoff must be honoured: not claimable before retryAt.
	if _, err := s.ClaimScanJob(ctx, "worker-b", now.Add(time.Minute), time.Minute); err == nil {
		t.Error("job was claimed before its backoff elapsed")
	}
	again, err := s.ClaimScanJob(ctx, "worker-b", retryAt.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatalf("claim after backoff: %v", err)
	}

	if err := s.FailScanJob(ctx, again.ID, "worker-b", "unreachable", time.Time{}, true); err != nil {
		t.Fatalf("fail (terminal): %v", err)
	}
	final, err := s.GetScanJob(ctx, again.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if final.Status != ScanJobFailed {
		t.Errorf("status after terminal failure = %q, want %q", final.Status, ScanJobFailed)
	}
	if _, err := s.ClaimScanJob(ctx, "worker-c", retryAt.Add(time.Hour), time.Minute); err == nil {
		t.Error("terminally failed job was claimed again")
	}
}

// Two-person control: response actions run root-level commands on a host, so the
// requester must not also be the approver.
func contractResponseTwoPersonControl(t *testing.T, ctx context.Context, s Store) {
	h := mustHost(t, ctx, s)
	action := mustResponse(t, ctx, s, h.ID, "alice")

	err := s.ApproveResponseAction(ctx, action.ID, "alice")
	if err == nil {
		t.Fatal("requester approved their own containment action")
	}
	var self ErrSelfApproval
	if !asErr(err, &self) {
		t.Fatalf("self-approval error = %T (%v), want ErrSelfApproval", err, err)
	}

	// The rejected approval must not have moved the action or recorded an approver.
	pending, err := s.GetResponseAction(ctx, action.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if pending.Status != ResponsePending {
		t.Errorf("status after blocked self-approval = %q, want %q", pending.Status, ResponsePending)
	}
	if pending.ApprovedBy != "" {
		t.Errorf("approved_by = %q after a blocked approval, want empty", pending.ApprovedBy)
	}

	// A second administrator may approve.
	if err := s.ApproveResponseAction(ctx, action.ID, "bob"); err != nil {
		t.Fatalf("approve by a second admin: %v", err)
	}
	approved, err := s.GetResponseAction(ctx, action.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if approved.Status != ResponseApproved || approved.ApprovedBy != "bob" {
		t.Fatalf("after approval: status=%q approved_by=%q", approved.Status, approved.ApprovedBy)
	}
	if approved.ApprovedAt == nil {
		t.Error("approved_at was not recorded")
	}

	// Approval is not idempotent — a decided action cannot be re-approved.
	if err := s.ApproveResponseAction(ctx, action.ID, "carol"); err == nil {
		t.Error("an already-approved action was approved a second time")
	}
}

// Single-administrator deployments may opt out. The opt-out must be honoured by
// both backends, otherwise the escape hatch works in dev and fails in production.
func contractResponseSelfApprovalOptOut(t *testing.T, ctx context.Context, s Store) {
	h := mustHost(t, ctx, s)
	action := mustResponse(t, ctx, s, h.ID, "solo")

	setSelfApproval(t, s, true)
	defer setSelfApproval(t, s, false)

	if err := s.ApproveResponseAction(ctx, action.ID, "solo"); err != nil {
		t.Fatalf("self-approval with the opt-out enabled: %v", err)
	}
	got, err := s.GetResponseAction(ctx, action.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != ResponseApproved || got.ApprovedBy != "solo" {
		t.Fatalf("after opt-out approval: status=%q approved_by=%q", got.Status, got.ApprovedBy)
	}
}

// Rejection closes the request without contacting the host and is terminal: no
// worker may pick it up afterwards.
func contractResponseReject(t *testing.T, ctx context.Context, s Store) {
	h := mustHost(t, ctx, s)
	action := mustResponse(t, ctx, s, h.ID, "alice")

	if err := s.RejectResponseAction(ctx, action.ID, "bob", "wrong host"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	got, err := s.GetResponseAction(ctx, action.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != ResponseRejected {
		t.Fatalf("status = %q, want %q", got.Status, ResponseRejected)
	}
	if got.RejectedBy != "bob" || got.RejectReason != "wrong host" {
		t.Errorf("rejected_by=%q reject_reason=%q", got.RejectedBy, got.RejectReason)
	}
	if got.RejectedAt == nil {
		t.Error("rejected_at was not recorded")
	}

	if _, err := s.ClaimResponseAction(ctx, "worker", time.Now().UTC(), time.Minute); err == nil {
		t.Fatal("a rejected action was claimed by a worker")
	}
	if err := s.ApproveResponseAction(ctx, action.ID, "carol"); err == nil {
		t.Error("a rejected action was subsequently approved")
	}
	if err := s.RejectResponseAction(ctx, action.ID, "carol", "again"); err == nil {
		t.Error("a rejected action was rejected twice")
	}
}

// An action that was never approved must be invisible to workers, whatever path
// created it. This is the check that holds if an approval guard is bypassed upstream.
func contractResponseClaimSkipsUnapproved(t *testing.T, ctx context.Context, s Store) {
	h := mustHost(t, ctx, s)
	mustResponse(t, ctx, s, h.ID, "alice")

	if _, err := s.ClaimResponseAction(ctx, "worker", time.Now().UTC(), time.Minute); err == nil {
		t.Fatal("a pending, unapproved action was claimed")
	}
}

func contractResponseCompleteRequiresLease(t *testing.T, ctx context.Context, s Store) {
	h := mustHost(t, ctx, s)
	action := mustResponse(t, ctx, s, h.ID, "alice")
	if err := s.ApproveResponseAction(ctx, action.ID, "bob"); err != nil {
		t.Fatalf("approve: %v", err)
	}

	now := time.Now().UTC()
	claimed, err := s.ClaimResponseAction(ctx, "worker-a", now, time.Minute)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if claimed.ID != action.ID {
		t.Fatalf("claimed %s, want %s", claimed.ID, action.ID)
	}
	if err := s.CompleteResponseAction(ctx, action.ID, "worker-b", "output"); err == nil {
		t.Error("a worker completed an action it does not hold")
	}
	if err := s.CompleteResponseAction(ctx, action.ID, "worker-a", "SIGTERM sent"); err != nil {
		t.Fatalf("complete by the lease holder: %v", err)
	}
	done, err := s.GetResponseAction(ctx, action.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if done.Status != ResponseSucceeded || done.Output != "SIGTERM sent" {
		t.Errorf("after completion: status=%q output=%q", done.Status, done.Output)
	}
}

// An expired session digest must not resolve to a user. Expiry is enforced on
// lookup, not only by the background sweeper, so a store that filters on delete
// alone would keep honouring stale cookies until the next sweep.
func contractSessionExpiry(t *testing.T, ctx context.Context, s Store) {
	u := &User{Username: "contract-user", PasswordHash: "x", Role: RoleViewer}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("create user: %v", err)
	}

	live := &Session{TokenHash: "live-digest", UserID: u.ID, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	dead := &Session{TokenHash: "dead-digest", UserID: u.ID, ExpiresAt: time.Now().UTC().Add(-time.Hour)}
	for _, sess := range []*Session{live, dead} {
		if err := s.CreateSession(ctx, sess); err != nil {
			t.Fatalf("create session: %v", err)
		}
	}

	if got, err := s.SessionUser(ctx, "live-digest"); err != nil || got.ID != u.ID {
		t.Fatalf("live session: user=%v err=%v", got, err)
	}
	if _, err := s.SessionUser(ctx, "dead-digest"); err == nil {
		t.Error("an expired session digest resolved to a user")
	}
	if _, err := s.SessionUser(ctx, "never-issued"); err == nil {
		t.Error("an unknown session digest resolved to a user")
	}

	n, err := s.DeleteExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Errorf("pruned %d sessions, want 1", n)
	}
	if _, err := s.SessionUser(ctx, "live-digest"); err != nil {
		t.Error("pruning removed a live session")
	}
}

// A sensor credential is bound to one host. If it validated against another host,
// one compromised sensor could inject observations for the whole fleet.
func contractSensorTokenScope(t *testing.T, ctx context.Context, s Store) {
	hostA := mustHost(t, ctx, s)
	hostB := &Host{Hostname: "contract-host-b", PrimaryIP: "10.0.0.2", SSHPort: 22,
		Mode: ModeScanOnly, Status: StatusPending}
	if err := s.CreateHost(ctx, hostB); err != nil {
		t.Fatalf("create host b: %v", err)
	}

	expires := time.Now().UTC().Add(time.Hour)
	tok := &SensorToken{HostID: hostA.ID, TokenHash: "digest-a", ExpiresAt: &expires}
	if err := s.CreateSensorToken(ctx, tok); err != nil {
		t.Fatalf("create sensor token: %v", err)
	}

	if ok, err := s.SensorTokenValid(ctx, hostA.ID, "digest-a"); err != nil || !ok {
		t.Fatalf("token rejected for its own host: ok=%v err=%v", ok, err)
	}
	if ok, _ := s.SensorTokenValid(ctx, hostB.ID, "digest-a"); ok {
		t.Error("a host-bound token validated against a different host")
	}
	if ok, _ := s.SensorTokenValid(ctx, hostA.ID, "digest-unknown"); ok {
		t.Error("an unknown digest validated")
	}

	past := time.Now().UTC().Add(-time.Minute)
	expired := &SensorToken{HostID: hostA.ID, TokenHash: "digest-expired", ExpiresAt: &past}
	if err := s.CreateSensorToken(ctx, expired); err != nil {
		t.Fatalf("create expired token: %v", err)
	}
	if ok, _ := s.SensorTokenValid(ctx, hostA.ID, "digest-expired"); ok {
		t.Error("an expired token validated")
	}

	if err := s.RevokeSensorToken(ctx, hostA.ID, tok.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if ok, _ := s.SensorTokenValid(ctx, hostA.ID, "digest-a"); ok {
		t.Error("a revoked token still validated")
	}
}

// Retention archives aged records instead of dropping them, and only touches
// observations in a terminal triage state; an open finding survives any age.
//
// LastSeen is assigned by the store, so rows cannot be backdated. Shrinking the
// threshold instead puts every row past the cutoff, isolating the property under
// test: eligibility is decided by status, not age.
func contractRetention(t *testing.T, ctx context.Context, s Store) {
	h := mustHost(t, ctx, s)
	now := time.Now().UTC()

	stale := mustObs(t, ctx, s, h.ID, "stale-resolved", now)
	if err := s.SetObservationStatus(ctx, stale.ID, ObsResolved); err != nil {
		t.Fatalf("set status: %v", err)
	}
	openOld := mustObs(t, ctx, s, h.ID, "stale-open", now)

	result, err := s.ApplyRetention(ctx, RetentionPolicy{ObservationAge: time.Nanosecond})
	if err != nil {
		t.Fatalf("apply retention: %v", err)
	}
	if result.Observations != 1 {
		t.Fatalf("archived %d observations, want 1", result.Observations)
	}
	if _, err := s.GetObservation(ctx, stale.ID); err == nil {
		t.Error("a resolved, aged observation survived retention")
	}
	if _, err := s.GetObservation(ctx, openOld.ID); err != nil {
		t.Error("an open observation was archived by age alone")
	}

	archive, err := s.ListArchive(ctx, "observation", 10)
	if err != nil {
		t.Fatalf("list archive: %v", err)
	}
	if len(archive) != 1 || archive[0].OriginalID != stale.ID {
		t.Fatalf("archive holds %d records: %+v", len(archive), archive)
	}
	if len(archive[0].Payload) == 0 {
		t.Error("archived record has an empty payload")
	}
}

// --- assertion helpers ---

// setSelfApproval flips the policy on whichever store is under test. The flag lives
// on the implementations, not the interface, hence the type switch.
func setSelfApproval(t *testing.T, s Store, allow bool) {
	t.Helper()
	switch impl := s.(type) {
	case *Memory:
		impl.AllowSelfApproval = allow
	case *Postgres:
		impl.AllowSelfApproval = allow
	default:
		t.Fatalf("unknown store implementation %T", s)
	}
}

func asErr[T error](err error, target *T) bool {
	for err != nil {
		if v, ok := err.(T); ok {
			*target = v
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
