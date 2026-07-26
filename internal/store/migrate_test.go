package store

import (
	"context"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/google/uuid"
)

func TestPendingMigrations(t *testing.T) {
	// Synthetic set: check ordering, that non-.sql files are ignored, and that
	// already-applied versions are skipped while order is preserved.
	fsys := fstest.MapFS{
		"0001_init.sql":      {},
		"0002_add_index.sql": {},
		"0003_widen_col.sql": {},
		"README.md":          {},
	}
	entries, err := fsys.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	all := pendingMigrations(map[string]bool{}, entries)
	want := []string{"0001_init", "0002_add_index", "0003_widen_col"}
	if !reflect.DeepEqual(all, want) {
		t.Fatalf("pending(none applied) = %v, want %v", all, want)
	}

	rest := pendingMigrations(map[string]bool{"0001_init": true, "0002_add_index": true}, entries)
	if !reflect.DeepEqual(rest, []string{"0003_widen_col"}) {
		t.Fatalf("pending(0001,0002 applied) = %v, want [0003_widen_col]", rest)
	}
}

func TestPendingMigrationsEmbedded(t *testing.T) {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	got := pendingMigrations(map[string]bool{}, entries)
	if len(got) == 0 || got[0] != "0001_init" {
		t.Fatalf("embedded migrations should start with 0001_init, got %v", got)
	}
	applied := map[string]bool{}
	for _, v := range got {
		applied[v] = true
	}
	if p := pendingMigrations(applied, entries); len(p) != 0 {
		t.Fatalf("all-applied should yield nothing pending, got %v", p)
	}
}

// Upgrade tests against a real Postgres. Migrations are the one part of bladedr that can
// destroy an operator's data, and they run automatically on startup — an upgrade is
// "deploy the new binary and restart", with no chance to inspect anything first. So the
// interesting assertion is not that the schema ends up correct, but that rows written
// under an older schema are still there and still readable afterwards.

// applyOnly applies a single embedded migration, bypassing the pending-set logic, so a
// test can park the schema at an arbitrary version.
func applyOnly(t *testing.T, p *Postgres, version string) {
	t.Helper()
	sql, err := migrationsFS.ReadFile("migrations/" + version + ".sql")
	if err != nil {
		t.Fatalf("read %s: %v", version, err)
	}
	if err := p.applyMigration(context.Background(), version, string(sql)); err != nil {
		t.Fatalf("apply %s: %v", version, err)
	}
}

// embeddedVersions lists every migration shipped in the binary, in apply order.
func embeddedVersions(t *testing.T) []string {
	t.Helper()
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	return pendingMigrations(map[string]bool{}, entries)
}

// resetToInitialSchema rebuilds the database as a 0.1.0 install: 0001 applied, nothing
// else, ledger recording just that.
func resetToInitialSchema(t *testing.T, p *Postgres) {
	t.Helper()
	dropAllTables(t, p)
	if _, err := p.pool.Exec(context.Background(), `CREATE TABLE schema_migrations (
		version    text PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		t.Fatalf("recreate ledger: %v", err)
	}
	applyOnly(t, p, "0001_init")
}

func TestUpgradeFromInitialSchemaKeepsData(t *testing.T) {
	ctx := context.Background()
	p := openTestPostgres(t)
	resetToInitialSchema(t, p)

	// Write rows the way 0.1.0 would have, using only columns 0001 defines.
	userID, hostID, scanID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	const sessionToken = "pre-upgrade-session-token"
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO users (id, username, password_hash, role) VALUES ($1,'legacy-admin','$2a$10$fakehash','admin')`, []any{userID}},
		{`INSERT INTO sessions (token, user_id, expires_at) VALUES ($1,$2, now() + interval '1 day')`, []any{sessionToken, userID}},
		{`INSERT INTO hosts (id, hostname, primary_ip, os_name, arch) VALUES ($1,'legacy-host','10.9.9.9','ubuntu','amd64')`, []any{hostID}},
		{`INSERT INTO scans (id, host_id, trigger, status, probe_version) VALUES ($1,$2,'manual','ok','0.1.0')`, []any{scanID, hostID}},
		{`INSERT INTO observations (host_id, scan_id, source, rule_id, category, title, severity, score, dedup_key, status, evidence)
		  VALUES ($1,$2,'agentless_probe','ld-so-preload-rootkit','evasion','Legacy finding','critical',95,'legacy-dedup','acknowledged','{"path":"/etc/ld.so.preload"}')`,
			[]any{hostID, scanID}},
	} {
		if _, err := p.pool.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("seed 0001-era row: %v", err)
		}
	}

	// The upgrade itself: exactly what restarting a newer binary does.
	if err := p.migrate(ctx); err != nil {
		t.Fatalf("upgrade from 0001 failed: %v", err)
	}

	applied, err := p.appliedMigrations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range embeddedVersions(t) {
		if !applied[v] {
			t.Errorf("migration %s did not get recorded", v)
		}
	}

	for _, c := range []struct {
		what  string
		query string
		args  []any
	}{
		{"user", `SELECT count(*) FROM users WHERE id=$1 AND username='legacy-admin' AND role='admin'`, []any{userID}},
		{"host", `SELECT count(*) FROM hosts WHERE id=$1 AND hostname='legacy-host' AND primary_ip='10.9.9.9'`, []any{hostID}},
		{"scan", `SELECT count(*) FROM scans WHERE id=$1 AND probe_version='0.1.0'`, []any{scanID}},
		{"observation", `SELECT count(*) FROM observations WHERE host_id=$1 AND dedup_key='legacy-dedup' AND status='acknowledged' AND severity='critical'`, []any{hostID}},
	} {
		var n int
		if err := p.pool.QueryRow(ctx, c.query, c.args...).Scan(&n); err != nil {
			t.Errorf("%s: query failed after upgrade: %v", c.what, err)
			continue
		}
		if n != 1 {
			t.Errorf("%s: found %d rows after upgrade, want 1 — the upgrade lost data", c.what, n)
		}
	}

	// The rows also have to be reachable through the API, not merely present: a column
	// added by a later migration still has to scan into the current struct.
	host, err := p.GetHost(ctx, hostID)
	if err != nil {
		t.Fatalf("GetHost after upgrade: %v", err)
	}
	if host.Hostname != "legacy-host" {
		t.Errorf("host read back as %q", host.Hostname)
	}
	obs, err := p.ListObservations(ctx, ObservationFilter{HostID: hostID})
	if err != nil {
		t.Fatalf("ListObservations after upgrade: %v", err)
	}
	if len(obs) != 1 || obs[0].RuleID != "ld-so-preload-rootkit" || obs[0].Status != ObsAcknowledged {
		t.Errorf("observation did not survive readable: %+v", obs)
	}

	// Sessions are the deliberate exception, and the only one. 0002 renames token to
	// token_hash and then empties the table, because the old column held plaintext
	// bearer credentials and there is no way to turn those into digests — you cannot
	// hash a value you are supposed to have forgotten. Operators get logged out once on
	// upgrade; that is the intended cost, so assert it rather than leaving it to be
	// "fixed" later by someone preserving the rows.
	var sessions int
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM sessions`).Scan(&sessions); err != nil {
		t.Fatalf("count sessions after upgrade: %v", err)
	}
	if sessions != 0 {
		t.Errorf("upgrade carried %d pre-hash session(s) forward; plaintext tokens must be invalidated", sessions)
	}
	if _, err := p.pool.Exec(ctx,
		`SELECT token_hash FROM sessions WHERE token_hash = $1`, sessionToken); err != nil {
		t.Errorf("sessions.token_hash missing after the rename: %v", err)
	}
}

// A restart must be a no-op. If migrate re-ran a file it would either error on an
// existing object or, worse, quietly re-apply a data change.
func TestMigrateIsIdempotent(t *testing.T) {
	ctx := context.Background()
	p := openTestPostgres(t)
	resetToInitialSchema(t, p)
	if err := p.migrate(ctx); err != nil {
		t.Fatalf("first upgrade: %v", err)
	}
	for i := range 3 {
		if err := p.migrate(ctx); err != nil {
			t.Fatalf("restart %d re-ran a migration: %v", i+1, err)
		}
	}
	var ledger int
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&ledger); err != nil {
		t.Fatal(err)
	}
	if want := len(embeddedVersions(t)); ledger != want {
		t.Errorf("ledger has %d rows after repeated restarts, want %d", ledger, want)
	}
}

// migrate's doc comment promises a database predating schema_migrations adopts cleanly by
// re-running the idempotent 0001. That path had no coverage, and it's the one an early
// adopter actually hits.
func TestMigrateAdoptsDatabaseWithoutLedger(t *testing.T) {
	ctx := context.Background()
	p := openTestPostgres(t)
	resetToInitialSchema(t, p)
	hostID := uuid.NewString()
	if _, err := p.pool.Exec(ctx, `INSERT INTO hosts (id, hostname) VALUES ($1,'pre-ledger-host')`, hostID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.pool.Exec(ctx, `DROP TABLE schema_migrations`); err != nil {
		t.Fatal(err)
	}

	if err := p.migrate(ctx); err != nil {
		t.Fatalf("adopting a pre-ledger database failed: %v", err)
	}
	host, err := p.GetHost(ctx, hostID)
	if err != nil || host.Hostname != "pre-ledger-host" {
		t.Fatalf("pre-ledger row lost: %+v, %v", host, err)
	}
	applied, err := p.appliedMigrations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range embeddedVersions(t) {
		if !applied[v] {
			t.Errorf("migration %s not recorded after adoption", v)
		}
	}
}

// A migration must never be recorded unless its SQL committed, or the next start skips a
// file that never ran.
func TestFailedMigrationIsNotRecorded(t *testing.T) {
	ctx := context.Background()
	p := openTestPostgres(t)
	resetToInitialSchema(t, p)
	if err := p.applyMigration(ctx, "9999_broken",
		`CREATE TABLE ok_first (id int); SELECT this_function_does_not_exist();`); err == nil {
		t.Fatal("a broken migration was accepted")
	}
	var n int
	if err := p.pool.QueryRow(ctx,
		`SELECT count(*) FROM schema_migrations WHERE version='9999_broken'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("a failed migration was recorded as applied")
	}
	if err := p.pool.QueryRow(ctx,
		`SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename='ok_first'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("a failed migration left a table behind; it did not roll back")
	}
}
