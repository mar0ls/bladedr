package store

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
)

// Shared setup for the tests that need a real Postgres. Both the contract suite and the
// migration tests wipe the database they are pointed at, so the DSN handling lives here
// rather than being duplicated (and half-guarded) in each file.

const destructiveEnv = "BLADEDR_TEST_DESTRUCTIVE"

// testDSN returns the DSN for a disposable Postgres, or "" when the caller should skip.
//
// The guard exists because these tests TRUNCATE every application table. Nothing in a
// DSN distinguishes a scratch database from the one an operator is actually using, and
// the obvious local value — the same postgres://bladedr:bladedr@localhost:5432/bladedr
// the README hands you for running the server — is exactly the one that hurts. So the
// database name has to say it is for tests, or the caller has to say so out loud.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("BLADEDR_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set BLADEDR_TEST_DATABASE_URL to run this suite against Postgres")
	}
	if os.Getenv(destructiveEnv) == "1" {
		return dsn
	}
	name, err := databaseName(dsn)
	if err != nil {
		t.Fatalf("BLADEDR_TEST_DATABASE_URL is not a usable DSN: %v", err)
	}
	if !strings.Contains(strings.ToLower(name), "test") {
		// Fail rather than skip: a silent skip here is how the production backend ends
		// up untested, which is the gap this suite exists to close.
		t.Fatalf(`refusing to wipe database %q: these tests TRUNCATE every table.

Point BLADEDR_TEST_DATABASE_URL at a database whose name contains "test", e.g.

    docker compose exec db createdb -U bladedr bladedr_test
    BLADEDR_TEST_DATABASE_URL=postgres://bladedr:bladedr@localhost:5432/bladedr_test go test ./internal/store/

or set %s=1 if you are certain %q is disposable.`, name, destructiveEnv, name)
	}
	return dsn
}

// databaseName pulls the database out of a DSN. pgx accepts both URL form and libpq
// keyword form, so handle the keyword form too instead of silently reading a URL path
// that isn't there — a DSN we can't parse must not be treated as safe.
func databaseName(dsn string) (string, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", err
		}
		if name := strings.TrimPrefix(u.Path, "/"); name != "" {
			return name, nil
		}
		return "", errors.New("DSN has no database in its path")
	}
	for _, field := range strings.Fields(dsn) {
		if key, value, ok := strings.Cut(field, "="); ok && key == "dbname" {
			return value, nil
		}
	}
	return "", errors.New("cannot determine the database name")
}

// openTestPostgres opens a guarded, empty database. OpenPostgres migrates on open, so
// the schema is at head when this returns.
func openTestPostgres(t *testing.T) *Postgres {
	t.Helper()
	pg, err := OpenPostgres(context.Background(), testDSN(t))
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(pg.Close)
	return pg
}

// dropAllTables removes the schema entirely, including schema_migrations, so a test can
// migrate from nothing. truncateAll deliberately leaves the migration ledger alone;
// this does not.
func dropAllTables(t *testing.T, p *Postgres) {
	t.Helper()
	ctx := context.Background()
	names, err := appTables(ctx, p, true)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	if len(names) == 0 {
		return
	}
	if _, err := p.pool.Exec(ctx, `DROP TABLE `+strings.Join(names, ", ")+` CASCADE`); err != nil {
		t.Fatalf("drop tables: %v", err)
	}
}

// appTables lists the tables this project owns. spatial_ref_sys belongs to PostGIS in
// the ParadeDB image and is never ours to touch; schema_migrations is the ledger, so
// only the migration tests ask for it.
func appTables(ctx context.Context, p *Postgres, includeLedger bool) ([]string, error) {
	excluded := []string{"spatial_ref_sys"}
	if !includeLedger {
		excluded = append(excluded, "schema_migrations")
	}
	rows, err := p.pool.Query(ctx, `SELECT quote_ident(tablename) FROM pg_tables
		WHERE schemaname='public' AND NOT (tablename = ANY($1))`, excluded)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}
