package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrate brings the schema up to date. It records applied files in a
// schema_migrations table and only runs the ones that are missing, each inside its
// own transaction (so a failing migration rolls back cleanly and isn't recorded).
// Existing databases that predate this table simply re-run the idempotent 0001
// migration once and get their version recorded.
func (p *Postgres) migrate(ctx context.Context) error {
	if _, err := p.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    text PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied, err := p.appliedMigrations(ctx)
	if err != nil {
		return err
	}
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, version := range pendingMigrations(applied, entries) {
		sql, err := migrationsFS.ReadFile("migrations/" + version + ".sql")
		if err != nil {
			return err
		}
		if err := p.applyMigration(ctx, version, string(sql)); err != nil {
			return fmt.Errorf("apply migration %s: %w", version, err)
		}
		log.Printf("applied migration %s", version)
	}
	return nil
}

// pendingMigrations returns the versions (filename without .sql) that are present in
// the embedded set but not yet applied, in filename order. embed.FS.ReadDir returns
// entries already sorted by name, which is the intended apply order (0001, 0002, …).
func pendingMigrations(applied map[string]bool, entries []fs.DirEntry) []string {
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		version := strings.TrimSuffix(e.Name(), ".sql")
		if !applied[version] {
			out = append(out, version)
		}
	}
	return out
}

func (p *Postgres) appliedMigrations(ctx context.Context) (map[string]bool, error) {
	rows, err := p.pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	applied := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

func (p *Postgres) applyMigration(ctx context.Context, version, sql string) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op
	if _, err := tx.Exec(ctx, sql); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
