package store

import (
	"context"
	"embed"
	"fmt"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrate applies the embedded schema files in filename order. Each file is run
// via the simple query protocol (no args), so multi-statement DDL works in one
// call. The schema is idempotent (CREATE ... IF NOT EXISTS), so this is safe to
// run on every startup.
func (p *Postgres) migrate(ctx context.Context) error {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, e := range entries { // embed.FS.ReadDir returns entries sorted by name
		if e.IsDir() {
			continue
		}
		sql, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return err
		}
		if _, err := p.pool.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("apply migration %s: %w", e.Name(), err)
		}
	}
	return nil
}
