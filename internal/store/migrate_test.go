package store

import (
	"reflect"
	"testing"
	"testing/fstest"
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
