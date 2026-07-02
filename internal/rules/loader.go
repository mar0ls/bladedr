package rules

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"bladedr/internal/probe"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// Builtin returns the detection rules shipped inside the binary.
func Builtin() ([]Rule, error) {
	entries, err := builtinFS.ReadDir("builtin")
	if err != nil {
		return nil, err
	}
	var all []Rule
	for _, e := range entries {
		data, err := builtinFS.ReadFile("builtin/" + e.Name())
		if err != nil {
			return nil, err
		}
		rs, err := ParseRules(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		all = append(all, rs...)
	}
	return dedupByID(all), nil
}

// LoadDir loads every *.yaml/*.yml rule file from a directory (runtime override).
func LoadDir(dir string) ([]Rule, error) {
	var all []Rule
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch filepath.Ext(path) {
		case ".yaml", ".yml":
		default:
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rs, err := ParseRules(data)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		all = append(all, rs...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return dedupByID(all), nil
}

func dedupByID(in []Rule) []Rule {
	seen := map[string]int{}
	var out []Rule
	for _, r := range in {
		if i, ok := seen[r.ID]; ok {
			out[i] = r // later definition wins
			continue
		}
		seen[r.ID] = len(out)
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// BundleFrom builds the probe-facing rule bundle from enabled rules.
func BundleFrom(rs []Rule) probe.RuleBundle {
	b := probe.RuleBundle{
		Schema:        probe.SchemaRuleBundle,
		BundleVersion: time.Now().UTC().Format(time.RFC3339),
	}
	for _, r := range rs {
		if r.IsEnabled() {
			b.Rules = append(b.Rules, r.ToBundleRule())
		}
	}
	return b
}

// Merge combines rule layers (builtin, filesystem dir, DB) into one active set.
// Later layers override earlier ones by ID, so a user rule can replace — or, with
// enabled:false, disable — a builtin rule of the same ID.
func Merge(layers ...[]Rule) []Rule {
	idx := map[string]int{}
	var out []Rule
	for _, layer := range layers {
		for _, r := range layer {
			if i, ok := idx[r.ID]; ok {
				out[i] = r
				continue
			}
			idx[r.ID] = len(out)
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Index maps rule IDs to their full definitions, for server-side enrichment.
func Index(rs []Rule) map[string]Rule {
	m := make(map[string]Rule, len(rs))
	for _, r := range rs {
		m[r.ID] = r
	}
	return m
}
