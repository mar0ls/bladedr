package risk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalProvenanceAndFleetIsolation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "external.jsonl")
	row := datasetRecord{RuleID: "sudoers-dangerous-rule", Category: "privilege", Severity: "high", Source: "agentless_probe", Label: "true_positive", Evidence: map[string]any{"line": "dev ALL=(ALL) NOPASSWD:ALL"}, Provenance: &DatasetProvenance{Dataset: "fixture", Version: "1", License: "CC-BY-4.0", SHA256: strings.Repeat("a", 64), RecordID: "event-1", Group: "scenario-1", LabelBasis: "event_ground_truth", ReviewedBy: "test", Mapping: "fixture-v1"}}
	write := func() {
		t.Helper()
		b, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	rows, err := LoadReviewedDataset(p)
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Source != sourceLab || rows[0].ScanID != "external:fixture:scenario-1" {
		t.Fatal(rows[0])
	}
	st := Evaluate(rows)
	if st.FleetLabeled != 0 {
		t.Fatalf("external rows counted as fleet: %+v", st)
	}
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p, append(append(b, '\n'), b...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadReviewedDataset(p); err == nil {
		t.Fatal("duplicate external row accepted")
	}
	write()
	for _, f := range Features(rows[0]) {
		if strings.Contains(f, "fixture") || strings.Contains(f, "scenario-1") {
			t.Fatal("provenance leaked into features", f)
		}
	}
	row.Provenance.LabelBasis = "time_window"
	write()
	if _, err = LoadReviewedDataset(p); err == nil {
		t.Fatal("time-only label accepted")
	}
	row.Provenance.LabelBasis = "event_ground_truth"
	row.Provenance.SHA256 = "wrong"
	write()
	if _, err = LoadReviewedDataset(p); err == nil {
		t.Fatal("invalid digest accepted")
	}
	row.Provenance = nil
	write()
	if _, err = LoadReviewedDataset(p); err == nil {
		t.Fatal("missing provenance accepted")
	}
	// Legacy lab files must not acquire fleet status from their source field.
	rows, err = LoadDataset(p)
	if err != nil || rows[0].Source != sourceLab {
		t.Fatalf("legacy import: %v %v", rows, err)
	}
}
