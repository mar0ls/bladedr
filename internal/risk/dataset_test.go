package risk

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bladedr/internal/store"
)

func TestLoadDatasetMissingFileIsNil(t *testing.T) {
	got, err := LoadDataset(filepath.Join(t.TempDir(), "nope.jsonl"))
	if err != nil || got != nil {
		t.Fatalf("missing file should be (nil,nil), got (%v,%v)", got, err)
	}
	if g, err := LoadDataset(""); err != nil || g != nil {
		t.Fatalf("empty path should be (nil,nil)")
	}
}

func TestLoadDatasetParsesPositives(t *testing.T) {
	p := filepath.Join(t.TempDir(), "dataset.jsonl")
	content := `{"technique":"suid-writable","variant":"stealthy","rule_id":"suid-in-writable-path","category":"privilege","severity":"high","mitre":["T1548.001"],"source":"lab","label":"true_positive","evidence":{"path":"/var/tmp/.fontcache/upd"}}
{"technique":"selinux-disabled","variant":"obvious","rule_id":"selinux-disabled","category":"evasion","severity":"medium","mitre":["T1562.001"],"source":"lab","label":"true_positive"}
{"technique":"benign-sysctl-dev","variant":"obvious","rule_id":"sysctl-hardening-disabled","category":"evasion","severity":"medium","source":"lab","label":"false_positive"}

`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := LoadDataset(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 3 {
		t.Fatalf("want 3 observations (blank line skipped), got %d", len(obs))
	}
	for _, o := range obs {
		if o.Source != "lab" {
			t.Errorf("source should be lab, got %q", o.Source)
		}
	}
	// The two true_positive records are the positive class; the benign one is negative.
	if LabelOf(obs[0].Status) != Positive || LabelOf(obs[1].Status) != Positive {
		t.Errorf("true_positive records must map to the positive class")
	}
	if LabelOf(obs[2].Status) != Negative {
		t.Errorf("a false_positive (benign-but-flagged) record must map to the negative class, got %q", obs[2].Status)
	}
	if obs[0].RuleID != "suid-in-writable-path" || obs[0].Category != "privilege" {
		t.Errorf("fields not parsed: %+v", obs[0])
	}
	// The record feeds straight into the model's features.
	feats := map[string]bool{}
	for _, f := range Features(obs[0]) {
		feats[f] = true
	}
	if !feats["rule:suid-in-writable-path"] || !feats["tech:T1548.001"] {
		t.Errorf("lab observation did not produce expected features: %v", feats)
	}
	_ = store.ObsAcknowledged
}

func TestBundledDatasetIsValid(t *testing.T) {
	records, err := LoadDataset(filepath.Join("..", "..", "poligon", "dataset.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) == 0 {
		t.Fatal("bundled dataset is empty")
	}
}

func TestLoadDatasetRejectsInvalidRecords(t *testing.T) {
	tests := []struct {
		name    string
		record  string
		wantErr string
	}{
		{
			name:    "malformed JSON",
			record:  `{"rule_id":`,
			wantErr: ":1: decode record:",
		},
		{
			name:    "missing rule",
			record:  `{"category":"evasion","severity":"medium","label":"true_positive"}`,
			wantErr: ":1: rule_id is required",
		},
		{
			name:    "missing category",
			record:  `{"rule_id":"r1","severity":"medium","label":"true_positive"}`,
			wantErr: ":1: category is required",
		},
		{
			name:    "missing severity",
			record:  `{"rule_id":"r1","category":"evasion","label":"true_positive"}`,
			wantErr: ":1: severity is required",
		},
		{
			name:    "unknown label",
			record:  `{"rule_id":"r1","category":"evasion","severity":"medium","label":"positive"}`,
			wantErr: `:1: label must be true_positive or false_positive, got "positive"`,
		},
		{
			name:    "missing label",
			record:  `{"rule_id":"r1","category":"evasion","severity":"medium"}`,
			wantErr: `:1: label must be true_positive or false_positive, got ""`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "dataset.jsonl")
			if err := os.WriteFile(path, []byte(tt.record+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := LoadDataset(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("LoadDataset error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
