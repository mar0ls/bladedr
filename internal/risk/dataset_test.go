package risk

import (
	"os"
	"path/filepath"
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

{"rule_id":""}
`
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	obs, err := LoadDataset(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 3 {
		t.Fatalf("want 3 observations (blank line + empty-rule skipped), got %d", len(obs))
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
