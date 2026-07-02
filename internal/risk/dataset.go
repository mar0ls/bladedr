package risk

import (
	"bufio"
	"encoding/json"
	"os"

	"bladedr/internal/store"
)

// datasetRecord is the subset of a poligon dataset.jsonl line the model needs.
// The lab writes a richer record (cmd/bladedr-lab); we read only the structural
// fields, mirroring risk.Features — evidence is carried but never featurised.
type datasetRecord struct {
	RuleID   string         `json:"rule_id"`
	Category string         `json:"category"`
	Severity string         `json:"severity"`
	Mitre    []string       `json:"mitre"`
	Source   string         `json:"source"`
	Label    string         `json:"label"` // "true_positive" (default) or "false_positive"
	Evidence map[string]any `json:"evidence"`
}

// LoadDataset reads a poligon dataset.jsonl into labelled observations. Every lab
// record is a technique-labelled true positive, so each becomes an acknowledged
// (positive-class) observation. A missing file is not an error (returns nil) — the
// model simply trains on prod triage alone until a lab run produces a dataset.
func LoadDataset(path string) ([]*store.Observation, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []*store.Observation
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r datasetRecord
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, err
		}
		if r.RuleID == "" {
			continue
		}
		src := r.Source
		if src == "" {
			src = "lab"
		}
		// Respect the record's label: a benign-but-flagged scenario is a negative.
		status := store.ObsAcknowledged // technique-labelled positive (default)
		if r.Label == "false_positive" {
			status = store.ObsFalsePositive
		}
		out = append(out, &store.Observation{
			RuleID:   r.RuleID,
			Category: r.Category,
			Severity: r.Severity,
			Mitre:    r.Mitre,
			Source:   src,
			Evidence: r.Evidence,
			Status:   status,
		})
	}
	return out, sc.Err()
}
