package risk

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
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
	Label    string         `json:"label"` // "true_positive" or "false_positive"
	Evidence map[string]any `json:"evidence"`
}

// LoadDataset reads a poligon dataset.jsonl into labelled observations. A missing file
// is not an error (returns nil) — the model simply trains on prod triage alone until a
// lab run produces a dataset.
//
// Every field is required, label included. An unlabelled lab record used to default to
// true_positive, which is the wrong way round for a training set: a benign-but-flagged
// scenario silently became a positive and taught the model the opposite of the point.
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
	lineNumber := 0
	for sc.Scan() {
		lineNumber++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r datasetRecord
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("%s:%d: decode record: %w", path, lineNumber, err)
		}
		if r.RuleID == "" {
			return nil, fmt.Errorf("%s:%d: rule_id is required", path, lineNumber)
		}
		if r.Category == "" {
			return nil, fmt.Errorf("%s:%d: category is required", path, lineNumber)
		}
		if r.Severity == "" {
			return nil, fmt.Errorf("%s:%d: severity is required", path, lineNumber)
		}
		src := r.Source
		if src == "" {
			src = "lab"
		}
		var status string
		switch r.Label {
		case "true_positive":
			status = store.ObsAcknowledged
		case "false_positive":
			status = store.ObsFalsePositive
		default:
			return nil, fmt.Errorf("%s:%d: label must be true_positive or false_positive, got %q", path, lineNumber, r.Label)
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
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s:%d: read record: %w", path, lineNumber+1, err)
	}
	return out, nil
}
