package risk

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"bladedr/internal/store"
)

// datasetRecord is the subset of a poligon dataset.jsonl line the model needs.
// The lab writes a richer record (cmd/bladedr-lab); we read only the structural
// fields plus validation group identifiers. Evidence supplies instance features;
// technique and scene identifiers are used only for holding related rows together.
type datasetRecord struct {
	Provenance *DatasetProvenance `json:"provenance,omitempty"`
	Technique  string             `json:"technique"`
	Scene      string             `json:"scene"`
	RuleID     string             `json:"rule_id"`
	Category   string             `json:"category"`
	Severity   string             `json:"severity"`
	Mitre      []string           `json:"mitre"`
	Source     string             `json:"source"`
	Label      string             `json:"label"` // "true_positive" or "false_positive"
	Evidence   map[string]any     `json:"evidence"`
}

// DatasetProvenance identifies reviewed external examples, never model features.
type DatasetProvenance struct {
	Dataset    string `json:"dataset"`
	Version    string `json:"version"`
	License    string `json:"license"`
	SHA256     string `json:"sha256"`
	RecordID   string `json:"record_id"`
	Group      string `json:"group"`
	LabelBasis string `json:"label_basis"`
	ReviewedBy string `json:"reviewed_by"`
	Mapping    string `json:"mapping"`
}

// LoadDataset reads lab or reviewed external JSONL. Missing files return nil.
// Required fields are rule_id, category, severity and an explicit label.
func LoadDataset(path string) ([]*store.Observation, error) {
	return loadDataset(path, false)
}

// LoadReviewedDataset requires provenance and evidence for every external row.
func LoadReviewedDataset(path string) ([]*store.Observation, error) {
	return loadDataset(path, true)
}

func loadDataset(path string, requireProvenance bool) ([]*store.Observation, error) {
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
	seenExternal := map[string]bool{}
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
		if requireProvenance && (r.Provenance == nil || len(r.Evidence) == 0) {
			return nil, fmt.Errorf("%s:%d: reviewed import requires provenance and evidence", path, lineNumber)
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
		// Imported examples never count as independently assessed fleet labels.
		src := sourceLab
		var status string
		switch r.Label {
		case "true_positive":
			status = store.ObsAcknowledged
		case "false_positive":
			status = store.ObsFalsePositive
		default:
			return nil, fmt.Errorf("%s:%d: label must be true_positive or false_positive, got %q", path, lineNumber, r.Label)
		}
		group := r.Technique
		if r.Scene != "" {
			group = "scene:" + r.Scene
		}
		if p := r.Provenance; p != nil {
			if p.Dataset == "" || p.Version == "" || p.License == "" || p.RecordID == "" || p.Group == "" || p.ReviewedBy == "" || p.Mapping == "" {
				return nil, fmt.Errorf("%s:%d: incomplete external provenance", path, lineNumber)
			}
			if len(p.SHA256) != 64 {
				return nil, fmt.Errorf("%s:%d: invalid provenance SHA256", path, lineNumber)
			}
			if _, err := hex.DecodeString(p.SHA256); err != nil {
				return nil, fmt.Errorf("%s:%d: invalid provenance SHA256", path, lineNumber)
			}
			if p.LabelBasis != "event_ground_truth" && p.LabelBasis != "reviewed_probe_capture" {
				return nil, fmt.Errorf("%s:%d: label requires event ground truth or reviewed probe capture", path, lineNumber)
			}
			group = "external:" + p.Dataset + ":" + p.Group
			key := p.Dataset + "\x00" + p.Version + "\x00" + p.RecordID
			if seenExternal[key] {
				return nil, fmt.Errorf("%s:%d: duplicate external record", path, lineNumber)
			}
			seenExternal[key] = true
		}
		out = append(out, &store.Observation{
			ScanID:   group,
			RuleID:   r.RuleID,
			Category: r.Category,
			Severity: r.Severity,
			Mitre:    r.Mitre,
			Source:   src,
			Evidence: r.Evidence,
			Status:   status,
			Verdict:  r.Label,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s:%d: read record: %w", path, lineNumber+1, err)
	}
	return out, nil
}
