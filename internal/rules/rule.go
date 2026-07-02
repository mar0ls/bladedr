// Package rules loads agentless detection rules (YAML + CEL) and evaluates them
// against a host snapshot. The full rule carries metadata (severity/score/mitre)
// used by the server during enrichment; the probe receives only the match logic
// via probe.BundleRule.
package rules

import (
	"bytes"
	"fmt"
	"io"

	"bladedr/internal/probe"
	"gopkg.in/yaml.v3"
)

// Severity levels, ordered.
const (
	SevInfo     = "info"
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"
)

// Rule is the full, server-side definition of a detection rule. It carries both
// yaml tags (file/API authoring) and json tags (DB storage of the definition).
type Rule struct {
	ID       string            `yaml:"id" json:"id"`
	Title    string            `yaml:"title" json:"title"`
	Category string            `yaml:"category" json:"category"`
	Severity string            `yaml:"severity" json:"severity"`
	Score    int               `yaml:"score" json:"score"`
	Mitre    []string          `yaml:"mitre" json:"mitre,omitempty"`
	Enabled  *bool             `yaml:"enabled" json:"enabled,omitempty"` // nil = enabled by default
	Foreach  string            `yaml:"foreach" json:"foreach,omitempty"`
	When     string            `yaml:"when" json:"when"`
	Evidence map[string]string `yaml:"evidence" json:"evidence,omitempty"`
	Dedup    []string          `yaml:"dedup" json:"dedup,omitempty"`
}

// IsEnabled reports whether the rule participates in scans (default true).
func (r Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// ToBundleRule strips metadata, leaving only what the probe needs to evaluate.
func (r Rule) ToBundleRule() probe.BundleRule {
	return probe.BundleRule{
		ID:       r.ID,
		Foreach:  r.Foreach,
		When:     r.When,
		Evidence: r.Evidence,
		Dedup:    r.Dedup,
	}
}

// ParseRules decodes one or more YAML documents (--- separated) into rules.
func ParseRules(data []byte) ([]Rule, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out []Rule
	for {
		var r Rule
		err := dec.Decode(&r)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode rule yaml: %w", err)
		}
		if r.ID == "" { // skip empty documents
			continue
		}
		if err := r.validate(); err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		out = append(out, r)
	}
	return out, nil
}

func (r Rule) validate() error {
	if r.ID == "" {
		return fmt.Errorf("missing 'id'")
	}
	if r.When == "" {
		return fmt.Errorf("missing 'when' expression")
	}
	switch r.Severity {
	case SevInfo, SevLow, SevMedium, SevHigh, SevCritical:
	case "":
		return fmt.Errorf("missing 'severity'")
	default:
		return fmt.Errorf("invalid severity %q", r.Severity)
	}
	return nil
}

// ValidateRule checks metadata and compiles the CEL expressions, so the API can
// reject a malformed rule at write time with a precise error.
func ValidateRule(r Rule) error {
	if err := r.validate(); err != nil {
		return err
	}
	_, err := NewEngineFromBundle(probe.RuleBundle{Rules: []probe.BundleRule{r.ToBundleRule()}})
	return err
}
