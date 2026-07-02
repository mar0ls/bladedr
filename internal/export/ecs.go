// Package export maps bladedr observations to interchange formats for SIEMs.
// The first format is Elastic Common Schema (ECS) as NDJSON, the lingua franca
// ingestible by Elasticsearch/Kibana, Filebeat, Logstash and most SIEMs.
package export

import (
	"bladedr/internal/store"
)

// ecsSeverity maps a textual severity to the ECS numeric event.severity scale
// (loosely aligned with common SIEM 0-100 conventions).
func ecsSeverity(sev string) int {
	switch sev {
	case "critical":
		return 99
	case "high":
		return 73
	case "medium":
		return 47
	case "low":
		return 21
	default:
		return 0
	}
}

// ToECS renders one observation (with its host, may be nil) as an ECS document.
// It is a pure function so it can be unit-tested and reused by any exporter.
func ToECS(o *store.Observation, h *store.Host) map[string]any {
	event := map[string]any{
		"kind":       "alert",
		"category":   []string{"intrusion_detection"},
		"type":       []string{"info"},
		"id":         o.ID,
		"module":     "bladedr",
		"dataset":    "bladedr.observation",
		"provider":   o.Source,
		"severity":   ecsSeverity(o.Severity),
		"risk_score": o.Score,
		"count":      o.Count,
	}
	if !o.FirstSeen.IsZero() {
		event["created"] = o.FirstSeen.UTC()
	}

	doc := map[string]any{
		"event":    event,
		"message":  o.Title,
		"rule":     map[string]any{"id": o.RuleID, "name": o.Title, "category": o.Category},
		"observer": map[string]any{"vendor": "bladedr", "product": "bladedr", "type": "host-scanner"},
		"tags":     []string{"bladedr", o.Severity},
	}
	ts := o.LastSeen
	if ts.IsZero() {
		ts = o.FirstSeen
	}
	doc["@timestamp"] = ts.UTC()

	// MITRE ATT&CK technique IDs → ECS threat.technique.id.
	if len(o.Mitre) > 0 {
		doc["threat"] = map[string]any{
			"framework": "MITRE ATT&CK",
			"technique": map[string]any{"id": o.Mitre},
		}
	}

	// Host context.
	host := map[string]any{}
	if h != nil {
		if h.Hostname != "" {
			host["name"] = h.Hostname
		}
		if h.ID != "" {
			host["id"] = h.ID
		}
		if h.PrimaryIP != "" {
			host["ip"] = []string{h.PrimaryIP}
		}
		if h.Arch != "" {
			host["architecture"] = h.Arch
		}
		os := map[string]any{}
		if h.OSName != "" {
			os["name"] = h.OSName
		}
		if h.OSVersion != "" {
			os["version"] = h.OSVersion
		}
		if h.Kernel != "" {
			os["kernel"] = h.Kernel
		}
		if len(os) > 0 {
			os["type"] = "linux"
			host["os"] = os
		}
	} else if o.HostID != "" {
		host["id"] = o.HostID
	}
	if len(host) > 0 {
		doc["host"] = host
	}

	// Triage state + evidence as labels (string map; ECS labels are flat).
	labels := map[string]any{
		"status":     o.Status,
		"source":     o.Source,
		"dedup_key":  o.DedupKey,
		"scan_id":    o.ScanID,
		"bladedr_id": o.ID,
	}
	doc["labels"] = labels
	if len(o.Evidence) > 0 {
		doc["bladedr"] = map[string]any{"evidence": o.Evidence}
	}
	return doc
}
