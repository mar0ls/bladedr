package export

import (
	"encoding/json"
	"testing"
	"time"

	"bladedr/internal/store"
)

func TestToECS(t *testing.T) {
	ts := time.Date(2026, 6, 14, 10, 0, 0, 0, time.UTC)
	o := &store.Observation{
		ID:        "obs-1",
		HostID:    "host-1",
		Source:    store.SourceAgentlessProbe,
		RuleID:    "ld-so-preload-rootkit",
		Category:  "kernel",
		Title:     "Entry in /etc/ld.so.preload",
		Severity:  "critical",
		Score:     90,
		Mitre:     []string{"T1574.006"},
		Evidence:  map[string]any{"file": "/etc/ld.so.preload"},
		Status:    store.ObsOpen,
		FirstSeen: ts,
		LastSeen:  ts,
		Count:     2,
	}
	h := &store.Host{ID: "host-1", Hostname: "web-01", PrimaryIP: "10.0.0.5", Arch: "amd64", OSName: "ubuntu"}

	doc := ToECS(o, h)

	// Round-trips to JSON cleanly (no unencodable values).
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	event := back["event"].(map[string]any)
	if event["kind"] != "alert" {
		t.Errorf("event.kind = %v, want alert", event["kind"])
	}
	if event["severity"].(float64) != 99 {
		t.Errorf("critical should map to ECS severity 99, got %v", event["severity"])
	}
	rule := back["rule"].(map[string]any)
	if rule["id"] != "ld-so-preload-rootkit" {
		t.Errorf("rule.id = %v", rule["id"])
	}
	host := back["host"].(map[string]any)
	if host["name"] != "web-01" {
		t.Errorf("host.name = %v", host["name"])
	}
	if ips := host["ip"].([]any); len(ips) != 1 || ips[0] != "10.0.0.5" {
		t.Errorf("host.ip = %v", host["ip"])
	}
	threat := back["threat"].(map[string]any)
	tech := threat["technique"].(map[string]any)
	if ids := tech["id"].([]any); len(ids) != 1 || ids[0] != "T1574.006" {
		t.Errorf("threat.technique.id = %v", tech["id"])
	}
	labels := back["labels"].(map[string]any)
	if labels["status"] != store.ObsOpen {
		t.Errorf("labels.status = %v", labels["status"])
	}
	if back["@timestamp"] == nil {
		t.Error("missing @timestamp")
	}
}

func TestToECSNilHost(t *testing.T) {
	o := &store.Observation{ID: "x", HostID: "h9", RuleID: "r", Severity: "low", LastSeen: time.Now()}
	doc := ToECS(o, nil)
	host := doc["host"].(map[string]any)
	if host["id"] != "h9" {
		t.Errorf("with nil host, host.id should fall back to HostID, got %v", host["id"])
	}
	if _, err := json.Marshal(doc); err != nil {
		t.Fatalf("marshal: %v", err)
	}
}
