package sensor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bladedr/internal/store"
)

const dockerPolicy = `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "shield-docker-socket-monitor"
  annotations:
    description: "Unexpected access to container runtime socket"
    mitre: "T1610,T1611"
    severity: "critical"
spec:
  kprobes:
    - call: "security_file_open"
`

const barePolicy = `apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "shield-ptrace-monitor"
spec:
  kprobes:
    - call: "ptrace_attach"
`

func TestLoadPolicyMeta(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "docker.yml"), []byte(dockerPolicy), 0o644)
	os.WriteFile(filepath.Join(dir, "ptrace.yaml"), []byte(barePolicy), 0o644)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore me"), 0o644)

	meta, err := LoadPolicyMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(meta) != 2 {
		t.Fatalf("want 2 policies, got %d", len(meta))
	}
	d := meta["shield-docker-socket-monitor"]
	if d.Severity != "critical" || len(d.Mitre) != 2 || d.Mitre[0] != "T1610" || d.Category != "privilege" {
		t.Errorf("docker policy meta wrong: %+v", d)
	}
	// A policy with no annotations still gets sane defaults + a derived category.
	p := meta["shield-ptrace-monitor"]
	if p.Severity != "medium" || p.Category != "evasion" || p.Title != "shield-ptrace-monitor" {
		t.Errorf("bare policy defaults wrong: %+v", p)
	}
}

// a real-shape Tetragon process_kprobe export line
const kprobeLine = `{"process_kprobe":{"process":{"pid":4321,"uid":0,"binary":"/usr/bin/runc","arguments":"exec -t abc"},"parent":{"pid":4000,"binary":"/usr/bin/dockerd"},"function_name":"security_file_open","policy_name":"shield-docker-socket-monitor","action":"KPROBE_ACTION_POST"},"time":"2026-06-22T12:00:00Z"}`

func TestParseAndMapEvent(t *testing.T) {
	meta := map[string]PolicyMeta{"shield-docker-socket-monitor": {
		Name: "shield-docker-socket-monitor", Title: "container socket access",
		Severity: "critical", Category: "privilege", Mitre: []string{"T1610"},
	}}

	ev, ok := ParseEvent([]byte(kprobeLine))
	if !ok {
		t.Fatal("expected a policy-matched event")
	}
	o := EventToObservation(ev, meta, "host-1")
	if o.Source != store.SourceEBPFSensor || o.RuleID != "shield-docker-socket-monitor" {
		t.Errorf("bad source/rule: %+v", o)
	}
	if o.Severity != "critical" || o.Score != 90 || o.Category != "privilege" {
		t.Errorf("metadata not joined: sev=%s score=%d cat=%s", o.Severity, o.Score, o.Category)
	}
	if o.Evidence["binary"] != "/usr/bin/runc" || o.Evidence["parent"] != "/usr/bin/dockerd" {
		t.Errorf("evidence wrong: %v", o.Evidence)
	}
	if o.DedupKey != "shield-docker-socket-monitor|/usr/bin/runc" {
		t.Errorf("dedup key wrong: %s", o.DedupKey)
	}
	if o.Status != store.ObsOpen || o.HostID != "host-1" {
		t.Errorf("host/status wrong: %+v", o)
	}
}

func TestParseEventIgnoresNonPolicyLines(t *testing.T) {
	for _, l := range []string{
		`{"process_exec":{"process":{"binary":"/bin/ls"}}}`, // base exec, no policy
		`{"process_exit":{"process":{"binary":"/bin/ls"}}}`,
		`not json`,
		``,
	} {
		if _, ok := ParseEvent([]byte(l)); ok {
			t.Errorf("should ignore non-policy line: %q", l)
		}
	}
}

func TestStreamMapsOnlyPolicyHits(t *testing.T) {
	meta := map[string]PolicyMeta{}
	input := kprobeLine + "\n" +
		`{"process_exec":{"process":{"binary":"/bin/ls"}}}` + "\n" +
		kprobeLine + "\n"
	var got []*store.Observation
	if err := Stream(strings.NewReader(input), meta, "h", func(o *store.Observation) { got = append(got, o) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 { // two kprobe hits, exec ignored
		t.Fatalf("want 2 observations, got %d", len(got))
	}
}
