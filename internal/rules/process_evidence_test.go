package rules

import (
	"testing"

	"bladedr/internal/probe"
)

func TestDeletedExecutableEvidenceDoesNotSuppressSystemBinary(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var selected []Rule
	for _, r := range rs {
		if r.ID == "deleted-running-binary" {
			selected = append(selected, r)
		}
	}
	if len(selected) != 1 {
		t.Fatal("rule missing")
	}
	eng, err := NewEngine(selected)
	if err != nil {
		t.Fatal(err)
	}
	for _, detail := range []*probe.ProcessExecutionEvidence{nil, {SHA256: "running-inode-digest", Stable: true}, {Errors: []string{"executable unavailable"}}} {
		snap := &probe.Snapshot{Processes: []probe.Process{{PID: 782, PPID: 1, UID: 0, Comm: "systemd-logind", Exe: "/usr/lib/systemd/systemd-logind", ExeDeleted: true, ExecutionEvidence: detail}}}
		findings, err := eng.Evaluate(snap)
		if err != nil || len(findings) != 1 {
			t.Fatalf("detection suppressed: %+v %v", findings, err)
		}
		ev := findings[0].Evidence
		if ev["ppid"] != float64(1) && ev["ppid"] != int64(1) {
			t.Fatalf("missing ppid: %+v", ev)
		}
		if detail != nil {
			execution, ok := ev["execution"].(map[string]any)
			if !ok || execution["sha256"] != detail.SHA256 {
				t.Fatalf("missing execution evidence: %+v", ev)
			}
		}
	}
}

func TestTemporaryExecutableEvidenceDoesNotSuppressProbeName(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var selected []Rule
	for _, r := range rs {
		if r.ID == "exec-from-world-writable" {
			selected = append(selected, r)
		}
	}
	if len(selected) != 1 {
		t.Fatal("rule missing")
	}
	eng, err := NewEngine(selected)
	if err != nil {
		t.Fatal(err)
	}
	for _, detail := range []*probe.ProcessExecutionEvidence{nil, {SHA256: "verified-digest", Stable: true, StartTicks: "123", Errors: []string{}}, {Errors: []string{"executable unavailable"}}} {
		snap := &probe.Snapshot{Processes: []probe.Process{{PID: 123, PPID: 42, UID: 1000, Exe: "/tmp/tmp.example/probe", ExecutionEvidence: detail}}}
		findings, err := eng.Evaluate(snap)
		if err != nil || len(findings) != 1 {
			t.Fatalf("detection suppressed: %+v %v", findings, err)
		}
		ev := findings[0].Evidence
		if ev["ppid"] != float64(42) && ev["ppid"] != int64(42) {
			t.Fatalf("missing ppid: %+v", ev)
		}
		if detail != nil {
			execution, ok := ev["execution"].(map[string]any)
			if !ok || execution["sha256"] != detail.SHA256 {
				t.Fatalf("missing structured evidence: %+v", ev)
			}
		}
	}
}

func TestSharedLibraryEvidenceDoesNotSuppressWritablePathFinding(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var selected []Rule
	for _, r := range rs {
		if r.ID == "process-library-from-writable-path" {
			selected = append(selected, r)
		}
	}
	if len(selected) != 1 {
		t.Fatal("rule missing")
	}
	eng, err := NewEngine(selected)
	if err != nil {
		t.Fatal(err)
	}
	for _, detail := range []*probe.ProcessExecutionEvidence{nil, {SHA256: "helper-digest", Stable: true}, {Errors: []string{"executable unavailable"}}} {
		snap := &probe.Snapshot{Processes: []probe.Process{{PID: 55, PPID: 1, UID: 0, Exe: "/opt/poligon/helper",
			MappedLibsWritable: []string{"/tmp/.x/lib.so"}, ExecutionEvidence: detail}}}
		findings, err := eng.Evaluate(snap)
		if err != nil || len(findings) != 1 {
			t.Fatalf("detection suppressed: %+v %v", findings, err)
		}
		ev := findings[0].Evidence
		if ev["ppid"] != float64(1) && ev["ppid"] != int64(1) {
			t.Fatalf("missing ppid: %+v", ev)
		}
		if detail != nil {
			execution, ok := ev["execution"].(map[string]any)
			if !ok || execution["sha256"] != detail.SHA256 {
				t.Fatalf("missing execution evidence: %+v", ev)
			}
		}
	}
}

func TestDeletedLibraryEvidenceDoesNotSuppressFinding(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var selected []Rule
	for _, r := range rs {
		if r.ID == "process-library-deleted" {
			selected = append(selected, r)
		}
	}
	if len(selected) != 1 {
		t.Fatal("rule missing")
	}
	eng, err := NewEngine(selected)
	if err != nil {
		t.Fatal(err)
	}
	snap := &probe.Snapshot{Processes: []probe.Process{{PID: 56, PPID: 1, UID: 0, Exe: "/opt/poligon/helper",
		MappedLibsDeleted: []string{"/run/.x/lib.so"}, ExecutionEvidence: &probe.ProcessExecutionEvidence{SHA256: "d", Stable: true}}}}
	findings, err := eng.Evaluate(snap)
	if err != nil || len(findings) != 1 {
		t.Fatalf("detection suppressed: %+v %v", findings, err)
	}
	ev := findings[0].Evidence
	if ev["ppid"] != float64(1) && ev["ppid"] != int64(1) {
		t.Fatalf("missing ppid: %+v", ev)
	}
	if execution, ok := ev["execution"].(map[string]any); !ok || execution["sha256"] != "d" {
		t.Fatalf("missing execution evidence: %+v", ev)
	}
}

// TestLdPreloadEvidenceDisambiguatesSharedExePath is the exact collision the dedup
// change exists for: three unrelated processes bare-launching the same generic binary
// all pick up the same ambient LD_PRELOAD (set system-wide in /etc/environment by a
// separate attack), but only one of them is itself the LD_PRELOAD technique — the ppid
// and the hash of what's actually running are what tell them apart. Exe-only dedup
// collapsed this to one observation with whichever process's evidence was last written.
func TestLdPreloadEvidenceDisambiguatesSharedExePath(t *testing.T) {
	rs, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var selected []Rule
	for _, r := range rs {
		if r.ID == "process-ld-preload-env" {
			selected = append(selected, r)
		}
	}
	if len(selected) != 1 {
		t.Fatal("rule missing")
	}
	eng, err := NewEngine(selected)
	if err != nil {
		t.Fatal(err)
	}
	snap := &probe.Snapshot{Processes: []probe.Process{
		{PID: 101, PPID: 1, Comm: "helper", Exe: "/opt/poligon/helper", PreloadEnv: "LD_PRELOAD=/var/tmp/.cache/lib.so",
			ExecutionEvidence: &probe.ProcessExecutionEvidence{SHA256: "sha-packet-sniffer", Stable: true}},
		{PID: 202, PPID: 1, Comm: "helper", Exe: "/opt/poligon/helper", PreloadEnv: "LD_PRELOAD=/var/tmp/.cache/libmetrics.so",
			ExecutionEvidence: &probe.ProcessExecutionEvidence{SHA256: "sha-preload-env-technique", Stable: true}},
	}}
	findings, err := eng.Evaluate(snap)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("same exe path must not collapse two distinct processes into one finding: got %d", len(findings))
	}
	seen := map[int]string{}
	for _, f := range findings {
		pid := int(f.Evidence["pid"].(float64))
		execution := f.Evidence["execution"].(map[string]any)
		seen[pid] = execution["sha256"].(string)
	}
	if seen[101] != "sha-packet-sniffer" || seen[202] != "sha-preload-env-technique" {
		t.Fatalf("evidence was not kept per-process: %+v", seen)
	}
}
