//go:build linux

package probe

import (
	"os/exec"
	"strings"
	"testing"
)

func TestBpfFDProgramID(t *testing.T) {
	for _, tt := range []struct {
		s    string
		want uint32
	}{{"pos: 0\nprog_id:\t55\n", 55}, {"link_id: 55\nprog_id: 2", 2}, {"prog_id: nope", 0}, {"", 0}} {
		if got := bpfFDProgramID(tt.s); got != tt.want {
			t.Fatalf("%q: %d", tt.s, got)
		}
	}
}
func TestBpfAttachmentIDs(t *testing.T) {
	link := map[string]any{"id": float64(55), "prog_id": float64(2), "type": "cgroup"}
	if bpfJSONContainsID(link, 55) || !bpfJSONContainsID(link, 2) {
		t.Fatal("link ID confused with program ID")
	}
	cg := map[string]any{"cgroup": "/sys/fs/cgroup/system.slice/example.service", "programs": []any{map[string]any{"id": float64(55), "attach_type": "cgroup_device"}}}
	if !bpfJSONContainsID(cg, 55) || bpfJSONContainsID(cg, 2) {
		t.Fatal("cgroup program association incorrect")
	}
}

func TestMissingBpftoolIsEvidenceNotAScanFailure(t *testing.T) {
	if _, err := exec.LookPath("bpftool"); err == nil {
		t.Skip("bpftool is installed; the unavailable path cannot be exercised")
	}
	programs := []BpfProg{{ID: 4294967295}} // an ID no process holds
	var collectorErrors []string
	enrichBpfPrograms(programs, &collectorErrors)
	for _, e := range collectorErrors {
		if strings.Contains(e, "bpftool") {
			t.Errorf("an absent optional tool must not make the scan partial: %q", e)
		}
	}
	found := false
	for _, e := range programs[0].EvidenceErrors {
		found = found || strings.Contains(e, "bpftool unavailable")
	}
	if !found {
		t.Errorf("the missing tool must still be reported on the program's evidence: %v", programs[0].EvidenceErrors)
	}
}
