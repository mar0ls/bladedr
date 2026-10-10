package scan

import (
	"bladedr/internal/probe"
	"bladedr/internal/store"
	"context"
	"testing"
)

func TestBpfBaselinePersistsEvidence(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	h := &store.Host{Hostname: "bpf-host"}
	_ = st.CreateHost(ctx, h)
	sc := &store.Scan{HostID: h.ID}
	_ = st.CreateScan(ctx, sc)
	r := &Runner{Store: st}
	_ = st.SaveBaseline(ctx, &store.Baseline{HostID: h.ID, Digest: map[string][]string{probe.DigestBpfPrograms: {}}})
	digest := map[string][]string{probe.DigestBpfPrograms: {"cgroup_device:abc"}}
	p := probe.BpfProg{ID: 55, Type: "cgroup_device", Tag: "abc", Name: "sd_devices", EvidenceStatus: "partial", Holders: []probe.BpfHolder{{PID: 1, Exe: "/usr/lib/systemd/systemd"}}}
	r.applyBaseline(ctx, h, sc, digest, p)
	rows, err := st.ListObservations(ctx, store.ObservationFilter{HostID: h.ID})
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows: %v %v", rows, err)
	}
	programs, ok := rows[0].Evidence["programs"].([]probe.BpfProg)
	if !ok || len(programs) != 1 || programs[0].Holders[0].PID != 1 {
		t.Fatalf("missing evidence: %#v", rows[0].Evidence)
	}
	if rows[0].Status != store.ObsOpen {
		t.Fatal("must not automatically triage")
	}
}
