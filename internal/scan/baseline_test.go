package scan

import (
	"context"
	"testing"

	"bladedr/internal/store"
)

func TestBaselineDriftDetection(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	host := &store.Host{Hostname: "h"}
	_ = st.CreateHost(ctx, host)
	sc := &store.Scan{HostID: host.ID}
	_ = st.CreateScan(ctx, sc)
	r := &Runner{Store: st}

	d1 := map[string][]string{
		"listening_ports": {"tcp/22"},
		"accounts":        {"root:0"},
	}

	// First scan establishes the baseline: no drift, no observations.
	if drift := r.applyBaseline(ctx, host, sc, d1); drift != 0 {
		t.Fatalf("establishing scan should report no drift, got %d", drift)
	}
	if obs, _ := st.ListObservations(ctx, store.ObservationFilter{HostID: host.ID}); len(obs) != 0 {
		t.Fatalf("establishing scan must create no observations, got %d", len(obs))
	}

	// No-change scan: still no drift (no false positives).
	if drift := r.applyBaseline(ctx, host, sc, d1); drift != 0 {
		t.Fatalf("no-change scan reported drift %d", drift)
	}

	// Drift scan: a new port and a new UID-0 account appear.
	d2 := map[string][]string{
		"listening_ports": {"tcp/22", "tcp/4444"},
		"accounts":        {"root:0", "evil:0"},
	}
	if drift := r.applyBaseline(ctx, host, sc, d2); drift == 0 {
		t.Fatal("drift scan should report drift > 0")
	}

	obs, _ := st.ListObservations(ctx, store.ObservationFilter{HostID: host.ID})
	if len(obs) != 2 {
		t.Fatalf("expected exactly 2 drift observations, got %d", len(obs))
	}
	seen := map[string]bool{}
	for _, o := range obs {
		if o.Source != store.SourceBaseline {
			t.Errorf("drift observation should have source=baseline, got %q", o.Source)
		}
		seen[o.RuleID+"|"+o.Evidence["item"].(string)] = true
	}
	if !seen["baseline-new-listening_ports|tcp/4444"] {
		t.Errorf("missing new-port drift: %v", seen)
	}
	if !seen["baseline-new-accounts|evil:0"] {
		t.Errorf("missing new-account drift: %v", seen)
	}
}

func TestFleetRarityScoring(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	r := &Runner{Store: st}

	common := map[string][]string{
		"kernel_modules":  {"ext4", "xfs"},
		"listening_ports": {"tcp/22"},
	}
	// 4 "normal" hosts that share the common state.
	for i := 0; i < 4; i++ {
		h := &store.Host{Hostname: "normal"}
		_ = st.CreateHost(ctx, h)
		_ = st.SaveBaseline(ctx, &store.Baseline{HostID: h.ID, Digest: common})
	}
	// 1 host with a unique module and a unique port.
	target := &store.Host{Hostname: "odd"}
	_ = st.CreateHost(ctx, target)
	targetDigest := map[string][]string{
		"kernel_modules":  {"ext4", "xfs", "diamorphine"},
		"listening_ports": {"tcp/22", "tcp/31337"},
	}
	_ = st.SaveBaseline(ctx, &store.Baseline{HostID: target.ID, Digest: targetDigest})

	sc := &store.Scan{HostID: target.ID}
	_ = st.CreateScan(ctx, sc)
	if score := r.applyRarity(ctx, target, sc, targetDigest); score == 0 {
		t.Fatal("expected rarity score > 0")
	}

	obs, _ := st.ListObservations(ctx, store.ObservationFilter{HostID: target.ID, Source: store.SourceFleet})
	seen := map[string]bool{}
	for _, o := range obs {
		seen[o.RuleID+"|"+o.Evidence["item"].(string)] = true
	}
	if !seen["fleet-rare-kernel_modules|diamorphine"] {
		t.Errorf("unique module should be flagged rare: %v", seen)
	}
	for _, o := range obs { // anomaly findings must carry a MITRE technique (UI shows it)
		if o.RuleID == "fleet-rare-kernel_modules" && (len(o.Mitre) == 0 || o.Mitre[0] != "T1547.006") {
			t.Errorf("rare kernel_modules finding should map to T1547.006, got %v", o.Mitre)
		}
	}
	if !seen["fleet-rare-listening_ports|tcp/31337"] {
		t.Errorf("unique port should be flagged rare: %v", seen)
	}
	if seen["fleet-rare-kernel_modules|ext4"] {
		t.Errorf("common module ext4 must NOT be flagged rare")
	}
	if len(obs) != 2 {
		t.Errorf("expected exactly 2 rare observations, got %d: %v", len(obs), seen)
	}
}

// A heterogeneous fleet must not flag a host's distro-specific items as "rare"
// just because other hosts run a different OS (the Proxmox-vs-Ubuntu noise).
func TestFleetRarityCohortIsolation(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	r := &Runner{Store: st}

	common := map[string][]string{"kernel_modules": {"ext4", "xfs"}}
	// 4 Ubuntu hosts (a real cohort).
	for i := 0; i < 4; i++ {
		h := &store.Host{Hostname: "ubu", OSName: "Ubuntu 24.04.4 LTS"}
		_ = st.CreateHost(ctx, h)
		_ = st.SaveBaseline(ctx, &store.Baseline{HostID: h.ID, Digest: common})
	}
	// A lone Debian/Proxmox host with distro-specific modules.
	prox := &store.Host{Hostname: "pve", OSName: "Debian GNU/Linux 13 (trixie)"}
	_ = st.CreateHost(ctx, prox)
	proxDigest := map[string][]string{"kernel_modules": {"zfs", "spl", "ext4"}}
	_ = st.SaveBaseline(ctx, &store.Baseline{HostID: prox.ID, Digest: proxDigest})

	sc := &store.Scan{HostID: prox.ID}
	_ = st.CreateScan(ctx, sc)
	// Proxmox cohort (debian-13) has only 1 host < minFleetHosts → no rarity noise.
	if score := r.applyRarity(ctx, prox, sc, proxDigest); score != 0 {
		t.Fatalf("lone-cohort host must not produce rarity findings, got score %d", score)
	}
	obs, _ := st.ListObservations(ctx, store.ObservationFilter{HostID: prox.ID, Source: store.SourceFleet})
	if len(obs) != 0 {
		t.Fatalf("expected 0 cross-OS rarity findings, got %d", len(obs))
	}
}
