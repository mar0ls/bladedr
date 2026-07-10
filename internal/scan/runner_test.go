package scan

import (
	"context"
	"errors"
	"testing"

	"bladedr/internal/probe"
	"bladedr/internal/rules"
	"bladedr/internal/store"
)

// fakeTransport returns a canned probe result (or error) instead of running a probe
// over SSH, so the Runner's scan pipeline is testable without a remote host.
type fakeTransport struct {
	result probe.ScanResult
	err    error
}

func (f fakeTransport) RunProbe(context.Context, probe.RuleBundle, bool) (probe.ScanResult, error) {
	return f.result, f.err
}

func TestRunnerScanCreatesObservations(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	rule := rules.Rule{ID: "test-rule", Title: "Test", Category: "process", Severity: "high", Score: 40, Mitre: []string{"T1059"}}
	r := &Runner{
		Store:     st,
		LoadRules: func(context.Context) ([]rules.Rule, error) { return []rules.Rule{rule}, nil },
		NewTransport: func(*store.Host) (Transport, error) {
			return fakeTransport{result: probe.ScanResult{
				ProbeVersion: "test",
				Findings:     []probe.Finding{{RuleID: "test-rule", DedupKey: "k1", Evidence: map[string]any{"pid": 1}}},
			}}, nil
		},
	}
	host := &store.Host{Hostname: "h"}
	if err := st.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	sc, err := r.Scan(ctx, host, store.TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Status != store.ScanOK {
		t.Fatalf("scan status = %q, want %q", sc.Status, store.ScanOK)
	}
	obs, _ := st.ListObservations(ctx, store.ObservationFilter{HostID: host.ID})
	if len(obs) != 1 {
		t.Fatalf("observations = %d, want 1", len(obs))
	}
	// The finding carries only a rule id + evidence; severity/category/mitre come from
	// the matched rule.
	if obs[0].Severity != "high" || obs[0].Category != "process" || obs[0].Source != store.SourceAgentlessProbe {
		t.Fatalf("observation not enriched from rule: %+v", obs[0])
	}
	if sc.RiskScore < 40 {
		t.Fatalf("risk score = %d, want >= 40 (the rule's score)", sc.RiskScore)
	}
}

func TestRunnerScanUnknownRuleIsSkipped(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	r := &Runner{
		Store:     st,
		LoadRules: func(context.Context) ([]rules.Rule, error) { return nil, nil }, // empty rule set
		NewTransport: func(*store.Host) (Transport, error) {
			return fakeTransport{result: probe.ScanResult{
				Findings: []probe.Finding{{RuleID: "no-such-rule", DedupKey: "k"}},
			}}, nil
		},
	}
	host := &store.Host{Hostname: "h"}
	_ = st.CreateHost(ctx, host)
	sc, err := r.Scan(ctx, host, store.TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Status != store.ScanOK {
		t.Fatalf("scan status = %q, want ok", sc.Status)
	}
	if obs, _ := st.ListObservations(ctx, store.ObservationFilter{HostID: host.ID}); len(obs) != 0 {
		t.Fatalf("a finding with no matching rule should be skipped, got %d observations", len(obs))
	}
}

func TestEnableSensorGuardErrors(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	host := &store.Host{Hostname: "h", Arch: "amd64"}

	// No sensor binary for the arch.
	if err := (&Runner{Store: st}).EnableSensor(ctx, host); err == nil {
		t.Fatal("EnableSensor without a sensor binary should error")
	}
	// Binary present but no policy bundle.
	r := &Runner{Store: st, SensorBins: map[string][]byte{"amd64": {0x1}}}
	if err := r.EnableSensor(ctx, host); err == nil {
		t.Fatal("EnableSensor without a policy bundle should error")
	}
	// Binary + policy but no SSH transport configured.
	r = &Runner{Store: st, SensorBins: map[string][]byte{"amd64": {0x1}}, PolicyTar: []byte{0x1}}
	if err := r.EnableSensor(ctx, host); err == nil {
		t.Fatal("EnableSensor without a sensor transport should error")
	}
}

func TestDisableSensorWithoutTransportSetsScanOnly(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	host := &store.Host{Hostname: "h", Mode: "scan_plus_sensor"}
	_ = st.CreateHost(ctx, host)

	if err := (&Runner{Store: st}).DisableSensor(ctx, host); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetHost(ctx, host.ID); got.Mode != "scan_only" {
		t.Fatalf("host mode = %q, want scan_only", got.Mode)
	}
}

func TestRunnerScanTransportFailureMarksUnreachable(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	r := &Runner{
		Store:     st,
		LoadRules: func(context.Context) ([]rules.Rule, error) { return nil, nil },
		NewTransport: func(*store.Host) (Transport, error) {
			return fakeTransport{err: errors.New("ssh down")}, nil
		},
	}
	host := &store.Host{Hostname: "h"}
	_ = st.CreateHost(ctx, host)

	sc, err := r.Scan(ctx, host, store.TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Status != store.ScanFailed {
		t.Fatalf("scan status = %q, want %q", sc.Status, store.ScanFailed)
	}
	if got, _ := st.GetHost(ctx, host.ID); got.Status != store.StatusUnreachable {
		t.Fatalf("failed scan should mark host %q, got %q", store.StatusUnreachable, got.Status)
	}
}
