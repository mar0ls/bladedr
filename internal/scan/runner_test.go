package scan

import (
	"context"
	"errors"
	"strings"
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

	// Every precondition failure is ErrSensorNotConfigured — a missing-setup error on
	// this install, not a failure to reach the host — so the API can tell the two apart
	// and answer 503, not 502 (bladedr/mar0ls#20: it answered 502 for all three).
	assertNotConfigured := func(t *testing.T, err error, want string) {
		t.Helper()
		var nc ErrSensorNotConfigured
		if !errors.As(err, &nc) {
			t.Fatalf("%v: want ErrSensorNotConfigured, got %T", err, err)
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}

	// No sensor binary for the arch.
	err := (&Runner{Store: st}).EnableSensor(ctx, host)
	assertNotConfigured(t, err, "BLADEDR_SENSOR_LINUX_AMD64")

	// Binary present but no policy bundle.
	r := &Runner{Store: st, SensorBins: map[string][]byte{"amd64": {0x1}}}
	err = r.EnableSensor(ctx, host)
	assertNotConfigured(t, err, "BLADEDR_POLICY_DIR")

	// Binary + policy but no SSH transport configured.
	r = &Runner{Store: st, SensorBins: map[string][]byte{"amd64": {0x1}}, PolicyTar: []byte{0x1}}
	err = r.EnableSensor(ctx, host)
	assertNotConfigured(t, err, "SSH transport")
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

func TestPartialScanRecordsWhatCouldNotBeCollected(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	r := &Runner{
		Store:     st,
		LoadRules: func(context.Context) ([]rules.Rule, error) { return nil, nil },
		NewTransport: func(*store.Host) (Transport, error) {
			return fakeTransport{result: probe.ScanResult{ProbeVersion: "t",
				CollectorErrors: []string{"kmsg open: operation not permitted", "private key scan: some home directories unreadable"}}}, nil
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
	if sc.Status != store.ScanPartial {
		t.Fatalf("status = %q, want partial", sc.Status)
	}
	if want := "kmsg open: operation not permitted; private key scan: some home directories unreadable"; sc.Error != want {
		t.Fatalf("a partial scan must say why: error = %q, want %q", sc.Error, want)
	}
}
