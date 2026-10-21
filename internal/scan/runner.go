// Package scan orchestrates an agentless scan: deliver the rule bundle + probe to
// a host, run it, then enrich the returned findings into stored observations.
package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"bladedr/internal/auth"
	"bladedr/internal/probe"
	"bladedr/internal/rules"
	"bladedr/internal/store"
)

// Transport delivers the probe + bundle to a host and returns its result.
type Transport interface {
	RunProbe(ctx context.Context, bundle probe.RuleBundle, emitSnapshot bool) (probe.ScanResult, error)
}

// Runner executes scans and persists results.
type Runner struct {
	Store store.Store
	// LoadRules returns the active rule set (builtin ∪ dir ∪ DB) at scan time, so
	// rules added/toggled via the API take effect on the next scan without restart.
	LoadRules    func(ctx context.Context) ([]rules.Rule, error)
	NewTransport func(h *store.Host) (Transport, error)

	// eBPF sensor deploy (scan_plus_sensor). SensorBins is per-arch sensor binaries,
	// PolicyTar the gzip'd TracingPolicy bundle, ServerURL how a host reaches the
	// control plane, and NewSensorTransport builds the SSH transport + sudo password
	// for a host. All optional; EnableSensor errors clearly when unconfigured.
	SensorBins         map[string][]byte
	PolicyTar          []byte
	ServerURL          string
	NewSensorTransport func(h *store.Host) (*SSHTransport, string, error)
}

// ErrSensorNotConfigured means this bladedr install is missing something EnableSensor
// needs (a sensor binary, a policy bundle, SSH wiring) — the server's own setup, not the
// target host. The API maps it to 503 rather than 502: the host was never contacted, so
// "bad gateway" would blame the wrong end.
type ErrSensorNotConfigured string

func (e ErrSensorNotConfigured) Error() string { return string(e) }

// EnableSensor deploys + starts the eBPF sensor on the host (over SSH) and sets the
// host to scan_plus_sensor.
func (r *Runner) EnableSensor(ctx context.Context, host *store.Host) error {
	arch := host.Arch
	if arch == "" {
		arch = "amd64"
	}
	bin := r.SensorBins[arch]
	if bin == nil {
		return ErrSensorNotConfigured(fmt.Sprintf("no sensor binary for arch %q (set BLADEDR_SENSOR_LINUX_%s)", arch, strings.ToUpper(arch)))
	}
	if len(r.PolicyTar) == 0 {
		return ErrSensorNotConfigured("no policy bundle configured (set BLADEDR_POLICY_DIR)")
	}
	if r.NewSensorTransport == nil {
		return ErrSensorNotConfigured("sensor deploy not available (no SSH transport)")
	}
	t, pw, err := r.NewSensorTransport(host)
	if err != nil {
		return err
	}
	rawToken := auth.NewToken()
	expires := time.Now().UTC().Add(90 * 24 * time.Hour)
	credential := &store.SensorToken{HostID: host.ID, TokenHash: auth.TokenDigest(rawToken), ExpiresAt: &expires}
	if err := r.Store.CreateSensorToken(ctx, credential); err != nil {
		return fmt.Errorf("create per-host sensor credential: %w", err)
	}
	if err := t.DeploySensor(ctx, bin, r.PolicyTar, r.ServerURL, host.ID, rawToken, pw); err != nil {
		_ = r.Store.RevokeSensorToken(ctx, host.ID, credential.ID)
		return err
	}
	// Keep the previous credential valid until the new deployment succeeds, then
	// revoke it. This gives rotations no authentication gap.
	if err := r.Store.RevokeOtherSensorTokens(ctx, host.ID, credential.ID); err != nil {
		return fmt.Errorf("revoke superseded sensor credentials: %w", err)
	}
	host.Mode = "scan_plus_sensor"
	return r.Store.UpdateHost(ctx, host)
}

// DisableSensor stops the sensor + Tetragon on the host (best-effort) and sets the
// host back to scan_only.
func (r *Runner) DisableSensor(ctx context.Context, host *store.Host) error {
	if r.NewSensorTransport != nil {
		if t, pw, err := r.NewSensorTransport(host); err == nil {
			if err := t.StopSensor(ctx, pw); err != nil {
				log.Printf("sensor: stop on %s: %v", host.ID, err)
			}
		}
	}
	if err := r.Store.RevokeSensorTokens(ctx, host.ID); err != nil {
		return err
	}
	host.Mode = "scan_only"
	return r.Store.UpdateHost(ctx, host)
}

// Scan runs one agentless scan against host and stores the resulting observations.
func (r *Runner) Scan(ctx context.Context, host *store.Host, trigger string) (*store.Scan, error) {
	return r.scan(ctx, host, trigger, nil)
}

func (r *Runner) scan(ctx context.Context, host *store.Host, trigger string, validateOwner func(context.Context) error) (*store.Scan, error) {
	now := time.Now().UTC()
	sc := &store.Scan{HostID: host.ID, Trigger: trigger, Status: store.ScanRunning, StartedAt: now}
	if err := r.Store.CreateScan(ctx, sc); err != nil {
		return nil, err
	}

	finish := func(status, errMsg string) (*store.Scan, error) {
		end := time.Now().UTC()
		sc.FinishedAt = &end
		sc.DurationMS = end.Sub(sc.StartedAt).Milliseconds()
		sc.Status = status
		sc.Error = errMsg
		_ = r.Store.UpdateScan(ctx, sc)
		// A failed scan marks the host unreachable so it's distinguishable from a
		// never-scanned "pending" host (e.g. devRhel with bad SSH credentials). Narrow
		// setter: a full UpdateHost here, built from this call's possibly-stale host
		// snapshot, would race a concurrent scan's or host-key-learn's own write to
		// the same row and could silently revert it (see SetHostOnline's doc).
		if status == store.ScanFailed {
			_ = r.Store.SetHostUnreachable(ctx, host.ID)
		}
		return sc, nil
	}

	activeRules, err := r.LoadRules(ctx)
	if err != nil {
		return finish(store.ScanFailed, "load rules: "+err.Error())
	}
	index := rules.Index(activeRules)

	transport, err := r.NewTransport(host)
	if err != nil {
		return finish(store.ScanFailed, "transport: "+err.Error())
	}

	bundle := rules.BundleFrom(activeRules)
	result, err := transport.RunProbe(ctx, bundle, false)
	// A transport can finish after cancellation, including after another worker
	// reclaimed its job. Do not ingest stale findings or mark the host unreachable.
	discard := func(cause error) (*store.Scan, error) {
		end := time.Now().UTC()
		sc.Status, sc.Error, sc.FinishedAt = store.ScanFailed, "discarded scan result: "+cause.Error(), &end
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if updateErr := r.Store.UpdateScan(cleanup, sc); updateErr != nil {
			return sc, fmt.Errorf("discard result (%v): %w", cause, updateErr)
		}
		return sc, cause
	}
	if ctx.Err() != nil {
		return discard(ctx.Err())
	}
	if validateOwner != nil {
		if ownerErr := validateOwner(ctx); ownerErr != nil {
			return discard(ownerErr)
		}
	}
	if err != nil {
		return finish(store.ScanFailed, "probe: "+err.Error())
	}
	sc.ProbeVersion = result.ProbeVersion

	risk := 0
	for _, f := range result.Findings {
		meta, ok := index[f.RuleID]
		if !ok {
			continue // unknown rule id; skip enrichment
		}
		obs := &store.Observation{
			HostID:   host.ID,
			ScanID:   sc.ID,
			Source:   store.SourceAgentlessProbe,
			RuleID:   f.RuleID,
			Category: meta.Category,
			Title:    meta.Title,
			Severity: meta.Severity,
			Score:    meta.Score,
			Mitre:    meta.Mitre,
			Evidence: f.Evidence,
			DedupKey: f.DedupKey,
			Status:   store.ObsOpen,
		}
		if _, err := r.Store.UpsertObservation(ctx, obs); err != nil {
			return finish(store.ScanFailed, "store observation: "+err.Error())
		}
		risk += meta.Score
	}

	inventory := takeInventory(result.StateDigest)
	risk += r.applyBaseline(ctx, host, sc, result.StateDigest, result.BpfPrograms...)
	risk += r.applyRarity(ctx, host, sc, result.StateDigest)
	risk += r.applyCredentialReuse(ctx, host, sc, inventory)
	if risk > 100 {
		risk = 100
	}
	sc.RiskScore = risk

	r.updateHostFromResult(ctx, host, result)

	status, detail := store.ScanOK, ""
	if len(result.CollectorErrors) > 0 {
		// What the collectors could not read is the answer to "why partial", so it is kept
		// in the scan's error field.
		status, detail = store.ScanPartial, strings.Join(result.CollectorErrors, "; ")
	}
	return finish(status, detail)
}

// baselineCategory maps a digest category to an observation category.
var baselineCategory = map[string]string{
	probe.DigestListeningPorts: "network",
	probe.DigestKernelModules:  "kernel",
	probe.DigestAccounts:       "credential",
	probe.DigestAuthorizedKeys: "credential",
	probe.DigestCron:           "persistence",
	probe.DigestSystemdUnits:   "persistence",
}

// categoryMitre maps baseline and fleet digest categories to ATT&CK techniques.
var categoryMitre = map[string][]string{
	probe.DigestListeningPorts: {"T1571"},
	probe.DigestKernelModules:  {"T1547.006"},
	probe.DigestAccounts:       {"T1136.001"},
	probe.DigestAuthorizedKeys: {"T1098.004"},
	probe.DigestCron:           {"T1053.003"},
	probe.DigestSystemdUnits:   {"T1543.002"},
	probe.DigestBpfPrograms:    {"T1547.006"},
}

// applyBaseline establishes the host baseline on the first scan, and on later
// scans emits a medium "new-since-baseline" observation for every digest item not
// in the baseline (drift). The baseline is frozen until re-established via the API,
// so genuine drift keeps surfacing until an operator acknowledges it. Returns the
// drift contribution to the scan risk score.
func (r *Runner) applyBaseline(ctx context.Context, host *store.Host, sc *store.Scan, digest map[string][]string, bpfPrograms ...probe.BpfProg) int {
	if len(digest) == 0 {
		return 0
	}
	base, err := r.Store.GetBaseline(ctx, host.ID)
	var nf store.ErrNotFound
	if errors.As(err, &nf) || base == nil {
		_ = r.Store.SaveBaseline(ctx, &store.Baseline{HostID: host.ID, Digest: digest})
		return 0 // baseline established this scan; no drift
	}
	if err != nil {
		return 0
	}
	drift := 0
	for cat, items := range digest {
		baseSet := make(map[string]bool, len(base.Digest[cat]))
		for _, b := range base.Digest[cat] {
			baseSet[b] = true
		}
		for _, it := range items {
			if baseSet[it] {
				continue
			}
			obs := &store.Observation{
				HostID:   host.ID,
				ScanID:   sc.ID,
				Source:   store.SourceBaseline,
				RuleID:   "baseline-new-" + cat,
				Category: baselineCategory[cat],
				Mitre:    categoryMitre[cat],
				Title:    "New " + cat + " since baseline: " + it,
				Severity: "medium",
				Score:    40,
				Evidence: map[string]any{"category": cat, "item": it},
				DedupKey: "baseline|" + cat + "|" + it,
				Status:   store.ObsOpen,
			}
			if cat == probe.DigestBpfPrograms {
				obs.Evidence["scan_started_at"] = sc.StartedAt
				var matches []probe.BpfProg
				for _, p := range bpfPrograms {
					if p.Type+":"+p.Tag == it {
						matches = append(matches, p)
					}
				}
				obs.Evidence["programs"] = matches
				if len(matches) == 0 {
					obs.Evidence["evidence_status"] = "unavailable"
				}
			}
			if _, err := r.Store.UpsertObservation(ctx, obs); err == nil {
				drift += 10
			}
		}
	}
	if drift > 50 {
		drift = 50
	}
	return drift
}

// minFleetHosts is the smallest fleet for which rarity scoring is meaningful.
const minFleetHosts = 4

// rarityCategory selects digest categories where "rare across the fleet" is a
// useful hunting signal (accounts/systemd units vary too much per host to score).
var rarityCategory = map[string]bool{
	probe.DigestKernelModules:  true,
	probe.DigestListeningPorts: true,
	probe.DigestAuthorizedKeys: true,
	probe.DigestCron:           true,
}

// applyRarity flags items that appear on very few hosts across the fleet — a
// kernel module / listener / key / cron present on 1 of N hosts is a hunting lead
// (e.g. a rootkit module unique to a compromised box). Low severity by design.
// Frequencies are computed from the stored per-host baselines.
// cohortKey groups hosts so fleet-rarity only compares like with like (distro +
// major version, e.g. "ubuntu-24", "debian-13"). Comparing a Proxmox/Debian host
// against Ubuntu hosts would flag every distro-specific module as "rare" — noise.
func cohortKey(h *store.Host) string {
	name := strings.ToLower(strings.TrimSpace(h.OSName))
	if name == "" {
		return "unknown"
	}
	fields := strings.Fields(name)
	distro := fields[0] // ubuntu / debian / centos / ...
	for _, f := range fields[1:] {
		num := f
		if i := strings.IndexAny(num, ".-"); i > 0 {
			num = num[:i]
		}
		if _, err := strconv.Atoi(num); err == nil {
			return distro + "-" + num
		}
	}
	return distro
}

func (r *Runner) applyRarity(ctx context.Context, host *store.Host, sc *store.Scan, digest map[string][]string) int {
	if len(digest) == 0 {
		return 0
	}
	bases, err := r.Store.ListBaselines(ctx)
	if err != nil {
		return 0
	}
	hosts, err := r.Store.ListHosts(ctx)
	if err != nil {
		return 0
	}
	cohortOf := map[string]string{}
	for _, h := range hosts {
		cohortOf[h.ID] = cohortKey(h)
	}
	myCohort := cohortKey(host)
	// Restrict the comparison set to the scanning host's cohort.
	cohort := bases[:0:0]
	for _, b := range bases {
		if cohortOf[b.HostID] == myCohort {
			cohort = append(cohort, b)
		}
	}
	if len(cohort) < minFleetHosts { // rarity is meaningless on a small cohort
		return 0
	}
	total := len(cohort)
	counts := map[string]map[string]int{} // category -> item -> host count
	for _, b := range cohort {
		for cat, items := range b.Digest {
			if !rarityCategory[cat] {
				continue
			}
			cm := counts[cat]
			if cm == nil {
				cm = map[string]int{}
				counts[cat] = cm
			}
			for _, it := range items {
				cm[it]++
			}
		}
	}
	rareMax := total / 20 // present on <= ~5% of the fleet
	if rareMax < 1 {
		rareMax = 1
	}
	score := 0
	for cat, items := range digest {
		if !rarityCategory[cat] {
			continue
		}
		for _, it := range items {
			n := counts[cat][it]
			if n == 0 || n > rareMax {
				continue
			}
			obs := &store.Observation{
				HostID:   host.ID,
				ScanID:   sc.ID,
				Source:   store.SourceFleet,
				RuleID:   "fleet-rare-" + cat,
				Category: baselineCategory[cat],
				Mitre:    categoryMitre[cat],
				Title:    "Rare in " + myCohort + " cohort (" + cat + " on " + itoa(n) + "/" + itoa(total) + " hosts): " + it,
				Severity: "low",
				Score:    15,
				Evidence: map[string]any{"category": cat, "item": it, "hosts_with": n, "cohort": myCohort, "cohort_size": total},
				DedupKey: "fleet|" + cat + "|" + it,
				Status:   store.ObsOpen,
			}
			if _, err := r.Store.UpsertObservation(ctx, obs); err == nil {
				score += 5
			}
		}
	}
	if score > 30 {
		score = 30
	}
	return score
}

func itoa(n int) string { return strconv.Itoa(n) }

func (r *Runner) updateHostFromResult(ctx context.Context, host *store.Host, res probe.ScanResult) {
	now := time.Now().UTC()
	// Narrow setter, not UpdateHost(ctx, host): host is a snapshot read at the start
	// of this scan, and a full overwrite from it would race (and could silently
	// revert) a concurrent scan's or host-key-learn's own write to the same row.
	// SetHostOnline only ever touches the columns a scan outcome actually knows
	// about, so two scans finishing close together just leave last-write-wins
	// semantics on those columns, not a lost update of unrelated fields.
	_ = r.Store.SetHostOnline(ctx, host.ID, now, res.Host.OS, res.Host.Kernel, res.Host.Arch, res.Host.Hostname)
}

// ----------------------------------------------------------------------------
// LocalTransport runs the probe binary on the local machine. Used for dev/tests
// and for scanning the server's own host. With ExtraArgs set to
// {"--snapshot-file", path} it replays a captured snapshot on any platform.
// ----------------------------------------------------------------------------

type LocalTransport struct {
	ProbeBin  string
	ExtraArgs []string
}

func (t LocalTransport) RunProbe(ctx context.Context, bundle probe.RuleBundle, emitSnapshot bool) (probe.ScanResult, error) {
	var res probe.ScanResult
	tmp, err := os.CreateTemp("", "bladedr-bundle-*.json")
	if err != nil {
		return res, err
	}
	defer os.Remove(tmp.Name())
	if err := json.NewEncoder(tmp).Encode(bundle); err != nil {
		tmp.Close()
		return res, err
	}
	tmp.Close()

	args := []string{"--rules", tmp.Name()}
	if emitSnapshot {
		args = append(args, "--emit-snapshot")
	}
	args = append(args, t.ExtraArgs...)

	// ProbeBin + ExtraArgs are operator-configured (the local probe path / args), not
	// request data — LocalTransport is the dev/self-scan path, so this is not injectable.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, t.ProbeBin, args...)
	out, err := cmd.Output()
	if err != nil {
		return res, decodeExecError(err)
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return res, fmt.Errorf("parse probe output: %w", err)
	}
	return res, nil
}

func decodeExecError(err error) error {
	if ee, ok := err.(*exec.ExitError); ok {
		return fmt.Errorf("probe failed: %s", string(ee.Stderr))
	}
	return err
}
