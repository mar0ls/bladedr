// Command bladedr-lab is the attack-emulation range orchestrator. It plants each
// EDR-T technique from poligon/manifest.yaml (in an "obvious" and a "stealthy"
// naming variant), runs the bladedr probe after each plant, diffs the findings
// against a clean baseline, and labels the new findings by technique. Output: a
// labelled dataset (dataset.jsonl) for the ML risk model, plus a detection-coverage
// report (which rules actually fire on a live host).
//
// Targets:
//
//	(default)            a disposable Docker container built from poligon/Dockerfile
//	--target user@host   a real Linux host over SSH (for privileged/kernel techniques
//	                     that a container can't do); password via BLADEDR_LAB_SSH_PASSWORD,
//	                     privileged steps use passwordless sudo on the target. Anything
//	                     beyond the privileged set also needs --disposable.
//
// It exercises the same detection engine as production (the probe + builtin rules).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"bladedr/internal/probe"
	"bladedr/internal/risk"
	"bladedr/internal/rules"
	"bladedr/internal/store"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

func main() {
	var (
		root       = flag.String("root", ".", "repo root (contains poligon/ and bin/)")
		image      = flag.String("image", "bladedr-poligon", "container image tag (docker target)")
		target     = flag.String("target", "", "SSH target user@host[:port] (default: a disposable container)")
		out        = flag.String("out", "poligon/dataset.jsonl", "labelled dataset output path")
		variants   = flag.String("variants", "obvious,stealthy", "comma-separated naming variants to run")
		only       = flag.String("only", "", "comma-separated technique ids to run (default: all)")
		appendDS   = flag.Bool("append", false, "append to the dataset instead of overwriting")
		scenesOut  = flag.String("scenes-out", "poligon/scenes.jsonl", "multi-technique scene dataset output path")
		keep       = flag.Bool("keep", false, "keep the container/working dir after the run")
		disposable = flag.Bool("disposable", false, "allow non-privileged techniques on an SSH --target (throwaway hosts only)")
		// Gates for CI. The run is informational without them: it prints MISSes and
		// exits 0, so wiring it up unguarded would watch coverage rot in silence.
		failOnMiss = flag.Bool("fail-on-miss", false, "exit non-zero if any scenario that ran did not fire its expected rule")
		wantTechs  = flag.Int("expect-techniques", 0, "exit non-zero unless exactly this many techniques were selected")
	)
	dumpBundle := flag.Bool("dump-bundle", false, "print the rule bundle JSON and exit (for ad-hoc probe runs)")
	flag.Parse()

	if *dumpBundle {
		b, _, err := buildBundle()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(b)
		return
	}

	if err := run(cfg{
		root: *root, image: *image, target: *target, out: *out,
		variants: splitCSV(*variants), only: splitSet(*only), appendDS: *appendDS, keep: *keep,
		scenesOut: *scenesOut, disposable: *disposable,
		failOnMiss: *failOnMiss, wantTechs: *wantTechs,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "bladedr-lab:", err)
		os.Exit(1)
	}
}

type cfg struct {
	root, image, target, out, scenesOut string
	variants                            []string
	only                                map[string]bool
	appendDS, keep, disposable          bool
	failOnMiss                          bool
	wantTechs                           int
}

func run(c cfg) error {
	bundle, meta, err := buildBundle()
	if err != nil {
		return fmt.Errorf("build rule bundle: %w", err)
	}
	var man manifest
	mb, err := os.ReadFile(filepath.Join(c.root, "poligon", "manifest.yaml"))
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	if err := yaml.Unmarshal(mb, &man); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}
	var techs []technique
	var skipped []string
	for _, t := range man.Techniques {
		if len(c.only) > 0 && !c.only[t.ID] {
			continue
		}
		if t.Requires == "privileged" && c.target == "" {
			skipped = append(skipped, t.ID) // needs root + a real host
			continue
		}
		techs = append(techs, t)
	}
	fmt.Printf("==> %d techniques, %d builtin rules, variants %v\n", len(techs), len(meta), c.variants)
	if len(skipped) > 0 {
		// Say this out loud. The coverage line below is over the techniques that ran,
		// so without this a run that quietly stopped exercising something still reports
		// a perfect score.
		fmt.Printf("==> %d technique(s) need a real host and were NOT exercised: %s\n",
			len(skipped), strings.Join(skipped, ", "))
	}
	if err := checkTargetScope(c, techs); err != nil {
		return err
	}
	if c.wantTechs > 0 && len(techs) != c.wantTechs {
		return fmt.Errorf("selected %d techniques, expected %d — the manifest or the skip rules changed; "+
			"update --expect-techniques deliberately rather than letting coverage drift", len(techs), c.wantTechs)
	}

	r, labDir, probePrefix, err := setupTarget(c)
	if err != nil {
		return err
	}
	defer r.teardown()

	// Match the probe to the target arch; build the runtime helper for it.
	arch, err := r.archName()
	if err != nil {
		return err
	}
	ga := goarch(strings.TrimSpace(arch))
	probeBin := filepath.Join(c.root, "bin", "bladedr-probe.linux-"+ga)
	if _, err := os.Stat(probeBin); err != nil {
		return fmt.Errorf("probe binary %s missing — run `make build` first: %w", probeBin, err)
	}
	helperBin := filepath.Join(os.TempDir(), "bladedr-labhelper-"+ga)
	hb := exec.Command("go", "build", "-o", helperBin, "./poligon/helpers/runtime")
	hb.Dir, hb.Stderr = c.root, os.Stderr
	hb.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+ga)
	if err := hb.Run(); err != nil {
		return fmt.Errorf("build lab helper: %w", err)
	}
	bf := filepath.Join(os.TempDir(), "bladedr-lab-bundle.json")
	if data, err := json.Marshal(bundle); err != nil {
		return err
	} else if err := os.WriteFile(bf, data, 0o644); err != nil {
		return err
	}
	if _, err := r.sh("mkdir -p " + labDir); err != nil {
		return fmt.Errorf("mkdir labdir: %w", err)
	}
	for _, f := range []struct {
		local, remote string
		exe           bool
	}{
		{probeBin, labDir + "/probe", true},
		{helperBin, labDir + "/helper", true},
		{filepath.Join(c.root, "poligon", "techniques.sh"), labDir + "/techniques.sh", false},
		{bf, labDir + "/bundle.json", false},
	} {
		if err := r.put(f.local, f.remote, f.exe); err != nil {
			return fmt.Errorf("upload %s: %w", filepath.Base(f.remote), err)
		}
	}

	scanCmd := probePrefix + labDir + "/probe --rules " + labDir + "/bundle.json"
	scan := func() ([]probe.Finding, error) {
		stdout, err := r.sh(scanCmd)
		if err != nil {
			return nil, fmt.Errorf("probe run: %w", err)
		}
		var res probe.ScanResult
		if err := json.Unmarshal([]byte(stdout), &res); err != nil {
			return nil, fmt.Errorf("parse scan result: %w (got %.120q)", err, stdout)
		}
		return res.Findings, nil
	}

	baseFindings, err := scan()
	if err != nil {
		return err
	}
	baseline := dedupSet(baseFindings)
	fmt.Printf("==> clean baseline: %d pre-existing findings (subtracted)\n\n", len(baseFindings))

	// On an SSH target, pass the sudo password to the technique script (used only by
	// sudo -S on stdin for privileged plant/clean steps; no persistent change).
	techEnv := ""
	if c.target != "" {
		techEnv = "BLADEDR_SUDO_PW=" + shellQuote(os.Getenv("BLADEDR_LAB_SSH_PASSWORD")) + " "
	}
	tech := func(id, act, v string) string {
		return techEnv + "LABDIR=" + labDir + " bash " + labDir + "/techniques.sh " + id + " " + act + " " + v
	}
	var dataset []example
	cov := map[covKey]bool{}
	for _, t := range techs {
		for _, v := range c.variants {
			v = strings.TrimSpace(v)
			if _, err := r.sh(tech(t.ID, "plant", v)); err != nil {
				fmt.Printf("  ! %-22s %-8s plant failed: %v\n", t.ID, v, err)
				// A plant can fail halfway — after it saved an original, after mkdir —
				// so clean regardless. Restoring what was never replaced is a no-op.
				r.sh(tech(t.ID, "clean", v))
				continue
			}
			fs, err := scan()
			if err != nil {
				return err
			}
			newF := newFindings(baseline, fs)
			exs := labelFindings(t, v, newF, meta)
			dataset = append(dataset, exs...)
			detected := len(exs) > 0 && exs[0].Detected
			cov[covKey{t.ID, v}] = detected
			mark := "MISS"
			if detected {
				mark = "ok"
			}
			fmt.Printf("  %-4s %-22s %-8s expect=%-28s found=%v\n", mark, t.ID, v, t.Expect, ruleIDs(newF))
			r.sh(tech(t.ID, "clean", v))
		}
	}

	// Scenes: several techniques on one host, scanned once, so the rows carry siblings.
	// Written to their own file rather than mixed into dataset.jsonl — a scene replants
	// techniques the loop above already covered, so merging them would duplicate rows and
	// quietly reweight the training set. Whether the sibling count separates an intrusion
	// from a busy-but-legitimate host is the open question these rows exist to answer.
	sceneRows, sceneFailures, err := runScenes(c, man.Scenes, techs, meta, baseline, tech, scan, r)
	if err != nil {
		return err
	}
	if c.failOnMiss && sceneFailures > 0 {
		return fmt.Errorf("%d scene plant(s) failed — the scene finding counts they produced are not comparable", sceneFailures)
	}
	if len(sceneRows) > 0 {
		if err := writeDataset(filepath.Join(c.root, c.scenesOut), sceneRows, false); err != nil {
			return err
		}
	}

	if err := writeDataset(filepath.Join(c.root, c.out), dataset, c.appendDS); err != nil {
		return err
	}
	hit, total := report(techs, c.variants, cov, dataset, sceneRows, c.out)
	if c.failOnMiss && hit != total {
		return fmt.Errorf("%d of %d scenarios did not fire their expected rule", total-hit, total)
	}
	return nil
}

// runScenes plants each scene's techniques together, scans once, and labels every
// finding that scan produced with the scene's class — so each row knows how many other
// findings shared its host. Techniques are cleaned in reverse order, so one that
// overwrote another's file is removed first.
//
// A scene is skipped rather than partially run when any of its techniques did not run
// here (a --only filter, or one that needs a privileged host): a scene missing a plant
// reports a smaller finding count for the wrong reason, which is worse than no row.
func runScenes(c cfg, scenes []scene, techs []technique, meta map[string]rules.Rule,
	baseline map[string]bool, tech func(id, act, v string) string,
	scan func() ([]probe.Finding, error), r runner) ([]example, int, error) {

	if len(scenes) == 0 {
		return nil, 0, nil
	}
	failedPlants := 0
	available := map[string]bool{}
	for _, t := range techs {
		available[t.ID] = true
	}

	var rows []example
	for _, sc := range scenes {
		var missing []string
		for _, id := range sc.Techniques {
			if !available[id] {
				missing = append(missing, id)
			}
		}
		if len(missing) > 0 {
			fmt.Printf("  skip scene %-22s (not exercised here: %s)\n", sc.ID, strings.Join(missing, ", "))
			continue
		}
		for _, v := range c.variants {
			v = strings.TrimSpace(v)
			planted := make([]string, 0, len(sc.Techniques))
			for _, id := range sc.Techniques {
				if _, err := r.sh(tech(id, "plant", v)); err != nil {
					// Counted, not just printed: a scene short one plant reports a
					// smaller finding count for a reason that has nothing to do with
					// detection, and that number would go straight into the dataset.
					fmt.Printf("  ! scene %s: %s plant failed: %v\n", sc.ID, id, err)
					failedPlants++
					r.sh(tech(id, "clean", v))
					continue
				}
				planted = append(planted, id)
			}
			fs, err := scan()
			if err != nil {
				return nil, failedPlants, err
			}
			newF := newFindings(baseline, fs)
			for _, f := range newF {
				m := meta[f.RuleID]
				rows = append(rows, example{
					Technique: sc.ID, Variant: v,
					RuleID: f.RuleID, Category: m.Category, Severity: m.Severity, Mitre: m.Mitre,
					Source: "lab", Label: sc.label(), Evidence: f.Evidence,
					Scene: sc.ID, SceneFindings: len(newF),
				})
			}
			fmt.Printf("  scene %-22s %-8s %d findings across %d rules (%d techniques planted)\n",
				sc.ID, v, len(newF), distinctRules(newF), len(planted))
			for i := len(planted) - 1; i >= 0; i-- {
				r.sh(tech(planted[i], "clean", v))
			}
		}
	}
	return rows, failedPlants, nil
}

// report prints the detection-coverage matrix, the generalisation check, and the
// dataset composition — the blue-team + ML summary of the run.
// report prints the run summary and returns the scenarios that fired and the total that
// ran, so the caller can turn that into an exit status.
//
// Attack and benign-but-flagged scenarios are counted separately. They answer different
// questions — "does the rule catch the attack" versus "does this legitimate config trip
// it too" — and one ratio over both is neither. The negative class is deliberately being
// grown towards the size the risk model needs, so folding it in would let benign
// scenarios inflate a number every reader takes for detection coverage.
func report(techs []technique, variants []string, cov map[covKey]bool, dataset, sceneRows []example, outPath string) (hitOut, totalOut int) {
	fired := func(t technique) (hit, total int) {
		for _, v := range variants {
			total++
			if cov[covKey{t.ID, strings.TrimSpace(v)}] {
				hit++
			}
		}
		return hit, total
	}
	var hit, total, benignHit, benignTotal, attacks int
	for _, t := range techs {
		h, n := fired(t)
		if t.label() == "false_positive" {
			benignHit, benignTotal = benignHit+h, benignTotal+n
			continue
		}
		hit, total, attacks = hit+h, total+n, attacks+1
	}
	fmt.Printf("\n==> detection coverage: %d/%d attack scenarios fired their expected rule\n", hit, total)
	// A benign scenario that stops firing is not good news either: it silently drops a
	// row from the negative class, which is the half of the training set the model is
	// short of. Reported next to coverage, never inside it.
	fmt.Printf("==> negative-class calibration: %d/%d benign scenarios still trip their ambiguous rule\n", benignHit, benignTotal)

	gen := 0
	for _, t := range techs {
		if t.label() == "false_positive" {
			continue
		}
		all := true
		for _, v := range variants {
			if !cov[covKey{t.ID, strings.TrimSpace(v)}] {
				all = false
			}
		}
		if all {
			gen++
		}
	}
	fmt.Printf("==> generalises across naming variants: %d/%d attack techniques\n", gen, attacks)

	tacticOf := map[string]string{}
	for _, t := range techs {
		tacticOf[t.ID] = t.Tactic
	}
	byTactic := map[string]int{}
	for _, e := range dataset {
		byTactic[tacticOf[e.Technique]]++
	}
	fmt.Printf("==> dataset: %d labelled examples -> %s\n", len(dataset), outPath)
	for tac, n := range byTactic {
		fmt.Printf("      %-12s %d\n", tac, n)
	}

	pos, neg := 0, 0
	for _, e := range dataset {
		switch risk.LabelOf(e.observation().Verdict) {
		case risk.Positive:
			pos++
		case risk.Negative:
			neg++
		}
	}
	fmt.Printf("==> ML: %d technique-labelled POSITIVES + %d benign-but-flagged NEGATIVES ready to mix with prod triage\n", pos, neg)

	// Feature ablation, printed on every run because it is the one number that says
	// whether the model learned anything beyond "which rule fired". Features() emits a
	// rule:<id> token; if the ranking survives only while that token is present, the
	// model is a lookup table over rule ids and its cross-validated score is measuring
	// memorisation. Both sides run the identical protocol (same folds, seeds, metrics),
	// so the gap is attributable to the withheld feature and nothing else.
	var labelled []*store.Observation
	for _, e := range dataset {
		labelled = append(labelled, e.observation())
	}
	full := risk.Evaluate(labelled)
	// The headline number, printed first because it is the one the model exists to move.
	// A rule that fires on both real findings and noise is only useful if the model can
	// tell two of its instances apart; a tied rule means it cannot, and the score it
	// returns is the rule's own static score wearing a model's clothes.
	if aMean, bMean, aN, bN := sceneFindingStats(sceneRows); aN+bN > 0 {
		fmt.Printf("==> scene co-occurrence: attack scenes %.1f findings on average (n=%d), benign scenes %.1f (n=%d)\n",
			aMean, aN, bMean, bN)
	}
	fmt.Printf("==> within-rule separation: %d of %d ambiguous rules are TIED — every instance scores the same (lower is better)\n",
		full.WithinRuleTied, full.WithinRuleRules)
	// Two ablations, because either alone misleads. Dropping "rule:" does not remove rule
	// identity — category, severity and the MITRE ids are rule metadata and reconstruct it
	// for most rules — so the block ablation is the one to read. The shape ablation says
	// how much of the ranking the instance-level features are carrying.
	noRuleBlock := risk.EvaluateWithout(labelled, "rule:", "cat:", "sev:", "tech:", "tac:")
	noShape := risk.EvaluateWithout(labelled, "shape:")
	fmt.Printf("==> feature ablation: ROC AUC %.3f (±%.3f) full | %.3f without instance-shape features | %.3f without any rule-derived feature\n",
		full.CVROCAUC, full.CVROCAUCStdDev, noShape.CVROCAUC, noRuleBlock.CVROCAUC)
	fmt.Printf("==> balanced accuracy: %.3f full | %.3f shape withheld (0.500 is chance)\n",
		full.CVBalancedAccuracy, noShape.CVBalancedAccuracy)
	fmt.Printf("==> lab-only trust check: %v (%s)\n", full.Trustworthy, full.Reason)
	// Both classes are returned to the caller: --fail-on-miss gates on every scenario
	// that ran, attack or benign, because either going quiet costs the model data.
	return hit + benignHit, total + benignTotal
}

func writeDataset(path string, dataset []example, appendMode bool) error {
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if appendMode {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, e := range dataset {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}

func ruleIDs(fs []probe.Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			out = append(out, f.RuleID)
		}
	}
	return out
}

func goarch(uname string) string {
	switch uname {
	case "aarch64", "arm64":
		return "arm64"
	default:
		return "amd64"
	}
}

func splitCSV(s string) []string { return strings.Split(s, ",") }

func splitSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			m[p] = true
		}
	}
	return m
}

// ---- targets ----------------------------------------------------------------

// checkTargetScope refuses to run the container-grade techniques on an SSH target
// unless the operator says the host is throwaway. They are written for a container that
// is deleted afterwards: while the run lasts the host carries a world-writable
// /etc/passwd, SUID root shells, uid-0 and passwordless accounts and a replaced
// sshd_config, and a run that dies mid-way leaves them there. The privileged set is
// what --target exists for, and it is reversible by design.
func checkTargetScope(c cfg, techs []technique) error {
	if c.target == "" || c.disposable {
		return nil
	}
	var unsafe []string
	for _, t := range techs {
		if t.Requires != "privileged" {
			unsafe = append(unsafe, t.ID)
		}
	}
	if len(unsafe) == 0 {
		return nil
	}
	return fmt.Errorf("%d non-privileged technique(s) selected for SSH target %s (%s); they weaken the host while "+
		"they run — pass --only with the privileged set, or --disposable if %s is a throwaway VM",
		len(unsafe), c.target, abbreviate(unsafe, 5), c.target)
}

func abbreviate(ids []string, n int) string {
	if len(ids) <= n {
		return strings.Join(ids, ", ")
	}
	return strings.Join(ids[:n], ", ") + fmt.Sprintf(", … +%d", len(ids)-n)
}

// runner abstracts where techniques run: exec a shell command, copy a file in.
type runner interface {
	archName() (string, error)
	put(local, remote string, exe bool) error
	sh(cmd string) (string, error)
	teardown()
}

// setupTarget returns a runner plus the lab working dir and the probe command
// prefix (sudo on a non-root SSH host so the probe can read privileged artifacts).
func setupTarget(c cfg) (runner, string, string, error) {
	if c.target == "" {
		fmt.Println("==> building poligon image")
		if err := docker(nil, "build", "-t", c.image, filepath.Join(c.root, "poligon")); err != nil {
			return nil, "", "", fmt.Errorf("docker build: %w", err)
		}
		name := fmt.Sprintf("bladedr-poligon-%d", time.Now().Unix())
		if err := docker(nil, "run", "-d", "--name", name, c.image); err != nil {
			return nil, "", "", fmt.Errorf("docker run: %w", err)
		}
		return &dockerRunner{name: name, keep: c.keep}, "/lab", "", nil
	}
	cl, err := dialSSH(c.target)
	if err != nil {
		return nil, "", "", fmt.Errorf("ssh dial %s: %w", c.target, err)
	}
	fmt.Printf("==> SSH target %s\n", c.target)
	// Run the probe as root via sudo -S so it can read /dev/kmsg (dmesg-based rules
	// like promiscuous-mode) — same access bladedr's real scan has. The password is
	// fed on stdin per scan; sudo -S consumes it, the probe gets clean stdin.
	probePrefix := "printf '%s\\n' " + shellQuote(os.Getenv("BLADEDR_LAB_SSH_PASSWORD")) + " | sudo -S "
	return &sshRunner{client: cl, labDir: "/tmp/bladedr-lab", keep: c.keep}, "/tmp/bladedr-lab", probePrefix, nil
}

// shellQuote single-quotes a string for safe embedding in a remote shell command.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

type dockerRunner struct {
	name string
	keep bool
}

func (d *dockerRunner) archName() (string, error) { return dockerOut(d.name, "uname", "-m") }
func (d *dockerRunner) sh(cmd string) (string, error) {
	return dockerOut(d.name, "sh", "-c", cmd)
}
func (d *dockerRunner) put(local, remote string, exe bool) error {
	if err := docker(nil, "cp", local, d.name+":"+remote); err != nil {
		return err
	}
	if exe {
		return docker(nil, "exec", d.name, "chmod", "+x", remote)
	}
	return nil
}
func (d *dockerRunner) teardown() {
	if !d.keep {
		docker(nil, "rm", "-f", d.name)
	}
}

type sshRunner struct {
	client *ssh.Client
	labDir string
	keep   bool
}

func (s *sshRunner) archName() (string, error) { return s.sh("uname -m") }
func (s *sshRunner) sh(cmd string) (string, error) {
	sess, err := s.client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var out bytes.Buffer
	sess.Stdout, sess.Stderr = &out, os.Stderr
	err = sess.Run(cmd)
	return out.String(), err
}
func (s *sshRunner) put(local, remote string, exe bool) error {
	data, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	sess, err := s.client.NewSession()
	if err != nil {
		return err
	}
	sess.Stdin, sess.Stderr = bytes.NewReader(data), os.Stderr
	if err := sess.Run("cat > '" + remote + "'"); err != nil {
		sess.Close()
		return err
	}
	sess.Close()
	if exe {
		_, err = s.sh("chmod +x '" + remote + "'")
	}
	return err
}
func (s *sshRunner) teardown() {
	if !s.keep {
		s.sh("rm -rf " + s.labDir)
	}
	s.client.Close()
}

// dialSSH connects to user@host[:port] using BLADEDR_LAB_SSH_PASSWORD. Host-key
// checking is skipped: this is a lab tool pointed at a throwaway box on a trusted
// LAN, not the production scanner (which pins host keys).
func dialSSH(target string) (*ssh.Client, error) {
	target = strings.TrimPrefix(target, "ssh://")
	user, host := "root", target
	if i := strings.IndexByte(target, '@'); i >= 0 {
		user, host = target[:i], target[i+1:]
	}
	if !strings.Contains(host, ":") {
		host += ":22"
	}
	pw := os.Getenv("BLADEDR_LAB_SSH_PASSWORD")
	if pw == "" {
		return nil, fmt.Errorf("set BLADEDR_LAB_SSH_PASSWORD for the SSH target")
	}
	ki := ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
		a := make([]string, len(qs))
		for i := range qs {
			a[i] = pw
		}
		return a, nil
	})
	cfg := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(pw), ki},
		// This is the LAB orchestrator pointed at a throwaway box on a trusted LAN, not
		// the production scanner (internal/scan/ssh.go pins host keys via TOFU).
		// nosemgrep: go.lang.security.audit.crypto.insecure_ssh.avoid-ssh-insecure-ignore-host-key
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", host, cfg)
}

// docker runs a docker command, streaming stderr; stdin optional.
func docker(stdin []byte, args ...string) error {
	cmd := exec.Command("docker", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// dockerOut runs `docker exec <name> <cmd...>` and returns stdout.
func dockerOut(name string, cmdArgs ...string) (string, error) {
	args := append([]string{"exec", name}, cmdArgs...)
	cmd := exec.Command("docker", args...)
	var stdout bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, os.Stderr
	err := cmd.Run()
	return stdout.String(), err
}
