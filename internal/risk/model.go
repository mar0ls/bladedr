// Package risk is bladedr's explainable risk-scoring tier: a multinomial Naive Bayes
// model trained on explicit analyst verdicts. It learns which structural features
// (the rule, its source, and the shape of the artifact it fired on) separate real
// findings from false positives, and outputs a 0-100 priority plus the features that
// drove it.
// Training and inference run in-process without an external ML runtime.
//
// It is a prioritiser, not a detector: rules decide what is a finding; this model
// ranks findings by how likely an analyst is to treat them as real, learned from past
// verdicts. Evaluate reports whether the labelled set is
// large/balanced/accurate enough to trust (see Stats.Trustworthy).
package risk

import (
	"math"
	// math/rand (not crypto/rand) is intentional: the fold shuffle has to be reproducible
	// from a seed, so the same observations always produce the same report. This is
	// evaluation resampling, not security or token material.
	// nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used
	"math/rand"
	"sort"
	"strconv"
	"strings"

	"bladedr/internal/store"
)

// Label is the supervised target derived from an observation's analyst verdict.
type Label int

const (
	Unlabeled Label = iota
	Negative        // explicitly assessed false_positive
	Positive        // explicitly assessed true_positive
)

// LabelOf consumes the independent analyst verdict, never workflow status.
// Only explicit true_positive/false_positive assessments supervise training.
func LabelOf(verdict string) Label {
	switch verdict {
	case store.ObsFalsePositive:
		return Negative
	case "true_positive":
		return Positive
	default:
		return Unlabeled
	}
}

// Features extracts structural tokens and coarse evidence classes. Literal paths,
// process names and arguments are excluded because they are attacker-controlled and
// do not generalise across hosts.
func Features(o *store.Observation) []string {
	feats := make([]string, 0, 10)
	add := func(feature string) {
		for _, existing := range feats {
			if existing == feature {
				return
			}
		}
		feats = append(feats, feature)
	}
	// Category, severity and MITRE IDs are rule-derived. Exclude them to avoid
	// counting correlated rule metadata as independent evidence.
	add("rule:" + o.RuleID)
	src := o.Source
	if src == sourceLab {
		// Lab records come from the agentless probe. Avoid a lab-only source token.
		src = "agentless_probe"
	}
	add("src:" + src)
	if c := pathClass(o.Evidence); c != "" {
		add("path:" + c)
	}
	if c := exeClass(o.Evidence); c != "" {
		add("exe:" + c)
	}
	if c := uidClass(o.Evidence); c != "" {
		add("uid:" + c)
	}
	if c := parentClass(o.Evidence); c != "" {
		add("parent:" + c)
	}
	// Instance-shape features. Everything above describes the *rule*: two instances of
	// the same rule share every one of those tokens, so a model built on them alone can
	// only re-rank rules, never rank inside one — which is the question triage actually
	// asks. These describe the artifact instead.
	//
	// The line they hold is that a feature must survive renaming. An attacker picks the
	// filename, the port and the account name freely, so those stay excluded (and the
	// obvious/stealthy variants exist to prove a model is not leaning on them). Whether
	// the artifact is hidden, which capability it carries, whether a grant names a group
	// or one account, whether it reaches for the dynamic linker — those are properties of
	// what the thing *does*, and changing them changes the artifact.
	ev := evidenceStrings(o.Evidence)
	if hasHiddenComponent(ev) {
		add("shape:hidden-path")
	}
	if c := capabilityClass(o.Evidence); c != "" {
		add("shape:cap-" + c)
	}
	if c := grantShape(ev); c != "" {
		add("shape:grant-" + c)
	}
	if referencesLinkerInjection(ev) {
		add("shape:linker-inject")
	}
	if hasInlineInterpreter(ev) {
		add("shape:inline-code")
	}
	if c := enforcementState(ev); c != "" {
		add("shape:enforce-" + c)
	}
	if hasShellStringExec(ev) {
		add("shape:shell-string-exec")
	}
	if c := tunnelShape(ev); c != "" {
		add("shape:tunnel-" + c)
	}
	if c := writableReach(o.Evidence); c != "" {
		add("shape:writable-" + c)
	}
	if keyExposedToOthers(o.Evidence) {
		add("shape:key-exposed")
	}
	return feats
}

// evidenceStrings flattens every string an evidence map carries, including those nested
// in the per-match lists rules emit (keys, matches, lines). The shape checks below read
// values, never keys, so a rule renaming an evidence field does not change the features.
func evidenceStrings(ev map[string]any) []string {
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(ev)
	return out
}

// transientRoots restrict hidden-path features to runtime and staging locations.
// Dot-directories elsewhere (e.g. ~/.ssh) are excluded.
var transientRoots = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/", "/dev/"}

// hasHiddenComponent detects dot-prefixed path components under transientRoots.
// This is a structural feature, not proof of concealment or malicious intent.
func hasHiddenComponent(values []string) bool {
	for _, v := range values {
		for _, field := range strings.Fields(v) {
			var under bool
			for _, root := range transientRoots {
				if strings.HasPrefix(field, root) {
					under = true
					break
				}
			}
			if !under {
				continue
			}
			if i := strings.Index(field, "/."); i >= 0 {
				rest := field[i+2:]
				// "/.." is traversal and "/." alone is the directory itself; neither is
				// a hidden name.
				if rest != "" && !strings.HasPrefix(rest, ".") && !strings.HasPrefix(rest, "/") {
					return true
				}
			}
		}
	}
	return false
}

// capabilityClass splits file capabilities by what they grant rather than by name.
// direct: capabilities that hand over root outright (setuid, dac_override, sys_admin,
// sys_module). observe: capabilities a profiler or backup agent legitimately needs
// (sys_ptrace, dac_read_search) — still worth flagging, far weaker as evidence of
// intent. The rule fires on both; only the model gets to weigh them differently.
func capabilityClass(ev map[string]any) string {
	caps, _ := ev["caps"].(string)
	if caps == "" {
		return ""
	}
	for _, c := range []string{"cap_setuid", "cap_setgid", "cap_dac_override", "cap_sys_admin", "cap_sys_module", "cap_sys_rawio"} {
		if strings.Contains(caps, c) {
			return "direct"
		}
	}
	for _, c := range []string{"cap_sys_ptrace", "cap_dac_read_search"} {
		if strings.Contains(caps, c) {
			return "observe"
		}
	}
	return "other"
}

// grantShape distinguishes group and account sudoers subjects without retaining names.
// Both forms can be legitimate or malicious.
func grantShape(values []string) string {
	for _, v := range values {
		f := strings.Fields(v)
		if len(f) < 2 || !strings.Contains(v, "ALL=") {
			continue
		}
		if strings.HasPrefix(f[0], "%") {
			return "group"
		}
		return "user"
	}
	return ""
}

// referencesLinkerInjection reports whether the artifact reaches for the dynamic linker
// (LD_PRELOAD, ld.so.preload, LD_LIBRARY_PATH). A backup key setting BORG_REPO and one
// setting LD_PRELOAD trip the same rule; only the second is loading code into every
// process the key touches.
func referencesLinkerInjection(values []string) bool {
	for _, v := range values {
		u := strings.ToUpper(v)
		if strings.Contains(u, "LD_PRELOAD") || strings.Contains(u, "LD_LIBRARY_PATH") ||
			strings.Contains(v, "ld.so.preload") {
			return true
		}
	}
	return false
}

// hasInlineInterpreter reports whether an interpreter is invoked with code on the command
// line (python -c, perl -e, sh -c "..."). Legitimate automation calls a script it ships;
// inline code in a cron line or a unit is how a payload avoids leaving a file to find.
func hasInlineInterpreter(values []string) bool {
	for _, v := range values {
		for _, p := range []string{"python -c", "python3 -c", "perl -e", "ruby -e", "bash -c", "sh -c", "php -r", "node -e"} {
			if strings.Contains(v, p) {
				return true
			}
		}
	}
	return false
}

// hasShellStringExec reports whether code hands a *string* to a shell (os.system,
// os.popen, shell=True, backticks) rather than executing an argv list. Both spawn a
// process and both trip the same rule; the string form exists to compose a command, and
// composing a command is what a payload does. Agent bootstraps ship an argv list.
func hasShellStringExec(values []string) bool {
	for _, v := range values {
		for _, p := range []string{"os.system(", "os.popen(", "shell=True", "subprocess.call(\"", "system("} {
			if strings.Contains(v, p) {
				return true
			}
		}
		if strings.Count(v, "`") >= 2 {
			return true
		}
	}
	return false
}

// tunnelShape separates a general-purpose pivot from a point-to-point forward. A dynamic
// SOCKS proxy (-D) reaches anything the host can reach, which is what lateral movement
// needs; a named port forward (-L/-R) reaches one service, which is what an operator
// opening a database through a bastion needs. Same rule, different reach.
func tunnelShape(values []string) string {
	for _, v := range values {
		l := strings.ToLower(v)
		switch {
		case strings.Contains(l, "socks"), strings.Contains(l, "(-d)"):
			return "dynamic"
		case strings.Contains(l, "port-forward"), strings.Contains(l, "(-r)"), strings.Contains(l, "(-l)"):
			return "forward"
		}
	}
	return ""
}

// writableReach reports who can write a root-executed config file: "other" (every
// account on the host) or "group" (one named non-root group). A unit file group-owned by
// deploy is how push-deploy works; the same file world-writable is nobody's deployment
// model. The rule cannot choose between them from a snapshot, so it reports both and
// leaves the weighing here.
func writableReach(ev map[string]any) string {
	v, _ := ev["via"].(string)
	switch v {
	case "other", "group":
		return v
	}
	return ""
}

// keyExposedToOthers reports a private key whose file mode lets the group or other users
// read it. Keeping a key at 0600 is the one control the owner has over a file the whole
// scheme depends on; a leaked or carelessly copied key is usually the 0644 one, an
// automation key someone set up deliberately usually is not. It reads the mode of a key
// finding only — the SUID rule's "mode" is a different thing and is left alone.
func keyExposedToOthers(ev map[string]any) bool {
	if _, isKey := ev["type"].(string); !isKey {
		return false
	}
	path, _ := ev["path"].(string)
	mode, _ := ev["mode"].(string)
	if !strings.Contains(path, "/.ssh/") && !strings.HasSuffix(path, ".pem") && !strings.HasSuffix(path, ".key") {
		return false
	}
	if len(mode) < 2 {
		return false
	}
	return mode[len(mode)-2:] != "00"
}

// enforcementState separates a security layer switched fully off from one left reporting.
// Both trip the same rule; "permissive" is a supported vendor configuration and still
// logs, "disabled" is neither.
func enforcementState(values []string) string {
	for _, v := range values {
		l := strings.ToLower(v)
		switch {
		case strings.Contains(l, "selinux=disabled"), strings.Contains(l, "=disabled"):
			return "off"
		case strings.Contains(l, "selinux=permissive"), strings.Contains(l, "=permissive"):
			return "permissive"
		}
	}
	return ""
}

// pathClass maps the first path-like evidence value — a file the finding is about, or a
// command a config will run — to a directory class.
func pathClass(ev map[string]any) string {
	keys := []string{"path", "binary", "exec_start", "exec_pre", "entry", "file", "dir", "interp", "interpreter", "shell", "module", "command"}
	for _, k := range keys {
		if s, ok := ev[k].(string); ok && strings.Contains(s, "/") {
			return dirClass(s)
		}
	}
	return ""
}

// exeClass is the directory class of a running process's executable. It is kept apart
// from pathClass because the same directory means opposite things in the two roles: a
// file planted under /usr/lib is tampering with the system, a process running from
// /usr/bin is the system. Folded into one token, a daemon left running across a package
// upgrade would look like tampering with a system file.
func exeClass(ev map[string]any) string {
	if s, ok := ev["exe"].(string); ok && strings.HasPrefix(s, "/") {
		return dirClass(s)
	}
	return ""
}

func dirClass(p string) string {
	if i := strings.IndexByte(p, ' '); i > 0 { // drop args after the binary
		p = p[:i]
	}
	switch {
	case strings.HasPrefix(p, "/tmp/"):
		return "tmp"
	case strings.HasPrefix(p, "/dev/shm/"):
		return "shm"
	case strings.HasPrefix(p, "/var/tmp/"):
		return "vartmp"
	case strings.HasPrefix(p, "/home/"):
		return "home"
	case strings.HasPrefix(p, "/root/"):
		return "root"
	case strings.HasPrefix(p, "/etc/"):
		return "etc"
	case strings.HasPrefix(p, "/usr/local/"):
		return "usrlocal"
	case strings.HasPrefix(p, "/usr/") || strings.HasPrefix(p, "/bin/") || strings.HasPrefix(p, "/sbin/") || strings.HasPrefix(p, "/lib"):
		return "system"
	case strings.HasPrefix(p, "/var/"):
		return "var"
	case strings.HasPrefix(p, "/run/"):
		return "run"
	default:
		return "other"
	}
}

// uidClass buckets the evidence uid into root/service/user (JSON numbers arrive as
// float64; ints are handled too).
func uidClass(ev map[string]any) string {
	v, ok := ev["uid"]
	if !ok {
		return ""
	}
	var u int
	switch n := v.(type) {
	case float64:
		u = int(n)
	case int:
		u = n
	default:
		return ""
	}
	switch {
	case u == 0:
		return "root"
	case u < 1000:
		return "service"
	default:
		return "user"
	}
}

// parentClass buckets the parent process basename into a coarse class (shell/web/
// cron/...), so the model can learn e.g. "shell spawned by a web server".
func parentClass(ev map[string]any) string {
	p, ok := ev["parent"].(string)
	if !ok || p == "" {
		return ""
	}
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	switch {
	case p == "bash" || p == "sh" || p == "dash" || p == "zsh" || p == "ksh":
		return "shell"
	case strings.Contains(p, "apache") || strings.Contains(p, "nginx") || strings.Contains(p, "httpd") || p == "php-fpm":
		return "web"
	case strings.Contains(p, "cron") || p == "atd":
		return "cron"
	case p == "systemd" || p == "init":
		return "init"
	case p == "python" || p == "python3" || p == "perl" || p == "ruby" || p == "node":
		return "interp"
	case strings.Contains(p, "mysqld") || strings.Contains(p, "postgres") || strings.Contains(p, "mariadb"):
		return "db"
	default:
		return "other"
	}
}

// featureFn extracts the feature tokens for an observation. Production always uses
// Features; the seam exists so an ablation can fit and score the same model with a
// class of features withheld, without a mutable global or a second implementation
// that could drift away from the real one.
type featureFn func(*store.Observation) []string

// Model is a trained multinomial Naive Bayes classifier with Laplace smoothing.
type Model struct {
	alpha     float64
	classDoc  [3]int // documents per class, indexed by Label
	classFeat [3]int // total feature occurrences per class
	featCount [3]map[string]int
	vocab     map[string]struct{}
	// feats is the extractor this model was fitted with; Score must use the same one,
	// or it would look up tokens the fit never saw. Nil means Features (the zero
	// value stays usable).
	feats featureFn
}

// featuresOf applies the model's extractor, defaulting to the production one.
func (m *Model) featuresOf(o *store.Observation) []string {
	if m.feats == nil {
		return Features(o)
	}
	return m.feats(o)
}

// Train fits a model on the explicitly assessed subset of obs. Unknown verdicts
// observations are ignored.
func Train(obs []*store.Observation) *Model { return trainWith(obs, Features) }

// trainWith is Train with an explicit extractor, so the ablation can fit on a reduced
// feature set.
func trainWith(obs []*store.Observation, feats featureFn) *Model {
	m := &Model{alpha: 1.0, vocab: map[string]struct{}{}, feats: feats}
	for i := range m.featCount {
		m.featCount[i] = map[string]int{}
	}
	for _, o := range obs {
		lbl := LabelOf(o.Verdict)
		if lbl == Unlabeled {
			continue
		}
		m.classDoc[lbl]++
		for _, f := range m.featuresOf(o) {
			m.featCount[lbl][f]++
			m.classFeat[lbl]++
			m.vocab[f] = struct{}{}
		}
	}
	return m
}

// Trained reports whether the model saw at least one example of each class and can
// therefore produce a meaningful score (otherwise Score falls back to the rule's
// static score).
func (m *Model) Trained() bool { return m.classDoc[Positive] > 0 && m.classDoc[Negative] > 0 }

func (m *Model) logProb(lbl Label, f string) float64 {
	return math.Log(float64(m.featCount[lbl][f])+m.alpha) -
		math.Log(float64(m.classFeat[lbl])+m.alpha*float64(len(m.vocab)))
}

// Contribution is one feature's pull on the score: log P(f|real) - log P(f|fp).
// Positive weight pushes toward "real"; negative toward "false positive".
type Contribution struct {
	Feature string  `json:"feature"`
	Weight  float64 `json:"weight"`
}

// Result is a scored observation: a 0-100 priority, the underlying probability of
// being a real finding, and the features that drove the score (explainability).
type Result struct {
	Priority int            `json:"priority"`
	Prob     float64        `json:"prob"`
	Trained  bool           `json:"trained"`
	Top      []Contribution `json:"top,omitempty"`
}

// Score returns the risk priority for an observation. Without both classes it
// returns the rule's static score and sets Trained to false.
func (m *Model) Score(o *store.Observation) Result {
	if !m.Trained() {
		p := float64(o.Score) / 100
		return Result{Priority: o.Score, Prob: p, Trained: false}
	}
	// Uniform class prior. The labelled set's own balance is not a base rate: the lab's
	// 141:54 reflects how many attack and benign scenarios were written, and triage
	// over-represents what an analyst chose to label. With a flat prior a finding with no
	// learned evidence scores 50 and the priority is the likelihood ratio alone.
	var logPos, logNeg float64
	contribs := make([]Contribution, 0, 8)
	for _, f := range m.featuresOf(o) {
		if _, known := m.vocab[f]; !known {
			// An unseen category carries no learned evidence for either class.
			// Ignoring it also avoids a bias toward the class with fewer tokens.
			continue
		}
		lp, ln := m.logProb(Positive, f), m.logProb(Negative, f)
		logPos += lp
		logNeg += ln
		contribs = append(contribs, Contribution{Feature: f, Weight: lp - ln})
	}
	p := positiveProbability(logPos, logNeg)
	sort.Slice(contribs, func(i, j int) bool {
		return math.Abs(contribs[i].Weight) > math.Abs(contribs[j].Weight)
	})
	if len(contribs) > 5 {
		contribs = contribs[:5]
	}
	return Result{Priority: int(math.Round(p * 100)), Prob: p, Trained: true, Top: contribs}
}

func positiveProbability(logPos, logNeg float64) float64 {
	if logPos >= logNeg {
		ratio := math.Exp(logNeg - logPos)
		return 1 / (1 + ratio)
	}
	ratio := math.Exp(logPos - logNeg)
	return ratio / (1 + ratio)
}

// Stats describes cross-validated model quality and training-set sufficiency.
type Stats struct {
	FleetLabeled          int     `json:"fleet_labeled"`
	FleetPositives        int     `json:"fleet_positives"`
	FleetNegatives        int     `json:"fleet_negatives"`
	FleetCVROCAUC         float64 `json:"fleet_cv_roc_auc"`
	FleetValidationReason string  `json:"fleet_validation_reason"`
	Labeled               int     `json:"labeled"`
	Positives             int     `json:"positives"`
	Negatives             int     `json:"negatives"`
	BaseRate              float64 `json:"base_rate"` // accuracy of always guessing the majority class
	CVAccuracy            float64 `json:"cv_accuracy"`
	CVBalancedAccuracy    float64 `json:"cv_balanced_accuracy"`
	CVPrecision           float64 `json:"cv_precision"`
	CVRecall              float64 `json:"cv_recall"`
	CVROCAUC              float64 `json:"cv_roc_auc"`
	CVBrierScore          float64 `json:"cv_brier_score"`
	// CVRepeats is how many independent seeded k-fold passes the figures above average
	// over, and CVROCAUCStdDev is the sample standard deviation of ROC AUC across them.
	// A single pass reports a number without saying whether that number holds: resample
	// the folds and a small or lopsided label set can move it a long way. The spread is
	// the part that says whether to believe the mean.
	CVRepeats      int     `json:"cv_repeats"`
	CVROCAUCStdDev float64 `json:"cv_roc_auc_stddev"`

	// WithinRuleRules and WithinRuleTied answer the question CVROCAUC cannot.
	//
	// CVROCAUC pools every observation, so most of what it measures is ranking one rule
	// above another — which the rule's own static score already does, deterministically
	// and without a model. The question only the model can answer is the one *inside* a
	// rule: this rule fires on both real findings and noise, so is this instance real?
	//
	// WithinRuleRules counts the rules triaged both ways. WithinRuleTied counts how many
	// of those the model scores identically for every instance — the degenerate case,
	// where no feature distinguishes them and the model is re-expressing the rule's
	// static score while appearing to be a second opinion.
	//
	// Deliberately a count and not an AUC. At these per-rule sizes a cross-validated
	// within-rule AUC is not measurable: holding out one instance of a rule that has
	// four shifts that rule's class balance in the training fold against the held-out
	// row's own label, and the figure inverts (measured at 0.159 on the poligon set,
	// below chance, from fold mechanics rather than from the model). A training-fit AUC
	// would have the opposite problem. The tie count is the part that is neither — it is
	// a property of the features, not of the split.
	WithinRuleRules int `json:"within_rule_rules"`
	WithinRuleTied  int `json:"within_rule_tied"`

	Trustworthy bool   `json:"trustworthy"`
	Reason      string `json:"reason"`
}

// withinRuleSeparation fits one model on all the labelled data and asks, for each rule
// triaged both ways, whether the model can produce more than one score across that
// rule's instances. It is a question about the features, not about generalisation, so
// it is measured on a single fit: if two instances share a feature vector, no split
// will ever tell them apart, and if they do not, the capacity is there to be trained.
func withinRuleSeparation(labeled []*store.Observation, feats featureFn) (rules, tied int) {
	m := trainWith(labeled, feats)
	if !m.Trained() {
		return 0, 0
	}
	type group struct {
		pos, neg int
		scores   map[float64]struct{}
	}
	byRule := map[string]*group{}
	for _, o := range labeled {
		g := byRule[o.RuleID]
		if g == nil {
			g = &group{scores: map[float64]struct{}{}}
			byRule[o.RuleID] = g
		}
		if LabelOf(o.Verdict) == Positive {
			g.pos++
		} else {
			g.neg++
		}
		g.scores[m.Score(o).Prob] = struct{}{}
	}
	for _, g := range byRule {
		if g.pos == 0 || g.neg == 0 {
			continue // a rule seen under one label only has nothing to separate
		}
		rules++
		if len(g.scores) == 1 {
			tied++
		}
	}
	return rules, tied
}

type prediction struct {
	prob     float64
	positive bool
	rule     string // the rule that fired, so within-rule ranking can be measured
}

// Evaluate uses deterministic grouped cross-validation, balancing labels while
// keeping related lab variants and each fleet host together.
func Evaluate(obs []*store.Observation) Stats { return evaluate(obs, Features) }

// EvaluateWithout is Evaluate with every feature token carrying the given prefix
// withheld — an ablation.
//
// The question it answers is whether the model is doing anything beyond memorising
// which rule fired. Features() emits "rule:<id>", and on a dataset where most rules
// appear under a single label that one token can reproduce the whole ranking: the
// model looks accurate while having learned a lookup table that cannot generalise to a
// rule it has not seen, or to a fleet where the same rule is sometimes noise.
// EvaluateWithout(obs, "rule:") strips it and re-runs the identical protocol, so the
// gap between the two ROC AUCs is the part of the ranking that rule identity was
// carrying. Comparable only because both sides use the same folds, seeds and metrics.
func EvaluateWithout(obs []*store.Observation, prefixes ...string) Stats {
	return evaluate(obs, func(o *store.Observation) []string {
		full := Features(o)
		kept := make([]string, 0, len(full))
		for _, f := range full {
			drop := false
			for _, p := range prefixes {
				if strings.HasPrefix(f, p) {
					drop = true
					break
				}
			}
			if !drop {
				kept = append(kept, f)
			}
		}
		return kept
	})
}

func evaluate(obs []*store.Observation, feats featureFn) Stats {
	var labeled []*store.Observation
	var pos, neg int
	for _, o := range obs {
		switch LabelOf(o.Verdict) {
		case Positive:
			pos++
			labeled = append(labeled, o)
		case Negative:
			neg++
			labeled = append(labeled, o)
		}
	}
	lab := 0
	for _, o := range labeled {
		if o.Source == sourceLab {
			lab++
		}
	}
	st := Stats{Labeled: len(labeled), Positives: pos, Negatives: neg}
	var fleet []*store.Observation
	for _, o := range labeled {
		if o.Source != sourceLab {
			fleet = append(fleet, o)
			if LabelOf(o.Verdict) == Positive {
				st.FleetPositives++
			} else {
				st.FleetNegatives++
			}
		}
	}
	st.FleetLabeled = len(fleet)
	if len(labeled) == 0 {
		st.Reason = "no labelled observations — use Confirm finding or Close as FP to supply analyst verdicts"
		return st
	}
	major := pos
	if neg > pos {
		major = neg
	}
	st.BaseRate = float64(major) / float64(len(labeled))

	minClass := min(pos, neg)
	if minClass >= 2 {
		folds := min(5, minClass)
		aucs := make([]float64, 0, cvRepeats)
		var acc, bal, prec, rec, auc, brier float64
		for r := 0; r < cvRepeats; r++ {
			// Fixed seed sequence: the same observations always produce the same report,
			// which matters for a number an operator may act on, while still measuring
			// across resamplings rather than trusting one arbitrary split.
			preds := crossValidate(labeled, folds, int64(r+1), feats)
			if len(preds) == 0 {
				break
			}
			a, b, p, rc, ac, br := predictionMetrics(preds)
			acc, bal, prec, rec, auc, brier = acc+a, bal+b, prec+p, rec+rc, auc+ac, brier+br
			aucs = append(aucs, ac)
		}
		n := float64(len(aucs))
		if n > 0 {
			st.CVAccuracy, st.CVBalancedAccuracy, st.CVPrecision = acc/n, bal/n, prec/n
			st.CVRecall, st.CVROCAUC, st.CVBrierScore = rec/n, auc/n, brier/n
			st.CVRepeats, st.CVROCAUCStdDev = len(aucs), stdDev(aucs)
		}
		st.WithinRuleRules, st.WithinRuleTied = withinRuleSeparation(labeled, feats)
	}

	switch {
	case len(labeled) < minLabeledTotal:
		st.Reason = "too few labelled observations (have " + strconv.Itoa(len(labeled)) +
			", need " + strconv.Itoa(minLabeledTotal) + "+) — keep triaging"
	// Before any quality figure: whose data is this? The attack range is roughly three
	// quarters positive because a range is mostly attacks, and a fleet is the other way
	// round — most of what a rule raises there is noise. A model fitted only on range
	// rows can look well separated and still be calibrated to a world that does not
	// exist, and every number below would be describing that world. Nothing here is
	// trustworthy until some of the labels came from the hosts being ranked.
	case lab == len(labeled):
		st.Reason = "every labelled observation came from the attack range — its class balance is not this " +
			"fleet's, so the ranking is calibrated to the lab; assess fleet findings with Confirm finding or Close as FP " +
			"and the model will fit to them"
	case minClass < minPerClass:
		st.Reason = "one class too small (have " + strconv.Itoa(minClass) + ", need " +
			strconv.Itoa(minPerClass) + "+ of each real and false-positive) — the fleet is mostly clean, " +
			"so generate the missing class via the attack-emulation lab"
	case min(st.FleetPositives, st.FleetNegatives) < minPerClass:
		st.Reason = "fleet validation needs " + strconv.Itoa(minPerClass) + "+ confirmed labels of each class from monitored hosts; lab labels do not satisfy this requirement"
	case st.CVRepeats == 0:
		st.Reason = "not enough independent groups of each class for held-out validation"
	case st.CVROCAUC < 0.65:
		st.Reason = "cross-validated ranking is weak (ROC AUC below 0.65) — current features don't separate real from false-positive yet"
	// Checked after the pooled figures, because it is the failure they hide: a model can
	// clear every gate above on between-rule ranking alone and still be unable to tell
	// two instances of the same rule apart. When that is true for most ambiguous rules,
	// the model is not adding information to the rule's static score — it is repeating
	// it, at the cost of looking like a second opinion.
	case st.WithinRuleRules > 0 && st.WithinRuleTied*2 > st.WithinRuleRules:
		st.Reason = "the model scores every instance of " + strconv.Itoa(st.WithinRuleTied) +
			" of " + strconv.Itoa(st.WithinRuleRules) + " ambiguous rules identically — it is re-expressing " +
			"the rule's static score, not ranking instances; the features do not describe the instance"
	case st.CVROCAUCStdDev > 0.10:
		// A good mean over unstable folds is not a good model, it is a small label set.
		// Reporting only the mean would present that as a result.
		st.Reason = "ranking quality swings between resamplings (ROC AUC ±" +
			strconv.FormatFloat(st.CVROCAUCStdDev, 'f', 2, 64) +
			") — the labelled set is too small or too uneven for this figure to mean much yet"
	default:
		st.Trustworthy = true
		st.Reason = "enough balanced, separable data to prioritise findings"
	}
	// Lab quality cannot stand in for deployment quality. Validate fleet labels
	// separately, holding each host out as a unit, before granting trust.
	if lab > 0 && len(fleet) > 0 {
		fs := evaluate(fleet, feats)
		st.FleetCVROCAUC, st.FleetValidationReason = fs.CVROCAUC, fs.Reason
		if st.Trustworthy && !fs.Trustworthy {
			st.Trustworthy = false
			st.Reason = "fleet-only validation: " + fs.Reason
		}
	} else if lab == 0 {
		st.FleetCVROCAUC, st.FleetValidationReason = st.CVROCAUC, st.Reason
	}
	return st
}

// crossValidate runs one grouped k-fold pass. Seeds give repeated partitions of
// the same groups, not new independent datasets or a held-out acceptance test.
// cvRepeats is how many independent seeded passes Evaluate averages. The methodology
// this borrows from (a streaming-NIDS label-efficiency study of ours) found single-split
// evaluation flips rankings between seeds, and used >= 6 seeds so a paired Wilcoxon test
// could clear its p-value floor. There is nothing to compare here — one model, no
// competing method — so this reports the spread instead of a significance test, but the
// reason for repeating at all is the same.
// sourceLab marks an observation produced by the attack-emulation range rather than by
// a scan of a real host. It is the value cmd/bladedr-lab writes into dataset.jsonl.
const sourceLab = "lab"

const cvRepeats = 7

// Operational size floors for trust evaluation, not statistical power guarantees.
// Grouped folds and fleet-only quality gates must also pass.
const (
	minPerClass     = 30
	minLabeledTotal = 2 * minPerClass
)

// stdDev is the sample standard deviation (n-1), matching how the spread across seeds is
// normally reported.
func stdDev(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	var mean float64
	for _, x := range xs {
		mean += x
	}
	mean /= float64(len(xs))
	var ss float64
	for _, x := range xs {
		ss += (x - mean) * (x - mean)
	}
	return math.Sqrt(ss / float64(len(xs)-1))
}

func crossValidate(labeled []*store.Observation, folds int, seed int64, feats featureFn) []prediction {
	foldOf, folds := groupedFolds(labeled, folds, seed)
	if folds < 2 {
		return nil
	}

	out := make([]prediction, 0, len(labeled))
	for fold := 0; fold < folds; fold++ {
		train := make([]*store.Observation, 0, len(labeled))
		for i, o := range labeled {
			if foldOf[i] != fold {
				train = append(train, o)
			}
		}
		model := trainWith(train, feats)
		if !model.Trained() {
			return nil
		}
		for i, o := range labeled {
			if foldOf[i] == fold {
				out = append(out, prediction{
					prob:     model.Score(o).Prob,
					positive: LabelOf(o.Verdict) == Positive,
					rule:     o.RuleID,
				})
			}
		}
	}
	return out
}

// Keep all naming variants of a lab technique, and all findings from a fleet
// host, on one side of the split. Labels and group IDs are never score features.
func groupedFolds(obs []*store.Observation, folds int, seed int64) ([]int, int) {
	groups := map[string][]int{}
	for i, o := range obs {
		key := "row:" + strconv.Itoa(i)
		if o.Source == sourceLab && o.ScanID != "" {
			key = "lab:" + o.ScanID
		} else if o.HostID != "" {
			key = "host:" + o.HostID
		}
		groups[key] = append(groups[key], i)
	}
	keys := make([]string, 0, len(groups))
	counts := [3]int{}
	for k, rows := range groups {
		keys = append(keys, k)
		seen := [3]bool{}
		for _, i := range rows {
			seen[LabelOf(obs[i].Verdict)] = true
		}
		for _, label := range []Label{Positive, Negative} {
			if seen[label] {
				counts[label]++
			}
		}
	}
	folds = min(folds, counts[Positive], counts[Negative])
	if folds < 2 {
		return nil, 0
	}
	sort.Strings(keys)
	rng := rand.New(rand.NewSource(seed))
	rng.Shuffle(len(keys), func(a, b int) { keys[a], keys[b] = keys[b], keys[a] })
	loads := make([][3]int, folds)
	assigned := make([]int, len(obs))
	for _, k := range keys {
		rows := groups[k]
		class := [3]int{}
		for _, i := range rows {
			class[LabelOf(obs[i].Verdict)]++
		}
		best := 0
		cost := func(f int) int { return class[Positive]*loads[f][Positive] + class[Negative]*loads[f][Negative] }
		for f := 1; f < folds; f++ {
			if cost(f) < cost(best) {
				best = f
			}
		}
		for _, i := range rows {
			assigned[i] = best
			loads[best][LabelOf(obs[i].Verdict)]++
		}
	}
	return assigned, folds
}

func predictionMetrics(predictions []prediction) (accuracy, balancedAccuracy, precision, recall, rocAUC, brier float64) {
	if len(predictions) == 0 {
		return 0, 0, 0, 0, 0, 0
	}

	var tp, tn, fp, fn int
	for _, p := range predictions {
		predictedPositive := p.prob >= 0.5
		switch {
		case p.positive && predictedPositive:
			tp++
		case p.positive:
			fn++
		case predictedPositive:
			fp++
		default:
			tn++
		}
		target := 0.0
		if p.positive {
			target = 1
		}
		delta := p.prob - target
		brier += delta * delta
	}

	accuracy = float64(tp+tn) / float64(len(predictions))
	recall = ratio(tp, tp+fn)
	specificity := ratio(tn, tn+fp)
	balancedAccuracy = (recall + specificity) / 2
	precision = ratio(tp, tp+fp)
	rocAUC = areaUnderROC(predictions)
	brier /= float64(len(predictions))
	return accuracy, balancedAccuracy, precision, recall, rocAUC, brier
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func areaUnderROC(predictions []prediction) float64 {
	ranked := append([]prediction(nil), predictions...)
	sort.SliceStable(ranked, func(i, j int) bool { return ranked[i].prob < ranked[j].prob })

	var rankSum float64
	var positives, negatives int
	for start := 0; start < len(ranked); {
		end := start + 1
		for end < len(ranked) && ranked[end].prob == ranked[start].prob {
			end++
		}
		averageRank := float64(start+1+end) / 2
		for _, p := range ranked[start:end] {
			if p.positive {
				rankSum += averageRank
				positives++
			} else {
				negatives++
			}
		}
		start = end
	}
	if positives == 0 || negatives == 0 {
		return 0
	}
	return (rankSum - float64(positives*(positives+1))/2) /
		float64(positives*negatives)
}
