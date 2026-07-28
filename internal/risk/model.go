// Package risk is bladedr's explainable risk-scoring tier: a multinomial Naive Bayes
// model trained on analyst-triaged observations. It learns which structural features
// (rule, category, severity, source, MITRE technique/tactic) separate real findings
// from false positives, and outputs a 0-100 priority plus the features that drove it.
// No external ML runtime — small, deterministic and auditable, matching bladedr's
// single-binary ethos.
//
// It is a prioritiser, not a detector: rules decide what is a finding; this model
// ranks findings by how likely an analyst is to treat them as real, learned from past
// triage. It is honest about small data — Evaluate reports whether the labelled set is
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

// Label is the supervised target derived from an observation's triage status.
type Label int

const (
	Unlabeled Label = iota
	Negative        // triaged false_positive
	Positive        // acknowledged
)

// LabelOf maps a triage status to a training label. Only unambiguous dispositions
// supervise the model: acknowledged = a real finding an analyst is working
// (positive), false_positive = noise the analyst dismissed (negative). Open
// (untriaged) and resolved are Unlabeled and excluded: "resolved" is ambiguous — it
// conflates "real threat, remediated" with "benign change, reviewed and closed" (and
// bladedr uses it heavily for the latter — benign baseline drift, test plants), so it
// would pollute the positive class. The poligon supplies clean, ground-truth positives
// instead (lab examples are written as acknowledged).
func LabelOf(status string) Label {
	switch status {
	case store.ObsFalsePositive:
		return Negative
	case store.ObsAcknowledged:
		return Positive
	default: // open, resolved -> not reliable supervision
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
	add("rule:" + o.RuleID)
	add("cat:" + o.Category)
	add("sev:" + o.Severity)
	add("src:" + o.Source)
	for _, m := range o.Mitre {
		add("tech:" + m)
		if i := strings.IndexByte(m, '.'); i > 0 { // tactic-level T1543 from T1543.002
			add("tac:" + m[:i])
		}
	}
	if c := pathClass(o.Evidence); c != "" {
		add("path:" + c)
	}
	if c := uidClass(o.Evidence); c != "" {
		add("uid:" + c)
	}
	if c := parentClass(o.Evidence); c != "" {
		add("parent:" + c)
	}
	return feats
}

// pathClass maps the first path-like evidence value to a directory class.
func pathClass(ev map[string]any) string {
	keys := []string{"path", "binary", "exec_start", "entry", "dir", "interp", "command"}
	var p string
	for _, k := range keys {
		if s, ok := ev[k].(string); ok && strings.Contains(s, "/") {
			p = s
			break
		}
	}
	if p == "" {
		return ""
	}
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

// Model is a trained multinomial Naive Bayes classifier with Laplace smoothing.
type Model struct {
	alpha     float64
	classDoc  [3]int // documents per class, indexed by Label
	classFeat [3]int // total feature occurrences per class
	featCount [3]map[string]int
	vocab     map[string]struct{}
}

// Train fits a model on the labelled (triaged) subset of obs. Unlabelled (open)
// observations are ignored.
func Train(obs []*store.Observation) *Model {
	m := &Model{alpha: 1.0, vocab: map[string]struct{}{}}
	for i := range m.featCount {
		m.featCount[i] = map[string]int{}
	}
	for _, o := range obs {
		lbl := LabelOf(o.Status)
		if lbl == Unlabeled {
			continue
		}
		m.classDoc[lbl]++
		for _, f := range Features(o) {
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
	total := float64(m.classDoc[Positive] + m.classDoc[Negative])
	logPos := math.Log(float64(m.classDoc[Positive]) / total)
	logNeg := math.Log(float64(m.classDoc[Negative]) / total)
	contribs := make([]Contribution, 0, 8)
	for _, f := range Features(o) {
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
	Labeled            int     `json:"labeled"`
	Positives          int     `json:"positives"`
	Negatives          int     `json:"negatives"`
	BaseRate           float64 `json:"base_rate"` // accuracy of always guessing the majority class
	CVAccuracy         float64 `json:"cv_accuracy"`
	CVBalancedAccuracy float64 `json:"cv_balanced_accuracy"`
	CVPrecision        float64 `json:"cv_precision"`
	CVRecall           float64 `json:"cv_recall"`
	CVROCAUC           float64 `json:"cv_roc_auc"`
	CVBrierScore       float64 `json:"cv_brier_score"`
	// CVRepeats is how many independent seeded k-fold passes the figures above average
	// over, and CVROCAUCStdDev is the sample standard deviation of ROC AUC across them.
	// A single pass reports a number without saying whether that number holds: resample
	// the folds and a small or lopsided label set can move it a long way. The spread is
	// the part that says whether to believe the mean.
	CVRepeats      int     `json:"cv_repeats"`
	CVROCAUCStdDev float64 `json:"cv_roc_auc_stddev"`
	Trustworthy    bool    `json:"trustworthy"`
	Reason         string  `json:"reason"`
}

type prediction struct {
	prob     float64
	positive bool
}

// Evaluate uses deterministic stratified cross-validation. Five folds keep the
// evaluation linear in the number of labelled observations.
func Evaluate(obs []*store.Observation) Stats {
	var labeled []*store.Observation
	var pos, neg int
	for _, o := range obs {
		switch LabelOf(o.Status) {
		case Positive:
			pos++
			labeled = append(labeled, o)
		case Negative:
			neg++
			labeled = append(labeled, o)
		}
	}
	st := Stats{Labeled: len(labeled), Positives: pos, Negatives: neg}
	if len(labeled) == 0 {
		st.Reason = "no triaged observations to learn from — triage findings (acknowledge/resolve vs false-positive) first"
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
			a, b, p, rc, ac, br := predictionMetrics(crossValidate(labeled, folds, int64(r+1)))
			acc, bal, prec, rec, auc, brier = acc+a, bal+b, prec+p, rec+rc, auc+ac, brier+br
			aucs = append(aucs, ac)
		}
		n := float64(cvRepeats)
		st.CVAccuracy, st.CVBalancedAccuracy, st.CVPrecision = acc/n, bal/n, prec/n
		st.CVRecall, st.CVROCAUC, st.CVBrierScore = rec/n, auc/n, brier/n
		st.CVRepeats, st.CVROCAUCStdDev = cvRepeats, stdDev(aucs)
	}

	switch {
	case len(labeled) < 30:
		st.Reason = "too few labelled observations (have " + strconv.Itoa(len(labeled)) + ", need ~30+) — keep triaging"
	case minClass < 8:
		st.Reason = "one class too small (need ~8+ of each real and false-positive) — the fleet is mostly clean, so generate real positives via the attack-emulation lab"
	case st.CVROCAUC < 0.65:
		st.Reason = "cross-validated ranking is weak (ROC AUC below 0.65) — current features don't separate real from false-positive yet"
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
	return st
}

// crossValidate runs one stratified k-fold pass. seed shuffles the order in which rows
// are dealt into folds; pass different seeds to get independent estimates.
//
// Without the shuffle, folds were assigned in the order rows came back from the store,
// so the reported metrics were a property of insertion order rather than of the data —
// two deployments holding identical observations could report different numbers, and
// nothing revealed that the number moved at all.
// cvRepeats is how many independent seeded passes Evaluate averages. The methodology
// this borrows from (a streaming-NIDS label-efficiency study of ours) found single-split
// evaluation flips rankings between seeds, and used >= 6 seeds so a paired Wilcoxon test
// could clear its p-value floor. There is nothing to compare here — one model, no
// competing method — so this reports the spread instead of a significance test, but the
// reason for repeating at all is the same.
const cvRepeats = 7

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

func crossValidate(labeled []*store.Observation, folds int, seed int64) []prediction {
	order := make([]int, len(labeled))
	for i := range order {
		order[i] = i
	}
	rng := rand.New(rand.NewSource(seed))
	rng.Shuffle(len(order), func(a, b int) { order[a], order[b] = order[b], order[a] })

	foldOf := make([]int, len(labeled))
	nextFold := [3]int{}
	for _, i := range order {
		label := LabelOf(labeled[i].Status)
		foldOf[i] = nextFold[label] % folds
		nextFold[label]++
	}

	out := make([]prediction, 0, len(labeled))
	for fold := 0; fold < folds; fold++ {
		train := make([]*store.Observation, 0, len(labeled))
		for i, o := range labeled {
			if foldOf[i] != fold {
				train = append(train, o)
			}
		}
		model := Train(train)
		for i, o := range labeled {
			if foldOf[i] == fold {
				out = append(out, prediction{
					prob:     model.Score(o).Prob,
					positive: LabelOf(o.Status) == Positive,
				})
			}
		}
	}
	return out
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
