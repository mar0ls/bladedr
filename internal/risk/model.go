// Package risk is bladedr's explainable risk-scoring tier: a multinomial Naive
// Bayes model trained on analyst-triaged observations. It learns which structural
// features (rule, category, severity, source, MITRE technique/tactic) separate
// real findings (acknowledged/resolved) from false positives, and outputs a 0-100
// priority plus the features that drove it. No external ML runtime — small,
// deterministic and auditable, matching bladedr's single-binary ethos.
//
// It is a PRIORITISER, not a detector: rules decide what is a finding; this model
// ranks findings by how likely an analyst is to treat them as real, learned from
// past triage. It is honest about small data — Evaluate reports whether the
// labelled set is large/balanced/accurate enough to trust (see Stats.Trustworthy).
package risk

import (
	"math"
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
	Positive        // acknowledged or resolved (an analyst engaged with it)
)

// LabelOf maps a triage status to a training label. Only unambiguous dispositions
// supervise the model: acknowledged = a real finding an analyst is working
// (positive), false_positive = noise the analyst dismissed (negative). Open
// (untriaged) and resolved are Unlabeled and excluded: "resolved" is ambiguous —
// it conflates "real threat, remediated" with "benign change, reviewed and closed"
// (and bladedr uses it heavily for the latter — benign baseline drift, test plants),
// so it would pollute the positive class. The poligon supplies clean, ground-truth
// positives instead (lab examples are written as acknowledged).
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

// Features extracts the structural, name-free feature tokens of an observation.
// Never the literal evidence (paths/names/args are attacker-controlled and won't
// generalise) — only the rule identity, its taxonomy, and COARSE CLASSES derived
// from evidence (path/uid/parent bucketed into a handful of categories). The
// classes let the model separate within a rule (e.g. a systemd ExecStart in
// path:tmp vs path:home) while staying name-free, so it still learns shape not IOCs.
func Features(o *store.Observation) []string {
	feats := []string{
		"rule:" + o.RuleID,
		"cat:" + o.Category,
		"sev:" + o.Severity,
		"src:" + o.Source,
	}
	for _, m := range o.Mitre {
		feats = append(feats, "tech:"+m)
		if i := strings.IndexByte(m, '.'); i > 0 { // tactic-level T1543 from T1543.002
			feats = append(feats, "tac:"+m[:i])
		}
	}
	if c := pathClass(o.Evidence); c != "" {
		feats = append(feats, "path:"+c)
	}
	if c := uidClass(o.Evidence); c != "" {
		feats = append(feats, "uid:"+c)
	}
	if c := parentClass(o.Evidence); c != "" {
		feats = append(feats, "parent:"+c)
	}
	return feats
}

// pathClass buckets the first path-like evidence value into a coarse, name-free
// class (tmp/shm/home/etc/...), so the model keys on WHERE not the literal path.
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

// Score returns the risk priority for an observation. Until the model has both
// classes it returns the rule's static score as a neutral prior (Trained=false),
// so the endpoint degrades gracefully on a fresh deployment.
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
		lp, ln := m.logProb(Positive, f), m.logProb(Negative, f)
		logPos += lp
		logNeg += ln
		contribs = append(contribs, Contribution{Feature: f, Weight: lp - ln})
	}
	p := 1.0 / (1.0 + math.Exp(logNeg-logPos)) // two-class softmax
	sort.Slice(contribs, func(i, j int) bool {
		return math.Abs(contribs[i].Weight) > math.Abs(contribs[j].Weight)
	})
	if len(contribs) > 5 {
		contribs = contribs[:5]
	}
	return Result{Priority: int(math.Round(p * 100)), Prob: p, Trained: true, Top: contribs}
}

// Stats is an honest assessment of whether there is enough labelled data to trust
// the model — the evidence behind "should we use ML yet?".
type Stats struct {
	Labeled     int     `json:"labeled"`
	Positives   int     `json:"positives"`
	Negatives   int     `json:"negatives"`
	BaseRate    float64 `json:"base_rate"`   // accuracy of always guessing the majority class
	CVAccuracy  float64 `json:"cv_accuracy"` // leave-one-out cross-validated accuracy
	Trustworthy bool    `json:"trustworthy"`
	Reason      string  `json:"reason"`
}

// Evaluate measures the model on the triaged set via leave-one-out cross-validation
// and decides whether the data is sufficient. The thresholds are conservative: a
// small or one-sided or non-separable set is reported as not yet trustworthy.
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

	correct := 0
	for i, o := range labeled {
		train := make([]*store.Observation, 0, len(labeled)-1)
		train = append(train, labeled[:i]...)
		train = append(train, labeled[i+1:]...)
		m := Train(train)
		pred := m.Score(o).Prob >= 0.5
		if pred == (LabelOf(o.Status) == Positive) {
			correct++
		}
	}
	st.CVAccuracy = float64(correct) / float64(len(labeled))

	minClass := pos
	if neg < pos {
		minClass = neg
	}
	switch {
	case len(labeled) < 30:
		st.Reason = "too few labelled observations (have " + strconv.Itoa(len(labeled)) + ", need ~30+) — keep triaging"
	case minClass < 8:
		st.Reason = "one class too small (need ~8+ of each real and false-positive) — the fleet is mostly clean, so generate real positives via the attack-emulation lab"
	case st.CVAccuracy <= st.BaseRate+0.05:
		st.Reason = "no better than guessing the majority class — current features don't separate real from false-positive yet"
	default:
		st.Trustworthy = true
		st.Reason = "enough balanced, separable data to prioritise findings"
	}
	return st
}
