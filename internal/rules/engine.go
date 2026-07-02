package rules

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"bladedr/internal/probe"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

// Engine compiles a set of rules into CEL programs and evaluates them against a
// snapshot. It is used inside the probe (on the host) but is platform-agnostic,
// so it can also be exercised in tests against fixture snapshots.
type Engine struct {
	rules []compiledRule
}

type compiledRule struct {
	id       string
	foreach  string
	when     cel.Program
	evidence map[string]cel.Program
	dedup    []cel.Program
}

// NewEngine compiles the given full rules (server-side). Only the match logic is
// used; metadata is ignored here.
func NewEngine(rs []Rule) (*Engine, error) {
	br := make([]probe.BundleRule, 0, len(rs))
	for _, r := range rs {
		if r.IsEnabled() {
			br = append(br, r.ToBundleRule())
		}
	}
	return NewEngineFromBundle(probe.RuleBundle{Rules: br})
}

// NewEngineFromBundle compiles the probe-facing bundle rules. This is what the
// probe uses on the host: it has no rule metadata, only match logic.
func NewEngineFromBundle(b probe.RuleBundle) (*Engine, error) {
	env, err := cel.NewEnv(
		cel.Variable("item", cel.DynType),
		cel.Variable("snapshot", cel.DynType),
	)
	if err != nil {
		return nil, fmt.Errorf("cel env: %w", err)
	}
	eng := &Engine{}
	for _, r := range b.Rules {
		cr := compiledRule{id: r.ID, foreach: r.Foreach, evidence: map[string]cel.Program{}}
		var perr error
		if cr.when, perr = compile(env, r.When); perr != nil {
			return nil, fmt.Errorf("rule %q when: %w", r.ID, perr)
		}
		for k, expr := range r.Evidence {
			if cr.evidence[k], perr = compile(env, expr); perr != nil {
				return nil, fmt.Errorf("rule %q evidence.%s: %w", r.ID, k, perr)
			}
		}
		for i, expr := range r.Dedup {
			p, perr := compile(env, expr)
			if perr != nil {
				return nil, fmt.Errorf("rule %q dedup[%d]: %w", r.ID, i, perr)
			}
			cr.dedup = append(cr.dedup, p)
		}
		eng.rules = append(eng.rules, cr)
	}
	return eng, nil
}

func compile(env *cel.Env, expr string) (cel.Program, error) {
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	return env.Program(ast)
}

// Evaluate runs every rule against the snapshot and returns the findings.
func (e *Engine) Evaluate(snap *probe.Snapshot) ([]probe.Finding, error) {
	snapMap, err := toMap(snap)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var findings []probe.Finding

	for _, r := range e.rules {
		items := []any{map[string]any{}} // host-level rule: one empty item
		if r.foreach != "" {
			raw, ok := lookupPath(snapMap, r.foreach).([]any)
			if !ok {
				continue // collection absent or empty
			}
			items = raw
		}
		for _, it := range items {
			act := map[string]any{"item": it, "snapshot": snapMap}
			matched, err := evalBool(r.when, act)
			if err != nil {
				return nil, fmt.Errorf("rule %q when eval: %w", r.id, err)
			}
			if !matched {
				continue
			}
			// Evidence is best-effort: the rule already matched, so a field that
			// can't be evaluated (e.g. an absent optional fact) is simply omitted
			// rather than aborting the finding.
			ev := make(map[string]any, len(r.evidence))
			for k, prg := range r.evidence {
				v, _, err := prg.Eval(act)
				if err != nil {
					continue
				}
				ev[k] = toNative(v)
			}
			findings = append(findings, probe.Finding{
				RuleID:     r.id,
				Evidence:   ev,
				DedupKey:   r.dedupKey(act),
				ObservedAt: now,
			})
		}
	}
	return findings, nil
}

func (r compiledRule) dedupKey(act map[string]any) string {
	if len(r.dedup) == 0 {
		return r.id
	}
	parts := make([]string, 0, len(r.dedup)+1)
	parts = append(parts, r.id)
	for _, prg := range r.dedup {
		v, _, err := prg.Eval(act)
		if err != nil {
			parts = append(parts, "?")
			continue
		}
		parts = append(parts, fmt.Sprint(v.Value()))
	}
	return strings.Join(parts, "|")
}

func evalBool(prg cel.Program, act map[string]any) (bool, error) {
	v, _, err := prg.Eval(act)
	if err != nil {
		return false, err
	}
	b, ok := v.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression did not return bool (got %T)", v.Value())
	}
	return b, nil
}

// toNative recursively converts a CEL value into plain Go types (maps, slices,
// scalars) so evidence serialises cleanly to JSON. CEL's own .Value() leaves
// nested list/map elements as CEL wrappers (e.g. results of filter()/map()).
func toNative(v ref.Val) any {
	switch vv := v.(type) {
	case traits.Lister:
		var out []any
		for it := vv.Iterator(); it.HasNext() == types.True; {
			out = append(out, toNative(it.Next()))
		}
		return out
	case traits.Mapper:
		out := map[string]any{}
		for it := vv.Iterator(); it.HasNext() == types.True; {
			k := it.Next()
			out[fmt.Sprint(k.Value())] = toNative(vv.Get(k))
		}
		return out
	default:
		return v.Value()
	}
}

// lookupPath resolves a dotted path (e.g. "persistence.systemd_units") through
// nested maps, so foreach can iterate collections nested under the snapshot.
func lookupPath(m map[string]any, path string) any {
	var cur any = m
	for _, part := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[part]
	}
	return cur
}

// toMap converts the snapshot to a map[string]any tree (JSON round-trip) so CEL
// can navigate it with snake_case field names matching the wire contract.
func toMap(snap *probe.Snapshot) (map[string]any, error) {
	b, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}
