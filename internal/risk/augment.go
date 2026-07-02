package risk

import (
	// math/rand (not crypto/rand) is intentional: synthetic data augmentation must be
	// DETERMINISTIC given a seed (reproducible training); this is ML resampling, not
	// security/token material.
	// nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used
	"math/rand"

	"bladedr/internal/store"
)

// Augment balances the labelled set by oversampling the minority class with
// feature-jittered synthetic copies, up to the majority count. Deterministic given
// seed.
//
// Honest about its limits: for the generative Naive Bayes this mainly corrects
// class imbalance (the priors) and smooths sparse feature cells — the larger
// modelling win is the richer name-free features in Features(). It must feed
// TRAINING/scoring ONLY, never the Evaluate cross-validation: oversampling before
// CV leaks (synthetic near-duplicates of a held-out row land in train and inflate
// accuracy), so Evaluate stays on real data and Augment is applied separately when
// fitting the scorer.
//
// The "jitter" is feature dropout: a synthetic copy may drop one evidence-derived
// class (path/uid/parent), so the model doesn't over-rely on a single co-occurring
// detail. The rule/category/severity/MITRE backbone is preserved.
func Augment(labeled []*store.Observation, seed int64) []*store.Observation {
	var pos, neg []*store.Observation
	for _, o := range labeled {
		switch LabelOf(o.Status) {
		case Positive:
			pos = append(pos, o)
		case Negative:
			neg = append(neg, o)
		}
	}
	out := append([]*store.Observation{}, labeled...)
	if len(pos) == 0 || len(neg) == 0 {
		return out // nothing to balance against
	}
	minority, target := neg, len(pos)
	if len(pos) < len(neg) {
		minority, target = pos, len(neg)
	}
	rng := rand.New(rand.NewSource(seed))
	for n := len(minority); n < target; n++ {
		out = append(out, jitter(minority[rng.Intn(len(minority))], rng))
	}
	return out
}

// jitter clones an observation, optionally dropping one evidence-derived class, so
// its Features() are a near-variant of the source rather than an exact duplicate.
func jitter(o *store.Observation, rng *rand.Rand) *store.Observation {
	c := *o
	c.Evidence = map[string]any{}
	for k, v := range o.Evidence {
		c.Evidence[k] = v
	}
	// 50% of the time drop one class-bearing evidence field.
	if rng.Intn(2) == 0 {
		switch rng.Intn(3) {
		case 0:
			delete(c.Evidence, "uid")
		case 1:
			delete(c.Evidence, "parent")
		case 2:
			for _, k := range []string{"path", "binary", "exec_start", "entry", "dir", "interp", "command"} {
				delete(c.Evidence, k)
			}
		}
	}
	return &c
}
