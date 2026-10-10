package risk

import (
	"testing"

	"bladedr/internal/store"
)

func TestValidationKeepsDependentRowsTogether(t *testing.T) {
	var rows []*store.Observation
	for _, source := range []string{sourceLab, store.SourceAgentlessProbe} {
		for _, label := range []string{store.ObsAcknowledged, store.ObsFalsePositive} {
			for _, group := range []string{"a", "b", "c"} {
				for i := 0; i < 3; i++ {
					o := obs("rule", "cat", "high", label)
					o.Source = source
					id := source + label + group
					if source == sourceLab {
						o.ScanID = id
					} else {
						o.HostID = id
					}
					rows = append(rows, o)
				}
			}
		}
	}
	for seed := int64(1); seed <= cvRepeats; seed++ {
		assigned, folds := groupedFolds(rows, 5, seed)
		if folds < 2 {
			t.Fatal("expected independent groups")
		}
		for i := 0; i < len(rows); i += 3 {
			if assigned[i] != assigned[i+1] || assigned[i] != assigned[i+2] {
				t.Fatalf("dependent rows split across folds at seed %d", seed)
			}
		}
	}
}

func TestOneFleetLabelDoesNotUnlockLabTrust(t *testing.T) {
	var data []*store.Observation
	for i := 0; i < minPerClass; i++ {
		for _, status := range []string{store.ObsAcknowledged, store.ObsFalsePositive} {
			rule := "positive"
			if status == store.ObsFalsePositive {
				rule = "negative"
			}
			o := obs(rule, "cat", "high", status)
			o.Source = sourceLab
			data = append(data, o)
		}
	}
	data = append(data, obs("positive", "cat", "high", store.ObsAcknowledged))
	s := Evaluate(data)
	if s.Trustworthy || s.FleetLabeled != 1 || s.FleetNegatives != 0 {
		t.Fatalf("one fleet label must not unlock trust: %+v", s)
	}
}

func TestSingleHostCannotValidateGeneralisation(t *testing.T) {
	var data []*store.Observation
	for i := 0; i < minPerClass; i++ {
		for _, status := range []string{store.ObsAcknowledged, store.ObsFalsePositive} {
			o := obs(status, "cat", "high", status)
			o.HostID = "one-host"
			data = append(data, o)
		}
	}
	s := Evaluate(data)
	if s.Trustworthy || s.CVRepeats != 0 {
		t.Fatalf("a single host cannot be both training and independent test: %+v", s)
	}
}
