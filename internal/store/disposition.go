package store

import "errors"

var ErrDisposition = errors.New("invalid action or finding is not confirmed")

// ObservationDisposition returns the workflow update; an empty verdict preserves assessment.
func ObservationDisposition(action string) (status, verdict string, err error) {
	switch action {
	case "take_ownership":
		return ObsAcknowledged, "", nil
	case "confirm_finding":
		return ObsAcknowledged, "true_positive", nil
	case "close_false_positive":
		return ObsFalsePositive, "false_positive", nil
	case "resolve":
		return ObsResolved, "", nil
	case "close_inconclusive":
		return ObsResolved, "unknown", nil
	case "reopen":
		return ObsOpen, "", nil
	default:
		return "", "", ErrDisposition
	}
}
