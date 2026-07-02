package sensor

import (
	"encoding/json"
	"strings"

	"bladedr/internal/store"
)

// tetragonEvent is the subset of a Tetragon JSON export line we consume. Only the
// policy-matched event kinds (kprobe/tracepoint/uprobe) carry a policy_name; base
// process_exec/exit events do not and are ignored.
type tetragonEvent struct {
	ProcessKprobe     *kprobeEvent `json:"process_kprobe"`
	ProcessTracepoint *kprobeEvent `json:"process_tracepoint"`
	ProcessUprobe     *kprobeEvent `json:"process_uprobe"`
	Time              string       `json:"time"`
}

type kprobeEvent struct {
	Process      *procInfo `json:"process"`
	Parent       *procInfo `json:"parent"`
	FunctionName string    `json:"function_name"`
	PolicyName   string    `json:"policy_name"`
	Action       string    `json:"action"`
}

type procInfo struct {
	PID       int    `json:"pid"`
	UID       int    `json:"uid"`
	Binary    string `json:"binary"`
	Arguments string `json:"arguments"`
}

// Event is the normalized policy hit extracted from a Tetragon line.
type Event struct {
	PolicyName string
	Function   string
	Time       string
	Process    *procInfo
	Parent     *procInfo
}

// ParseEvent decodes one Tetragon JSON export line, returning the policy hit and
// true when the line is a policy-matched event (carries a policy_name). Base exec
// events, exits, and malformed lines return ok=false.
func ParseEvent(line []byte) (*Event, bool) {
	line = trimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		return nil, false
	}
	var te tetragonEvent
	if json.Unmarshal(line, &te) != nil {
		return nil, false
	}
	k := te.ProcessKprobe
	if k == nil {
		k = te.ProcessTracepoint
	}
	if k == nil {
		k = te.ProcessUprobe
	}
	if k == nil || k.PolicyName == "" {
		return nil, false
	}
	return &Event{
		PolicyName: k.PolicyName,
		Function:   k.FunctionName,
		Time:       te.Time,
		Process:    k.Process,
		Parent:     k.Parent,
	}, true
}

// EventToObservation maps a policy hit to a bladedr observation, joining the policy
// metadata (severity/MITRE/title/category) from the loaded bundle. A policy with no
// metadata still maps (medium / runtime). Dedup is policy+binary, so repeated hits
// of the same binary collapse onto one observation (Count increments server-side).
func EventToObservation(ev *Event, meta map[string]PolicyMeta, hostID string) *store.Observation {
	m, ok := meta[ev.PolicyName]
	if !ok {
		m = PolicyMeta{Name: ev.PolicyName, Title: ev.PolicyName, Severity: "medium", Category: "runtime"}
	}
	ev_ := map[string]any{"function": ev.Function}
	binary := ""
	if ev.Process != nil {
		binary = ev.Process.Binary
		ev_["binary"] = ev.Process.Binary
		ev_["args"] = ev.Process.Arguments
		ev_["pid"] = ev.Process.PID
		ev_["uid"] = ev.Process.UID
	}
	if ev.Parent != nil {
		ev_["parent"] = ev.Parent.Binary
	}
	return &store.Observation{
		HostID:   hostID,
		Source:   store.SourceEBPFSensor,
		RuleID:   ev.PolicyName,
		Category: m.Category,
		Title:    m.Title,
		Severity: m.Severity,
		Score:    severityScore(m.Severity),
		Mitre:    m.Mitre,
		Evidence: ev_,
		DedupKey: ev.PolicyName + "|" + binary,
		Status:   store.ObsOpen,
	}
}

// severityScore maps a severity label to a 0-100 score (mirrors the agentless rule
// scores / the ECS export bands), so sensor and agentless observations rank together.
func severityScore(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 90
	case "high":
		return 75
	case "medium":
		return 50
	case "low":
		return 25
	default:
		return 40
	}
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r') {
		b = b[1:]
	}
	for len(b) > 0 {
		c := b[len(b)-1]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			break
		}
		b = b[:len(b)-1]
	}
	return b
}
