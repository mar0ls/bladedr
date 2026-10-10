package risk

import (
	"testing"

	"bladedr/internal/store"
)

func featureSet(o *store.Observation) map[string]bool {
	set := map[string]bool{}
	for _, f := range Features(o) {
		set[f] = true
	}
	return set
}

func withEvidence(ev map[string]any) *store.Observation {
	return &store.Observation{RuleID: "r", Category: "c", Severity: "high", Source: "scan", Evidence: ev}
}

// A dot-component only means concealment under a transient, world-writable root. The
// first version of this feature counted every dot-path, so it fired on both classes of
// any rule whose evidence quotes ~/.ssh or ~/.config and tied them — the exact failure
// the feature was added to fix.
func TestHiddenPathOnlyCountsTransientRoots(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   map[string]any
		want bool
	}{
		{"payload under a hidden dir in /tmp", map[string]any{"exe": "/tmp/.x/run"}, true},
		{"hidden dir under /run", map[string]any{"exe": "/run/.cache/agent"}, true},
		{"ssh client config", map[string]any{"path": "/root/.ssh/config"}, false},
		{"user dotfile", map[string]any{"path": "/home/deploy/.bashrc"}, false},
		{"ordinary system path", map[string]any{"path": "/usr/local/bin/agent"}, false},
		{"parent traversal is not a hidden name", map[string]any{"path": "/tmp/../etc/passwd"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := featureSet(withEvidence(tc.ev))["shape:hidden-path"]; got != tc.want {
				t.Errorf("shape:hidden-path = %v, want %v for %v", got, tc.want, tc.ev)
			}
		})
	}
}

// Capabilities are split by what they grant, not by name: an APM agent with
// cap_sys_ptrace and an implant with cap_setuid trip the same rule.
func TestCapabilityClassSplitsByWhatItGrants(t *testing.T) {
	for caps, want := range map[string]string{
		"cap_setuid":           "shape:cap-direct",
		"cap_sys_admin":        "shape:cap-direct",
		"cap_sys_ptrace":       "shape:cap-observe",
		"cap_dac_read_search":  "shape:cap-observe",
		"cap_net_bind_service": "shape:cap-other",
	} {
		if !featureSet(withEvidence(map[string]any{"caps": caps}))[want] {
			t.Errorf("%s should produce %s", caps, want)
		}
	}
	if len(featureSet(withEvidence(map[string]any{"path": "/usr/bin/x"}))) == 0 {
		t.Error("an observation with no caps should still produce features")
	}
}

// A grant to a role is an administrative pattern; a grant to one account is what an
// intruder writes. The group's name is never featurised, only the shape of the grant.
func TestGrantShapeSeparatesGroupFromUser(t *testing.T) {
	group := featureSet(withEvidence(map[string]any{"line": "%backup ALL=(root) NOPASSWD: /usr/bin/tar"}))
	user := featureSet(withEvidence(map[string]any{"line": "baduser ALL=(root) NOPASSWD: /usr/bin/find"}))
	if !group["shape:grant-group"] || group["shape:grant-user"] {
		t.Errorf("a %%group grant should be shape:grant-group, got %v", group)
	}
	if !user["shape:grant-user"] || user["shape:grant-group"] {
		t.Errorf("a single-account grant should be shape:grant-user, got %v", user)
	}
	if group["shape:grant-backup"] || user["shape:grant-baduser"] {
		t.Error("the grantee's name must never become a feature")
	}
}

// Reaching for the dynamic linker is the difference between a backup key that sets a
// repo path and one that loads code into every process the key touches.
func TestLinkerInjectionIsDetectedInNestedEvidence(t *testing.T) {
	malicious := withEvidence(map[string]any{"keys": []any{
		map[string]any{"options": `environment="LD_PRELOAD=/tmp/.x/evil.so"`},
	}})
	benign := withEvidence(map[string]any{"keys": []any{
		map[string]any{"options": `environment="BORG_REPO=/srv/backup"`},
	}})
	if !featureSet(malicious)["shape:linker-inject"] {
		t.Error("LD_PRELOAD nested in a key list should be found")
	}
	if featureSet(benign)["shape:linker-inject"] {
		t.Error("a repo path is not linker injection")
	}
}

func TestShellStringExecAndTunnelShape(t *testing.T) {
	sys := featureSet(withEvidence(map[string]any{"imports": []any{"import os; os.system('id')"}}))
	argv := featureSet(withEvidence(map[string]any{"imports": []any{"import os, subprocess; subprocess.Popen(['/usr/local/bin/apm-agent'])"}}))
	if !sys["shape:shell-string-exec"] {
		t.Error("os.system hands a string to a shell and should be flagged")
	}
	if argv["shape:shell-string-exec"] {
		t.Error("an argv list is not shell-string execution")
	}

	socks := featureSet(withEvidence(map[string]any{"tunnel": "dynamic SOCKS proxy (-D): ssh -fND 1080 jump@10.0.0.5"}))
	fwd := featureSet(withEvidence(map[string]any{"tunnel": "remote port-forward (-R): ssh -fNR 15432:localhost:5432 bastion@10.0.0.9"}))
	if !socks["shape:tunnel-dynamic"] || !fwd["shape:tunnel-forward"] {
		t.Errorf("a general-purpose pivot and a point-to-point forward must differ: %v vs %v", socks, fwd)
	}
}

// The diagnostic that drives the gate: when two instances of a rule are indistinguishable
// the model must report them as tied rather than implying it ranked them.
func TestWithinRuleSeparationCountsTiedRules(t *testing.T) {
	var data []*store.Observation
	for i := 0; i < minPerClass; i++ {
		// Same rule, identical evidence, opposite labels: nothing can separate these.
		tied := func(st string) *store.Observation {
			verdict := "false_positive"
			if st == store.ObsAcknowledged {
				verdict = "true_positive"
			}
			return &store.Observation{RuleID: "tied-rule", Category: "c", Severity: "high",
				Source: "scan", Status: st, Verdict: verdict, Evidence: map[string]any{"note": "identical"}}
		}
		data = append(data, tied(store.ObsAcknowledged), tied(store.ObsFalsePositive))
		// Same rule, evidence that differs in shape: separable.
		data = append(data,
			&store.Observation{RuleID: "split-rule", Category: "c", Severity: "high", Source: "scan",
				Status: store.ObsAcknowledged, Verdict: "true_positive", Evidence: map[string]any{"exe": "/tmp/.x/run"}},
			&store.Observation{RuleID: "split-rule", Category: "c", Severity: "high", Source: "scan",
				Status: store.ObsFalsePositive, Verdict: "false_positive", Evidence: map[string]any{"exe": "/usr/local/bin/agent"}})
	}
	st := Evaluate(data)
	if st.WithinRuleRules != 2 {
		t.Fatalf("both rules carry each label; want 2 measurable rules, got %d", st.WithinRuleRules)
	}
	if st.WithinRuleTied != 1 {
		t.Errorf("exactly the rule with identical evidence should be tied, got %d tied", st.WithinRuleTied)
	}
}

func TestKeyExposedToOthers(t *testing.T) {
	cases := []struct {
		name string
		ev   map[string]any
		want bool
	}{
		{"world-readable key", map[string]any{"path": "/root/.ssh/id_ed25519_leak", "type": "ssh-ed25519", "mode": "0644"}, true},
		{"group-readable key", map[string]any{"path": "/home/a/.ssh/id_rsa", "type": "rsa", "mode": "0640"}, true},
		{"owner-only key", map[string]any{"path": "/root/.ssh/ci_deploy", "type": "ssh-ed25519", "mode": "0600"}, false},
		{"a SUID finding's mode is not a key's", map[string]any{"path": "/tmp/.x/rootshell", "mode": "4755", "uid": 0}, false},
		{"not under .ssh or a key name", map[string]any{"path": "/etc/foo", "type": "x", "mode": "0644"}, false},
		{"no mode", map[string]any{"path": "/root/.ssh/k", "type": "rsa"}, false},
	}
	for _, c := range cases {
		if got := keyExposedToOthers(c.ev); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
