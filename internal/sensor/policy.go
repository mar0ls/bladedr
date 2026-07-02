// Package sensor is bladedr's eBPF tier: a thin wrapper around Tetragon. It loads
// the linux-probe-shield TracingPolicies, consumes Tetragon's JSON event stream,
// and maps each policy hit to a bladedr observation (source=ebpf_sensor) posted to
// the server — so runtime techniques (exec, injection, container escape, fileless,
// C2) land in the same observations table as the agentless findings.
//
// The detection logic lives entirely in the Tetragon policies (loaded 1:1); this
// package only carries metadata and forwards events, so the eBPF tier drops onto
// the existing core without re-engineering it.
package sensor

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// PolicyMeta is the severity/MITRE/title context attached to a Tetragon policy.
// It is read from the TracingPolicy's metadata.annotations (the linux-probe-shield
// policies carry description/mitre/severity there).
type PolicyMeta struct {
	Name     string   // TracingPolicy metadata.name == event policy_name
	Title    string   // from annotations.description (or the name)
	Severity string   // from annotations.severity (default "medium")
	Category string   // derived from the policy name (coarse), default "runtime"
	Mitre    []string // from annotations.mitre ("T1610,T1611" -> [...])
}

// tracingPolicy is the subset of a Tetragon TracingPolicy we read.
type tracingPolicy struct {
	Metadata struct {
		Name        string            `yaml:"name"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
}

// LoadPolicyMeta parses every TracingPolicy in dir into a name->metadata map. A
// policy with no annotations still gets an entry (severity medium, category from
// the name) so its events are still attributed.
func LoadPolicyMeta(dir string) (map[string]PolicyMeta, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := map[string]PolicyMeta{}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || (!strings.HasSuffix(n, ".yml") && !strings.HasSuffix(n, ".yaml")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		var tp tracingPolicy
		if yaml.Unmarshal(data, &tp) != nil || tp.Metadata.Name == "" {
			continue
		}
		out[tp.Metadata.Name] = metaFrom(tp)
	}
	return out, nil
}

func metaFrom(tp tracingPolicy) PolicyMeta {
	a := tp.Metadata.Annotations
	m := PolicyMeta{Name: tp.Metadata.Name, Severity: "medium", Category: categoryOf(tp.Metadata.Name)}
	if a != nil {
		if d := a["description"]; d != "" {
			m.Title = d
		}
		if s := a["severity"]; s != "" {
			m.Severity = strings.ToLower(s)
		}
		if mt := a["mitre"]; mt != "" {
			for _, t := range strings.Split(mt, ",") {
				if t = strings.TrimSpace(t); t != "" {
					m.Mitre = append(m.Mitre, t)
				}
			}
		}
	}
	if m.Title == "" {
		m.Title = tp.Metadata.Name
	}
	return m
}

// categoryOf derives a coarse tactic category from the policy name, so the risk
// model gets a useful (name-free) feature. Falls back to "runtime".
func categoryOf(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "shell-spawn") || strings.Contains(n, "exec") || strings.Contains(n, "memfd") || strings.Contains(n, "compiler"):
		return "execution"
	case strings.Contains(n, "network") || strings.Contains(n, "tcp") || strings.Contains(n, "udp") || strings.Contains(n, "dns"):
		return "network"
	case strings.Contains(n, "ptrace") || strings.Contains(n, "proc-mem") || strings.Contains(n, "antidebug") || strings.Contains(n, "log-tampering") || strings.Contains(n, "hidden"):
		return "evasion"
	case strings.Contains(n, "docker") || strings.Contains(n, "setns") || strings.Contains(n, "pivot-root") || strings.Contains(n, "unshare") || strings.Contains(n, "capability") || strings.Contains(n, "suid") || strings.Contains(n, "setuid") || strings.Contains(n, "gtfobins"):
		return "privilege"
	case strings.Contains(n, "lkm") || strings.Contains(n, "bpf") || strings.Contains(n, "module") || strings.Contains(n, "kernel") || strings.Contains(n, "core-pattern") || strings.Contains(n, "umh") || strings.Contains(n, "cve"):
		return "kernel"
	case strings.Contains(n, "crontab") || strings.Contains(n, "systemd") || strings.Contains(n, "udev") || strings.Contains(n, "ssh") || strings.Contains(n, "pam") || strings.Contains(n, "persistence") || strings.Contains(n, "binfmt"):
		return "persistence"
	case strings.Contains(n, "credential") || strings.Contains(n, "sensitive-files") || strings.Contains(n, "etc-writes"):
		return "credential"
	default:
		return "runtime"
	}
}
