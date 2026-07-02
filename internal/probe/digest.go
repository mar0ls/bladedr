package probe

import (
	"fmt"
	"sort"
)

// Baseline digest categories.
const (
	DigestListeningPorts = "listening_ports"
	DigestKernelModules  = "kernel_modules"
	DigestAccounts       = "accounts"
	DigestAuthorizedKeys = "authorized_keys"
	DigestCron           = "cron"
	DigestSystemdUnits   = "systemd_units"
	DigestBpfPrograms    = "bpf_programs"
)

// BuildStateDigest summarises a snapshot into per-category sets of stable item
// identities. The server compares this against a stored baseline to surface drift
// (a new port/module/account/key/cron/unit since the baseline was established).
// It is platform-independent so it can be unit-tested with fixtures.
func BuildStateDigest(s *Snapshot) map[string][]string {
	d := map[string][]string{}

	for _, sk := range s.ListeningSockets {
		// Skip the ephemeral/dynamic range (32768-60999): RPC services (rpcbind,
		// rpc.statd, NFS, container runtimes) bind a different high port each boot, so
		// baselining them produces pure churn — a new baseline-new-listening_ports
		// every scan with no security value. Persistent backdoors bind a stable,
		// usually low/well-known port (still baselined); known backdoor ports are
		// covered by the suspicious-port-listener rule regardless of this digest.
		if sk.LPort >= 32768 {
			continue
		}
		d[DigestListeningPorts] = append(d[DigestListeningPorts], fmt.Sprintf("%s/%d", sk.Proto, sk.LPort))
	}
	for _, m := range s.KernelModules {
		// Baseline only OUT-OF-TREE modules. In-tree modules (netfilter xt_*/nf_*,
		// veth/overlay/bridge, *_diag, ib_*, ...) load and unload on demand on any
		// container/network-active host, so baselining them is pure churn. The
		// security-relevant drift is a new out-of-tree module (the rootkit/driver
		// class); hidden and unsigned modules are caught by dedicated signature rules
		// regardless of the baseline.
		if m.OutOfTree {
			d[DigestKernelModules] = append(d[DigestKernelModules], m.Name)
		}
	}
	for _, a := range s.Accounts {
		d[DigestAccounts] = append(d[DigestAccounts], fmt.Sprintf("%s:%d", a.Name, a.UID))
	}
	for _, akf := range s.Persistence.AuthorizedKeys {
		for _, k := range akf.Keys {
			d[DigestAuthorizedKeys] = append(d[DigestAuthorizedKeys], akf.Owner+":"+k.SHA256)
		}
	}
	for _, c := range s.Persistence.Cron {
		d[DigestCron] = append(d[DigestCron], c.Path+" :: "+c.Line)
	}
	for _, u := range s.Persistence.SystemdUnits {
		d[DigestSystemdUnits] = append(d[DigestSystemdUnits], u.Name)
	}
	for _, p := range s.BpfPrograms {
		// Identify by type+tag (instruction hash): stable across reloads and PID
		// churn, and program names are often empty. A new (type,tag) is drift.
		d[DigestBpfPrograms] = append(d[DigestBpfPrograms], p.Type+":"+p.Tag)
	}

	for k, v := range d {
		d[k] = sortedUnique(v)
	}
	return d
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
