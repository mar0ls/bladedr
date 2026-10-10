package scan

import (
	"context"
	"testing"

	"bladedr/internal/probe"
	"bladedr/internal/rules"
	"bladedr/internal/store"
)

// fleet builds a runner whose transport returns, per host, the state digest that host's
// probe would report — enough to drive the credential-reuse analysis end to end.
type fleet struct {
	t       *testing.T
	st      *store.Memory
	r       *Runner
	digests map[string]map[string][]string
	hosts   map[string]*store.Host
}

func newFleet(t *testing.T) *fleet {
	f := &fleet{t: t, st: store.NewMemory(), digests: map[string]map[string][]string{}, hosts: map[string]*store.Host{}}
	f.r = &Runner{
		Store:     f.st,
		LoadRules: func(context.Context) ([]rules.Rule, error) { return nil, nil },
		NewTransport: func(h *store.Host) (Transport, error) {
			d := map[string][]string{}
			for k, v := range f.digests[h.Hostname] {
				d[k] = append([]string(nil), v...)
			}
			return fakeTransport{result: probe.ScanResult{ProbeVersion: "t", StateDigest: d}}, nil
		},
	}
	return f
}

func (f *fleet) scan(name string, digest map[string][]string) {
	f.t.Helper()
	ctx := context.Background()
	h := f.hosts[name]
	if h == nil {
		h = &store.Host{Hostname: name}
		if err := f.st.CreateHost(ctx, h); err != nil {
			f.t.Fatal(err)
		}
		f.hosts[name] = h
	}
	f.digests[name] = digest
	if _, err := f.r.Scan(ctx, h, store.TriggerManual); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fleet) findings(host, rule string) []*store.Observation {
	f.t.Helper()
	obs, err := f.st.ListObservations(context.Background(), store.ObservationFilter{HostID: f.hosts[host].ID})
	if err != nil {
		f.t.Fatal(err)
	}
	var out []*store.Observation
	for _, o := range obs {
		if o.RuleID == rule {
			out = append(out, o)
		}
	}
	return out
}

func TestSharedSSHKeyIsReportedOnceItIsOnASecondHost(t *testing.T) {
	f := newFleet(t)
	key := "dev:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	f.scan("a", map[string][]string{probe.DigestAuthorizedKeys: {key}})
	if got := f.findings("a", "fleet-shared-ssh-key"); len(got) != 0 {
		t.Fatalf("a key on a single host is not shared: %d findings", len(got))
	}
	f.scan("b", map[string][]string{probe.DigestAuthorizedKeys: {"root:" + key[4:]}})
	got := f.findings("b", "fleet-shared-ssh-key")
	if len(got) != 1 {
		t.Fatalf("host b shares a key with a: %d findings", len(got))
	}
	ev := got[0].Evidence
	if ev["hosts_with"] != 2 || ev["root"] != true || len(ev["also_on"].([]string)) != 1 || ev["also_on"].([]string)[0] != "a" {
		t.Errorf("evidence should say 2 hosts, root, also on a: %+v", ev)
	}
	// The earlier host learns of it on its next scan.
	f.scan("a", map[string][]string{probe.DigestAuthorizedKeys: {key}})
	if got := f.findings("a", "fleet-shared-ssh-key"); len(got) != 1 {
		t.Fatalf("host a should now report the shared key: %d findings", len(got))
	}
}

func TestRemovedKeyStopsCountingAsShared(t *testing.T) {
	f := newFleet(t)
	key := "dev:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	f.scan("a", map[string][]string{probe.DigestAuthorizedKeys: {key}})
	f.scan("b", map[string][]string{probe.DigestAuthorizedKeys: {"ops:" + key[4:]}})
	// a drops the key. The inventory is replaced, not accumulated, so a fresh host that
	// has it is not told it is shared with a.
	f.scan("a", map[string][]string{probe.DigestAuthorizedKeys: {"dev:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}})
	f.scan("c", map[string][]string{probe.DigestAuthorizedKeys: {"x:" + key[4:]}})
	for _, o := range f.findings("c", "fleet-shared-ssh-key") {
		for _, h := range o.Evidence["also_on"].([]string) {
			if h == "a" {
				t.Errorf("a no longer authorizes the key but is still listed: %+v", o.Evidence)
			}
		}
	}
}

func TestSharedPasswordHashAcrossHostsAndAccounts(t *testing.T) {
	f := newFleet(t)
	f.scan("a", map[string][]string{probe.DigestPasswordHashes: {"root:1111111111111111", "admin:2222222222222222"}})
	if got := f.findings("a", "fleet-shared-password-hash"); len(got) != 0 {
		t.Fatalf("distinct hashes on one host are fine: %d", len(got))
	}
	f.scan("b", map[string][]string{probe.DigestPasswordHashes: {"root:1111111111111111"}})
	got := f.findings("b", "fleet-shared-password-hash")
	if len(got) != 1 || got[0].Severity != "medium" {
		t.Fatalf("b shares root's hash with a: %+v", got)
	}
	if got[0].Evidence["hosts_with"] != 2 {
		t.Errorf("hosts_with = %v", got[0].Evidence["hosts_with"])
	}
	// One hash on two accounts of the same host is the same weakness without a second host.
	f.scan("c", map[string][]string{probe.DigestPasswordHashes: {"root:3333333333333333", "deploy:3333333333333333"}})
	if got := f.findings("c", "fleet-shared-password-hash"); len(got) != 1 {
		t.Fatalf("two accounts sharing a hash on one host: %d findings", len(got))
	}
	// And neither a fingerprint nor a hash is ever stored in the baseline.
	if b, err := f.st.GetBaseline(context.Background(), f.hosts["a"].ID); err == nil {
		if _, ok := b.Digest[probe.DigestPasswordHashes]; ok {
			t.Error("password hash fingerprints must not enter the baseline")
		}
	}
}

func TestPrivateKeyThatOpensOtherHosts(t *testing.T) {
	f := newFleet(t)
	pub := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	f.scan("target", map[string][]string{probe.DigestAuthorizedKeys: {"deploy:" + pub}})
	f.scan("jump", map[string][]string{probe.DigestPrivateKeys: {"ci:" + pub + ":plain"}})
	got := f.findings("jump", "ssh-private-key-grants-access")
	if len(got) != 1 || got[0].Severity != "medium" {
		t.Fatalf("an unprotected key authorized on another host: %+v", got)
	}
	if on := got[0].Evidence["authorized_on"].([]string); len(on) != 1 || on[0] != "target" {
		t.Errorf("authorized_on = %v", on)
	}
	// Protected by a passphrase: still a path, but not a free one.
	f.scan("jump2", map[string][]string{probe.DigestPrivateKeys: {"ci:" + pub + ":locked"}})
	if got := f.findings("jump2", "ssh-private-key-grants-access"); len(got) != 1 || got[0].Severity != "low" {
		t.Fatalf("a passphrase-protected key should rate low: %+v", got)
	}
	// The same private key on a second host is a copied credential.
	if got := f.findings("jump2", "fleet-private-key-copied"); len(got) != 1 {
		t.Fatalf("private key copied to a second host: %d findings", len(got))
	}
}

func TestFleetOnlyCategoriesAreNotBaselined(t *testing.T) {
	f := newFleet(t)
	f.scan("a", map[string][]string{probe.DigestPasswordHashes: {"root:aaaa"}, probe.DigestAccounts: {"root:0"}})
	f.scan("a", map[string][]string{probe.DigestPasswordHashes: {"root:bbbb"}, probe.DigestAccounts: {"root:0"}})
	if got := f.findings("a", "baseline-new-password_hashes"); len(got) != 0 {
		t.Fatalf("a changed password must not raise a drift alert: %d", len(got))
	}
}

func TestHostThatRemovesAllItsKeysStopsSharingThem(t *testing.T) {
	f := newFleet(t)
	key := "dev:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	f.scan("a", map[string][]string{probe.DigestAuthorizedKeys: {key}})
	// a is cleaned up completely: its digest now has no keys at all, not a different key.
	f.scan("a", map[string][]string{})
	f.scan("b", map[string][]string{probe.DigestAuthorizedKeys: {"ops:" + key[4:]}})
	if got := f.findings("b", "fleet-shared-ssh-key"); len(got) != 0 {
		t.Fatalf("a no longer authorizes any key, so nothing is shared with it: %+v", got[0].Evidence)
	}
}
