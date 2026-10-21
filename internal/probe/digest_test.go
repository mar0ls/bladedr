package probe

import (
	"reflect"
	"testing"
)

func TestBuildStateDigest(t *testing.T) {
	s := &Snapshot{
		ListeningSockets: []Socket{{Proto: "tcp", LPort: 22}, {Proto: "tcp", LPort: 22}, {Proto: "tcp", LPort: 80}, {Proto: "tcp", LPort: 45093}},
		KernelModules:    []KernelModule{{Name: "ext4"}, {Name: "veth"}, {Name: "evilrk", OutOfTree: true}},
		Accounts:         []Account{{Name: "root", UID: 0}, {Name: "dev", UID: 1000}},
	}
	s.Persistence.AuthorizedKeys = []AuthKeysFile{{Owner: "root", Keys: []AuthKey{{SHA256: "abc"}}}}
	s.Accounts = append(s.Accounts,
		Account{Name: "svc", UID: 999, Shell: "/usr/sbin/nologin", PasswordFingerprint: "fp-nologin"},
		Account{Name: "daemon", UID: 2, Shell: "/bin/false", PasswordFingerprint: "fp-false"},
		Account{Name: "nopass", UID: 1001, Shell: "/bin/bash"}, // no fingerprint: shadow unreadable or locked
	)
	s.Accounts[1].PasswordFingerprint = "fp-dev" // dev, a real login account
	s.PrivateKeys = []PrivateKeyFile{
		{Owner: "root", PubSHA256: "keyA", Encrypted: false},
		{Owner: "dev", PubSHA256: "keyB", Encrypted: true},
		{Owner: "root", PubSHA256: ""}, // unparsed key: no public half to compare, excluded
	}
	s.Persistence.Cron = []CronEntry{{Path: "/etc/crontab", Line: "* * * * * root id"}}
	s.Persistence.SystemdUnits = []SystemdUnit{{Name: "cron.service"}}
	s.BpfPrograms = []BpfProg{{Type: "kprobe", Tag: "deadbeef"}, {Type: "kprobe", Tag: "deadbeef"}}

	d := BuildStateDigest(s)

	// a login account's hash fingerprint is baselined for fleet reuse comparison...
	if got := d[DigestPasswordHashes]; !reflect.DeepEqual(got, []string{"dev:fp-dev"}) {
		t.Errorf("password_hashes = %v, want only the real login account", got)
	}
	// ...a service account's (nologin/false shell) is not, however it got a fingerprint:
	// its hash being shared is not a lateral-movement path if nothing can log in with it.
	for _, excluded := range []string{"svc:fp-nologin", "daemon:fp-false"} {
		for _, got := range d[DigestPasswordHashes] {
			if got == excluded {
				t.Errorf("password_hashes included a non-login account: %v", d[DigestPasswordHashes])
			}
		}
	}
	if got := d[DigestPrivateKeys]; !reflect.DeepEqual(got, []string{"dev:keyB:locked", "root:keyA:plain"}) {
		t.Errorf("private_keys = %v", got)
	}
	if got := d[DigestCron]; !reflect.DeepEqual(got, []string{"/etc/crontab :: * * * * * root id"}) {
		t.Errorf("cron = %v", got)
	}
	if got := d[DigestSystemdUnits]; !reflect.DeepEqual(got, []string{"cron.service"}) {
		t.Errorf("systemd_units = %v", got)
	}
	// Two loads of the identical (type, tag) dedupe to one baseline entry.
	if got := d[DigestBpfPrograms]; !reflect.DeepEqual(got, []string{"kprobe:deadbeef"}) {
		t.Errorf("bpf_programs = %v, want one deduplicated entry", got)
	}

	// ports deduplicated and sorted; the ephemeral 45093 is excluded (RPC churn)
	if got := d[DigestListeningPorts]; !reflect.DeepEqual(got, []string{"tcp/22", "tcp/80"}) {
		t.Errorf("listening_ports = %v", got)
	}
	// only the out-of-tree module is baselined; in-tree ext4/veth churn is excluded
	if got := d[DigestKernelModules]; !reflect.DeepEqual(got, []string{"evilrk"}) {
		t.Errorf("kernel_modules = %v", got)
	}
	if got := d[DigestAccounts]; !reflect.DeepEqual(got, []string{"daemon:2", "dev:1000", "nopass:1001", "root:0", "svc:999"}) {
		t.Errorf("accounts = %v", got)
	}
	if got := d[DigestAuthorizedKeys]; !reflect.DeepEqual(got, []string{"root:abc"}) {
		t.Errorf("authorized_keys = %v", got)
	}
}
