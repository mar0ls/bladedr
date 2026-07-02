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

	d := BuildStateDigest(s)

	// ports deduplicated and sorted; the ephemeral 45093 is excluded (RPC churn)
	if got := d[DigestListeningPorts]; !reflect.DeepEqual(got, []string{"tcp/22", "tcp/80"}) {
		t.Errorf("listening_ports = %v", got)
	}
	// only the out-of-tree module is baselined; in-tree ext4/veth churn is excluded
	if got := d[DigestKernelModules]; !reflect.DeepEqual(got, []string{"evilrk"}) {
		t.Errorf("kernel_modules = %v", got)
	}
	if got := d[DigestAccounts]; !reflect.DeepEqual(got, []string{"dev:1000", "root:0"}) {
		t.Errorf("accounts = %v", got)
	}
	if got := d[DigestAuthorizedKeys]; !reflect.DeepEqual(got, []string{"root:abc"}) {
		t.Errorf("authorized_keys = %v", got)
	}
}
