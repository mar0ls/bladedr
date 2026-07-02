package probe

import (
	"reflect"
	"testing"
)

func entries(msgs ...string) []KernelLogEntry {
	out := make([]KernelLogEntry, len(msgs))
	for i, m := range msgs {
		out[i] = KernelLogEntry{Message: m}
	}
	return out
}

func TestPromiscInterfacesFiltersVirtual(t *testing.T) {
	log := entries(
		// Proxmox virtualization noise — must be filtered:
		"tap103i0: entered promiscuous mode",
		"fwpr103p0: entered promiscuous mode",
		"fwln103i0: entered promiscuous mode",
		"vmbr0: entered promiscuous mode",
		"veth1a2b: entered promiscuous mode",
		"docker0: entered promiscuous mode",
		"fwpr103p0 (unregistering): left promiscuous mode", // "left" is ignored entirely
		// Real signal — physical NIC sniffing:
		"e1000e 0000:00:1f.6 eno1: entered promiscuous mode",
	)
	got := promiscInterfaces(log)
	if !reflect.DeepEqual(got, []string{"eno1"}) {
		t.Fatalf("expected only the physical NIC eno1, got %v", got)
	}
}

func TestOutOfTreeModulesAllowlist(t *testing.T) {
	log := entries(
		"spl: loading out-of-tree module taints kernel.",           // OpenZFS — legit
		"zfs: module license 'CDDL' taints kernel.",                // OpenZFS — legit
		"nvidia: loading out-of-tree module taints kernel.",        // GPU driver — legit
		"vboxdrv: loading out-of-tree module taints kernel.",       // VirtualBox — legit
		"diamorphine: loading out-of-tree module taints kernel.",   // rootkit — KEEP
		"reptile_mod: module verification failed: tainting kernel", // rootkit — KEEP
	)
	got := outOfTreeModules(log)
	want := []string{
		"diamorphine: loading out-of-tree module taints kernel.",
		"reptile_mod: module verification failed: tainting kernel",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("allowlist failed.\n got:  %v\n want: %v", got, want)
	}
}
