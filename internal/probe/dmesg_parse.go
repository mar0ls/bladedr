package probe

import "strings"

// virtualIfacePrefixes are interface name prefixes that legitimately enter
// promiscuous mode on virtualization / container / bridge hosts (Proxmox tap &
// firewall bridges, libvirt, docker, k8s CNIs, …). Promiscuous on these is
// expected, so they are not a sniffing signal.
var virtualIfacePrefixes = []string{
	"tap", "fwpr", "fwln", "fwbr", "vmbr", "veth", "virbr", "docker", "br-",
	"cni", "cali", "cilium", "lxcbr", "lxdbr", "ovs-", "genev", "vxlan",
	"kube", "flannel", "weave", "antrea", "macvtap",
}

func isVirtualIface(name string) bool {
	n := strings.ToLower(name)
	for _, p := range virtualIfacePrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// promiscIface extracts the interface name from a "<… > <iface>: entered
// promiscuous mode" kernel message (the iface is the last token before the colon,
// after any driver/PCI prefix).
func promiscIface(msg string) string {
	i := strings.Index(msg, ": entered promiscuous mode")
	if i < 0 {
		return ""
	}
	fields := strings.Fields(strings.TrimSpace(msg[:i]))
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// promiscInterfaces returns the non-virtual interfaces that entered promiscuous
// mode — a real sniffer signal. Bridge/tap/VM/CNI interfaces are filtered out.
func promiscInterfaces(log []KernelLogEntry) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range log {
		if !strings.Contains(e.Message, "entered promiscuous mode") {
			continue
		}
		iface := promiscIface(e.Message)
		if iface == "" || isVirtualIface(iface) || seen[iface] {
			continue
		}
		seen[iface] = true
		out = append(out, iface)
	}
	return out
}

// legitOutOfTreeModules are well-known signed-but-out-of-tree DKMS modules that
// taint the kernel legitimately (ZFS/SPL, GPU/hypervisor drivers, WireGuard, …).
var legitOutOfTreeModules = map[string]bool{
	"spl": true, "zfs": true, "znvpair": true, "zavl": true, "zcommon": true,
	"zlua": true, "zunicode": true, "zzstd": true, "icp": true,
	"wireguard": true, "v4l2loopback": true, "vmmon": true, "vmnet": true,
	"vboxdrv": true, "vboxnetflt": true, "vboxnetadp": true, "vboxpci": true,
	"acpi_call": true, "ddcci": true, "zenpower": true, "openrazer": true,
	"rtl8812au": true, "rtl88x2bu": true, "8812au": true, "lkrg": true,
}

func isLegitOutOfTreeModule(mod string) bool {
	m := strings.ToLower(mod)
	for _, p := range []string{"nvidia", "vbox", "vmw_", "zfs", "spl"} {
		if strings.HasPrefix(m, p) {
			return true
		}
	}
	return legitOutOfTreeModules[m]
}

// outOfTreeModuleName pulls the module token from a "<mod>: … taints kernel"
// message; returns "" when the message has no single leading module name.
func outOfTreeModuleName(msg string) string {
	if i := strings.IndexByte(msg, ':'); i > 0 {
		if f := strings.Fields(msg[:i]); len(f) == 1 {
			return f[0]
		}
	}
	return ""
}

// outOfTreeModules returns kernel taint / out-of-tree-load messages whose module
// is NOT a known-legit DKMS module — i.e. candidate LKM rootkit loads.
func outOfTreeModules(log []KernelLogEntry) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range log {
		m := e.Message
		if !strings.Contains(m, "loading out-of-tree module") &&
			!strings.Contains(m, "module verification failed") &&
			!strings.Contains(m, "tainting kernel") &&
			!strings.Contains(m, "loading test module taints kernel") {
			continue
		}
		if mod := outOfTreeModuleName(m); mod != "" && isLegitOutOfTreeModule(mod) {
			continue
		}
		if seen[m] {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	return out
}
