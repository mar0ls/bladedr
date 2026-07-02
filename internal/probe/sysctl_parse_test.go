package probe

import "testing"

func TestSysctlHardeningDisabled(t *testing.T) {
	cases := map[string]string{
		"kernel.yama.ptrace_scope = 0":          "kernel.yama.ptrace_scope=0",
		"kernel.kptr_restrict=0":                "kernel.kptr_restrict=0",
		"-kernel.unprivileged_bpf_disabled = 0": "kernel.unprivileged_bpf_disabled=0",
		"kernel/dmesg_restrict = 0":             "kernel.dmesg_restrict=0", // '/'-style key
		// must NOT match:
		"kernel.yama.ptrace_scope = 1": "",
		"kernel.kptr_restrict = 2":     "",
		"# kernel.kptr_restrict = 0":   "",
		"net.core.somaxconn = 0":       "",
		"kernel.sysrq = 176":           "",
	}
	for line, want := range cases {
		if got := sysctlHardeningDisabled(line); got != want {
			t.Errorf("sysctlHardeningDisabled(%q) = %q, want %q", line, got, want)
		}
	}
}
