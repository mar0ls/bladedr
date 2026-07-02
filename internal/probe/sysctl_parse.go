package probe

import "strings"

// hardeningDisableKeys are kernel sysctls whose security value is "off" at 0.
// Distros default these to 1/2; a config line setting them to 0 persistently
// weakens process-injection / info-leak / BPF defenses (T1562.001).
var hardeningDisableKeys = map[string]bool{
	"kernel.yama.ptrace_scope":         true,
	"kernel.kptr_restrict":             true,
	"kernel.unprivileged_bpf_disabled": true,
	"kernel.dmesg_restrict":            true,
}

// sysctlHardeningDisabled returns "key=0" when a sysctl line disables a hardening
// control, else "". Handles '/'-style keys and the leading '-' ignore-error form.
func sysctlHardeningDisabled(line string) string {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
		return ""
	}
	t = strings.TrimPrefix(t, "-")
	i := strings.IndexByte(t, '=')
	if i < 0 {
		return ""
	}
	key := strings.ReplaceAll(strings.TrimSpace(t[:i]), "/", ".")
	val := strings.TrimSpace(t[i+1:])
	if hardeningDisableKeys[key] && val == "0" {
		return key + "=0"
	}
	return ""
}
