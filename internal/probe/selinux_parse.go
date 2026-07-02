package probe

import "strings"

// selinuxConfigMode returns the configured SELinux mode ("disabled"/"permissive")
// when /etc/selinux/config turns SELinux off, else "" (enforcing or unset). The
// file only exists on RPM/SELinux distros, so a non-enforcing value there means
// SELinux was deliberately weakened — a defense-evasion signal (T1562.001/T6293).
func selinuxConfigMode(content string) string {
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		key, val, ok := strings.Cut(t, "=")
		if !ok || strings.TrimSpace(key) != "SELINUX" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(val)) {
		case "disabled":
			return "disabled"
		case "permissive":
			return "permissive"
		}
	}
	return ""
}

// selinuxBootDisable reports the kernel cmdline token that disables SELinux at
// boot (selinux=0 or enforcing=0), else "". Parsed from /proc/cmdline or a GRUB
// GRUB_CMDLINE_LINUX value — a persistent, boot-level way to keep SELinux off.
func selinuxBootDisable(cmdline string) string {
	for _, tok := range strings.Fields(cmdline) {
		switch strings.Trim(tok, `"'`) {
		case "selinux=0":
			return "selinux=0"
		case "enforcing=0":
			return "enforcing=0"
		}
	}
	return ""
}
