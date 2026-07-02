package probe

import "strings"

// aptRepoInsecure reports whether an apt source line disables signature
// verification: a one-line `deb [trusted=yes]` / allow-insecure option, or a
// deb822 `Trusted: yes` stanza line. Such a repo accepts unsigned packages —
// a supply-chain backdoor vector (EDR-T6213/T6144).
func aptRepoInsecure(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return false
	}
	low := strings.ToLower(t)
	if strings.Contains(low, "trusted=yes") ||
		strings.Contains(low, "allow-insecure=yes") ||
		strings.Contains(low, "allow-downgrade-to-insecure=yes") {
		return true
	}
	if k, v, ok := strings.Cut(low, ":"); ok && strings.TrimSpace(k) == "trusted" {
		return strings.TrimSpace(v) == "yes"
	}
	return false
}

// yumGpgcheckOff reports whether a yum/dnf line disables PACKAGE signature
// checking (gpgcheck=0). It deliberately does NOT flag repo_gpgcheck=0 (repo
// METADATA signing): packages are still verified by gpgcheck, and repo_gpgcheck=0
// is the shipped default of common repos such as EPEL, so flagging it produces a
// false positive on every RHEL host that has EPEL enabled.
func yumGpgcheckOff(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
		return false
	}
	k, v, ok := strings.Cut(t, "=")
	if !ok {
		return false
	}
	if strings.ToLower(strings.TrimSpace(k)) == "gpgcheck" {
		return strings.TrimSpace(v) == "0"
	}
	return false
}
