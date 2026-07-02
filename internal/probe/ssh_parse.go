package probe

import (
	"path/filepath"
	"strings"
)

// sshTunnelKind classifies an `ssh` client command line as a tunnel/pivot, or "".
// It flags dynamic SOCKS (-D, a pivot), remote forwarding (-R, exposes/pivots) and
// persistent background tunnels (-N together with -f). Plain interactive local
// forwarding (-L alone) is NOT flagged — too commonly legitimate. Short-option
// clusters like "-fNR" are parsed letter-by-letter.
func sshTunnelKind(cmdline string) string {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return ""
	}
	switch filepath.Base(fields[0]) {
	case "ssh", "autossh":
	default:
		return ""
	}
	letters := map[rune]bool{}
	for _, tok := range fields[1:] {
		if len(tok) < 2 || tok[0] != '-' || tok[1] == '-' {
			continue // skip args and long options
		}
		for _, c := range tok[1:] {
			if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
				break // attached value (e.g. -D1080) — stop at first non-letter
			}
			letters[c] = true
		}
	}
	switch {
	case letters['D']:
		return "dynamic SOCKS proxy (-D)"
	case letters['R']:
		return "remote port-forward (-R)"
	case letters['N'] && letters['f']:
		return "persistent background tunnel (-N -f)"
	}
	return ""
}
