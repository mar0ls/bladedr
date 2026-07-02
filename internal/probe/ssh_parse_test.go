package probe

import "testing"

func TestSshTunnelKind(t *testing.T) {
	flag := map[string]bool{
		"ssh -D 1080 user@jump":                 true, // SOCKS pivot
		"ssh -fND 1080 user@jump":               true, // combined cluster
		"ssh -R 9090:localhost:80 user@server":  true, // remote forward
		"/usr/bin/ssh -fNR 9090:localhost:80 x": true, // abs path + cluster
		"ssh -fNL 8080:db:3306 user@jump":       true, // persistent local tunnel (N+f)
		"autossh -M 0 -fND 1080 user@jump":      true, // autossh
		// not flagged:
		"ssh -L 8080:db:3306 user@jump": false, // plain interactive local forward
		"ssh user@host":                 false, // normal session
		"sshd: user [priv]":             false, // server side
		"scp file user@host:/tmp":       false,
		"ssh -v user@host":              false,
	}
	for cmd, want := range flag {
		got := sshTunnelKind(cmd) != ""
		if got != want {
			t.Errorf("sshTunnelKind(%q) flagged=%v, want %v (=%q)", cmd, got, want, sshTunnelKind(cmd))
		}
	}
}
