package probe

import "testing"

func TestAptRepoInsecure(t *testing.T) {
	yes := []string{
		"deb [trusted=yes] http://evil.example/repo ./",
		"deb [arch=amd64 trusted=yes] https://x/y z main",
		"Trusted: yes",
		"  trusted: yes",
		"deb [allow-insecure=yes] http://x ./",
	}
	no := []string{
		"deb http://archive.ubuntu.com/ubuntu noble main",
		"deb [signed-by=/usr/share/keyrings/k.gpg] https://x y main",
		"# deb [trusted=yes] http://x ./",
		"URIs: https://download.docker.com/linux/ubuntu",
	}
	for _, l := range yes {
		if !aptRepoInsecure(l) {
			t.Errorf("expected insecure: %q", l)
		}
	}
	for _, l := range no {
		if aptRepoInsecure(l) {
			t.Errorf("expected secure: %q", l)
		}
	}
}

func TestYumGpgcheckOff(t *testing.T) {
	if !yumGpgcheckOff("gpgcheck=0") || !yumGpgcheckOff("gpgcheck = 0") {
		t.Error("should flag gpgcheck=0 (package signature verification off)")
	}
	// repo_gpgcheck=0 is metadata-only and the EPEL default — must NOT flag.
	for _, l := range []string{"gpgcheck=1", "#gpgcheck=0", "enabled=0", "gpgkey=file:///x", "repo_gpgcheck=0"} {
		if yumGpgcheckOff(l) {
			t.Errorf("should not flag: %q", l)
		}
	}
}
