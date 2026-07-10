package scan

import (
	"os/exec"
	"strings"
	"testing"
)

// TestShellArgRoundTrip feeds hostile strings through shellArg into a real /bin/sh
// and checks they come back byte-for-byte. If the quoting let any metacharacter
// escape, the echoed value would differ (or the shell would error).
func TestShellArgRoundTrip(t *testing.T) {
	cases := []string{
		"simple",
		"with spaces",
		"single'quote",
		"a'b'c",
		`$(touch /tmp/pwned)`,
		"`id`",
		"a;b|c&d",
		"semi; rm -rf /",
		`double"quote`,
		"back\\slash",
		"new\nline",
		"tab\there",
		"* ? [glob]",
		"# comment",
		"",
	}
	for _, in := range cases {
		out, err := exec.Command("/bin/sh", "-c", "printf %s "+shellArg(in)).Output()
		if err != nil {
			t.Fatalf("shellArg(%q) produced an unrunnable command: %v", in, err)
		}
		if string(out) != in {
			t.Errorf("round-trip mismatch: shellArg(%q) -> %q", in, string(out))
		}
	}
}

func TestWrapSudoNoPassword(t *testing.T) {
	// Empty password: command runs as-is (root SSH user or NOPASSWD sudo).
	if got := wrapSudo("", "whoami"); got != "whoami" {
		t.Fatalf("wrapSudo without password should pass the command through, got %q", got)
	}
}

func TestWrapSudoPipesQuotedPassword(t *testing.T) {
	got := wrapSudo("p@ss'word", "id")
	if !strings.Contains(got, "sudo -S id") {
		t.Fatalf("wrapSudo should invoke sudo -S: %q", got)
	}
	if !strings.HasPrefix(got, "printf ") {
		t.Fatalf("wrapSudo should feed the password via printf: %q", got)
	}
	// The password contains a single quote; it must be shell-escaped, not left raw.
	if strings.Contains(got, "p@ss'word |") || strings.Contains(got, "'p@ss'word'") {
		t.Fatalf("password not safely quoted: %q", got)
	}
	if !strings.Contains(got, shellArg("p@ss'word")) {
		t.Fatalf("password should be passed through shellArg: %q", got)
	}
}
