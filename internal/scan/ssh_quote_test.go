package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	if !strings.Contains(got, "sudo -S sh -c") {
		t.Fatalf("wrapSudo should run the command under sh -c: %q", got)
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

// The string-shape assertions above would have passed throughout the period when
// wrapSudo was broken: they check what the command looks like, never what a shell does
// with it. Run the wrapped command through /bin/sh with a stub sudo and assert the whole
// compound statement reaches it — a variable set in the first fragment has to survive to
// the last, which is exactly what failed on a real password-sudo host.
func TestWrapSudoKeepsCompoundCommandsIntact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell")
	}
	dir := t.TempDir()
	// Stub sudo: drop the -S flag and exec the rest, so "sudo -S sh -c '…'" behaves like
	// a real sudo would without needing one.
	if err := os.WriteFile(filepath.Join(dir, "sudo"),
		[]byte("#!/bin/sh\n[ \"$1\" = \"-S\" ] && shift\ncat >/dev/null\nexec \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// The shape kill_process builds: an assignment, then statements that depend on it.
	cmd := `pid=4242; printf 'saw pid=%s\n' "$pid"; [ -n "$pid" ] || exit 1`
	sh := exec.Command("/bin/sh", "-c", wrapSudo("secret", cmd))
	sh.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := sh.CombinedOutput()
	if err != nil {
		t.Fatalf("wrapped command failed: %v (%s)", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "saw pid=4242" {
		t.Errorf("compound command was split before sudo saw it: %q", got)
	}
}
