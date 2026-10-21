package scan

import (
	"io"
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
	got, stdin := wrapSudo("", "whoami")
	if got != "whoami" {
		t.Fatalf("wrapSudo without password should pass the command through, got %q", got)
	}
	if stdin != nil {
		t.Fatal("no password means nothing to feed over stdin")
	}
}

// TestWrapSudoDoesNotLeakPasswordInCommandText is the regression test for the same
// finding fixed in probeCommand: sshd hands the returned command text to the remote
// shell as its argv, which any local account can read off that process in `ps` for
// as long as it runs. The password must travel only as real stdin, never as a
// literal (however carefully quoted) inside the command string.
func TestWrapSudoDoesNotLeakPasswordInCommandText(t *testing.T) {
	const pw = "p@ss'word"
	got, stdin := wrapSudo(pw, "id")
	if strings.Contains(got, pw) {
		t.Fatalf("password leaked into command text (visible to any local account via ps): %q", got)
	}
	if !strings.Contains(got, "sudo -S sh -c") {
		t.Fatalf("wrapSudo should run the command under sh -c: %q", got)
	}
	if stdin == nil {
		t.Fatal("a password-escalation command must carry the password as stdin")
	}
	fed, err := io.ReadAll(stdin)
	if err != nil {
		t.Fatal(err)
	}
	if string(fed) != pw+"\n" {
		t.Fatalf("stdin = %q, want the password newline-terminated", fed)
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
	wrapped, stdin := wrapSudo("secret", cmd)
	sh := exec.Command("/bin/sh", "-c", wrapped)
	sh.Stdin = stdin
	sh.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := sh.CombinedOutput()
	if err != nil {
		t.Fatalf("wrapped command failed: %v (%s)", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "saw pid=4242" {
		t.Errorf("compound command was split before sudo saw it: %q", got)
	}
}
