package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// runCacheScript executes the guard the way the remote host does — through /bin/sh
// — and reports the exit status plus stderr. The guard is shell, so asserting on a
// Go-side reimplementation would prove nothing about what actually runs on target.
func runCacheScript(t *testing.T, dir string, env ...string) (bool, string) {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", cacheDirScript(dir))
	cmd.Env = append(os.Environ(), env...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	return err == nil, stderr.String()
}

// stubLS puts an `ls` on PATH that reports the given mode string for any argument, so
// the guard can be tested against output this machine cannot actually produce. The
// script calls `ls` unqualified, which is what makes the interposition work.
func stubLS(t *testing.T, mode string) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s 2 %s %s 4096 Jan 1 00:00 stub\\n' " + mode + " \"$(id -u)\" \"$(id -g)\"\n"
	if err := os.WriteFile(filepath.Join(dir, "ls"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return "PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH")
}

func TestCacheDirScriptCreatesPrivateDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell guard")
	}
	dir := filepath.Join(t.TempDir(), "cache")
	ok, stderr := runCacheScript(t, dir)
	if !ok {
		t.Fatalf("guard rejected a directory it created itself: %s", stderr)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("cache dir mode = %04o, want 0700", perm)
	}
}

func TestCacheDirScriptAcceptsExistingPrivateDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell guard")
	}
	dir := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if ok, stderr := runCacheScript(t, dir); !ok {
		t.Fatalf("guard rejected an existing 0700 dir: %s", stderr)
	}
}

// A directory another local account can write to is the precondition for planting a
// same-named probe binary at the predictable cache path. mkdir -p leaves the mode of
// an existing directory untouched, so the guard — not mkdir — has to catch this.
func TestCacheDirScriptRejectsWorldWritableDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell guard")
	}
	for _, mode := range []os.FileMode{0o777, 0o770, 0o755, 0o707} {
		dir := filepath.Join(t.TempDir(), "cache")
		if err := os.Mkdir(dir, mode); err != nil {
			t.Fatal(err)
		}
		// os.Mkdir applies umask; force the mode we are actually testing.
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		ok, stderr := runCacheScript(t, dir)
		if ok {
			t.Fatalf("guard accepted a dir with mode %04o", mode.Perm())
		}
		if !strings.Contains(stderr, "unsafe mode") {
			t.Fatalf("mode %04o: stderr = %q, want an unsafe-mode diagnostic", mode.Perm(), stderr)
		}
	}
}

// `ls -ld` does not dereference, so a symlink parked at the cache path is reported
// as a symlink and rejected. Without this, mkdir -p and `[ -d ]` both follow the
// link and the scan would stage its binaries wherever the link points.
func TestCacheDirScriptRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell guard")
	}
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "cache")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	ok, stderr := runCacheScript(t, link)
	if ok {
		t.Fatal("guard accepted a symlinked cache path")
	}
	if !strings.Contains(stderr, "unsafe mode") {
		t.Fatalf("stderr = %q, want an unsafe-mode diagnostic", stderr)
	}
}

// ls appends '.' for an SELinux context and '+' for an ACL, so a correctly-permissioned
// directory reads as `drwx------.` on every RHEL-derived distro. A literal comparison
// against "drwx------" fails closed there and no scan runs at all. macOS cannot produce
// either suffix, hence the stubbed ls.
func TestCacheDirScriptAcceptsSELinuxAndACLSuffixes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell guard")
	}
	for _, mode := range []string{"drwx------", "drwx------.", "drwx------+"} {
		dir := filepath.Join(t.TempDir(), "cache")
		ok, stderr := runCacheScript(t, dir, stubLS(t, mode))
		if !ok {
			t.Errorf("guard rejected mode %q: %s", mode, stderr)
		}
	}
}

// The suffix must not become a way to smuggle a permissive mode past the check.
// drwxr-----+ is the shape GNU ls actually produces for an access ACL that grants a
// named user read: the ACL mask is printed in the group field, so the mode itself is no
// longer private and must be refused on that basis, suffix notwithstanding.
func TestCacheDirScriptRejectsSuffixedPermissiveModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell guard")
	}
	for _, mode := range []string{"drwxr-xr-x.", "drwxrwxrwx+", "drwx-----x.", "drwxr-----+", "lrwxrwxrwx"} {
		dir := filepath.Join(t.TempDir(), "cache")
		ok, stderr := runCacheScript(t, dir, stubLS(t, mode))
		if ok {
			t.Errorf("guard accepted mode %q", mode)
		} else if !strings.Contains(stderr, "unsafe mode") {
			t.Errorf("mode %q: stderr = %q, want an unsafe-mode diagnostic", mode, stderr)
		}
	}
}

// The cache path is interpolated into a shell command, so a directory name carrying
// shell metacharacters must not escape its quoting.
func TestCacheDirScriptQuotesDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell guard")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "a b';touch pwned;'")
	if ok, stderr := runCacheScript(t, dir); !ok {
		t.Fatalf("guard rejected a quoted path: %s", stderr)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("literal directory was not created: %v", err)
	}
	if _, err := os.Stat("pwned"); err == nil {
		t.Fatal("injected command executed")
	}
}
