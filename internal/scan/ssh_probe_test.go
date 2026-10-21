package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// stubSudo answers `-l` from STUB_SUDO_ALLOW, checks a -S password against
// STUB_SUDO_PW, and otherwise execs the command — enough of sudo to drive
// probeCommand's branches through a real shell.
const stubSudo = `#!/bin/sh
list=0 pw=0
while [ $# -gt 0 ]; do
  case "$1" in
    -n) shift ;;
    -S) pw=1; shift ;;
    -p) shift 2 ;;
    -l) list=1; shift ;;
    *) break ;;
  esac
done
if [ $pw = 1 ]; then read -r got; [ "$got" = "$STUB_SUDO_PW" ] || exit 1; fi
if [ $list = 1 ]; then [ "$STUB_SUDO_ALLOW" = 1 ]; exit $?; fi
[ "$STUB_SUDO_ALLOW" = 1 ] || exit 1
echo sudo >> "$STUB_SUDO_LOG"
exec "$@"
`

type probeFixture struct {
	dir, probe, bundle, probeSum, bundleSum, log string
	env                                          []string
}

func newProbeFixture(t *testing.T) probeFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell")
	}
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("Linux flock required; run shell integration tests on Linux")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte(stubSudo), 0o755); err != nil {
		t.Fatal(err)
	}
	probeSrc := []byte("#!/bin/sh\necho \"ran=$0 args=$*\"\n")
	bundleSrc := []byte(`{"rules":[]}`)
	f := probeFixture{
		dir:    dir,
		probe:  filepath.Join(dir, "probe-abc"),
		bundle: filepath.Join(dir, "rules-1.json"),
		log:    filepath.Join(dir, "sudo.log"),
	}
	if err := os.WriteFile(f.probe, probeSrc, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.bundle, bundleSrc, 0o600); err != nil {
		t.Fatal(err)
	}
	ps, bs := sha256.Sum256(probeSrc), sha256.Sum256(bundleSrc)
	f.probeSum, f.bundleSum = hex.EncodeToString(ps[:]), hex.EncodeToString(bs[:])
	f.env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "STUB_SUDO_LOG="+f.log)
	return f
}

func (f probeFixture) run(t *testing.T, cmd string, env ...string) (string, error) {
	t.Helper()
	return f.runWithStdin(t, cmd, nil, env...)
}

func (f probeFixture) runWithStdin(t *testing.T, cmd string, stdin io.Reader, env ...string) (string, error) {
	t.Helper()
	cmd = strings.ReplaceAll(cmd, "/run/bladedr-probe", filepath.Join(f.dir, "root-lock"))
	cmd = strings.ReplaceAll(cmd, probeCacheDir+"/scan-lock", filepath.Join(f.dir, "user-lock"))
	sh := exec.Command("/bin/sh", "-c", cmd)
	sh.Env = append(append([]string{}, f.env...), env...)
	sh.Stdin = stdin
	out, err := sh.Output()
	return strings.TrimSpace(string(out)), err
}

func (f probeFixture) usedSudo() bool {
	_, err := os.Stat(f.log)
	return err == nil
}

func TestRemoteProbeLockSerializesAttempts(t *testing.T) {
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("requires Linux flock")
	}
	dir := t.TempDir()
	lock, gate, started, second := dir+"/lock", dir+"/gate", dir+"/started", dir+"/second"
	firstCmd := exec.Command("sh", "-c", lockedProbeScript(lock, "touch "+shellArg(started)+"; while [ ! -e "+shellArg(gate)+" ]; do sleep 0.02; done"))
	if err := firstCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer firstCmd.Process.Kill()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first probe not started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	secondCmd := exec.Command("sh", "-c", lockedProbeScript(lock, "touch "+shellArg(second)))
	if err := secondCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer secondCmd.Process.Kill()
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(second); !os.IsNotExist(err) {
		t.Fatal("second probe started while first holds lock")
	}
	if err := os.WriteFile(gate, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := firstCmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := secondCmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(second); err != nil {
		t.Fatal("second probe did not resume", err)
	}
	if _, err := os.Stat(lock + "/scan.lock"); err != nil {
		t.Fatal("lock inode removed", err)
	}
}

func TestRemoteProbeLockRejectsUnsafePaths(t *testing.T) {
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("requires Linux flock")
	}
	for _, kind := range []string{"directory symlink", "file symlink", "writable directory"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			lock := dir + "/lock"
			marker := dir + "/ran"
			if kind == "directory symlink" {
				if err := os.Symlink(dir, lock); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(lock, 0700); err != nil {
					t.Fatal(err)
				}
				if kind == "file symlink" {
					if err := os.Symlink(dir+"/target", lock+"/scan.lock"); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Chmod(lock, 0777); err != nil {
						t.Fatal(err)
					}
				}
			}
			cmd := exec.Command("sh", "-c", lockedProbeScript(lock, "touch "+shellArg(marker)))
			if err := cmd.Run(); err == nil {
				t.Fatal("unsafe lock accepted")
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("probe executed")
			}
		})
	}
}

func TestProbeCommandRootRunsDirectly(t *testing.T) {
	f := newProbeFixture(t)
	cmd, stdin := probeCommand("root", "", f.probe, f.probeSum, f.bundle, f.bundleSum, false)
	out, err := f.runWithStdin(t, cmd, stdin, "STUB_SUDO_ALLOW=1")
	if err != nil {
		t.Fatal(err)
	}
	if out != "ran="+f.probe+" args=--rules "+f.bundle || f.usedSudo() {
		t.Fatalf("root account should run the cached probe without sudo, got %q (sudo used: %v)", out, f.usedSudo())
	}
}

func TestProbeCommandEscalatesFromRootOwnedCopy(t *testing.T) {
	for name, tc := range map[string]struct{ pw, env string }{
		"passwordless": {"", ""},
		"password":     {"s3cr'et", "STUB_SUDO_PW=s3cr'et"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newProbeFixture(t)
			cmd, stdin := probeCommand("dev", tc.pw, f.probe, f.probeSum, f.bundle, f.bundleSum, true)
			out, err := f.runWithStdin(t, cmd, stdin, "STUB_SUDO_ALLOW=1", tc.env)
			if err != nil {
				t.Fatal(err)
			}
			if !f.usedSudo() {
				t.Fatalf("probe did not run under sudo: %q", out)
			}
			ran, args, _ := strings.Cut(strings.TrimPrefix(out, "ran="), " args=")
			if ran == f.probe || filepath.Base(ran) != "probe" {
				t.Fatalf("privileged run executed %q, want a copy outside the scan account's cache", ran)
			}
			if !strings.HasSuffix(args, "/rules.json --emit-snapshot") {
				t.Fatalf("copied bundle or flags not passed through: %q", args)
			}
			if _, err := os.Stat(filepath.Dir(ran)); !os.IsNotExist(err) {
				t.Fatalf("root-owned copy %s was left behind", filepath.Dir(ran))
			}
		})
	}
}

func TestProbeCommandFallsBackWithoutSudoRights(t *testing.T) {
	for name, env := range map[string][]string{
		"not in sudoers": {"STUB_SUDO_ALLOW=0"},
		"wrong password": {"STUB_SUDO_ALLOW=1", "STUB_SUDO_PW=other"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newProbeFixture(t)
			cmd, stdin := probeCommand("dev", "pw", f.probe, f.probeSum, f.bundle, f.bundleSum, false)
			out, err := f.runWithStdin(t, cmd, stdin, env...)
			if err != nil {
				t.Fatalf("an account without sudo must still get the unprivileged scan: %v", err)
			}
			if out != "ran="+f.probe+" args=--rules "+f.bundle || f.usedSudo() {
				t.Fatalf("expected the unprivileged probe, got %q (sudo used: %v)", out, f.usedSudo())
			}
		})
	}
}

// TestProbeCommandDoesNotLeakPasswordInCommandText is the regression test for the
// sudo-password-in-argv finding: sshd execs the remote shell with the command text
// as its argv, which any local account can read off that process in `ps` for as
// long as it runs. The password must only ever travel as real stdin bytes (which
// run() pipes through a dedicated channel, invisible to `ps`), never as a quoted
// literal inside the command string itself.
func TestProbeCommandDoesNotLeakPasswordInCommandText(t *testing.T) {
	const pw = "s3cr3t-sudo-password"
	cmd, stdin := probeCommand("dev", pw, "/probe", "digest", "/rules.json", "digest", false)
	if strings.Contains(cmd, pw) {
		t.Fatalf("password leaked into command text (visible to any local account via ps): %q", cmd)
	}
	if stdin == nil {
		t.Fatal("a password-escalation command must carry the password as stdin")
	}
	got, err := io.ReadAll(stdin)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != pw+"\n" {
		t.Fatalf("stdin = %q, want the password newline-terminated", got)
	}
}

func TestProbeCommandRefusesTamperedProbe(t *testing.T) {
	f := newProbeFixture(t)
	cmd, _ := probeCommand("dev", "", f.probe, f.probeSum, f.bundle, f.bundleSum, false)
	// The swap the copy-and-verify step exists for: the scan account rewrites the
	// cached binary after the server's digest check.
	if err := os.WriteFile(f.probe, []byte("#!/bin/sh\necho owned\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := f.run(t, cmd, "STUB_SUDO_ALLOW=1")
	if err == nil || strings.Contains(out, "owned") {
		t.Fatalf("a probe changed after upload ran as root: out=%q err=%v", out, err)
	}
}
