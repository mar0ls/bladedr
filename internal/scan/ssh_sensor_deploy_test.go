package scan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVerifyDigestScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell guard")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("hello"))
	good := hex.EncodeToString(sum[:])
	run := func(digest string) (bool, string) {
		script := verifyDigestScript(shellArg(path), shellArg(digest), "test file")
		cmd := exec.Command("/bin/sh", "-c", script)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		return cmd.Run() == nil, stderr.String()
	}
	if ok, stderr := run(good); !ok {
		t.Fatalf("correct digest rejected: %s", stderr)
	}
	if ok, stderr := run(strings.Repeat("0", 64)); ok {
		t.Fatal("mismatched digest accepted")
	} else if !strings.Contains(stderr, "test file changed after upload") {
		t.Fatalf("stderr = %q", stderr)
	}
}

// emptyTarGz is a minimal valid gzipped tar with no entries: enough for
// sensorDeployScript's extraction and per-file loop, which skip cleanly over an
// empty policy directory.
func emptyTarGz(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type sensorDeployFixture struct {
	src, dest string
	env       []string
	dockerLog string
}

// newSensorDeployFixture stages a fake sensor binary, policy bundle and token the
// way DeploySensor's uploads would have left them, and stubs the external commands
// the privileged half of the script shells out to (docker, setsid) so the test
// never touches the real system. `command` is overridden as a shell function
// local to this script invocation so `command -v systemctl` always reports
// absent, deterministically taking the nohup fallback branch regardless of
// whether this machine (dev or CI) happens to have systemctl on PATH — the
// systemd branch writes to /etc/systemd/system, which a test must never do.
func newSensorDeployFixture(t *testing.T) sensorDeployFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell guard")
	}
	root := t.TempDir()
	src, dest := filepath.Join(root, "src"), filepath.Join(root, "dest")
	bin := filepath.Join(root, "bin")
	for _, dir := range []string{src, dest, bin} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dockerLog := filepath.Join(root, "docker.log")
	dockerStub := "#!/bin/sh\necho \"$*\" >> " + shellArg(dockerLog) + "\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(dockerStub), 0o755); err != nil {
		t.Fatal(err)
	}
	// macOS has no setsid; the stub just execs its argument directly, which is
	// enough since the caller already backgrounds the whole line with `&`.
	if err := os.WriteFile(filepath.Join(bin, "setsid"), []byte("#!/bin/sh\nexec \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "sensor-token"), []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	return sensorDeployFixture{
		src: src, dest: dest, dockerLog: dockerLog,
		env: append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH")),
	}
}

func (f sensorDeployFixture) run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	script := strings.NewReplacer(
		"SRC=/tmp/.bladedr", "SRC="+shellArg(f.src),
		"B=/opt/bladedr", "B="+shellArg(f.dest),
	).Replace(sensorDeployScript)
	// Force the nohup fallback: see newSensorDeployFixture's doc comment.
	script = "command() { return 1; }\n" + script
	cmd := exec.Command("/bin/sh", "-c", script, "deploy.sh")
	cmd.Args = append(cmd.Args, args...)
	cmd.Env = f.env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (f sensorDeployFixture) writeSensor(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(f.src, "sensor")
	if err := os.WriteFile(path, content, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func (f sensorDeployFixture) writePolicies(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(f.src, "policies.tgz")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestSensorDeployScriptAcceptsMatchingDigests(t *testing.T) {
	f := newSensorDeployFixture(t)
	sensorBin := []byte("#!/bin/sh\nexit 0\n")
	policies := emptyTarGz(t)
	f.writeSensor(t, sensorBin)
	f.writePolicies(t, policies)
	out, err := f.run(t, "http://server", "host-1", digestOf(sensorBin), digestOf(policies))
	if err != nil {
		t.Fatalf("deploy failed: %v (%s)", err, out)
	}
	if !strings.Contains(out, "sensor deployed") {
		t.Fatalf("missing deploy confirmation: %s", out)
	}
	info, err := os.Stat(filepath.Join(f.dest, "sensor"))
	if err != nil {
		t.Fatalf("sensor binary not installed: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("sensor binary mode = %v, want 0755", info.Mode().Perm())
	}
	dockerLog, _ := os.ReadFile(f.dockerLog)
	if !strings.Contains(string(dockerLog), "bladedr-tetragon") {
		t.Fatalf("docker was not invoked: %s", dockerLog)
	}
}

// TestSensorDeployScriptRejectsTamperedSensorBinary is the regression test for the
// deploy-time elevation-of-privilege finding: the sensor binary is uploaded to a
// directory the scan (non-root) account owns, then a later, separate privileged
// step copies and runs it as root. Without a digest check, anyone holding that
// account — but not root — could swap the file in the window between upload and
// this run and have their substitute executed as root. The digest here
// deliberately does not match what's on disk, simulating exactly that swap.
func TestSensorDeployScriptRejectsTamperedSensorBinary(t *testing.T) {
	f := newSensorDeployFixture(t)
	policies := emptyTarGz(t)
	f.writeSensor(t, []byte("swapped-after-upload"))
	f.writePolicies(t, policies)
	out, err := f.run(t, "http://server", "host-1", strings.Repeat("0", 64), digestOf(policies))
	if err == nil {
		t.Fatalf("tampered sensor binary was accepted: %s", out)
	}
	if !strings.Contains(out, "sensor binary changed after upload") {
		t.Fatalf("missing refusal message: %s", out)
	}
	if info, statErr := os.Stat(filepath.Join(f.dest, "sensor")); statErr == nil && info.Mode().Perm() == 0o755 {
		t.Fatal("tampered sensor binary was left world-executable at the install path")
	}
	if dockerLog, statErr := os.Stat(f.dockerLog); statErr == nil {
		t.Fatalf("docker (and therefore the tampered binary's path) must never be reached: log exists, size=%d", dockerLog.Size())
	}
}

func TestSensorDeployScriptRejectsTamperedPolicyBundle(t *testing.T) {
	f := newSensorDeployFixture(t)
	sensorBin := []byte("#!/bin/sh\nexit 0\n")
	f.writeSensor(t, sensorBin)
	f.writePolicies(t, []byte("swapped-after-upload"))
	out, err := f.run(t, "http://server", "host-1", digestOf(sensorBin), strings.Repeat("0", 64))
	if err == nil {
		t.Fatalf("tampered policy bundle was accepted: %s", out)
	}
	if !strings.Contains(out, "policy bundle changed after upload") {
		t.Fatalf("missing refusal message: %s", out)
	}
	if entries, _ := os.ReadDir(filepath.Join(f.dest, "policies")); len(entries) != 0 {
		t.Fatalf("tampered policy bundle must not be extracted: %v", entries)
	}
	if _, statErr := os.Stat(f.dockerLog); statErr == nil {
		t.Fatal("docker must never be reached when the policy bundle fails verification")
	}
}
