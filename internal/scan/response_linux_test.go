//go:build linux

package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bladedr/internal/store"
)

// TestKillProcessCommandToleratesDeletedBinary is the regression test for the
// PID-reuse guard refusing to kill exactly the process a deleted-running-binary
// finding flags: readlink -f on /proc/$pid/exe appends " (deleted)" once the
// backing file is gone, which an expected_exe copied from that finding's
// evidence.exe (stored by the probe without the suffix) never carries.
func TestKillProcessCommandToleratesDeletedBinary(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "payload")
	data, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, data, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	base := "/proc/" + itoa(cmd.Process.Pid)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if link, err := os.Readlink(base + "/exe"); err == nil && link == exe {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child executable was not observable")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.Remove(exe); err != nil {
		t.Fatal(err)
	}

	r := &Runner{}
	action := &store.ResponseAction{
		Playbook: PlaybookKillProcess,
		DryRun:   true, // the guard runs regardless; dry-run just skips the actual kill
		Params:   map[string]string{"pid": itoa(cmd.Process.Pid), "expected_exe": exe},
	}
	command, err := r.responseCommand(&store.Host{}, action)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
	if err != nil {
		t.Fatalf("guard refused a deleted binary matching its own (suffix-stripped) path: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "exe="+exe) {
		t.Errorf("output did not report the stripped path: %s", out)
	}
}
