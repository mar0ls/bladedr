//go:build linux

package probe

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNeedsExecutionEvidence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		process Process
		want    bool
	}{
		{"temporary", Process{Exe: "/tmp/probe"}, true},
		{"deleted system binary", Process{Exe: "/usr/lib/systemd/systemd-logind", ExeDeleted: true}, true},
		{"installed system binary", Process{Exe: "/usr/lib/systemd/systemd-logind"}, false},
		{"anonymous memfd", Process{Exe: "/memfd:payload", ExeDeleted: true, ExeMemfd: true}, false},
		{"unreadable executable", Process{ExeDeleted: true}, false},
		{"library loaded from writable path", Process{Exe: "/opt/app/helper", MappedLibsWritable: []string{"/tmp/.x/lib.so"}}, true},
		{"library loaded from a deleted path", Process{Exe: "/opt/app/helper", MappedLibsDeleted: []string{"/run/.x/lib.so"}}, true},
		{"non-system LD_PRELOAD", Process{Exe: "/opt/app/helper", PreloadEnv: "LD_PRELOAD=/tmp/evil.so"}, true},
		{"none of the ambiguous conditions", Process{Exe: "/opt/app/helper"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsExecutionEvidence(tc.process); got != tc.want {
				t.Fatalf("needsExecutionEvidence = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestExecutionEvidenceDeletedRunningFile(t *testing.T) {
	// A live /proc/PID/exe remains readable after unlink. Replacing the pathname
	// must not make the collector hash the replacement instead of the running inode.
	data, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(t.TempDir(), "sleep")
	if err := os.WriteFile(exe, data, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	base := fmt.Sprintf("/proc/%d", cmd.Process.Pid)
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
	if err := os.WriteFile(exe, []byte("replacement binary"), 0700); err != nil {
		t.Fatal(err)
	}
	e := collectExecutionEvidence(base, exe)
	want := fmt.Sprintf("%x", sha256.Sum256(data))
	if !e.Stable || e.SHA256 != want || e.PPID != os.Getpid() {
		t.Fatalf("running inode evidence lost: %+v", e)
	}
}

func processFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	base := filepath.Join(root, "123")
	for _, dir := range []string{base, filepath.Join(root, "5"), filepath.Join(root, "fs/tmp/locked")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	f := append([]string{"S", "5", "5", "42"}, strings.Fields(strings.Repeat("0 ", 15))...)
	f = append(f, "123456")
	if err := os.WriteFile(base+"/stat", []byte("123 (probe (test)) "+strings.Join(f, " ")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+"/cgroup", []byte("0::/session-42.scope\n"), 0600); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(root, "fs/tmp/locked/probe")
	if err := os.WriteFile(exe, []byte("fixture executable"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{base + "/exe": exe, base + "/root": "/", root + "/5/exe": "/usr/bin/sh"} {
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	return base, exe
}

func TestExecutionEvidence(t *testing.T) {
	base, exe := processFixture(t)
	e := collectExecutionEvidence(base, exe)
	want := fmt.Sprintf("%x", sha256.Sum256([]byte("fixture executable")))
	if !e.Stable || e.SHA256 != want || e.PPID != 5 || e.SessionID != 42 || e.StartTicks != "123456" || e.ParentExe != "/usr/bin/sh" {
		t.Fatalf("bad evidence: %+v", e)
	}
	if len(e.Paths) == 0 || e.Paths[0].Mode != "0100700" {
		t.Fatalf("missing executable mode: %+v", e.Paths)
	}
	if len(e.Errors) != 0 || len(e.Paths) < 3 {
		t.Fatalf("incomplete path evidence: %+v", e)
	}
}

func TestExecutionEvidenceRejectsChangedExecutable(t *testing.T) {
	base, exe := processFixture(t)
	e := collectExecutionEvidence(base, exe+"-old")
	if e.Stable || e.SHA256 != "" || len(e.Errors) == 0 {
		t.Fatalf("changed executable accepted: %+v", e)
	}
}

func TestExecutionEvidenceMissingAndOversize(t *testing.T) {
	base, exe := processFixture(t)
	if err := os.Truncate(exe, maxProcessHashBytes+1); err != nil {
		t.Fatal(err)
	}
	e := collectExecutionEvidence(base, exe)
	if e.SHA256 != "" || !strings.Contains(strings.Join(e.Errors, ";"), "hash limit") {
		t.Fatalf("oversize hash: %+v", e)
	}
	if err := os.Remove(base + "/exe"); err != nil {
		t.Fatal(err)
	}
	e = collectExecutionEvidence(base, exe)
	if e.Stable || e.SHA256 != "" || len(e.Errors) == 0 {
		t.Fatalf("missing process treated as verified: %+v", e)
	}
}

func TestProcessIdentityRejectsMalformedStat(t *testing.T) {
	base := t.TempDir()
	for _, value := range []string{"", "1 bad", "1 (x) S 2", "1 (x) " + strings.Repeat("x ", 20)} {
		if err := os.WriteFile(base+"/stat", []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := processIdentity(base); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}
