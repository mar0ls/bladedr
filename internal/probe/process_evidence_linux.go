//go:build linux

package probe

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxProcessHashBytes = 64 << 20

func temporaryExecutable(exe string) bool {
	return strings.HasPrefix(exe, "/tmp/") || strings.HasPrefix(exe, "/var/tmp/") || strings.HasPrefix(exe, "/dev/shm/")
}

// needsExecutionEvidence covers every condition under which one of the rules sharing
// item.exe-keyed dedup can fire: a temporary or deleted own executable, a library
// loaded from a writable/deleted path, or an injected LD_PRELOAD/LD_AUDIT. Any one of
// these is also the ambiguous case — the same exe path reused by unrelated processes —
// so whichever rule fires gets the ppid/parent/cgroup/hash to tell them apart.
func needsExecutionEvidence(p Process) bool {
	return p.Exe != "" && (temporaryExecutable(p.Exe) || (p.ExeDeleted && !p.ExeMemfd) ||
		len(p.MappedLibsWritable) > 0 || len(p.MappedLibsDeleted) > 0 || p.PreloadEnv != "")
}

func processIdentity(base string) (ticks string, ppid, session int, err error) {
	b, err := os.ReadFile(base + "/stat")
	if err != nil {
		return "", 0, 0, err
	}
	// comm can contain spaces and parentheses; numeric fields follow the last ')'.
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return "", 0, 0, fmt.Errorf("missing comm delimiter")
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return "", 0, 0, fmt.Errorf("short process stat")
	}
	ppid, err = strconv.Atoi(f[1])
	if err != nil {
		return "", 0, 0, err
	}
	session, err = strconv.Atoi(f[3])
	if err != nil {
		return "", 0, 0, err
	}
	if _, err = strconv.ParseUint(f[19], 10, 64); err != nil {
		return "", 0, 0, err
	}
	return f[19], ppid, session, nil
}

func collectExecutionEvidence(base, exe string) *ProcessExecutionEvidence {
	e := &ProcessExecutionEvidence{CollectedAt: time.Now().UTC(), Errors: []string{}, Paths: []ProcessPathEvidence{}}
	fail := func(message string) { e.Errors = append(e.Errors, message) }
	ticks, parent, session, err := processIdentity(base)
	if err != nil {
		fail("process identity unavailable")
		return e
	}
	e.StartTicks, e.PPID, e.SessionID = ticks, parent, session
	parentBase := filepath.Join(filepath.Dir(base), strconv.Itoa(parent))
	if e.ParentExe, err = os.Readlink(parentBase + "/exe"); err != nil {
		fail("parent executable unavailable")
	}
	if cgroup, err := os.ReadFile(base + "/cgroup"); err == nil {
		e.Cgroup = string(cgroup)
	} else {
		fail("cgroup unavailable")
	}
	f, err := os.Open(base + "/exe")
	if err != nil {
		fail("executable unavailable")
		return e
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() {
		fail("executable is not a readable regular file")
		return e
	}
	addPath := func(path string, info os.FileInfo) {
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			e.Paths = append(e.Paths, ProcessPathEvidence{Path: path, UID: st.Uid, GID: st.Gid, Mode: fmt.Sprintf("%#o", st.Mode)})
		}
	}
	addPath("/proc/PID/exe", before)
	if before.Size() > maxProcessHashBytes {
		fail("executable exceeds 64 MiB hash limit")
	} else {
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(f, maxProcessHashBytes+1))
		if err != nil || n > maxProcessHashBytes {
			fail("executable hash incomplete")
		} else {
			e.SHA256 = fmt.Sprintf("%x", h.Sum(nil))
		}
	}
	// Resolve ancestor metadata in the target's mount namespace. Lstat preserves
	// symlinks as evidence; these samples do not assert effective ACL permissions.
	for path, depth := filepath.Dir(exe), 0; depth < 32; path, depth = filepath.Dir(path), depth+1 {
		info, err := os.Lstat(base + "/root" + path)
		if err != nil {
			fail("ancestor metadata unavailable: " + path)
		} else {
			addPath(path, info)
		}
		if path == "/" {
			break
		}
	}
	after, statErr := f.Stat()
	current, currentErr := os.Stat(base + "/exe")
	endTicks, endParent, _, identityErr := processIdentity(base)
	link, linkErr := os.Readlink(base + "/exe")
	e.Stable = statErr == nil && currentErr == nil && identityErr == nil && linkErr == nil &&
		ticks == endTicks && parent == endParent && strings.TrimSuffix(link, " (deleted)") == exe &&
		os.SameFile(before, current) && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
	if !e.Stable {
		e.SHA256 = ""
		fail("process or executable changed during collection")
	}
	return e
}
