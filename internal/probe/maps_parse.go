package probe

import (
	"bufio"
	"io"
	"strings"
)

// maxMappedLibs bounds the evidence per process: a process that maps hundreds of
// libraries from /tmp (a build farm) needs a sample, not a list.
const maxMappedLibs = 8

// mapsScanLimit bounds the lines read from one /proc/PID/maps, so a JVM or database
// with tens of thousands of mappings cannot make a scan slow.
const mapsScanLimit = 50000

// writableLibRoots are the world-writable locations a shared library has no business
// being loaded from. Anyone who can write there can put the file there.
var writableLibRoots = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}

// systemLibRoots are where a deleted library is routine rather than suspicious: a package
// upgrade replaces libc under every running process, and those processes then map
// "/usr/lib/.../libc.so.6 (deleted)" until they restart.
var systemLibRoots = []string{"/usr/", "/lib", "/bin/", "/sbin/", "/opt/", "/snap/", "/var/lib/", "/nix/"}

// scanMaps reads /proc/PID/maps and returns two samples: executable file mappings under a
// world-writable directory, and executable mappings of files that have been deleted from
// outside the system library directories.
//
// Only executable mappings count. Programs mmap plenty of data from /tmp (the JVM's
// hsperfdata, shared-memory ring buffers), none of which is loaded code. The process's
// own executable is skipped — running from /tmp is exec-from-world-writable's finding,
// and reporting its mapping again would raise two alerts for one fact.
func scanMaps(r io.Reader, exe string) (writable, deleted []string) {
	seenW, seenD := map[string]bool{}, map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for lines := 0; sc.Scan() && lines < mapsScanLimit; lines++ {
		// address perms offset dev inode path — the path may contain spaces.
		f := strings.SplitN(sc.Text(), " ", 6)
		if len(f) < 6 || len(f[1]) < 3 || f[1][2] != 'x' || f[4] == "0" {
			continue
		}
		path := strings.TrimLeft(f[5], " ")
		if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "/memfd:") {
			continue // anonymous or memfd-backed: JIT and shader caches map those routinely
		}
		gone := strings.HasSuffix(path, " (deleted)")
		path = strings.TrimSuffix(path, " (deleted)")
		if path == exe {
			continue
		}
		// Not exclusive: a library loaded from /tmp and then deleted is both at once, and
		// each rule should be able to say so.
		if hasAnyPrefix(path, writableLibRoots) && !seenW[path] && len(writable) < maxMappedLibs {
			seenW[path] = true
			writable = append(writable, path)
		}
		if gone && !hasAnyPrefix(path, systemLibRoots) && !seenD[path] && len(deleted) < maxMappedLibs {
			seenD[path] = true
			deleted = append(deleted, path)
		}
	}
	return writable, deleted
}

// preloadFromEnviron returns "LD_PRELOAD=…" or "LD_AUDIT=…" from a /proc/PID/environ dump
// when it names a library outside the system library directories, and "" otherwise.
//
// Preloading is legitimate and common on the system side — jemalloc and tcmalloc in
// services, libgtk3-nocsd on Ubuntu desktops, libfaketime in test runs — and those sit
// under the library directories. A value pointing into /tmp, a home directory or a
// relative path is the shape of an injected library, so that is what is reported.
func preloadFromEnviron(environ []byte) string {
	for _, kv := range strings.Split(string(environ), "\x00") {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || (name != "LD_PRELOAD" && name != "LD_AUDIT") || strings.TrimSpace(value) == "" {
			continue
		}
		for _, lib := range strings.FieldsFunc(value, func(r rune) bool { return r == ':' || r == ' ' }) {
			if !isSystemLibrary(lib) {
				return name + "=" + value
			}
		}
	}
	return ""
}

// isSystemLibrary reports a library path under a distribution library directory. A bare
// soname ("libjemalloc.so.2") is resolved by the loader from those same directories.
func isSystemLibrary(lib string) bool {
	if !strings.Contains(lib, "/") {
		return true
	}
	return hasAnyPrefix(lib, []string{"/usr/lib", "/usr/local/lib", "/lib", "/opt/"}) && !strings.Contains(lib, "..")
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
