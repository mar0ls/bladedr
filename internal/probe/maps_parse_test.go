package probe

import (
	"reflect"
	"strings"
	"testing"
)

func TestScanMaps(t *testing.T) {
	maps := strings.Join([]string{
		"55d0c8a00000-55d0c8a21000 r-xp 00000000 fd:01 1048601 /usr/bin/python3.12",
		"7f1a00000000-7f1a00021000 r-xp 00000000 fd:01 2000001 /tmp/.x/libhook.so",
		"7f1a00021000-7f1a00200000 r--p 00021000 fd:01 2000001 /tmp/.x/libhook.so",
		"7f1a10000000-7f1a10021000 r-xp 00000000 fd:01 2000002 /var/tmp/.cache/libcache.so",
		"7f1a20000000-7f1a20021000 r-xp 00000000 fd:01 2000003 /tmp/dir with space/lib b.so (deleted)",
		"7f1a30000000-7f1a30021000 r-xp 00000000 fd:01 3000001 /run/.x/libgone.so (deleted)",
		"7f1a40000000-7f1a40021000 r-xp 00000000 fd:01 3000002 /usr/lib/x86_64-linux-gnu/libc.so.6 (deleted)",
		"7f1a50000000-7f1a50021000 r-xp 00000000 fd:01 3000003 /lib/x86_64-linux-gnu/libz.so.1 (deleted)",
		"7f1a60000000-7f1a60021000 rw-s 00000000 fd:01 4000001 /tmp/hsperfdata_app/1234",
		"7f1a70000000-7f1a70021000 r--p 00000000 fd:01 4000002 /tmp/readonly-data.so",
		"7f1a80000000-7f1a80021000 r-xp 00000000 00:01 5000001 /memfd:doublemapper (deleted)",
		"7f1a90000000-7f1a90021000 rwxp 00000000 00:00 0",
		"7f1aa0000000-7f1aa0021000 r-xp 00000000 fd:01 6000001 /tmp/self-exe",
		"7f1ab0000000-7f1ab0021000 r-xp 00000000 fd:01 7000001 /opt/vendor/lib/libold.so (deleted)",
		"7ffd1a000000-7ffd1a021000 rw-p 00000000 00:00 0 [stack]",
	}, "\n")
	writable, deleted := scanMaps(strings.NewReader(maps), "/tmp/self-exe")
	wantW := []string{"/tmp/.x/libhook.so", "/var/tmp/.cache/libcache.so", "/tmp/dir with space/lib b.so"}
	wantD := []string{"/tmp/dir with space/lib b.so", "/run/.x/libgone.so"}
	if !reflect.DeepEqual(writable, wantW) {
		t.Errorf("writable = %q, want %q", writable, wantW)
	}
	if !reflect.DeepEqual(deleted, wantD) {
		t.Errorf("deleted = %q, want %q (package-upgrade and /opt deletions are routine)", deleted, wantD)
	}
}

func TestScanMapsBoundsEvidence(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 40; i++ {
		b.WriteString("7f1a00000000-7f1a00021000 r-xp 00000000 fd:01 2000001 /tmp/lib")
		b.WriteString(strings.Repeat("x", i))
		b.WriteString(".so\n")
	}
	if w, _ := scanMaps(strings.NewReader(b.String()), ""); len(w) != maxMappedLibs {
		t.Errorf("evidence not bounded: %d entries", len(w))
	}
}

func TestPreloadFromEnviron(t *testing.T) {
	cases := []struct{ env, want string }{
		{"PATH=/usr/bin\x00HOME=/root\x00", ""},
		{"LD_PRELOAD=/tmp/.x/evil.so\x00", "LD_PRELOAD=/tmp/.x/evil.so"},
		{"A=1\x00LD_PRELOAD=/home/dev/tools/libfaketime.so.1\x00", "LD_PRELOAD=/home/dev/tools/libfaketime.so.1"},
		{"LD_AUDIT=./audit.so\x00", "LD_AUDIT=./audit.so"},
		{"LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.2\x00", ""},
		{"LD_PRELOAD=libgtk3-nocsd.so.0\x00", ""},
		{"LD_PRELOAD=/usr/lib/libok.so:/tmp/evil.so\x00", "LD_PRELOAD=/usr/lib/libok.so:/tmp/evil.so"},
		{"LD_PRELOAD=/usr/lib/../../tmp/evil.so\x00", "LD_PRELOAD=/usr/lib/../../tmp/evil.so"},
		{"LD_PRELOAD=\x00", ""},
		{"NOT_LD_PRELOAD=/tmp/x.so\x00", ""},
	}
	for _, c := range cases {
		if got := preloadFromEnviron([]byte(c.env)); got != c.want {
			t.Errorf("preloadFromEnviron(%q) = %q, want %q", c.env, got, c.want)
		}
	}
}
