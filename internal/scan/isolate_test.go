package scan

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"bladedr/internal/store"
)

// The playbook filters the same SSH connection that carries it, so the ruleset has to
// become active all at once. Executed against a stub nft rather than asserted on the
// command string: the previous version read correctly and stranded the host every time.
func TestIsolateLoadsItsRulesetInOneTransaction(t *testing.T) {
	r := &Runner{ServerURL: "http://192.168.50.10:8080"}
	cmd, err := r.responseCommand(&store.Host{SSHPort: 22},
		&store.ResponseAction{Playbook: PlaybookIsolateHost, Params: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	stub := "#!/bin/sh\nprintf 'CALL %s\\n' \"$*\" >> " + dir + "/log\n" +
		"if [ \"$1\" = \"-f\" ]; then cat >> " + dir + "/ruleset; fi\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	c := exec.Command("/bin/sh", "-c", wrapSudo("pw", cmd))
	sudo := "#!/bin/sh\n[ \"$1\" = \"-S\" ] && shift\ncat >/dev/null\nexec \"$@\"\n"
	os.WriteFile(filepath.Join(dir, "sudo"), []byte(sudo), 0o755)
	c.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("komenda padla: %v\n%s", err, out)
	}
	rs, _ := os.ReadFile(filepath.Join(dir, "ruleset"))
	// Both directions, statelessly. Conntrack does not know about a session that predates
	// the table, so relying on it alone drops the replies and strands the host.
	for _, need := range []string{
		"policy drop",
		"tcp dport 22 accept", "tcp sport 22 accept",
		"ct state established,related accept",
		"daddr 192.168.50.10 tcp dport 8080 accept",
		"saddr 192.168.50.10 tcp sport 8080 accept",
	} {
		if !strings.Contains(string(rs), need) {
			t.Errorf("brak w rulesecie: %q", need)
		}
	}
	// One -f call, not a rule at a time. Statement-by-statement is what cut the SSH
	// session carrying the commands: the drop policy landed first and the accept rules
	// never ran.
	log, _ := os.ReadFile(filepath.Join(dir, "log"))
	if n := strings.Count(string(log), "CALL -f"); n != 1 {
		t.Errorf("ruleset applied in %d transactions, want exactly 1:\n%s", n, log)
	}
	if strings.Contains(string(log), "CALL add chain") || strings.Contains(string(log), "CALL add rule") {
		t.Errorf("rules added one by one; the host loses its transport before they finish:\n%s", log)
	}
}
