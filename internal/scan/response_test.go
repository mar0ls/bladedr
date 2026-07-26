package scan

import (
	"strings"
	"testing"

	"bladedr/internal/store"
)

func TestValidateResponseRequestRejectsArbitraryOrUnsafeInput(t *testing.T) {
	cases := []struct {
		playbook string
		params   map[string]string
	}{
		{"shell", map[string]string{"command": "rm -rf /"}},
		{PlaybookKillProcess, map[string]string{"pid": "1", "expected_exe": "/bin/init"}},
		{PlaybookKillProcess, map[string]string{"pid": "42", "expected_exe": "relative"}},
		{PlaybookDisableSystemdUnit, map[string]string{"unit": "ssh.service; reboot"}},
		{PlaybookIsolateHost, map[string]string{"control_plane_ip": "control.example"}},
	}
	for _, tc := range cases {
		if err := ValidateResponseRequest(tc.playbook, tc.params); err == nil {
			t.Errorf("accepted unsafe %s params=%v", tc.playbook, tc.params)
		}
	}
}

func TestResponseCommandsAreAllowlistedAndDryRunDoesNotMutate(t *testing.T) {
	runner := &Runner{ServerURL: "https://192.0.2.10:8443"}
	host := &store.Host{SSHPort: 2222}
	action := &store.ResponseAction{Playbook: PlaybookIsolateHost, Params: map[string]string{}, DryRun: true}
	command, err := runner.responseCommand(host, action)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(command, "nft add") || !strings.Contains(command, "dry-run") {
		t.Fatalf("unsafe dry-run command: %s", command)
	}
	action.DryRun = false
	command, err = runner.responseCommand(host, action)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"bladedr_response", "tcp dport 2222", "192.0.2.10", "tcp dport 8443"} {
		if !strings.Contains(command, required) {
			t.Errorf("isolation command missing %q: %s", required, command)
		}
	}
}

// Anything ValidateResponseRequest accepts has to survive all the way to a command,
// because validation runs when the action is requested and the command is only built
// after a second admin approves it. A parameter set that splits the two means the
// operator finds out it was wrong at the point of no return.
func TestAcceptedIsolationParamsAlwaysProduceACommand(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]string
		want   string
	}{
		{"ip only, port from server URL", map[string]string{"control_plane_ip": "10.0.0.5"}, "10.0.0.5 tcp dport 8443"},
		{"ip and port", map[string]string{"control_plane_ip": "10.0.0.5", "control_plane_port": "9000"}, "10.0.0.5 tcp dport 9000"},
		{"port only, ip from server URL", map[string]string{"control_plane_port": "9000"}, "192.0.2.10 tcp dport 9000"},
		{"neither, both from server URL", map[string]string{}, "192.0.2.10 tcp dport 8443"},
	}
	runner := &Runner{ServerURL: "https://192.0.2.10:8443"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateResponseRequest(PlaybookIsolateHost, tc.params); err != nil {
				t.Fatalf("validation rejected %v: %v", tc.params, err)
			}
			command, err := runner.responseCommand(&store.Host{SSHPort: 22},
				&store.ResponseAction{Playbook: PlaybookIsolateHost, Params: tc.params})
			if err != nil {
				t.Fatalf("validation accepted %v but execution refused it: %v", tc.params, err)
			}
			if !strings.Contains(command, tc.want) {
				t.Errorf("command missing %q: %s", tc.want, command)
			}
		})
	}
}

// The default port depends on the scheme, and only applies when neither the request
// nor the URL names one.
func TestIsolationPortDefaultsToScheme(t *testing.T) {
	for url, want := range map[string]string{
		"https://192.0.2.10": "tcp dport 443",
		"http://192.0.2.10":  "tcp dport 80",
	} {
		runner := &Runner{ServerURL: url}
		command, err := runner.responseCommand(&store.Host{SSHPort: 22},
			&store.ResponseAction{Playbook: PlaybookIsolateHost, Params: map[string]string{}})
		if err != nil {
			t.Fatalf("%s: %v", url, err)
		}
		if !strings.Contains(command, want) {
			t.Errorf("%s: command missing %q: %s", url, want, command)
		}
	}
}

// A DNS name still has to be refused from either source: name resolution is the first
// thing to break once the drop policy is in place.
func TestIsolationRefusesDNSNames(t *testing.T) {
	runner := &Runner{ServerURL: "https://bladedr.example:8443"}
	if _, err := runner.responseCommand(&store.Host{SSHPort: 22},
		&store.ResponseAction{Playbook: PlaybookIsolateHost, Params: map[string]string{}}); err == nil {
		t.Error("accepted a DNS name from the server URL")
	}
	if err := ValidateResponseRequest(PlaybookIsolateHost,
		map[string]string{"control_plane_ip": "bladedr.example"}); err == nil {
		t.Error("accepted a DNS name as control_plane_ip")
	}
}
