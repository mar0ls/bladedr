package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"bladedr/internal/store"
	"github.com/google/uuid"
)

const (
	PlaybookKillProcess        = "kill_process"
	PlaybookDisableSystemdUnit = "disable_systemd_unit"
	PlaybookIsolateHost        = "isolate_host"
	PlaybookRestoreNetwork     = "restore_network"
)

var systemdUnitPattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,200}$`)

// ValidateResponseRequest rejects arbitrary commands and malformed parameters
// before an action can enter the approval queue.
func ValidateResponseRequest(playbook string, params map[string]string) error {
	switch playbook {
	case PlaybookKillProcess:
		pid, err := strconv.Atoi(params["pid"])
		if err != nil || pid <= 1 {
			return errors.New("kill_process requires numeric pid > 1")
		}
		if !strings.HasPrefix(params["expected_exe"], "/") {
			return errors.New("kill_process requires an absolute expected_exe to guard against PID reuse")
		}
	case PlaybookDisableSystemdUnit:
		if !systemdUnitPattern.MatchString(params["unit"]) {
			return errors.New("disable_systemd_unit requires a valid unit name")
		}
	case PlaybookIsolateHost:
		if value := params["control_plane_ip"]; value != "" && net.ParseIP(value) == nil {
			return errors.New("control_plane_ip must be a literal IPv4 or IPv6 address")
		}
		if value := params["control_plane_port"]; value != "" {
			port, err := strconv.Atoi(value)
			if err != nil || port < 1 || port > 65535 {
				return errors.New("control_plane_port must be between 1 and 65535")
			}
		}
	case PlaybookRestoreNetwork:
	default:
		return fmt.Errorf("unsupported response playbook %q", playbook)
	}
	return nil
}

// ExecuteResponse runs one allowlisted response action through the host's existing
// pinned SSH transport. Output is capped before it is persisted.
func (r *Runner) ExecuteResponse(ctx context.Context, action *store.ResponseAction) (string, error) {
	host, err := r.Store.GetHost(ctx, action.HostID)
	if err != nil {
		return "", err
	}
	if r.NewSensorTransport == nil {
		return "", errors.New("response transport unavailable")
	}
	transport, sudoPassword, err := r.NewSensorTransport(host)
	if err != nil {
		return "", err
	}
	command, err := r.responseCommand(host, action)
	if err != nil {
		return "", err
	}
	client, err := transport.dial(ctx)
	if err != nil {
		return "", err
	}
	defer client.Close()
	output, err := run(client, wrapSudo(sudoPassword, command), nil)
	if len(output) > 64<<10 {
		output = append(output[:64<<10], []byte("\n[output truncated]")...)
	}
	if err != nil {
		return string(output), fmt.Errorf("response %s: %w", action.Playbook, err)
	}
	return string(output), nil
}

func (r *Runner) responseCommand(host *store.Host, action *store.ResponseAction) (string, error) {
	if err := ValidateResponseRequest(action.Playbook, action.Params); err != nil {
		return "", err
	}
	switch action.Playbook {
	case PlaybookKillProcess:
		pid := action.Params["pid"]
		expected := shellArg(action.Params["expected_exe"])
		inspect := `pid=` + pid + `; if [ ! -e "/proc/$pid" ]; then echo "process $pid already absent"; exit 0; fi; ` +
			`actual=$(readlink -f "/proc/$pid/exe") || exit 1; printf 'pid=%s exe=%s\n' "$pid" "$actual"; ` +
			`[ "$actual" = ` + expected + ` ] || { echo "executable mismatch; refusing" >&2; exit 1; }`
		if action.DryRun {
			return inspect + `; echo 'dry-run: would send SIGTERM'`, nil
		}
		return inspect + `; kill -TERM "$pid"; echo 'SIGTERM sent'`, nil
	case PlaybookDisableSystemdUnit:
		unit := shellArg(action.Params["unit"])
		if action.DryRun {
			return `systemctl show --no-pager --property=Id,LoadState,ActiveState,UnitFileState ` + unit, nil
		}
		return `systemctl disable --now ` + unit + ` && systemctl show --no-pager --property=Id,ActiveState,UnitFileState ` + unit, nil
	case PlaybookIsolateHost:
		ip, port, err := r.controlPlaneEndpoint(action.Params)
		if err != nil {
			return "", err
		}
		sshPort := host.SSHPort
		if sshPort <= 0 {
			sshPort = 22
		}
		family := "ip"
		if strings.Contains(ip, ":") {
			family = "ip6"
		}
		if action.DryRun {
			return fmt.Sprintf("printf 'dry-run: would isolate host; allow SSH tcp/%d and control plane %s:%d\\n'; nft list table inet bladedr_response 2>/dev/null || true", sshPort, ip, port), nil
		}
		// One transaction, via `nft -f`. Built statement by statement, the drop policy
		// lands before the accept rules and the very SSH session carrying these commands
		// is cut mid-script: the shell dies, the remaining rules never run, and the host
		// is left filtering everything with nothing allowed. That is not a race, it is
		// what happens every time the transport being filtered is the transport running
		// the commands. Loading the whole ruleset at once makes the policy and its
		// exceptions take effect together, so an established connection is never dropped.
		// Stateless port rules in both directions, not just conntrack. A connection that
		// existed before this table did is not in the conntrack table — verified on a
		// Rocky host, zero entries for the live SSH session — so "ct state established"
		// matches nothing for it. Inbound packets passed on dport, the replies had no
		// matching rule, and the session hung on the output policy. Which is to say the
		// firewall cut the transport it was being installed over, atomically or not.
		ruleset := fmt.Sprintf(`table inet bladedr_response {
  chain input {
    type filter hook input priority -200; policy drop;
    iif lo accept
    ct state established,related accept
    tcp dport %[1]d accept
    %[2]s saddr %[3]s tcp sport %[4]d accept
  }
  chain output {
    type filter hook output priority -200; policy drop;
    oif lo accept
    ct state established,related accept
    tcp sport %[1]d accept
    %[2]s daddr %[3]s tcp dport %[4]d accept
  }
}`, sshPort, family, ip, port)
		commands := []string{
			"command -v nft >/dev/null || { echo 'nft is required' >&2; exit 1; }",
			// Removing the old table only ever loosens filtering, so it cannot strand
			// the host even though it is a separate transaction from the load below.
			"nft delete table inet bladedr_response 2>/dev/null || true",
			// Piped rather than a heredoc: these statements get joined with ";" and the
			// whole thing is re-quoted for sudo, and a heredoc terminator stops working
			// the moment anything follows it on its line.
			"printf '%s\\n' " + shellArg(ruleset) + " | nft -f -",
			"nft list table inet bladedr_response",
		}
		return strings.Join(commands, "; "), nil
	case PlaybookRestoreNetwork:
		if action.DryRun {
			return `nft list table inet bladedr_response 2>/dev/null || echo 'network isolation is not active'; echo 'dry-run: would remove only the bladedr_response table'`, nil
		}
		return `nft delete table inet bladedr_response 2>/dev/null || true; echo 'bladedr network isolation removed'`, nil
	default:
		return "", fmt.Errorf("unsupported response playbook %q", action.Playbook)
	}
}

// controlPlaneEndpoint resolves the one address the isolated host is still allowed to
// reach. IP and port are filled in independently: giving just control_plane_ip is the
// common case (the operator knows the address, the port is whatever the server already
// listens on), and it used to pass validation and then fail here, after a second admin
// had already approved the action.
func (r *Runner) controlPlaneEndpoint(params map[string]string) (string, int, error) {
	u, parseErr := url.Parse(r.ServerURL)
	if parseErr != nil {
		u = &url.URL{}
	}

	ip := params["control_plane_ip"]
	if ip == "" {
		ip = u.Hostname()
	}
	if net.ParseIP(ip) == nil {
		// A DNS name is worthless here: resolution is the first thing to break under
		// a default-drop policy, so the host would lose the control plane too.
		return "", 0, errors.New("isolate_host requires a literal control_plane_ip; DNS names are unsafe after network containment")
	}

	port, _ := strconv.Atoi(params["control_plane_port"])
	if port == 0 {
		port, _ = strconv.Atoi(u.Port())
	}
	if port == 0 {
		port = 80
		if u.Scheme == "https" {
			port = 443
		}
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("control-plane port %d is out of range", port)
	}
	return ip, port, nil
}

type ResponseQueue struct {
	Store        store.Store
	Runner       *Runner
	PollInterval time.Duration
	Lease        time.Duration
	Timeout      time.Duration
	WorkerID     string
}

func (q *ResponseQueue) defaults() {
	if q.PollInterval <= 0 {
		q.PollInterval = time.Second
	}
	if q.Lease <= 0 {
		q.Lease = 3 * time.Minute
	}
	if q.Timeout <= 0 {
		q.Timeout = 2 * time.Minute
	}
	if q.WorkerID == "" {
		q.WorkerID = uuid.NewString()
	}
}

func (q *ResponseQueue) Run(ctx context.Context) {
	q.defaults()
	ticker := time.NewTicker(q.PollInterval)
	defer ticker.Stop()
	for {
		worked, _ := q.RunOne(ctx)
		if worked {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (q *ResponseQueue) RunOne(ctx context.Context) (bool, error) {
	q.defaults()
	workerID := q.WorkerID
	action, err := q.Store.ClaimResponseAction(ctx, workerID, time.Now().UTC(), q.Lease)
	if err != nil {
		var missing store.ErrNotFound
		if errors.As(err, &missing) {
			return false, nil
		}
		return false, err
	}
	actionCtx, cancel := context.WithTimeout(ctx, q.Timeout)
	output, runErr := q.Runner.ExecuteResponse(actionCtx, action)
	cancel()
	if runErr != nil {
		if output != "" {
			runErr = fmt.Errorf("%w; output: %s", runErr, output)
		}
		return true, q.Store.FailResponseAction(ctx, action.ID, workerID, runErr.Error())
	}
	return true, q.Store.CompleteResponseAction(ctx, action.ID, workerID, output)
}
