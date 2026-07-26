package scan

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"bladedr/internal/probe"
	"golang.org/x/crypto/ssh"
)

// SSHTransport uploads the probe binary + rule bundle to a remote host over SSH,
// runs the probe once, captures its stdout, then removes everything. This is the
// agentless production path: nothing persistent is left on the host.
type SSHTransport struct {
	Addr string // host:port
	User string
	Auth []ssh.AuthMethod
	// ExpectedHostKey, if set, is the pinned host key (authorized_keys line). The
	// handshake fails on mismatch (MITM protection). If empty, the first observed
	// key is accepted (TOFU) and reported via OnLearnHostKey for pinning.
	ExpectedHostKey string
	OnLearnHostKey  func(key string)
	ProbeBinary     []byte // statically-linked probe for the target arch
	Timeout         time.Duration
}

func NewSSHTransport(host, ipPort string, user string, auth []ssh.AuthMethod, probeBin []byte) *SSHTransport {
	return &SSHTransport{
		Addr:        ipPort,
		User:        user,
		Auth:        auth,
		ProbeBinary: probeBin,
		Timeout:     30 * time.Second,
	}
}

// AuthFor builds SSH auth methods from a credential's type and decrypted secret.
func AuthFor(authType, secret string) ([]ssh.AuthMethod, error) {
	switch authType {
	case "ssh_key":
		signer, err := ssh.ParsePrivateKey([]byte(secret))
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	case "password":
		// Offer both the "password" method and "keyboard-interactive" (answering
		// every prompt with the password) — many PAM-backed sshd configs only
		// accept the latter, where a plain ssh.Password fails with "[none]".
		ki := ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			ans := make([]string, len(questions))
			for i := range ans {
				ans[i] = secret
			}
			return ans, nil
		})
		return []ssh.AuthMethod{ssh.Password(secret), ki}, nil
	default:
		return nil, fmt.Errorf("unsupported auth type %q over SSH", authType)
	}
}

// hostKeyCallback enforces pinning (when ExpectedHostKey is set) or trust-on-
// first-use (when empty), mirroring Sandfly's host-key verification.
func (t *SSHTransport) hostKeyCallback(_ string, _ net.Addr, key ssh.PublicKey) error {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	if t.ExpectedHostKey == "" {
		if t.OnLearnHostKey != nil {
			t.OnLearnHostKey(line)
		}
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(line), []byte(t.ExpectedHostKey)) == 1 {
		return nil
	}
	return fmt.Errorf("host key mismatch for %s (possible MITM); pinned=%q got=%q", t.Addr, t.ExpectedHostKey, line)
}

const probeCacheDir = "/tmp/.bladedr"

// cacheDirScript prepares the staging directory and refuses to continue unless it is
// mode 0700 and owned by the scan account. /tmp is world-writable and the probe path
// is content-addressed from a public artifact, so without this any local user can
// pre-create the directory, plant a binary at the predictable path and have the next
// scan execute it as the scan account — usually root.
//
// mkdir -p won't chmod a directory that already exists, so the mode gets its own
// check. ls -ld doesn't dereference, which is what catches a symlink parked at the
// cache path; -n prints uids numerically because the owner may not resolve to a name.
//
// The mode is matched as a prefix, not compared literally: ls appends '.' when the
// file carries an SELinux context and '+' when it carries an ACL, so `drwx------.` on
// anything RHEL-derived is the normal case, not an attack.
func cacheDirScript(dir string) string {
	d := shellArg(dir)
	return `set -u
d=` + d + `
mkdir -p -m 0700 "$d" 2>/dev/null || true
[ -e "$d" ] || { echo "staging dir $d could not be created" >&2; exit 1; }
set -- $(ls -ldn "$d")
case "$1" in
  drwx------|drwx------[.+]) ;;
  *) echo "staging dir $d has unsafe mode $1; refusing" >&2; exit 1 ;;
esac
[ "$3" = "$(id -u)" ] || { echo "staging dir $d is owned by uid $3, not $(id -u); refusing" >&2; exit 1; }`
}

// probeCached reports whether the cached probe is byte-identical to the binary we are
// about to run. The old size check was not enough: any same-length substitute passed
// it. An entry we can't verify — no sha256sum on the host, unreadable file — counts as
// a miss and gets re-uploaded, so an unusual host costs an upload instead of trust.
func (t *SSHTransport) probeCached(client *ssh.Client, path, digest string) bool {
	out, err := run(client, "sha256sum "+path+" 2>/dev/null", nil)
	if err != nil {
		return false
	}
	fields := strings.Fields(string(out))
	return len(fields) > 0 && fields[0] == digest
}

func (t *SSHTransport) RunProbe(ctx context.Context, bundle probe.RuleBundle, emitSnapshot bool) (probe.ScanResult, error) {
	var res probe.ScanResult

	cfg := &ssh.ClientConfig{
		User:            t.User,
		Auth:            t.Auth,
		HostKeyCallback: t.hostKeyCallback,
		Timeout:         t.Timeout,
	}
	d := net.Dialer{Timeout: t.Timeout}
	conn, err := d.DialContext(ctx, "tcp", t.Addr)
	if err != nil {
		return res, fmt.Errorf("dial %s: %w", t.Addr, err)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, t.Addr, cfg)
	if err != nil {
		return res, fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	// Honor context cancellation/timeout: closing the client aborts any in-flight
	// session, so a host that hangs after connect can't block the scan (or the
	// scheduler) past the scan deadline.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			client.Close()
		case <-stop:
		}
	}()

	// Probe caching: the probe binary is content-addressed (sha256) and kept at a
	// stable path, so repeated scheduled scans skip the multi-MB upload entirely.
	// The (small) rule bundle is uploaded per scan since it changes with the active
	// rule set.
	sum := sha256.Sum256(t.ProbeBinary)
	digest := hex.EncodeToString(sum[:])
	probePath := probeCacheDir + "/probe-" + digest[:12]
	bundlePath := probeCacheDir + "/rules-" + randHex(8) + ".json"
	defer func() { _, _ = run(client, "rm -f "+bundlePath, nil) }()

	if out, err := run(client, cacheDirScript(probeCacheDir), nil); err != nil {
		return res, fmt.Errorf("prepare probe cache: %w (%s)", err, bytes.TrimSpace(out))
	}
	if !t.probeCached(client, probePath, digest) {
		// Atomic install: write to a per-upload temp name, then rename over the
		// cached path. Concurrent scans of the same host therefore never execute a
		// half-written probe and never clobber each other's staging file.
		staging := probePath + ".tmp." + randHex(6)
		install := "cat > " + staging + " && chmod 0700 " + staging + " && mv -f " + staging + " " + probePath
		if _, err := run(client, install, bytes.NewReader(t.ProbeBinary)); err != nil {
			_, _ = run(client, "rm -f "+staging, nil)
			return res, fmt.Errorf("upload probe: %w", err)
		}
	}
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		return res, err
	}
	if _, err := run(client, "cat > "+bundlePath, bytes.NewReader(bundleJSON)); err != nil {
		return res, fmt.Errorf("upload bundle: %w", err)
	}

	cmd := probePath + " --rules " + bundlePath
	if emitSnapshot {
		cmd += " --emit-snapshot"
	}
	out, err := run(client, cmd, nil)
	if err != nil {
		return res, fmt.Errorf("run probe: %w", err)
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return res, fmt.Errorf("parse probe output: %w", err)
	}
	return res, nil
}

// run executes a single command in its own session, optionally piping stdin, and
// returns stdout. When stdin is provided it is copied through an explicit
// StdinPipe that is closed afterward, so the remote command sees EOF (important
// for streaming a multi-MB probe binary through `cat`). Stderr is folded into
// the returned error.
func run(client *ssh.Client, cmd string, stdin io.Reader) ([]byte, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	var out, errb bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &errb

	if stdin == nil {
		if err := sess.Run(cmd); err != nil {
			return out.Bytes(), fmt.Errorf("%w: %s", err, strings.TrimSpace(errb.String()))
		}
		return out.Bytes(), nil
	}

	wc, err := sess.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := sess.Start(cmd); err != nil {
		return nil, err
	}
	if _, err := io.Copy(wc, stdin); err != nil {
		wc.Close()
		return nil, err
	}
	wc.Close()
	if err := sess.Wait(); err != nil {
		return out.Bytes(), fmt.Errorf("%w: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ParsePrivateKey is a small helper for building a signer from PEM key bytes.
func ParsePrivateKey(pem []byte) (ssh.Signer, error) {
	return ssh.ParsePrivateKey(pem)
}

// dial opens an SSH client to the host, closing it when ctx is cancelled so a hung
// host can't block past the deadline.
func (t *SSHTransport) dial(ctx context.Context) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{User: t.User, Auth: t.Auth, HostKeyCallback: t.hostKeyCallback, Timeout: t.Timeout}
	d := net.Dialer{Timeout: t.Timeout}
	conn, err := d.DialContext(ctx, "tcp", t.Addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", t.Addr, err)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, t.Addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(c, chans, reqs)
	go func() { <-ctx.Done(); client.Close() }()
	return client, nil
}

// DeploySensor installs and starts the eBPF sensor on the host: it uploads the
// sensor binary + the policy bundle (gzip tar) + a deploy script, then runs the
// script as root (Tetragon + the sensor need root). sudoPW (the host's password,
// when password-auth) lets a non-root SSH user escalate via `sudo -S`; for a root
// or NOPASSWD user pass "". The privileged script runs under one sudo so its
// docker/tetragon/sensor steps don't each re-prompt.
func (t *SSHTransport) DeploySensor(ctx context.Context, sensorBin, policyTar []byte, serverURL, hostID, ingestToken, sudoPW string) error {
	client, err := t.dial(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	// Same ownership guarantee as the scan path: the staging directory holds the
	// sensor binary and the ingest credential before the privileged script consumes
	// them, so it must not be writable by another local account.
	if out, err := run(client, cacheDirScript(probeCacheDir), nil); err != nil {
		return fmt.Errorf("prepare staging dir: %w (%s)", err, bytes.TrimSpace(out))
	}
	if _, err := run(client, "cat > /tmp/.bladedr/sensor && chmod +x /tmp/.bladedr/sensor", bytes.NewReader(sensorBin)); err != nil {
		return fmt.Errorf("upload sensor: %w", err)
	}
	if _, err := run(client, "cat > /tmp/.bladedr/policies.tgz", bytes.NewReader(policyTar)); err != nil {
		return fmt.Errorf("upload policies: %w", err)
	}
	// Upload the credential over SSH stdin into a mode-0600 file. It must not be an
	// argument of the remote shell, where it would be observable through process
	// listings while deployment is in progress.
	if _, err := run(client, "umask 077; cat > /tmp/.bladedr/sensor-token", strings.NewReader(ingestToken)); err != nil {
		return fmt.Errorf("upload sensor credential: %w", err)
	}
	if _, err := run(client, "cat > /tmp/.bladedr/deploy.sh", strings.NewReader(sensorDeployScript)); err != nil {
		return fmt.Errorf("upload script: %w", err)
	}
	cmd := wrapSudo(sudoPW, "sh /tmp/.bladedr/deploy.sh "+shellArg(serverURL)+" "+shellArg(hostID))
	if out, err := run(client, cmd, nil); err != nil {
		return fmt.Errorf("deploy: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// StopSensor tears down the sensor + Tetragon on the host (systemd unit if present,
// else the nohup fallback).
func (t *SSHTransport) StopSensor(ctx context.Context, sudoPW string) error {
	client, err := t.dial(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	// Tear down the container first and unconditionally, so its removal never depends
	// on an earlier step (systemctl/pkill) succeeding; each step is isolated with
	// `|| true` because the host may hold a partial install. `docker stop` before
	// `rm -f` handles the `--restart` policy cleanly.
	stop := `docker stop bladedr-tetragon >/dev/null 2>&1 || true
docker rm -f bladedr-tetragon >/dev/null 2>&1 || true
if command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now bladedr-sensor >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/bladedr-sensor.service
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
pkill -f '[/]opt/bladedr/sensor' 2>/dev/null || true
pkill -f '[/]tmp/.bladedr/sensor' 2>/dev/null || true
echo "left=$(docker ps -q -f name=bladedr-tetragon | wc -l)"`
	cmd := wrapSudo(sudoPW, "sh -c "+shellArg(stop))
	out, err := run(client, cmd, nil)
	if err != nil {
		return fmt.Errorf("stop sensor: %w (%s)", err, bytes.TrimSpace(out))
	}
	if !bytes.Contains(out, []byte("left=0")) {
		return fmt.Errorf("sensor teardown incomplete: %s", bytes.TrimSpace(out))
	}
	return nil
}

// wrapSudo runs cmd as root: when a password is given it is piped to `sudo -S`;
// otherwise cmd runs as-is (the SSH user is root or has passwordless sudo inside).
func wrapSudo(pw, cmd string) string {
	if pw == "" {
		return cmd
	}
	return "printf '%s\\n' " + shellArg(pw) + " | sudo -S " + cmd
}

// shellArg single-quotes a string for safe use in a remote shell command.
func shellArg(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// sensorDeployScript runs on the host as root. Args: $1=control-plane URL, $2=host id.
// It installs the sensor + curated policy bundle into a persistent dir (/opt/bladedr,
// so it survives reboot), launches Tetragon as a restart-always container, and runs
// the sensor as a systemd unit (Restart=always, After=docker) — falling back to nohup
// where systemd is absent.
//
// The token is not an argument: it arrives over SSH stdin in a mode-0600 file, which
// the script reads and immediately unlinks, then writes into a mode-0600
// EnvironmentFile. Passing it in argv would expose it in `ps` on the target for the
// length of the deployment, and the unit file itself is world-readable.
const sensorDeployScript = `#!/bin/sh
set -u
SERVER="${1:?server url}"; HOSTID="${2:?host id}"
SRC=/tmp/.bladedr; B=/opt/bladedr
TOKEN=$(cat "$SRC/sensor-token") || { echo "sensor credential missing"; exit 1; }
rm -f "$SRC/sensor-token"
mkdir -p "$B/policies" "$B/off" "$B/export"
cp "$SRC/sensor" "$B/sensor"; chmod 0755 "$B/sensor"
rm -rf "$B/policies"/* "$B/off"/*
tar xzf "$SRC/policies.tgz" -C "$B/policies" 2>/dev/null || { echo "untar failed"; exit 1; }
cd "$B/policies" || exit 1
rm -f *.backup
for f in *.yml *.yaml; do
  [ -f "$f" ] || continue
  case "$f" in *cve-*|*dirtyfrag*|*iouring*|*userfaultfd*) mv "$f" "$B/off/"; continue;; esac
  for s in $(grep -E "^[[:space:]]*-?[[:space:]]*call:" "$f" | sed -E 's/.*call:[[:space:]]*"?([^"]+)"?.*/\1/'); do
    case "$s" in sys_*|__*) continue;; esac
    grep -qw "$s" /proc/kallsyms || { mv "$f" "$B/off/"; break; }
  done
done
docker rm -f bladedr-tetragon >/dev/null 2>&1
docker run -d --name bladedr-tetragon --restart unless-stopped --privileged --pid=host --cgroupns=host \
  -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf:ro -v /sys/fs/bpf:/sys/fs/bpf:rw \
  -v "$B/policies":/etc/tetragon/tetragon.tp.d:ro -v "$B/export":/var/log/tetragon:rw \
  quay.io/cilium/tetragon:v1.7.0 --export-filename /var/log/tetragon/tetragon.log \
  --tracing-policy-dir /etc/tetragon/tetragon.tp.d >/dev/null || { echo "tetragon start failed"; exit 1; }
printf 'BLADEDR_INGEST_TOKEN=%s\n' "$TOKEN" > "$B/sensor.env"; chmod 0600 "$B/sensor.env"
ARGS="--export-file $B/export/tetragon.log --policy-dir $B/policies --server $SERVER --host-id $HOSTID"
if command -v systemctl >/dev/null 2>&1; then
  cat > /etc/systemd/system/bladedr-sensor.service <<UNIT
[Unit]
Description=bladedr eBPF sensor (Tetragon -> control plane)
After=docker.service network-online.target
Wants=network-online.target
[Service]
EnvironmentFile=$B/sensor.env
ExecStart=$B/sensor $ARGS
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable bladedr-sensor >/dev/null 2>&1
  # restart (not enable --now, a no-op when already active) so a re-deploy picks up
  # the new binary/policies/unit even if the sensor is already running.
  systemctl restart bladedr-sensor >/dev/null 2>&1
  echo "sensor deployed (systemd): policies=$(ls "$B/policies"/*.y*ml 2>/dev/null | wc -l) skipped=$(ls "$B/off" 2>/dev/null | wc -l)"
else
  pkill -f '[/]opt/bladedr/sensor' 2>/dev/null; sleep 3
  BLADEDR_INGEST_TOKEN="$TOKEN" setsid nohup "$B/sensor" $ARGS >"$B/sensor.log" 2>&1 &
  echo "sensor deployed (nohup; no systemd): policies=$(ls "$B/policies"/*.y*ml 2>/dev/null | wc -l)"
fi
`
