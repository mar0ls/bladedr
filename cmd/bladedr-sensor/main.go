// Command bladedr-sensor is the eBPF tier: a thin wrapper around Tetragon. It loads
// the linux-probe-shield TracingPolicies into Tetragon, consumes Tetragon's JSON
// event stream, maps each policy hit to a bladedr observation (source=ebpf_sensor)
// and posts batches to the server — the runtime counterpart of the agentless probe.
//
//	bladedr-sensor --server http://control:8080 --host-id <id> --policy-dir ./linux-probe-shield
//
// By default it launches and supervises Tetragon (needs root + a BTF-capable
// kernel). With --export-file it instead follows an existing Tetragon JSON export
// (when Tetragon runs as its own service), and --dry-run prints observations
// instead of posting (for bring-up).
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"

	"bladedr/internal/sensor"
	"bladedr/internal/store"
)

// version is overridden at release build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		server      = flag.String("server", "http://localhost:8080", "bladedr control-plane base URL")
		hostID      = flag.String("host-id", "", "this host's bladedr id (required unless --dry-run)")
		policyDir   = flag.String("policy-dir", "linux-probe-shield", "Tetragon TracingPolicy bundle dir")
		tetragon    = flag.String("tetragon", "tetragon", "tetragon binary path")
		exportFile  = flag.String("export-file", "", "follow an existing Tetragon JSON export instead of launching tetragon")
		interval    = flag.Duration("interval", 5*time.Second, "how often to flush a batch of observations")
		token       = flag.String("token", "", "ingest bearer token (BLADEDR_INGEST_TOKEN on the server)")
		dryRun      = flag.Bool("dry-run", false, "print observations instead of posting")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *token == "" {
		*token = os.Getenv("BLADEDR_INGEST_TOKEN")
	}

	meta, err := sensor.LoadPolicyMeta(*policyDir)
	if err != nil {
		fatal("load policies: " + err.Error())
	}
	fmt.Fprintf(os.Stderr, "bladedr-sensor %s: loaded %d policies from %s\n", version, len(meta), *policyDir)
	if *hostID == "" && !*dryRun {
		fatal("missing --host-id")
	}

	src, cleanup, err := eventSource(*tetragon, *policyDir, *exportFile)
	if err != nil {
		fatal(err.Error())
	}
	defer cleanup()

	// Flush batches off a channel so reading the (blocking) event stream and posting
	// to the server don't stall each other.
	ch := make(chan *store.Observation, 4096)
	go flusher(ch, *server, *hostID, *token, *interval, *dryRun)
	if err := sensor.Stream(src, meta, *hostID, func(o *store.Observation) { ch <- o }); err != nil {
		fatal("stream: " + err.Error())
	}
}

// eventSource returns the Tetragon JSON stream: either a followed export file or
// the stdout of a supervised tetragon process.
func eventSource(tetragonBin, policyDir, exportFile string) (io.Reader, func(), error) {
	if exportFile != "" {
		// On boot (systemd) Tetragon may not have created its export yet; wait for it
		// rather than crashing (with Restart=always a crash would just busy-loop).
		var f *os.File
		for i := 0; i < 60; i++ {
			if ff, err := os.Open(exportFile); err == nil {
				f = ff
				break
			}
			time.Sleep(time.Second)
		}
		if f == nil {
			return nil, func() {}, fmt.Errorf("export file %s did not appear", exportFile)
		}
		return follow(f), func() { f.Close() }, nil
	}
	// tetragonBin + policyDir come from operator-set flags (not request/network data);
	// the sensor only launches a configured binary, so this is not user-injectable.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.Command(tetragonBin, "--tracing-policy-dir", policyDir, "--export-filename", "/dev/stdout")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, func() {}, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, func() {}, fmt.Errorf("start tetragon (%s): %w", tetragonBin, err)
	}
	fmt.Fprintf(os.Stderr, "bladedr-sensor: tetragon pid %d, policies from %s\n", cmd.Process.Pid, policyDir)
	return stdout, func() { cmd.Process.Kill(); cmd.Wait() }, nil
}

// follow turns a file into a tail -f style reader: read to EOF, then poll for more.
func follow(f *os.File) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		r := bufio.NewReader(f)
		for {
			n, err := io.Copy(pw, r)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			if n == 0 {
				time.Sleep(time.Second)
			}
		}
	}()
	return pr
}

func flusher(ch <-chan *store.Observation, server, hostID, token string, interval time.Duration, dryRun bool) {
	t := time.NewTicker(interval)
	defer t.Stop()
	buf := &eventBuffer{}
	send := func(batch []*store.Observation) error {
		if dryRun {
			for _, o := range batch {
				fmt.Printf("[%s] %s %s %v\n", o.Severity, o.RuleID, o.Evidence["binary"], o.Mitre)
			}
			return nil
		}
		if err := post(server, hostID, token, batch); err != nil {
			// Logged here (not in flush) so the backoff naturally throttles the noise:
			// while backing off, flush returns without calling send.
			fmt.Fprintf(os.Stderr, "bladedr-sensor: post failed, %d event(s) buffered: %v\n", len(buf.pending), err)
			return err
		}
		return nil
	}
	for {
		select {
		case o, ok := <-ch:
			if !ok {
				buf.flush(time.Now(), send)
				return
			}
			buf.add(o)
			if len(buf.pending) >= maxPostBatch {
				buf.flush(time.Now(), send)
			}
		case <-t.C:
			buf.flush(time.Now(), send)
			if buf.dropped > 0 {
				fmt.Fprintf(os.Stderr, "bladedr-sensor: buffer full, dropped %d oldest event(s)\n", buf.dropped)
				buf.dropped = 0
			}
		}
	}
}

func post(server, hostID, token string, batch []*store.Observation) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/api/v1/hosts/%s/events", server, hostID)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("server %s", resp.Status)
	}
	return nil
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "bladedr-sensor:", msg)
	os.Exit(1)
}
