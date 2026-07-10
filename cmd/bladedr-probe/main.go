// Command bladedr-probe is the agentless, ephemeral collector. The server uploads
// it together with a rule bundle, runs it once, reads the JSON result from stdout,
// then removes it. It carries the CEL engine and evaluates detections on the host.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"bladedr/internal/probe"
	"bladedr/internal/rules"
)

// version is overridden at release build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		rulesPath    = flag.String("rules", "", "path to rule bundle JSON (required unless --version)")
		session      = flag.String("session", "", "scan session id (for logging)")
		emitSnapshot = flag.Bool("emit-snapshot", false, "include the raw snapshot in the result")
		snapshotFile = flag.String("snapshot-file", "", "evaluate this captured snapshot instead of collecting from /proc")
		showVersion  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}
	if *rulesPath == "" {
		fatal("missing --rules")
	}

	bundle, err := loadBundle(*rulesPath)
	if err != nil {
		fatal("load rules: " + err.Error())
	}
	eng, err := rules.NewEngineFromBundle(bundle)
	if err != nil {
		fatal("compile rules: " + err.Error())
	}

	snap, err := loadOrCollect(*snapshotFile)
	if err != nil {
		fatal("collect: " + err.Error())
	}

	findings, err := eng.Evaluate(snap)
	if err != nil {
		fatal("evaluate: " + err.Error())
	}

	result := probe.ScanResult{
		Schema:          probe.SchemaScanResult,
		ProbeVersion:    version,
		BundleVersion:   bundle.BundleVersion,
		CollectedAt:     snap.CollectedAt,
		Host:            snap.Host,
		Findings:        findings,
		CollectorErrors: snap.CollectorErrors,
	}
	if result.CollectedAt.IsZero() {
		result.CollectedAt = time.Now().UTC()
	}
	result.StateDigest = probe.BuildStateDigest(snap)
	if *emitSnapshot {
		result.Snapshot = snap
	}
	_ = *session

	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(result); err != nil {
		fatal("encode result: " + err.Error())
	}
}

func loadBundle(path string) (probe.RuleBundle, error) {
	var b probe.RuleBundle
	data, err := os.ReadFile(path)
	if err != nil {
		return b, err
	}
	if err := json.Unmarshal(data, &b); err != nil {
		return b, err
	}
	return b, nil
}

func loadOrCollect(snapshotFile string) (*probe.Snapshot, error) {
	if snapshotFile != "" {
		data, err := os.ReadFile(snapshotFile)
		if err != nil {
			return nil, err
		}
		var s probe.Snapshot
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, err
		}
		return &s, nil
	}
	return probe.Collect()
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "bladedr-probe: "+msg)
	os.Exit(1)
}
