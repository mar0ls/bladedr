// Command bladedr-atomic captures two reviewed Atomic artifact tests in an isolated container.
// It never executes commands read from upstream YAML or targets a host over SSH.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"bladedr/internal/probe"
	"bladedr/internal/risk"
	"bladedr/internal/rules"
)

const specDigest = "292386dac7ae7745958e1c4997c0b54dae3041cc924c94d594d837712cbfecba"
const atomicCommit = "388942adbd9641f4dfdcf079d7efe9a75ec0ac43"

type capture struct {
	RuleID     string                 `json:"rule_id"`
	Category   string                 `json:"category"`
	Severity   string                 `json:"severity"`
	Source     string                 `json:"source"`
	Label      string                 `json:"label"`
	Evidence   map[string]any         `json:"evidence"`
	Provenance risk.DatasetProvenance `json:"provenance"`
}

func main() {
	spec := flag.String("spec", "", "pinned T1548.001 YAML (checksum verified, not executed)")
	binary := flag.String("probe", "", "Linux probe matching the image architecture")
	image := flag.String("image", "bladedr-poligon-atomic", "local disposable lab image")
	out := flag.String("out", "", "new output JSONL path; existing files are not overwritten")
	disposable := flag.Bool("disposable", false, "acknowledge creation and deletion of a network-isolated lab container")
	flag.Parse()
	if !*disposable {
		fmt.Fprintln(os.Stderr, "--disposable is required")
		os.Exit(1)
	}
	if err := run(*spec, *binary, *image, *out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func docker(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker %s: %w: %.1000s", args[0], err, b)
	}
	return b, nil
}

func digest(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(b)), nil
}

func run(spec, binary, image, out string) (runErr error) {
	hash, err := digest(spec)
	if err != nil {
		return err
	}
	if hash != specDigest {
		return fmt.Errorf("unreviewed Atomic YAML checksum")
	}
	probeHash, err := digest(binary)
	if err != nil {
		return err
	}
	if out == "" {
		return fmt.Errorf("output path required")
	}
	if _, err = os.Stat(out); !os.IsNotExist(err) {
		return fmt.Errorf("output must not exist")
	}
	rs, err := rules.Builtin()
	if err != nil {
		return err
	}
	bundle := probe.RuleBundle{Schema: probe.SchemaRuleBundle, BundleVersion: "atomic-pilot-v1"}
	meta := map[string]rules.Rule{}
	for _, r := range rs {
		if r.IsEnabled() {
			bundle.Rules = append(bundle.Rules, r.ToBundleRule())
			meta[r.ID] = r
		}
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp("", "bladedr-atomic-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	bundlePath := filepath.Join(tmp, "bundle.json")
	if err = os.WriteFile(bundlePath, data, 0600); err != nil {
		return err
	}
	name := fmt.Sprintf("bladedr-atomic-%d", time.Now().UnixNano())
	if _, err = docker("run", "-d", "--network", "none", "--pids-limit", "128", "--memory", "512m", "--cpus", "1", "--name", name, image); err != nil {
		return err
	}
	defer func() {
		if _, err := docker("rm", "-f", name); err != nil {
			runErr = fmt.Errorf("lab cleanup failed: %w (capture error: %v)", err, runErr)
		}
	}()
	for _, file := range []struct{ src, dst string }{{binary, "/lab/probe"}, {bundlePath, "/lab/bundle.json"}} {
		if _, err = docker("cp", file.src, name+":"+file.dst); err != nil {
			return err
		}
	}
	if _, err = docker("exec", name, "chmod", "700", "/lab/probe"); err != nil {
		return err
	}
	scan := func() ([]probe.Finding, error) {
		b, err := docker("exec", name, "/lab/probe", "--rules", "/lab/bundle.json")
		if err != nil {
			return nil, err
		}
		var res probe.ScanResult
		if err = json.Unmarshal(b, &res); err != nil {
			return nil, err
		}
		return res.Findings, nil
	}
	baseline, err := scan()
	if err != nil {
		return err
	}
	base := map[string]bool{}
	for _, f := range baseline {
		base[f.DedupKey] = true
	}
	var rows []capture
	for _, test := range []struct{ guid, rule, operation string }{
		{"759055b3-3885-4582-a8ec-c00c9d64dd79", "suid-in-writable-path", "chmod 4755"},
		{"1ac3272f-9bcf-443a-9888-4b1d3de785c1", "file-capability-in-writable", "setcap cap_setuid=ep"},
	} {
		for _, variant := range []string{"obvious", "stealthy"} {
			path := "/tmp/evilBinary"
			if variant == "stealthy" {
				path = "/var/tmp/fontcache-helper"
			}
			// Fixed paths and operations only; no upstream shell interpolation.
			if _, err = docker("exec", name, "sh", "-ec", "touch "+path+"; chmod 0755 "+path); err != nil {
				return err
			}
			control, err := scan()
			if err != nil {
				return err
			}
			if hasRulePath(control, test.rule, path) {
				return fmt.Errorf("benign control unexpectedly matched %s", test.rule)
			}
			if _, err = docker("exec", name, "sh", "-ec", test.operation+" "+path); err != nil {
				return err
			}
			findings, err := scan()
			if err != nil {
				return err
			}
			matched := false
			for _, f := range findings {
				if f.RuleID != test.rule || base[f.DedupKey] || !evidenceHasPath(f.Evidence, path) {
					continue
				}
				r := meta[f.RuleID]
				matched = true
				rows = append(rows, capture{r.ID, r.Category, r.Severity, "lab", "true_positive", f.Evidence, risk.DatasetProvenance{Dataset: "atomic-red-team", Version: atomicCommit, License: "MIT", SHA256: hash, RecordID: test.guid + ":" + variant, Group: "T1548.001", LabelBasis: "reviewed_probe_capture", ReviewedBy: "bladedr-atomic/v1 automated artifact checks", Mapping: "atomic-artifact-v1"}})
			}
			if !matched {
				return fmt.Errorf("expected %s missing for %s", test.rule, path)
			}
			if _, err = docker("exec", name, "rm", "--", path); err != nil {
				return err
			}
			cleaned, err := scan()
			if err != nil {
				return err
			}
			if hasRulePath(cleaned, test.rule, path) {
				return fmt.Errorf("cleanup finding remains")
			}
			fmt.Fprintf(os.Stderr, "PASS %s %s: control, expected finding, cleanup\n", test.guid, variant)
		}
	}
	f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(f)
	for _, row := range rows {
		if err = encoder.Encode(row); err != nil {
			f.Close()
			return err
		}
	}
	if err = f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "captured=%d probe_sha256=%s bundle_sha256=%x; independent groups=1; deployment unchanged\n", len(rows), probeHash, sha256.Sum256(data))
	return nil
}

func evidenceHasPath(e map[string]any, path string) bool {
	value, ok := e["path"].(string)
	return ok && strings.TrimSpace(value) == path
}

func hasRulePath(fs []probe.Finding, rule, path string) bool {
	for _, f := range fs {
		if f.RuleID == rule && evidenceHasPath(f.Evidence, path) {
			return true
		}
	}
	return false
}
