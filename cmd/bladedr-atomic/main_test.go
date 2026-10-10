package main

import (
	"bladedr/internal/probe"
	"os"
	"path/filepath"
	"testing"
)

func TestUnreviewedSpecRejectedBeforeDocker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spec.yaml")
	if err := os.WriteFile(path, []byte("unreviewed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(path, "missing-probe", "image", "out"); err == nil {
		t.Fatal("unreviewed spec accepted")
	}
}
func TestExpectedFindingRequiresExactPath(t *testing.T) {
	fs := []probe.Finding{{RuleID: "suid-in-writable-path", Evidence: map[string]any{"path": "/tmp/evilBinary"}}}
	if !hasRulePath(fs, "suid-in-writable-path", "/tmp/evilBinary") || hasRulePath(fs, "suid-in-writable-path", "/tmp/other") || hasRulePath(fs, "other", "/tmp/evilBinary") {
		t.Fatal("incorrect expected match")
	}
}
