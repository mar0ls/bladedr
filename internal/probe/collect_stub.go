//go:build !linux

package probe

import (
	"fmt"
	"runtime"
)

// Collect is unavailable on non-Linux platforms. bladedr targets Linux hosts;
// on other platforms the probe can still run in --snapshot-file mode (re-evaluating
// a previously captured snapshot), which does not call Collect.
func Collect() (*Snapshot, error) {
	return nil, fmt.Errorf("bladedr-probe collection is Linux-only (running on %s); use --snapshot-file to re-evaluate a captured snapshot", runtime.GOOS)
}
