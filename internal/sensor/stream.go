package sensor

import (
	"bufio"
	"io"

	"bladedr/internal/store"
)

// Stream reads Tetragon JSON export lines from r and invokes fn with each mapped
// observation (policy-matched events only). It returns when r is exhausted or
// errors; for a live Tetragon stream r blocks, so Stream runs until the process or
// pipe closes.
func Stream(r io.Reader, meta map[string]PolicyMeta, hostID string, fn func(*store.Observation)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20) // Tetragon lines can be large
	for sc.Scan() {
		if ev, ok := ParseEvent(sc.Bytes()); ok {
			fn(EventToObservation(ev, meta, hostID))
		}
	}
	return sc.Err()
}
