//go:build linux

package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// All enrichment is read-only and bounded. bpftool is optional; no install,
// pinning or attachment is performed. Absence of a holder is not attribution.
func enrichBpfPrograms(programs []BpfProg, collectorErrors *[]string) {
	if len(programs) == 0 {
		return
	}
	byID := map[uint32]*BpfProg{}
	for i := range programs {
		byID[programs[i].ID] = &programs[i]
	}
	entries, err := os.ReadDir("/proc")
	// errs are failures of the scan itself (cannot list /proc, permission denied, limits hit)
	// and make it partial. notes are about optional enrichment (bpftool) and are attached to
	// each program's evidence only: a host without bpftool is not a host that was scanned badly.
	var errs, notes []string
	if err != nil {
		errs = append(errs, "proc inventory unavailable")
	}
	deadline := time.Now().Add(3 * time.Second)
	files := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if time.Now().After(deadline) || files >= 20000 {
			errs = append(errs, "holder collection limit reached")
			break
		}
		root := filepath.Join("/proc", entry.Name())
		fds, err := os.ReadDir(filepath.Join(root, "fdinfo"))
		if err != nil {
			if os.IsPermission(err) {
				errs = appendOnce(errs, "holder fdinfo permission denied")
			}
			continue
		}
		for _, fd := range fds {
			files++
			if files > 20000 {
				break
			}
			data, err := os.ReadFile(filepath.Join(root, "fdinfo", fd.Name()))
			if err != nil {
				// An fd closed or a process exited between the directory read and this
				// read. On a live host that is routine and says nothing about the
				// evidence we did collect; flagging it made nearly every scan partial.
				if !os.IsNotExist(err) {
					errs = appendOnce(errs, "holder fdinfo unreadable")
				}
				continue
			}
			id := bpfFDProgramID(string(data))
			p := byID[id]
			if p == nil {
				continue
			}
			// The probe's transient enumeration descriptors have already been closed.
			exe, e := os.Readlink(filepath.Join(root, "exe"))
			if e != nil {
				p.EvidenceErrors = appendOnce(p.EvidenceErrors, "holder executable unavailable")
			}
			cg, e := os.ReadFile(filepath.Join(root, "cgroup"))
			if e != nil {
				p.EvidenceErrors = appendOnce(p.EvidenceErrors, "holder cgroup unavailable")
			}
			found := false
			for _, h := range p.Holders {
				if h.PID == pid {
					found = true
				}
			}
			if !found && len(p.Holders) < 128 {
				p.Holders = append(p.Holders, BpfHolder{PID: pid, Exe: exe, Cgroup: strings.TrimSpace(string(cg))})
			}
		}
	}
	var sources []json.RawMessage
	tool, err := exec.LookPath("bpftool")
	if err != nil {
		notes = append(notes, "bpftool unavailable: attachments not collected")
	} else {
		for _, args := range [][]string{{"-j", "link", "show"}, {"-j", "cgroup", "tree"}} {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			var output bpfBoundedOutput
			command := exec.CommandContext(ctx, tool, args...)
			command.Stdout = &output
			e := command.Run()
			data := output.Bytes()
			cancel()
			if e != nil || len(data) > 2*1024*1024 || !json.Valid(data) {
				notes = append(notes, fmt.Sprintf("bpftool %s unavailable or invalid", args[1]))
				continue
			}
			sources = append(sources, json.RawMessage(data))
		}
	}
	for i := range programs {
		p := &programs[i]
		var attachments []any
		for _, source := range sources {
			var items []any
			if json.Unmarshal(source, &items) != nil {
				notes = appendOnce(notes, "unsupported bpftool JSON shape")
				continue
			}
			for _, item := range items {
				if bpfJSONContainsID(item, p.ID) {
					attachments = append(attachments, item)
				}
			}
		}
		if len(attachments) > 0 {
			p.Attachments, _ = json.Marshal(attachments)
		}
		p.EvidenceErrors = append(p.EvidenceErrors, errs...)
		p.EvidenceErrors = append(p.EvidenceErrors, notes...)
		p.EvidenceStatus = "partial" // never claims original loader attribution
		if len(p.Holders) == 0 {
			p.EvidenceErrors = appendOnce(p.EvidenceErrors, "no observable process holder; original loader unknown")
		}
		if len(attachments) == 0 {
			p.EvidenceErrors = appendOnce(p.EvidenceErrors, "attachment not observed; program may have disappeared or use another attachment type")
		}
	}
	if len(errs) > 0 {
		*collectorErrors = append(*collectorErrors, "BPF evidence incomplete: "+strings.Join(errs, "; "))
	}
}

// Bound memory as well as elapsed time when invoking the optional helper.
type bpfBoundedOutput struct{ bytes.Buffer }

func (b *bpfBoundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 2*1024*1024 {
		return 0, fmt.Errorf("BPF output limit exceeded")
	}
	return b.Buffer.Write(p)
}

func appendOnce(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}
func bpfFDProgramID(s string) uint32 {
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(k) == "prog_id" {
			id, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
			return uint32(id)
		}
	}
	return 0
}
func bpfJSONContainsID(v any, id uint32) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			// link.id is a link identifier, not a program identifier. Only
			// cgroup program entries (attach_type present) use id for programs.
			_, isCgroupProgram := x["attach_type"]
			_, isLink := x["prog_id"]
			if k == "prog_id" || (k == "id" && isCgroupProgram && !isLink) {
				if n, ok := v.(float64); ok && n == float64(id) {
					return true
				}
			}
		}
		for _, v := range x {
			if bpfJSONContainsID(v, id) {
				return true
			}
		}
	case []any:
		for _, v := range x {
			if bpfJSONContainsID(v, id) {
				return true
			}
		}
	}
	return false
}
