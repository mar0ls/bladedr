package scan

import (
	"context"
	"sync"
	"testing"
	"time"

	"bladedr/internal/store"
)

// stubRunner records which hosts were scanned, instead of running a real probe.
type stubRunner struct {
	mu      sync.Mutex
	scanned []string
}

func (s *stubRunner) Scan(_ context.Context, h *store.Host, trigger string) (*store.Scan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanned = append(s.scanned, h.ID+":"+trigger)
	return &store.Scan{HostID: h.ID, Trigger: trigger}, nil
}

func (s *stubRunner) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.scanned)
}

func TestSchedulerRunDue(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	h1 := &store.Host{Hostname: "h1"}
	h2 := &store.Host{Hostname: "h2"}
	_ = st.CreateHost(ctx, h1)
	_ = st.CreateHost(ctx, h2)

	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	run := &stubRunner{}
	sched := &Scheduler{Store: st, Runner: run, Now: func() time.Time { return now }, Logf: func(string, ...any) {}}

	// Due single-host schedule.
	due := &store.Schedule{HostID: h1.ID, IntervalS: 3600, Enabled: true, NextRun: now.Add(-time.Minute)}
	_ = st.CreateSchedule(ctx, due)
	// Not yet due.
	future := &store.Schedule{HostID: h2.ID, IntervalS: 3600, Enabled: true, NextRun: now.Add(time.Hour)}
	_ = st.CreateSchedule(ctx, future)
	// Disabled (due but off).
	off := &store.Schedule{HostID: h2.ID, IntervalS: 3600, Enabled: false, NextRun: now.Add(-time.Minute)}
	_ = st.CreateSchedule(ctx, off)

	sched.RunDue(ctx)

	if run.count() != 1 {
		t.Fatalf("expected exactly 1 scan (only the due+enabled schedule), got %d (%v)", run.count(), run.scanned)
	}
	if run.scanned[0] != h1.ID+":"+store.TriggerScheduled {
		t.Errorf("wrong host scanned: %v", run.scanned)
	}

	// The fired schedule must have advanced NextRun by the interval and set LastRun.
	got, _ := st.GetSchedule(ctx, due.ID)
	if !got.NextRun.Equal(now.Add(time.Hour)) {
		t.Errorf("NextRun should advance by interval, got %v", got.NextRun)
	}
	if got.LastRun == nil || !got.LastRun.Equal(now) {
		t.Errorf("LastRun should be set to now, got %v", got.LastRun)
	}

	// Second run at the same instant: nothing is due now.
	sched.RunDue(ctx)
	if run.count() != 1 {
		t.Fatalf("no schedule should be due on the second run, got %d total", run.count())
	}
}

func TestSchedulerAllHosts(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	for _, n := range []string{"a", "b", "c"} {
		_ = st.CreateHost(ctx, &store.Host{Hostname: n})
	}
	now := time.Now().UTC()
	run := &stubRunner{}
	sched := &Scheduler{Store: st, Runner: run, Now: func() time.Time { return now }, Logf: func(string, ...any) {}}

	// Empty HostID = fleet-wide: every host gets scanned.
	_ = st.CreateSchedule(ctx, &store.Schedule{IntervalS: 3600, Enabled: true, NextRun: now.Add(-time.Second)})
	sched.RunDue(ctx)

	if run.count() != 3 {
		t.Fatalf("fleet-wide schedule should scan all 3 hosts, got %d", run.count())
	}
}
