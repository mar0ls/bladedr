package scan

import (
	"context"
	"log"
	"time"

	"bladedr/internal/store"
)

// scanRunner is the subset of *Runner the scheduler needs; an interface so the
// due-evaluation logic can be unit-tested with a stub.
type scanRunner interface {
	Scan(ctx context.Context, h *store.Host, trigger string) (*store.Scan, error)
}

// Scheduler runs due scan schedules from the store on a fixed tick. A schedule
// with an empty HostID targets every host; otherwise just the named host. After
// firing a schedule its LastRun/NextRun are advanced by IntervalS.
type Scheduler struct {
	Store       store.Store
	Runner      scanRunner
	Tick        time.Duration    // how often to check for due schedules (default 30s)
	ScanTimeout time.Duration    // per-host scan deadline (default 5m); bounds a hung host
	Now         func() time.Time // injectable clock (tests)
	Logf        func(string, ...any)
}

func (s *Scheduler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *Scheduler) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// Run blocks, evaluating due schedules every Tick until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	tick := s.Tick
	if tick <= 0 {
		tick = 30 * time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	s.logf("scheduler started (tick %s)", tick)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.RunDue(ctx)
		}
	}
}

// RunDue fires every enabled schedule whose NextRun has passed, then advances it.
// Exported and clock-injectable so it can be driven directly from tests.
func (s *Scheduler) RunDue(ctx context.Context) {
	now := s.now()
	scheds, err := s.Store.ListSchedules(ctx)
	if err != nil {
		s.logf("scheduler: list schedules: %v", err)
		return
	}
	for _, sc := range scheds {
		if !sc.Enabled || now.Before(sc.NextRun) {
			continue
		}
		s.fire(ctx, sc)
		t := now
		sc.LastRun = &t
		sc.NextRun = nextRun(now, sc.IntervalS)
		if err := s.Store.UpdateSchedule(ctx, sc); err != nil {
			s.logf("scheduler: update schedule %s: %v", sc.ID, err)
		}
	}
}

// fire runs the schedule's target scan(s). Per-host errors are logged, not fatal,
// so one unreachable host doesn't stop the rest of the fleet.
func (s *Scheduler) fire(ctx context.Context, sc *store.Schedule) {
	var hosts []*store.Host
	var err error
	switch {
	case sc.HostID != "":
		var h *store.Host
		if h, err = s.Store.GetHost(ctx, sc.HostID); err == nil {
			hosts = []*store.Host{h}
		}
	case sc.CollectionID != "":
		hosts, err = s.Store.CollectionHosts(ctx, sc.CollectionID)
	default:
		hosts, err = s.Store.ListHosts(ctx)
	}
	if err != nil {
		s.logf("scheduler: schedule %s resolve hosts: %v", sc.ID, err)
		return
	}
	timeout := s.ScanTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	for _, h := range hosts {
		sctx, cancel := context.WithTimeout(ctx, timeout)
		_, err := s.Runner.Scan(sctx, h, store.TriggerScheduled)
		cancel()
		if err != nil {
			s.logf("scheduler: scan host %s: %v", h.ID, err)
		}
	}
}

// nextRun advances a fire time by the interval, skipping any periods already
// missed (e.g. after downtime) so we don't backlog-fire repeatedly.
func nextRun(from time.Time, intervalS int64) time.Time {
	if intervalS <= 0 {
		intervalS = 3600
	}
	return from.Add(time.Duration(intervalS) * time.Second)
}
