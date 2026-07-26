package scan

import (
	"context"
	"errors"
	"testing"
	"time"

	"bladedr/internal/probe"
	"bladedr/internal/rules"
	"bladedr/internal/store"
)

func TestQueueEnqueueIsPerHostIdempotent(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	h := &store.Host{Hostname: "host"}
	_ = st.CreateHost(ctx, h)
	q := &Queue{Store: st}
	a, err := q.Enqueue(ctx, h, store.TriggerAPI)
	if err != nil {
		t.Fatal(err)
	}
	b, err := q.Enqueue(ctx, h, store.TriggerScheduled)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != b.ID {
		t.Fatalf("duplicate active jobs created: %s != %s", a.ID, b.ID)
	}
}

func TestQueueRunOneCompletesScan(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	h := &store.Host{Hostname: "host"}
	_ = st.CreateHost(ctx, h)
	runner := &Runner{
		Store:     st,
		LoadRules: func(context.Context) ([]rules.Rule, error) { return nil, nil },
		NewTransport: func(*store.Host) (Transport, error) {
			return fakeTransport{result: probe.ScanResult{ProbeVersion: "test"}}, nil
		},
	}
	q := &Queue{Store: st, Runner: runner, ScanTimeout: time.Second}
	job, err := q.Enqueue(ctx, h, store.TriggerAPI)
	if err != nil {
		t.Fatal(err)
	}
	worked, err := q.RunOne(ctx)
	if err != nil || !worked {
		t.Fatalf("RunOne = %v, %v", worked, err)
	}
	got, err := st.GetScanJob(ctx, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.ScanJobSucceeded || got.ScanID == "" {
		t.Fatalf("job not completed: %+v", got)
	}
}

// A host that fails every scan must back off and eventually stop, otherwise it spins
// on the queue and starves everything behind it. This is also the only path that
// reaches Queue.fail, where the backoff exponent is computed.
func TestFailedScanBacksOffThenGivesUp(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	h := &store.Host{Hostname: "host"}
	_ = st.CreateHost(ctx, h)
	runner := &Runner{
		Store:     st,
		LoadRules: func(context.Context) ([]rules.Rule, error) { return nil, nil },
		NewTransport: func(*store.Host) (Transport, error) {
			return fakeTransport{err: errors.New("ssh down")}, nil
		},
	}
	q := &Queue{Store: st, Runner: runner, ScanTimeout: time.Second}
	job, err := q.Enqueue(ctx, h, store.TriggerAPI)
	if err != nil {
		t.Fatal(err)
	}

	var lastDelay time.Duration
	for attempt := 1; attempt <= 3; attempt++ {
		// Claim ignores next_attempt_at only once it has passed, so drive the clock
		// by claiming directly rather than waiting out the real backoff.
		claimed, err := st.ClaimScanJob(ctx, "w", time.Now().UTC().Add(time.Hour), time.Minute)
		if err != nil {
			t.Fatalf("attempt %d: job vanished from the queue: %v", attempt, err)
		}
		if err := q.fail(ctx, "w", claimed, errors.New("ssh down")); err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		got, err := st.GetScanJob(ctx, job.ID)
		if err != nil {
			t.Fatal(err)
		}
		if attempt < 3 {
			if got.Status != store.ScanJobQueued {
				t.Fatalf("attempt %d: status = %s, want it queued for retry", attempt, got.Status)
			}
			delay := time.Until(got.NextAttemptAt)
			if delay <= lastDelay {
				t.Errorf("attempt %d: delay %s did not grow past %s", attempt, delay, lastDelay)
			}
			lastDelay = delay
			continue
		}
		if got.Status != store.ScanJobFailed {
			t.Fatalf("after %d attempts status = %s, want it given up", attempt, got.Status)
		}
	}
	if _, err := st.ClaimScanJob(ctx, "w", time.Now().UTC().Add(24*time.Hour), time.Minute); err == nil {
		t.Error("a job that exhausted its attempts is still claimable")
	}
}

func TestExpiredLeaseCanBeReclaimed(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	h := &store.Host{Hostname: "host"}
	_ = st.CreateHost(ctx, h)
	job, _ := st.EnqueueScanJob(ctx, &store.ScanJob{HostID: h.ID, Trigger: store.TriggerAPI})
	now := time.Now().UTC()
	first, err := st.ClaimScanJob(ctx, "worker-a", now, time.Second)
	if err != nil || first.ID != job.ID {
		t.Fatalf("first claim: %+v, %v", first, err)
	}
	second, err := st.ClaimScanJob(ctx, "worker-b", now.Add(2*time.Second), time.Second)
	if err != nil || second.ID != job.ID || second.Attempts != 2 {
		t.Fatalf("reclaim: %+v, %v", second, err)
	}
}
