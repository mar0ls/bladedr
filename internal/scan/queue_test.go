package scan

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"bladedr/internal/probe"
	"bladedr/internal/rules"
	"bladedr/internal/store"
)

type deferredTransport struct {
	started chan struct{}
	release chan struct{}
	err     error
}

func (t deferredTransport) RunProbe(context.Context, probe.RuleBundle, bool) (probe.ScanResult, error) {
	close(t.started)
	<-t.release // Simulate a remote command that outlives ownership/cancellation.
	return probe.ScanResult{Findings: []probe.Finding{{RuleID: "test", DedupKey: "stale"}}}, t.err
}

func TestQueueDiscardsResultsAfterClockJumpAndReclaim(t *testing.T) {
	for _, remoteErr := range []error{nil, errors.New("old SSH connection closed")} {
		t.Run(fmt.Sprint(remoteErr), func(t *testing.T) {
			ctx := context.Background()
			st := store.NewMemory()
			h := &store.Host{Hostname: "host", Status: store.StatusOnline}
			if err := st.CreateHost(ctx, h); err != nil {
				t.Fatal(err)
			}
			tr := deferredTransport{started: make(chan struct{}), release: make(chan struct{}), err: remoteErr}
			r := &Runner{Store: st, LoadRules: func(context.Context) ([]rules.Rule, error) { return []rules.Rule{{ID: "test"}}, nil }, NewTransport: func(*store.Host) (Transport, error) { return tr, nil }}
			q := &Queue{Store: st, Runner: r}
			job, err := q.Enqueue(ctx, h, store.TriggerAPI)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { _, err := q.RunOne(ctx); done <- err }()
			select {
			case <-tr.started:
			case <-time.After(3 * time.Second):
				t.Fatal("transport did not start")
			}
			// Advance only the durable lease clock; the old remote call still runs.
			claimed, err := st.ClaimScanJob(ctx, "replacement", time.Now().Add(time.Hour), time.Minute)
			close(tr.release)
			if err != nil || claimed.ID != job.ID {
				t.Fatalf("reclaim: %+v %v", claimed, err)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("stale worker completed")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("worker did not return")
			}
			obs, _ := st.ListObservations(ctx, store.ObservationFilter{HostID: h.ID})
			if len(obs) != 0 {
				t.Fatalf("stale observations persisted: %+v", obs)
			}
			current, _ := st.GetHost(ctx, h.ID)
			if current.Status != store.StatusOnline {
				t.Fatalf("old failure changed host: %s", current.Status)
			}
			currentJob, _ := st.GetScanJob(ctx, job.ID)
			if currentJob.Status != store.ScanJobRunning {
				t.Fatalf("replacement job modified: %+v", currentJob)
			}
		})
	}
}

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
