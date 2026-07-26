package scan

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"bladedr/internal/store"
	"github.com/google/uuid"
)

// Queue executes durable scan jobs. Store-level claiming and leases make workers
// safe across multiple server processes; the partial unique index on host_id keeps
// a host to one active job regardless of worker count.
type Queue struct {
	Store        store.Store
	Runner       *Runner
	Workers      int
	PollInterval time.Duration
	Lease        time.Duration
	ScanTimeout  time.Duration
	WorkerID     string
	Logf         func(string, ...any)
}

func (q *Queue) defaults() {
	if q.Workers <= 0 {
		q.Workers = 4
	}
	if q.PollInterval <= 0 {
		q.PollInterval = time.Second
	}
	if q.Lease <= 0 {
		q.Lease = 90 * time.Second
	}
	if q.ScanTimeout <= 0 {
		q.ScanTimeout = 5 * time.Minute
	}
	if q.WorkerID == "" {
		q.WorkerID = uuid.NewString()
	}
}

func (q *Queue) logf(format string, args ...any) {
	if q.Logf != nil {
		q.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// Enqueue returns the existing active job when the host is already queued or
// running. This makes API retries and overlapping schedules idempotent.
func (q *Queue) Enqueue(ctx context.Context, host *store.Host, trigger string) (*store.ScanJob, error) {
	return q.Store.EnqueueScanJob(ctx, &store.ScanJob{
		HostID: host.ID, Trigger: trigger, Status: store.ScanJobQueued, MaxAttempts: 3,
	})
}

// Run starts a bounded worker pool and blocks until ctx is cancelled.
func (q *Queue) Run(ctx context.Context) {
	q.defaults()
	q.logf("scan queue started (workers=%d lease=%s)", q.Workers, q.Lease)
	done := make(chan struct{}, q.Workers)
	for i := 0; i < q.Workers; i++ {
		go func() {
			q.worker(ctx, q.WorkerID+"/"+uuid.NewString())
			done <- struct{}{}
		}()
	}
	<-ctx.Done()
	for i := 0; i < q.Workers; i++ {
		<-done
	}
}

func (q *Queue) worker(ctx context.Context, workerID string) {
	ticker := time.NewTicker(q.PollInterval)
	defer ticker.Stop()
	for {
		worked, err := q.runOne(ctx, workerID)
		if err != nil {
			q.logf("scan queue worker: %v", err)
		}
		if worked {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RunOne is a deterministic single-job hook used by tests and operational tools.
func (q *Queue) RunOne(ctx context.Context) (bool, error) {
	q.defaults()
	return q.runOne(ctx, q.WorkerID+"/manual")
}

func (q *Queue) runOne(ctx context.Context, workerID string) (bool, error) {
	job, err := q.Store.ClaimScanJob(ctx, workerID, time.Now().UTC(), q.Lease)
	if err != nil {
		var missing store.ErrNotFound
		if errors.As(err, &missing) {
			return false, nil
		}
		return false, err
	}
	host, err := q.Store.GetHost(ctx, job.HostID)
	if err != nil {
		return true, q.fail(ctx, workerID, job, err)
	}

	scanCtx, cancel := context.WithTimeout(ctx, q.ScanTimeout)
	done := make(chan struct{})
	go q.heartbeat(scanCtx, cancel, done, workerID, job.ID)
	sc, scanErr := q.Runner.Scan(scanCtx, host, job.Trigger)
	close(done)
	cancel()
	if scanErr == nil && sc.Status == store.ScanFailed {
		scanErr = fmt.Errorf("scan failed: %s", sc.Error)
	}
	if scanErr != nil {
		return true, q.fail(ctx, workerID, job, scanErr)
	}
	if err := q.Store.CompleteScanJob(ctx, job.ID, workerID, sc.ID); err != nil {
		return true, err
	}
	return true, nil
}

func (q *Queue) heartbeat(ctx context.Context, cancel context.CancelFunc, done <-chan struct{}, workerID, jobID string) {
	interval := q.Lease / 3
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			if err := q.Store.RenewScanJobLease(ctx, jobID, workerID, time.Now().UTC().Add(q.Lease)); err != nil {
				// Ownership was lost; stop the scan before another worker reclaims it.
				cancel()
				return
			}
		}
	}
}

func (q *Queue) fail(ctx context.Context, workerID string, job *store.ScanJob, cause error) error {
	terminal := job.Attempts >= job.MaxAttempts
	// 5s, 10s, 20s ... capped at five minutes. Claim increments Attempts before we
	// ever get here, so the exponent should never go negative — but a negative shift
	// is a panic, and this runs on a worker goroutine where a panic takes the server
	// down with it. Not worth betting the process on a store implementation detail.
	shift := max(job.Attempts-1, 0)
	delay := 5 * time.Second * time.Duration(1<<min(shift, 6))
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	return q.Store.FailScanJob(ctx, job.ID, workerID, cause.Error(), time.Now().UTC().Add(delay), terminal)
}
