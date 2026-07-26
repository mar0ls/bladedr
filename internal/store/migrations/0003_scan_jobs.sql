CREATE TABLE scan_jobs (
    id              uuid PRIMARY KEY,
    host_id         uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    trigger         text NOT NULL CHECK (trigger IN ('scheduled','manual','api')),
    status          text NOT NULL CHECK (status IN ('queued','running','succeeded','failed')),
    attempts        int NOT NULL DEFAULT 0,
    max_attempts    int NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 20),
    worker_id       text,
    lease_until     timestamptz,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    scan_id         uuid REFERENCES scans(id) ON DELETE SET NULL,
    error           text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- This is both a per-host concurrency limit and the idempotency boundary used by
-- schedules and repeated API clicks. Finished jobs no longer participate.
CREATE UNIQUE INDEX scan_jobs_one_active_per_host ON scan_jobs (host_id)
    WHERE status IN ('queued','running');
CREATE INDEX scan_jobs_claim ON scan_jobs (next_attempt_at, created_at)
    WHERE status IN ('queued','running');
CREATE INDEX scan_jobs_host_created ON scan_jobs (host_id, created_at DESC);
