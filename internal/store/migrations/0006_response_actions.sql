CREATE TABLE response_actions (
    id           uuid PRIMARY KEY,
    host_id      uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    playbook     text NOT NULL CHECK (playbook IN ('kill_process','disable_systemd_unit','isolate_host','restore_network')),
    params       jsonb NOT NULL DEFAULT '{}',
    dry_run      boolean NOT NULL DEFAULT true,
    status       text NOT NULL CHECK (status IN ('pending','approved','running','succeeded','failed')),
    requested_by text NOT NULL,
    approved_by  text,
    worker_id    text,
    lease_until  timestamptz,
    output       text,
    error        text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    approved_at  timestamptz,
    started_at   timestamptz,
    finished_at  timestamptz,
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX response_actions_claim ON response_actions (created_at)
    WHERE status IN ('approved','running');
CREATE INDEX response_actions_host_created ON response_actions (host_id, created_at DESC);
