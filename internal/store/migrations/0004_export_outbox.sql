ALTER TABLE export_targets
    ADD COLUMN name text,
    ADD COLUMN secret_enc bytea,
    ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now();
UPDATE export_targets SET name=type WHERE name IS NULL;
ALTER TABLE export_targets ALTER COLUMN name SET NOT NULL;

CREATE TABLE export_outbox (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id      uuid NOT NULL REFERENCES export_targets(id) ON DELETE CASCADE,
    observation_id uuid NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
    status         text NOT NULL DEFAULT 'queued'
                   CHECK (status IN ('queued','delivering','sent','dead')),
    attempts       int NOT NULL DEFAULT 0,
    max_attempts   int NOT NULL DEFAULT 10,
    worker_id      text,
    lease_until    timestamptz,
    available_at   timestamptz NOT NULL DEFAULT now(),
    last_error     text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    delivered_at   timestamptz
);
CREATE INDEX export_outbox_claim ON export_outbox (available_at, created_at)
    WHERE status IN ('queued','delivering');
CREATE INDEX export_outbox_dead ON export_outbox (updated_at DESC)
    WHERE status='dead';
