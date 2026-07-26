-- Two-person control for response actions.
--
-- Approval now requires an administrator other than the requester, and a pending
-- request can be closed without contacting the host. That adds a terminal
-- 'rejected' state plus the columns recording who rejected it and why.
--
-- The status CHECK is replaced rather than extended: Postgres has no "ALTER
-- CONSTRAINT ... ADD VALUE" for CHECK, so the old constraint is dropped by the name
-- assigned in 0006 and re-created with the full value set.

ALTER TABLE response_actions
    ADD COLUMN IF NOT EXISTS rejected_by   text,
    ADD COLUMN IF NOT EXISTS reject_reason text,
    ADD COLUMN IF NOT EXISTS rejected_at   timestamptz;

ALTER TABLE response_actions
    DROP CONSTRAINT IF EXISTS response_actions_status_check;

ALTER TABLE response_actions
    ADD CONSTRAINT response_actions_status_check
    CHECK (status IN ('pending','approved','rejected','running','succeeded','failed'));

-- A rejected action is terminal and must never be picked up by a worker. The claim
-- index only covers approved/running, so rejection is invisible to ClaimResponseAction
-- by construction; this constraint documents and enforces the same invariant at the
-- row level.
ALTER TABLE response_actions
    DROP CONSTRAINT IF EXISTS response_actions_rejected_terminal;

ALTER TABLE response_actions
    ADD CONSTRAINT response_actions_rejected_terminal
    CHECK (status <> 'rejected' OR (rejected_by IS NOT NULL AND worker_id IS NULL));
