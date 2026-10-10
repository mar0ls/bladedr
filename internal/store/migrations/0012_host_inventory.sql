-- Current credential inventory per host, for correlating SSH keys and password hashes
-- across the fleet. Not the baseline: that is frozen at the first scan, so a key added
-- afterwards would never appear in it, and reuse is a statement about the present.
CREATE TABLE IF NOT EXISTS host_inventory (
    host_id    uuid PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    items      jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now()
);
