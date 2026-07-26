CREATE TABLE retention_archive (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind        text NOT NULL CHECK (kind IN ('observation','scan','audit')),
    original_id text NOT NULL,
    archived_at timestamptz NOT NULL DEFAULT now(),
    payload     jsonb NOT NULL
);
CREATE INDEX retention_archive_kind_time ON retention_archive (kind, archived_at DESC);
CREATE INDEX observations_cursor ON observations (last_seen DESC, id DESC);
CREATE INDEX audit_log_cursor ON audit_log (ts DESC, id DESC);

