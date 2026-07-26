CREATE INDEX IF NOT EXISTS observations_status_cursor
    ON observations (status, last_seen DESC, id DESC);
