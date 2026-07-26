-- Authentication hardening for the 1.0 line.
-- Existing sessions are intentionally invalidated: values in the old `token`
-- column were bearer credentials, not digests.
ALTER TABLE sessions RENAME COLUMN token TO token_hash;
DELETE FROM sessions;

ALTER TABLE users
    ADD COLUMN mfa_secret_enc bytea,
    ADD COLUMN mfa_enabled boolean NOT NULL DEFAULT false;

CREATE TABLE sensor_tokens (
    id         uuid PRIMARY KEY,
    host_id    uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX sensor_tokens_host_active ON sensor_tokens (host_id)
    WHERE revoked_at IS NULL;
