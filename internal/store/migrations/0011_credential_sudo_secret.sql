-- Optional sudo password, sealed exactly like secret_enc. A key-authenticated account has
-- no password for the scan to escalate with; this holds one without changing how it logs in.
ALTER TABLE credentials ADD COLUMN sudo_secret_enc bytea;
