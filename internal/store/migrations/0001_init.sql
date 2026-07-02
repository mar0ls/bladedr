-- bladedr schema — PostgreSQL + pg_search (ParadeDB). See DESIGN.md section 3.
-- The data plane (scans, observations) lives here too; observations carry a BM25
-- index for full-text hunting.

CREATE EXTENSION IF NOT EXISTS pg_search;

CREATE TABLE IF NOT EXISTS credentials (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL,
    username    text NOT NULL,
    auth_type   text NOT NULL CHECK (auth_type IN ('ssh_key','password','ssh_agent')),
    secret_ref  text,            -- pointer to Vault/SSM, or
    secret_enc  bytea,           -- envelope-encrypted key/password (never plaintext)
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS hosts (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname      text,
    primary_ip    text,
    ssh_port      int NOT NULL DEFAULT 22,
    credential_id uuid REFERENCES credentials(id) ON DELETE SET NULL,
    ssh_host_key  text,            -- pinned SSH host key (authorized_keys line), TOFU
    os_name       text,
    os_version    text,
    kernel        text,
    arch          text,
    mode          text NOT NULL DEFAULT 'scan_only' CHECK (mode IN ('scan_only','scan_plus_sensor')),
    status        text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','online','unreachable','disabled')),
    tags          jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_seen     timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS collections (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text NOT NULL,
    description     text,
    membership_type text NOT NULL CHECK (membership_type IN ('static','dynamic')),
    membership_rule jsonb NOT NULL DEFAULT '{}'::jsonb,  -- {hostname_glob, ip_cidr[], tags[]}
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS collection_members (
    collection_id uuid REFERENCES collections(id) ON DELETE CASCADE,
    host_id       uuid REFERENCES hosts(id) ON DELETE CASCADE,
    PRIMARY KEY (collection_id, host_id)
);

CREATE TABLE IF NOT EXISTS rules (
    id         text PRIMARY KEY,
    source     text NOT NULL CHECK (source IN ('builtin','yaml','user','tetragon')),
    category   text,
    severity   text,
    mitre      jsonb NOT NULL DEFAULT '[]'::jsonb,
    enabled    boolean NOT NULL DEFAULT true,
    definition jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS schedules (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text NOT NULL DEFAULT '',
    host_id       uuid REFERENCES hosts(id) ON DELETE CASCADE,        -- set = one host
    collection_id uuid REFERENCES collections(id) ON DELETE CASCADE,  -- set = collection's hosts
    interval_s    bigint NOT NULL,                                    -- NULL host+collection = all hosts
    enabled       boolean NOT NULL DEFAULT true,
    last_run      timestamptz,
    next_run      timestamptz NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS export_targets (
    id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    type    text NOT NULL CHECK (type IN ('elasticsearch','kibana','webhook','syslog')),
    config  jsonb NOT NULL,
    filter  jsonb NOT NULL DEFAULT '{}'::jsonb,
    enabled boolean NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS scans (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id       uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    trigger       text NOT NULL CHECK (trigger IN ('scheduled','manual','api')),
    status        text NOT NULL CHECK (status IN ('running','ok','partial','failed')),
    probe_version text,
    started_at    timestamptz NOT NULL DEFAULT now(),
    finished_at   timestamptz,
    duration_ms   bigint NOT NULL DEFAULT 0,
    error         text,
    risk_score    int NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS scans_host_started ON scans (host_id, started_at DESC);

CREATE TABLE IF NOT EXISTS observations (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id     uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    scan_id     uuid REFERENCES scans(id) ON DELETE SET NULL,   -- NULL for eBPF stream
    source      text NOT NULL CHECK (source IN ('agentless_probe','ebpf_sensor','baseline','fleet')),
    rule_id     text NOT NULL,
    category    text,
    title       text,
    severity    text NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    score       int NOT NULL DEFAULT 0,
    mitre       jsonb NOT NULL DEFAULT '[]'::jsonb,
    evidence    jsonb NOT NULL DEFAULT '{}'::jsonb,
    evidence_text text,                                          -- flattened, for BM25
    dedup_key   text NOT NULL,
    status      text NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','resolved','false_positive')),
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    count       int NOT NULL DEFAULT 1,
    UNIQUE (host_id, dedup_key)
);
CREATE INDEX IF NOT EXISTS obs_host_status ON observations (host_id, status);
CREATE INDEX IF NOT EXISTS obs_severity_last ON observations (severity, last_seen DESC);
CREATE INDEX IF NOT EXISTS obs_rule ON observations (rule_id);

-- Per-host baseline digest for the drift engine.
CREATE TABLE IF NOT EXISTS baselines (
    host_id    uuid PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    digest     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- BM25 full-text index for hunting (pg_search). Query with the @@@ operator, e.g.
--   SELECT * FROM observations WHERE observations @@@ 'evidence_text:tmp OR title:rootkit';
CREATE INDEX IF NOT EXISTS observations_bm25 ON observations
USING bm25 (id, title, rule_id, evidence_text)
WITH (key_field = 'id');

-- Console users + sessions (auth / RBAC). Roles: admin | operator | viewer.
CREATE TABLE IF NOT EXISTS users (
    id            uuid PRIMARY KEY,
    username      text UNIQUE NOT NULL,
    password_hash text NOT NULL,
    role          text NOT NULL,
    disabled      boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    token      text PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);

-- Security audit log (append-only): logins, user/role changes, sensor deploys, RBAC denials.
CREATE TABLE IF NOT EXISTS audit_log (
    id        uuid PRIMARY KEY,
    ts        timestamptz NOT NULL DEFAULT now(),
    actor     text,
    actor_ip  text,
    action    text NOT NULL,
    target    text,
    result    text NOT NULL,
    detail    text
);
CREATE INDEX IF NOT EXISTS audit_log_ts ON audit_log (ts DESC);
