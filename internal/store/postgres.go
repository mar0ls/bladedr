package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres is the production Store backed by PostgreSQL + pg_search (ParadeDB).
// The free-text query path uses the BM25 index (observations_bm25).
type Postgres struct {
	pool *pgxpool.Pool
}

// OpenPostgres connects and verifies the pool. Schema must already be applied
// (internal/store/migrations/0001_init.sql).
func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	p := &Postgres{pool: pool}
	if err := p.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return p, nil
}

func (p *Postgres) Close() { p.pool.Close() }

type rowScanner interface{ Scan(dest ...any) error }

// --- hosts ---

func (p *Postgres) CreateHost(ctx context.Context, h *Host) error {
	if h.ID == "" {
		h.ID = uuid.NewString()
	}
	if h.CreatedAt.IsZero() {
		h.CreatedAt = time.Now().UTC()
	}
	tags := mustJSON(h.Tags, "{}")
	_, err := p.pool.Exec(ctx, `
		INSERT INTO hosts (id, hostname, primary_ip, ssh_port, credential_id, ssh_host_key,
		                   os_name, os_version, kernel, arch, mode, status, tags, last_seen, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		h.ID, nullStr(h.Hostname), nullStr(h.PrimaryIP), h.SSHPort, nullUUID(h.CredentialID),
		nullStr(h.SSHHostKey), nullStr(h.OSName), nullStr(h.OSVersion), nullStr(h.Kernel),
		nullStr(h.Arch), h.Mode, h.Status, tags, h.LastSeen, h.CreatedAt)
	return err
}

const hostCols = `id, hostname, primary_ip, ssh_port, credential_id, ssh_host_key, os_name,
	os_version, kernel, arch, mode, status, tags, last_seen, created_at`

func scanHost(row rowScanner) (*Host, error) {
	var h Host
	var hostname, ip, credID, sshKey, osName, osVer, kernel, arch *string
	var tags []byte
	if err := row.Scan(&h.ID, &hostname, &ip, &h.SSHPort, &credID, &sshKey, &osName, &osVer,
		&kernel, &arch, &h.Mode, &h.Status, &tags, &h.LastSeen, &h.CreatedAt); err != nil {
		return nil, err
	}
	h.Hostname = deref(hostname)
	h.PrimaryIP = deref(ip)
	h.CredentialID = deref(credID)
	h.SSHHostKey = deref(sshKey)
	h.OSName = deref(osName)
	h.OSVersion = deref(osVer)
	h.Kernel = deref(kernel)
	h.Arch = deref(arch)
	_ = json.Unmarshal(tags, &h.Tags)
	return &h, nil
}

func (p *Postgres) GetHost(ctx context.Context, id string) (*Host, error) {
	row := p.pool.QueryRow(ctx, `SELECT `+hostCols+` FROM hosts WHERE id=$1`, id)
	h, err := scanHost(row)
	return h, notFound(err, "host", id)
}

func (p *Postgres) ListHosts(ctx context.Context) ([]*Host, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+hostCols+` FROM hosts ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (p *Postgres) UpdateHost(ctx context.Context, h *Host) error {
	ct, err := p.pool.Exec(ctx, `
		UPDATE hosts SET hostname=$2, primary_ip=$3, ssh_port=$4, credential_id=$5,
		  ssh_host_key=$6, os_name=$7, os_version=$8, kernel=$9, arch=$10, mode=$11,
		  status=$12, tags=$13, last_seen=$14 WHERE id=$1`,
		h.ID, nullStr(h.Hostname), nullStr(h.PrimaryIP), h.SSHPort, nullUUID(h.CredentialID),
		nullStr(h.SSHHostKey), nullStr(h.OSName), nullStr(h.OSVersion), nullStr(h.Kernel),
		nullStr(h.Arch), h.Mode, h.Status, mustJSON(h.Tags, "{}"), h.LastSeen)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound{"host", h.ID}
	}
	return nil
}

func (p *Postgres) DeleteHost(ctx context.Context, id string) error {
	ct, err := p.pool.Exec(ctx, `DELETE FROM hosts WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound{"host", id}
	}
	return nil
}

// --- credentials ---

func (p *Postgres) CreateCredential(ctx context.Context, c *Credential) error {
	if c.ID == "" {
		c.ID = uuid.NewString()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	_, err := p.pool.Exec(ctx, `
		INSERT INTO credentials (id, name, username, auth_type, secret_enc, created_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		c.ID, c.Name, c.Username, c.AuthType, c.SecretEnc, c.CreatedAt)
	return err
}

func scanCred(row rowScanner) (*Credential, error) {
	var c Credential
	if err := row.Scan(&c.ID, &c.Name, &c.Username, &c.AuthType, &c.SecretEnc, &c.CreatedAt); err != nil {
		return nil, err
	}
	return &c, nil
}

func (p *Postgres) GetCredential(ctx context.Context, id string) (*Credential, error) {
	row := p.pool.QueryRow(ctx, `SELECT id, name, username, auth_type, secret_enc, created_at FROM credentials WHERE id=$1`, id)
	c, err := scanCred(row)
	return c, notFound(err, "credential", id)
}

func (p *Postgres) ListCredentials(ctx context.Context) ([]*Credential, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, name, username, auth_type, secret_enc, created_at FROM credentials ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Credential
	for rows.Next() {
		c, err := scanCred(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) DeleteCredential(ctx context.Context, id string) error {
	ct, err := p.pool.Exec(ctx, `DELETE FROM credentials WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound{"credential", id}
	}
	return nil
}

// --- scans ---

func (p *Postgres) CreateScan(ctx context.Context, s *Scan) error {
	if s.ID == "" {
		s.ID = uuid.NewString()
	}
	if s.StartedAt.IsZero() {
		s.StartedAt = time.Now().UTC()
	}
	_, err := p.pool.Exec(ctx, `
		INSERT INTO scans (id, host_id, trigger, status, probe_version, started_at,
		                   finished_at, duration_ms, error, risk_score)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		s.ID, s.HostID, s.Trigger, s.Status, nullStr(s.ProbeVersion), s.StartedAt,
		s.FinishedAt, s.DurationMS, nullStr(s.Error), s.RiskScore)
	return err
}

func (p *Postgres) UpdateScan(ctx context.Context, s *Scan) error {
	ct, err := p.pool.Exec(ctx, `
		UPDATE scans SET status=$2, probe_version=$3, finished_at=$4, duration_ms=$5,
		  error=$6, risk_score=$7 WHERE id=$1`,
		s.ID, s.Status, nullStr(s.ProbeVersion), s.FinishedAt, s.DurationMS,
		nullStr(s.Error), s.RiskScore)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound{"scan", s.ID}
	}
	return nil
}

const scanCols = `id, host_id, trigger, status, probe_version, started_at, finished_at, duration_ms, error, risk_score`

func scanScan(row rowScanner) (*Scan, error) {
	var s Scan
	var probeVer, errMsg *string
	if err := row.Scan(&s.ID, &s.HostID, &s.Trigger, &s.Status, &probeVer, &s.StartedAt,
		&s.FinishedAt, &s.DurationMS, &errMsg, &s.RiskScore); err != nil {
		return nil, err
	}
	s.ProbeVersion = deref(probeVer)
	s.Error = deref(errMsg)
	return &s, nil
}

func (p *Postgres) GetScan(ctx context.Context, id string) (*Scan, error) {
	row := p.pool.QueryRow(ctx, `SELECT `+scanCols+` FROM scans WHERE id=$1`, id)
	s, err := scanScan(row)
	return s, notFound(err, "scan", id)
}

func (p *Postgres) ListScansByHost(ctx context.Context, hostID string) ([]*Scan, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+scanCols+` FROM scans WHERE host_id=$1 ORDER BY started_at DESC`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Scan
	for rows.Next() {
		s, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// --- observations ---

const obsCols = `id, host_id, scan_id, source, rule_id, category, title, severity, score,
	mitre, evidence, dedup_key, status, first_seen, last_seen, count`

func (p *Postgres) UpsertObservation(ctx context.Context, o *Observation) (*Observation, error) {
	if o.ID == "" {
		o.ID = uuid.NewString()
	}
	if o.Status == "" {
		o.Status = ObsOpen
	}
	row := p.pool.QueryRow(ctx, `
		INSERT INTO observations (id, host_id, scan_id, source, rule_id, category, title,
		  severity, score, mitre, evidence, evidence_text, dedup_key, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (host_id, dedup_key) DO UPDATE SET
		  last_seen = now(), count = observations.count + 1, score = EXCLUDED.score,
		  severity = EXCLUDED.severity, evidence = EXCLUDED.evidence,
		  evidence_text = EXCLUDED.evidence_text, scan_id = EXCLUDED.scan_id
		RETURNING `+obsCols,
		o.ID, o.HostID, nullUUID(o.ScanID), o.Source, o.RuleID, nullStr(o.Category),
		nullStr(o.Title), o.Severity, o.Score, mustJSON(o.Mitre, "[]"),
		mustJSON(o.Evidence, "{}"), flattenEvidence(o.Title, o.Evidence), o.DedupKey, o.Status)
	return scanObs(row)
}

func scanObs(row rowScanner) (*Observation, error) {
	var o Observation
	var scanID, category, title *string
	var mitre, evidence []byte
	if err := row.Scan(&o.ID, &o.HostID, &scanID, &o.Source, &o.RuleID, &category, &title,
		&o.Severity, &o.Score, &mitre, &evidence, &o.DedupKey, &o.Status,
		&o.FirstSeen, &o.LastSeen, &o.Count); err != nil {
		return nil, err
	}
	o.ScanID = deref(scanID)
	o.Category = deref(category)
	o.Title = deref(title)
	_ = json.Unmarshal(mitre, &o.Mitre)
	_ = json.Unmarshal(evidence, &o.Evidence)
	return &o, nil
}

func (p *Postgres) ListObservations(ctx context.Context, f ObservationFilter) ([]*Observation, error) {
	var conds []string
	var args []any
	add := func(cond string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf(cond, len(args)))
	}
	if f.HostID != "" {
		add("host_id = $%d", f.HostID)
	}
	if f.Severity != "" {
		add("severity = $%d", f.Severity)
	}
	if f.Status != "" {
		add("status = $%d", f.Status)
	}
	if f.Source != "" {
		add("source = $%d", f.Source)
	}
	if f.RuleID != "" {
		add("rule_id = $%d", f.RuleID)
	}
	if f.Query != "" {
		// BM25 full-text via pg_search; id is the index key_field.
		args = append(args, f.Query)
		n := len(args)
		conds = append(conds, fmt.Sprintf(
			"(id @@@ paradedb.match('evidence_text', $%d) OR id @@@ paradedb.match('title', $%d) OR id @@@ paradedb.match('rule_id', $%d))",
			n, n, n))
	}

	q := `SELECT ` + obsCols + ` FROM observations`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY last_seen DESC"
	if f.Limit > 0 {
		args = append(args, f.Limit)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Observation
	for rows.Next() {
		o, err := scanObs(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (p *Postgres) GetObservation(ctx context.Context, id string) (*Observation, error) {
	row := p.pool.QueryRow(ctx, `SELECT `+obsCols+` FROM observations WHERE id=$1`, id)
	o, err := scanObs(row)
	return o, notFound(err, "observation", id)
}

func (p *Postgres) SetObservationStatus(ctx context.Context, id, status string) error {
	ct, err := p.pool.Exec(ctx, `UPDATE observations SET status=$2 WHERE id=$1`, id, status)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound{"observation", id}
	}
	return nil
}

// --- rules ---

func (p *Postgres) UpsertRule(ctx context.Context, r *RuleRecord) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO rules (id, source, category, severity, mitre, enabled, definition)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (id) DO UPDATE SET
		  source=EXCLUDED.source, category=EXCLUDED.category, severity=EXCLUDED.severity,
		  mitre=EXCLUDED.mitre, enabled=EXCLUDED.enabled, definition=EXCLUDED.definition`,
		r.ID, r.Source, nullStr(r.Category), nullStr(r.Severity), mustJSON(r.Mitre, "[]"),
		r.Enabled, []byte(r.Definition))
	return err
}

func scanRule(row rowScanner) (*RuleRecord, error) {
	var r RuleRecord
	var category, severity *string
	var mitre, def []byte
	if err := row.Scan(&r.ID, &r.Source, &category, &severity, &mitre, &r.Enabled, &def); err != nil {
		return nil, err
	}
	r.Category = deref(category)
	r.Severity = deref(severity)
	_ = json.Unmarshal(mitre, &r.Mitre)
	r.Definition = json.RawMessage(def)
	return &r, nil
}

func (p *Postgres) ListRules(ctx context.Context) ([]*RuleRecord, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, source, category, severity, mitre, enabled, definition FROM rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*RuleRecord
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) GetRule(ctx context.Context, id string) (*RuleRecord, error) {
	row := p.pool.QueryRow(ctx, `SELECT id, source, category, severity, mitre, enabled, definition FROM rules WHERE id=$1`, id)
	r, err := scanRule(row)
	return r, notFound(err, "rule", id)
}

func (p *Postgres) DeleteRule(ctx context.Context, id string) error {
	ct, err := p.pool.Exec(ctx, `DELETE FROM rules WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound{"rule", id}
	}
	return nil
}

func (p *Postgres) SetRuleEnabled(ctx context.Context, id string, enabled bool) error {
	ct, err := p.pool.Exec(ctx, `UPDATE rules SET enabled=$2 WHERE id=$1`, id, enabled)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound{"rule", id}
	}
	return nil
}

// --- baselines ---

func (p *Postgres) GetBaseline(ctx context.Context, hostID string) (*Baseline, error) {
	row := p.pool.QueryRow(ctx, `SELECT host_id, digest, created_at FROM baselines WHERE host_id=$1`, hostID)
	var b Baseline
	var digest []byte
	if err := row.Scan(&b.HostID, &digest, &b.CreatedAt); err != nil {
		return nil, notFound(err, "baseline", hostID)
	}
	_ = json.Unmarshal(digest, &b.Digest)
	return &b, nil
}

func (p *Postgres) SaveBaseline(ctx context.Context, b *Baseline) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO baselines (host_id, digest, created_at) VALUES ($1,$2,now())
		ON CONFLICT (host_id) DO UPDATE SET digest=EXCLUDED.digest, created_at=now()`,
		b.HostID, mustJSON(b.Digest, "{}"))
	return err
}

func (p *Postgres) DeleteBaseline(ctx context.Context, hostID string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM baselines WHERE host_id=$1`, hostID)
	return err
}

func (p *Postgres) ListBaselines(ctx context.Context) ([]*Baseline, error) {
	rows, err := p.pool.Query(ctx, `SELECT host_id, digest, created_at FROM baselines`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Baseline
	for rows.Next() {
		var b Baseline
		var digest []byte
		if err := rows.Scan(&b.HostID, &digest, &b.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(digest, &b.Digest)
		out = append(out, &b)
	}
	return out, rows.Err()
}

func (p *Postgres) CreateSchedule(ctx context.Context, s *Schedule) error {
	if s.ID == "" {
		s.ID = uuid.NewString()
	}
	_, err := p.pool.Exec(ctx, `
		INSERT INTO schedules (id, name, host_id, collection_id, interval_s, enabled, last_run, next_run, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())`,
		s.ID, s.Name, nullStr(s.HostID), nullStr(s.CollectionID), s.IntervalS, s.Enabled, s.LastRun, s.NextRun)
	if err == nil && s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	return err
}

func scanSchedule(row interface{ Scan(...any) error }) (*Schedule, error) {
	var s Schedule
	var hostID, collID *string
	if err := row.Scan(&s.ID, &s.Name, &hostID, &collID, &s.IntervalS, &s.Enabled, &s.LastRun, &s.NextRun, &s.CreatedAt); err != nil {
		return nil, err
	}
	if hostID != nil {
		s.HostID = *hostID
	}
	if collID != nil {
		s.CollectionID = *collID
	}
	return &s, nil
}

const scheduleCols = `id, name, host_id, collection_id, interval_s, enabled, last_run, next_run, created_at`

func (p *Postgres) GetSchedule(ctx context.Context, id string) (*Schedule, error) {
	row := p.pool.QueryRow(ctx, `SELECT `+scheduleCols+` FROM schedules WHERE id=$1`, id)
	s, err := scanSchedule(row)
	if err != nil {
		return nil, notFound(err, "schedule", id)
	}
	return s, nil
}

func (p *Postgres) ListSchedules(ctx context.Context) ([]*Schedule, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+scheduleCols+` FROM schedules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Schedule
	for rows.Next() {
		s, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *Postgres) UpdateSchedule(ctx context.Context, s *Schedule) error {
	tag, err := p.pool.Exec(ctx, `
		UPDATE schedules SET name=$2, host_id=$3, collection_id=$4, interval_s=$5, enabled=$6, last_run=$7, next_run=$8
		WHERE id=$1`,
		s.ID, s.Name, nullStr(s.HostID), nullStr(s.CollectionID), s.IntervalS, s.Enabled, s.LastRun, s.NextRun)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound{"schedule", s.ID}
	}
	return nil
}

func (p *Postgres) DeleteSchedule(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM schedules WHERE id=$1`, id)
	return err
}

// --- collections ---

func membershipType(dynamic bool) string {
	if dynamic {
		return "dynamic"
	}
	return "static"
}

func (p *Postgres) CreateCollection(ctx context.Context, c *Collection) error {
	if c.ID == "" {
		c.ID = uuid.NewString()
	}
	rule := map[string]any{"tags": c.MatchTags}
	_, err := p.pool.Exec(ctx, `
		INSERT INTO collections (id, name, description, membership_type, membership_rule, created_at)
		VALUES ($1,$2,$3,$4,$5,now())`,
		c.ID, c.Name, nullStr(c.Description), membershipType(c.Dynamic), mustJSON(rule, "{}"))
	if err == nil && c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	return err
}

func scanCollection(row interface{ Scan(...any) error }) (*Collection, error) {
	var c Collection
	var desc *string
	var mtype string
	var rule []byte
	if err := row.Scan(&c.ID, &c.Name, &desc, &mtype, &rule, &c.CreatedAt); err != nil {
		return nil, err
	}
	if desc != nil {
		c.Description = *desc
	}
	c.Dynamic = mtype == "dynamic"
	var r struct {
		Tags map[string]string `json:"tags"`
	}
	_ = json.Unmarshal(rule, &r)
	c.MatchTags = r.Tags
	return &c, nil
}

const collectionCols = `id, name, description, membership_type, membership_rule, created_at`

func (p *Postgres) GetCollection(ctx context.Context, id string) (*Collection, error) {
	row := p.pool.QueryRow(ctx, `SELECT `+collectionCols+` FROM collections WHERE id=$1`, id)
	c, err := scanCollection(row)
	if err != nil {
		return nil, notFound(err, "collection", id)
	}
	return c, nil
}

func (p *Postgres) ListCollections(ctx context.Context) ([]*Collection, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+collectionCols+` FROM collections ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Collection
	for rows.Next() {
		c, err := scanCollection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) UpdateCollection(ctx context.Context, c *Collection) error {
	rule := map[string]any{"tags": c.MatchTags}
	tag, err := p.pool.Exec(ctx, `
		UPDATE collections SET name=$2, description=$3, membership_type=$4, membership_rule=$5 WHERE id=$1`,
		c.ID, c.Name, nullStr(c.Description), membershipType(c.Dynamic), mustJSON(rule, "{}"))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound{"collection", c.ID}
	}
	return nil
}

func (p *Postgres) DeleteCollection(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM collections WHERE id=$1`, id)
	return err
}

func (p *Postgres) AddCollectionMember(ctx context.Context, collectionID, hostID string) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO collection_members (collection_id, host_id) VALUES ($1,$2)
		ON CONFLICT DO NOTHING`, collectionID, hostID)
	return err
}

func (p *Postgres) RemoveCollectionMember(ctx context.Context, collectionID, hostID string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM collection_members WHERE collection_id=$1 AND host_id=$2`, collectionID, hostID)
	return err
}

func (p *Postgres) CollectionHosts(ctx context.Context, id string) ([]*Host, error) {
	c, err := p.GetCollection(ctx, id)
	if err != nil {
		return nil, err
	}
	var rows pgx.Rows
	if c.Dynamic {
		rows, err = p.pool.Query(ctx, `SELECT `+hostCols+` FROM hosts WHERE tags @> $1::jsonb ORDER BY id`, mustJSON(c.MatchTags, "{}"))
	} else {
		rows, err = p.pool.Query(ctx, `
			SELECT `+hostCols+` FROM hosts h
			JOIN collection_members m ON m.host_id = h.id
			WHERE m.collection_id = $1 ORDER BY h.id`, id)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// --- helpers ---

func mustJSON(v any, fallback string) []byte {
	if v == nil {
		return []byte(fallback)
	}
	b, err := json.Marshal(v)
	if err != nil || len(b) == 0 || string(b) == "null" {
		return []byte(fallback)
	}
	return b
}

// flattenEvidence builds the BM25 source text from the title and evidence values.
func flattenEvidence(title string, ev map[string]any) string {
	var b strings.Builder
	b.WriteString(title)
	for k, v := range ev {
		b.WriteByte(' ')
		b.WriteString(k)
		b.WriteByte(' ')
		fmt.Fprint(&b, v)
	}
	return b.String()
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullUUID returns nil for empty FK uuid strings (so they become SQL NULL).
func nullUUID(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func notFound(err error, kind, id string) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound{kind, id}
	}
	return err
}

// --- users + sessions ---

func (p *Postgres) CreateUser(ctx context.Context, u *User) error {
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO users (id, username, password_hash, role, disabled, created_at)
		VALUES ($1,$2,$3,$4,$5,$6)`, u.ID, u.Username, u.PasswordHash, u.Role, u.Disabled, u.CreatedAt)
	return err
}

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.Disabled, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (p *Postgres) GetUser(ctx context.Context, id string) (*User, error) {
	row := p.pool.QueryRow(ctx, `SELECT id, username, password_hash, role, disabled, created_at FROM users WHERE id=$1`, id)
	u, err := scanUser(row)
	return u, notFound(err, "user", id)
}

func (p *Postgres) GetUserByName(ctx context.Context, username string) (*User, error) {
	row := p.pool.QueryRow(ctx, `SELECT id, username, password_hash, role, disabled, created_at FROM users WHERE username=$1`, username)
	u, err := scanUser(row)
	return u, notFound(err, "user", username)
}

func (p *Postgres) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, username, password_hash, role, disabled, created_at FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (p *Postgres) UpdateUser(ctx context.Context, u *User) error {
	_, err := p.pool.Exec(ctx, `UPDATE users SET username=$2, password_hash=$3, role=$4, disabled=$5 WHERE id=$1`,
		u.ID, u.Username, u.PasswordHash, u.Role, u.Disabled)
	return err
}

func (p *Postgres) DeleteUser(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	return err
}

func (p *Postgres) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := p.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func (p *Postgres) CreateSession(ctx context.Context, s *Session) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO sessions (token, user_id, expires_at) VALUES ($1,$2,$3)`,
		s.Token, s.UserID, s.ExpiresAt)
	return err
}

func (p *Postgres) SessionUser(ctx context.Context, token string) (*User, error) {
	row := p.pool.QueryRow(ctx, `SELECT u.id, u.username, u.password_hash, u.role, u.disabled, u.created_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token=$1 AND s.expires_at > now()`, token)
	u, err := scanUser(row)
	return u, notFound(err, "session", "")
}

func (p *Postgres) DeleteSession(ctx context.Context, token string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM sessions WHERE token=$1`, token)
	return err
}

// --- audit log ---

func (p *Postgres) AppendAudit(ctx context.Context, e *AuditEvent) error {
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO audit_log (id, ts, actor, actor_ip, action, target, result, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, e.ID, e.Time, e.Actor, e.ActorIP, e.Action, e.Target, e.Result, e.Detail)
	return err
}

func (p *Postgres) ListAudit(ctx context.Context, limit int) ([]*AuditEvent, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := p.pool.Query(ctx, `SELECT id, ts, actor, actor_ip, action, target, result, detail
		FROM audit_log ORDER BY ts DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.ID, &e.Time, &e.Actor, &e.ActorIP, &e.Action, &e.Target, &e.Result, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}
