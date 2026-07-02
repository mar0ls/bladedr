// Package store defines the persistence interface and domain types. The default
// implementation is in-memory (dev/tests); the production backend is PostgreSQL
// + pg_search (BM25), wired behind the same Store interface (see internal/store/migrations/).
package store

import (
	"context"
	"encoding/json"
	"time"
)

// RuleRecord is a user/DB-managed detection rule. Definition holds the full rule
// (id, when, evidence, …) as JSON; the denormalised columns drive listing.
type RuleRecord struct {
	ID         string          `json:"id"`
	Source     string          `json:"source"`
	Category   string          `json:"category"`
	Severity   string          `json:"severity"`
	Mitre      []string        `json:"mitre,omitempty"`
	Enabled    bool            `json:"enabled"`
	Definition json.RawMessage `json:"definition"`
}

// Host monitoring mode (DESIGN 3.1).
const (
	ModeScanOnly       = "scan_only"
	ModeScanPlusSensor = "scan_plus_sensor"
)

// Host status.
const (
	StatusPending     = "pending"
	StatusOnline      = "online"
	StatusUnreachable = "unreachable"
	StatusDisabled    = "disabled"
)

// Observation source.
const (
	SourceAgentlessProbe = "agentless_probe"
	SourceEBPFSensor     = "ebpf_sensor"
	SourceBaseline       = "baseline"
	SourceFleet          = "fleet"
)

// User roles (RBAC). admin manages users + credentials and may do anything;
// operator may read and perform non-admin mutations (triage, scan, rules, sensor);
// viewer is read-only.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

// User is a console account. The password is stored only as a bcrypt hash.
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	Disabled     bool      `json:"disabled"`
	CreatedAt    time.Time `json:"created_at"`
}

// AuditEvent is one security-relevant action recorded for the audit log (logins,
// user/role changes, sensor deploys, RBAC denials, host/credential changes).
type AuditEvent struct {
	ID      string    `json:"id"`
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"`    // username, or attempted username for a failed login
	ActorIP string    `json:"actor_ip"` // client IP
	Action  string    `json:"action"`   // e.g. "login", "user.create", "sensor.enable", "access.denied"
	Target  string    `json:"target"`   // affected object (username, host id, path, ...)
	Result  string    `json:"result"`   // "ok" | "denied" | "fail"
	Detail  string    `json:"detail,omitempty"`
}

// Session is an authenticated session token (cookie for the UI, bearer for the API).
type Session struct {
	Token     string    `json:"-"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Scan trigger. These MUST match the scans.trigger CHECK constraint in the schema
// (migrations/0001_init.sql); using a value outside this set makes every affected
// scan insert fail. Keep them as constants so the scheduler and API can't drift
// from the constraint (the bug where "scheduler"/"schedule_manual" silently broke
// all scheduled scans).
const (
	TriggerScheduled = "scheduled" // fired by the background scheduler
	TriggerManual    = "manual"    // a human triggered it (UI button, run-schedule-now)
	TriggerAPI       = "api"       // direct API call
)

// Schedule is a recurring scan job. Target precedence: HostID (one host), else
// CollectionID (the collection's hosts), else all hosts (fleet-wide). IntervalS is
// the period in seconds; the scheduler fires due schedules and advances NextRun.
type Schedule struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	HostID       string     `json:"host_id,omitempty"`       // set = just this host
	CollectionID string     `json:"collection_id,omitempty"` // set = this collection's hosts
	IntervalS    int64      `json:"interval_s"`
	Enabled      bool       `json:"enabled"`
	LastRun      *time.Time `json:"last_run,omitempty"`
	NextRun      time.Time  `json:"next_run"`
	CreatedAt    time.Time  `json:"created_at"`
}

// Collection groups hosts for scheduling/filtering. Static collections have an
// explicit member list; dynamic collections include any host whose tags are a
// superset of MatchTags. CollectionHosts resolves the effective membership.
type Collection struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Dynamic     bool              `json:"dynamic"`
	MatchTags   map[string]string `json:"match_tags,omitempty"` // dynamic: host must have all these tags
	CreatedAt   time.Time         `json:"created_at"`
}

// tagsMatch reports whether host tags contain every key=value in want.
func tagsMatch(hostTags, want map[string]string) bool {
	for k, v := range want {
		if hostTags[k] != v {
			return false
		}
	}
	return true
}

// Baseline is a host's established "known-good" state digest. Later scans diff
// their digest against it to surface drift (new ports/modules/accounts/keys/...).
type Baseline struct {
	HostID    string              `json:"host_id"`
	Digest    map[string][]string `json:"digest"`
	CreatedAt time.Time           `json:"created_at"`
}

// Observation lifecycle status.
const (
	ObsOpen          = "open"
	ObsAcknowledged  = "acknowledged"
	ObsResolved      = "resolved"
	ObsFalsePositive = "false_positive"
)

// Scan status.
const (
	ScanRunning = "running"
	ScanOK      = "ok"
	ScanPartial = "partial"
	ScanFailed  = "failed"
)

// Credential auth types.
const (
	AuthSSHKey   = "ssh_key"
	AuthPassword = "password"
	AuthSSHAgent = "ssh_agent"
)

// Credential holds SSH login material. SecretEnc is the sealed secret (private
// key or password); it is never exposed through the API (json:"-") and, per the
// split-trust model, the server cannot decrypt it without the node private key.
type Credential struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Username  string    `json:"username"`
	AuthType  string    `json:"auth_type"`
	SecretEnc []byte    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

type Host struct {
	ID           string            `json:"id"`
	Hostname     string            `json:"hostname"`
	PrimaryIP    string            `json:"primary_ip"`
	SSHPort      int               `json:"ssh_port"`
	CredentialID string            `json:"credential_id,omitempty"`
	SSHHostKey   string            `json:"ssh_host_key,omitempty"` // pinned host key (TOFU)
	OSName       string            `json:"os_name,omitempty"`
	OSVersion    string            `json:"os_version,omitempty"`
	Kernel       string            `json:"kernel,omitempty"`
	Arch         string            `json:"arch,omitempty"`
	Mode         string            `json:"mode"`
	Status       string            `json:"status"`
	Tags         map[string]string `json:"tags,omitempty"`
	LastSeen     *time.Time        `json:"last_seen,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

type Scan struct {
	ID           string     `json:"id"`
	HostID       string     `json:"host_id"`
	Trigger      string     `json:"trigger"`
	Status       string     `json:"status"`
	ProbeVersion string     `json:"probe_version,omitempty"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	DurationMS   int64      `json:"duration_ms"`
	Error        string     `json:"error,omitempty"`
	RiskScore    int        `json:"risk_score"`
}

type Observation struct {
	ID        string         `json:"id"`
	HostID    string         `json:"host_id"`
	ScanID    string         `json:"scan_id,omitempty"`
	Source    string         `json:"source"`
	RuleID    string         `json:"rule_id"`
	Category  string         `json:"category"`
	Title     string         `json:"title"`
	Severity  string         `json:"severity"`
	Score     int            `json:"score"`
	Mitre     []string       `json:"mitre,omitempty"`
	Evidence  map[string]any `json:"evidence,omitempty"`
	DedupKey  string         `json:"dedup_key"`
	Status    string         `json:"status"`
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
	Count     int            `json:"count"`
}

// ObservationFilter narrows list queries. Zero-value fields are ignored.
type ObservationFilter struct {
	HostID   string
	Severity string
	Status   string
	Source   string
	RuleID   string
	Query    string // free-text (BM25 in Postgres; substring in memory)
	Limit    int
}

// Store is the persistence contract. All methods are safe for concurrent use.
type Store interface {
	CreateHost(ctx context.Context, h *Host) error
	GetHost(ctx context.Context, id string) (*Host, error)
	ListHosts(ctx context.Context) ([]*Host, error)
	UpdateHost(ctx context.Context, h *Host) error
	DeleteHost(ctx context.Context, id string) error

	// Credentials. CreateCredential stores already-sealed SecretEnc. Get returns
	// the sealed secret for internal use by the scan runner; the API never exposes it.
	CreateCredential(ctx context.Context, c *Credential) error
	GetCredential(ctx context.Context, id string) (*Credential, error)
	ListCredentials(ctx context.Context) ([]*Credential, error)
	DeleteCredential(ctx context.Context, id string) error

	CreateScan(ctx context.Context, s *Scan) error
	UpdateScan(ctx context.Context, s *Scan) error
	GetScan(ctx context.Context, id string) (*Scan, error)
	ListScansByHost(ctx context.Context, hostID string) ([]*Scan, error)

	// UpsertObservation dedups on (HostID, DedupKey): existing rows have their
	// LastSeen/Count/Score refreshed; new ones are inserted as open.
	UpsertObservation(ctx context.Context, o *Observation) (*Observation, error)
	ListObservations(ctx context.Context, f ObservationFilter) ([]*Observation, error)
	GetObservation(ctx context.Context, id string) (*Observation, error)
	SetObservationStatus(ctx context.Context, id, status string) error

	// User/DB-managed rules (merged with builtin rules at scan time).
	UpsertRule(ctx context.Context, r *RuleRecord) error
	ListRules(ctx context.Context) ([]*RuleRecord, error)
	GetRule(ctx context.Context, id string) (*RuleRecord, error)
	DeleteRule(ctx context.Context, id string) error
	SetRuleEnabled(ctx context.Context, id string, enabled bool) error

	// Per-host baseline (drift engine). GetBaseline returns ErrNotFound when none.
	GetBaseline(ctx context.Context, hostID string) (*Baseline, error)
	SaveBaseline(ctx context.Context, b *Baseline) error
	DeleteBaseline(ctx context.Context, hostID string) error
	ListBaselines(ctx context.Context) ([]*Baseline, error) // for fleet rarity scoring

	// Recurring scan schedules, driven by the background scheduler.
	CreateSchedule(ctx context.Context, s *Schedule) error
	GetSchedule(ctx context.Context, id string) (*Schedule, error)
	ListSchedules(ctx context.Context) ([]*Schedule, error)
	UpdateSchedule(ctx context.Context, s *Schedule) error
	DeleteSchedule(ctx context.Context, id string) error

	// Host collections (static member list or dynamic tag rule).
	CreateCollection(ctx context.Context, c *Collection) error
	GetCollection(ctx context.Context, id string) (*Collection, error)
	ListCollections(ctx context.Context) ([]*Collection, error)
	UpdateCollection(ctx context.Context, c *Collection) error
	DeleteCollection(ctx context.Context, id string) error
	AddCollectionMember(ctx context.Context, collectionID, hostID string) error
	RemoveCollectionMember(ctx context.Context, collectionID, hostID string) error
	CollectionHosts(ctx context.Context, id string) ([]*Host, error) // resolved membership

	// Console users + sessions (auth/RBAC).
	CreateUser(ctx context.Context, u *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByName(ctx context.Context, username string) (*User, error)
	ListUsers(ctx context.Context) ([]*User, error)
	UpdateUser(ctx context.Context, u *User) error
	DeleteUser(ctx context.Context, id string) error
	CountUsers(ctx context.Context) (int, error)
	CreateSession(ctx context.Context, s *Session) error
	SessionUser(ctx context.Context, token string) (*User, error) // valid (unexpired) session -> user
	DeleteSession(ctx context.Context, token string) error

	// Security audit log (append-only).
	AppendAudit(ctx context.Context, e *AuditEvent) error
	ListAudit(ctx context.Context, limit int) ([]*AuditEvent, error)
}

// ErrNotFound is returned when a lookup misses.
type ErrNotFound struct{ Kind, ID string }

func (e ErrNotFound) Error() string { return e.Kind + " not found: " + e.ID }
