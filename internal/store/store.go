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
	ID           string `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"`
	Disabled     bool   `json:"disabled"`
	MFASecretEnc []byte `json:"-"`
	MFAEnabled   bool   `json:"mfa_enabled"`
	// MustChangePassword blocks every route except changing the password. Set when the
	// password was generated rather than chosen, or reset by another admin — in both
	// cases someone other than the account holder has seen it.
	MustChangePassword bool      `json:"must_change_password"`
	CreatedAt          time.Time `json:"created_at"`
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
	TokenHash string    `json:"-"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SensorToken is a one-host machine credential. Only TokenHash is persisted;
// the bearer value is returned once when it is minted and cannot be recovered.
type SensorToken struct {
	ID        string     `json:"id"`
	HostID    string     `json:"host_id"`
	TokenHash string     `json:"-"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
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

const (
	ScanJobQueued    = "queued"
	ScanJobRunning   = "running"
	ScanJobSucceeded = "succeeded"
	ScanJobFailed    = "failed"
)

// ScanJob is the durable control record for asynchronous scans. A running job is
// owned only until LeaseUntil; another server may reclaim it after a crash.
type ScanJob struct {
	ID            string     `json:"id"`
	HostID        string     `json:"host_id"`
	Trigger       string     `json:"trigger"`
	Status        string     `json:"status"`
	Attempts      int        `json:"attempts"`
	MaxAttempts   int        `json:"max_attempts"`
	WorkerID      string     `json:"-"`
	LeaseUntil    *time.Time `json:"lease_until,omitempty"`
	NextAttemptAt time.Time  `json:"next_attempt_at"`
	ScanID        string     `json:"scan_id,omitempty"`
	Error         string     `json:"error,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

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
	HostID     string
	Severity   string
	Status     string
	Source     string
	RuleID     string
	Query      string // free-text (BM25 in Postgres; substring in memory)
	Limit      int
	BeforeTime time.Time
	BeforeID   string
}

type AuditFilter struct {
	Limit      int
	BeforeTime time.Time
	BeforeID   string
}

type RetentionPolicy struct {
	ObservationAge time.Duration
	ScanAge        time.Duration
	AuditAge       time.Duration
	ArchiveAge     time.Duration
}

type RetentionResult struct {
	Observations int `json:"observations"`
	Scans        int `json:"scans"`
	Audit        int `json:"audit"`
	Archive      int `json:"archive"`
}

type ArchivedRecord struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	OriginalID string          `json:"original_id"`
	ArchivedAt time.Time       `json:"archived_at"`
	Payload    json.RawMessage `json:"payload"`
}

// Response action lifecycle. A request enters as pending and needs a second admin
// to move it to approved before any worker will claim it; rejected is terminal and
// closes the request without contacting the host.
const (
	ResponsePending   = "pending"
	ResponseApproved  = "approved"
	ResponseRejected  = "rejected"
	ResponseRunning   = "running"
	ResponseSucceeded = "succeeded"
	ResponseFailed    = "failed"
)

// ResponseAction is one queued containment operation against a host. Playbook and
// Params are validated against a fixed allowlist before the row is written; the
// worker never executes an operator-supplied command string.
//
// RequestedBy and ApprovedBy implement two-person control: the store rejects an
// approval whose approver equals the requester, so a single compromised or mistaken
// admin account cannot both raise and authorise a destructive action.
type ResponseAction struct {
	ID           string            `json:"id"`
	HostID       string            `json:"host_id"`
	Playbook     string            `json:"playbook"`
	Params       map[string]string `json:"params"`
	DryRun       bool              `json:"dry_run"`
	Status       string            `json:"status"`
	RequestedBy  string            `json:"requested_by"`
	ApprovedBy   string            `json:"approved_by,omitempty"`
	RejectedBy   string            `json:"rejected_by,omitempty"`
	RejectReason string            `json:"reject_reason,omitempty"`
	WorkerID     string            `json:"-"`
	LeaseUntil   *time.Time        `json:"lease_until,omitempty"`
	Output       string            `json:"output,omitempty"`
	Error        string            `json:"error,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	ApprovedAt   *time.Time        `json:"approved_at,omitempty"`
	RejectedAt   *time.Time        `json:"rejected_at,omitempty"`
	StartedAt    *time.Time        `json:"started_at,omitempty"`
	FinishedAt   *time.Time        `json:"finished_at,omitempty"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

const (
	ExportWebhook       = "webhook"
	ExportElasticsearch = "elasticsearch"
	ExportSyslog        = "syslog"

	DeliveryQueued     = "queued"
	DeliveryDelivering = "delivering"
	DeliverySent       = "sent"
	DeliveryDead       = "dead"
)

// ExportTarget contains only non-secret routing configuration. SecretEnc stores a
// sealed webhook bearer token or Elasticsearch API key and is never serialized.
type ExportTarget struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Config    map[string]string `json:"config"`
	SecretEnc []byte            `json:"-"`
	Enabled   bool              `json:"enabled"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type ExportDelivery struct {
	ID            string     `json:"id"`
	TargetID      string     `json:"target_id"`
	ObservationID string     `json:"observation_id"`
	Status        string     `json:"status"`
	Attempts      int        `json:"attempts"`
	MaxAttempts   int        `json:"max_attempts"`
	WorkerID      string     `json:"-"`
	LeaseUntil    *time.Time `json:"lease_until,omitempty"`
	AvailableAt   time.Time  `json:"available_at"`
	LastError     string     `json:"last_error,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DeliveredAt   *time.Time `json:"delivered_at,omitempty"`
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
	EnqueueScanJob(ctx context.Context, job *ScanJob) (*ScanJob, error)
	GetScanJob(ctx context.Context, id string) (*ScanJob, error)
	ListScanJobs(ctx context.Context, hostID string, limit int) ([]*ScanJob, error)
	ClaimScanJob(ctx context.Context, workerID string, now time.Time, lease time.Duration) (*ScanJob, error)
	RenewScanJobLease(ctx context.Context, id, workerID string, until time.Time) error
	CompleteScanJob(ctx context.Context, id, workerID, scanID string) error
	FailScanJob(ctx context.Context, id, workerID, message string, retryAt time.Time, terminal bool) error

	// UpsertObservation dedups on (HostID, DedupKey): existing rows have their
	// LastSeen/Count/Score refreshed; new ones are inserted as open.
	UpsertObservation(ctx context.Context, o *Observation) (*Observation, error)
	ListObservations(ctx context.Context, f ObservationFilter) ([]*Observation, error)
	GetObservation(ctx context.Context, id string) (*Observation, error)
	SetObservationStatus(ctx context.Context, id, status string) error

	CreateExportTarget(ctx context.Context, target *ExportTarget) error
	GetExportTarget(ctx context.Context, id string) (*ExportTarget, error)
	ListExportTargets(ctx context.Context) ([]*ExportTarget, error)
	UpdateExportTarget(ctx context.Context, target *ExportTarget) error
	DeleteExportTarget(ctx context.Context, id string) error
	ClaimExportDelivery(ctx context.Context, workerID string, now time.Time, lease time.Duration) (*ExportDelivery, error)
	RenewExportDeliveryLease(ctx context.Context, id, workerID string, until time.Time) error
	CompleteExportDelivery(ctx context.Context, id, workerID string) error
	FailExportDelivery(ctx context.Context, id, workerID, message string, retryAt time.Time, terminal bool) error
	ListDeadExportDeliveries(ctx context.Context, limit int) ([]*ExportDelivery, error)
	RetryExportDelivery(ctx context.Context, id string) error

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
	SessionUser(ctx context.Context, tokenHash string) (*User, error) // valid (unexpired) digest -> user
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteExpiredSessions(ctx context.Context) (int, error) // housekeeping; returns rows removed

	// Per-host sensor credentials. Callers hash bearer tokens before crossing the
	// store boundary so neither implementation ever receives a reusable secret.
	CreateSensorToken(ctx context.Context, t *SensorToken) error
	SensorTokenValid(ctx context.Context, hostID, tokenHash string) (bool, error)
	ListSensorTokens(ctx context.Context, hostID string) ([]*SensorToken, error)
	RevokeSensorToken(ctx context.Context, hostID, tokenID string) error
	RevokeOtherSensorTokens(ctx context.Context, hostID, keepTokenID string) error
	RevokeSensorTokens(ctx context.Context, hostID string) error

	// Security audit log (append-only).
	AppendAudit(ctx context.Context, e *AuditEvent) error
	ListAudit(ctx context.Context, limit int) ([]*AuditEvent, error)
	ListAuditPage(ctx context.Context, filter AuditFilter) ([]*AuditEvent, error)
	ApplyRetention(ctx context.Context, policy RetentionPolicy) (RetentionResult, error)
	ListArchive(ctx context.Context, kind string, limit int) ([]*ArchivedRecord, error)

	CreateResponseAction(ctx context.Context, action *ResponseAction) error
	GetResponseAction(ctx context.Context, id string) (*ResponseAction, error)
	ListResponseActions(ctx context.Context, hostID string, limit int) ([]*ResponseAction, error)
	// ApproveResponseAction returns ErrSelfApproval when approver is the requester.
	ApproveResponseAction(ctx context.Context, id, approver string) error
	RejectResponseAction(ctx context.Context, id, rejector, reason string) error
	ClaimResponseAction(ctx context.Context, workerID string, now time.Time, lease time.Duration) (*ResponseAction, error)
	RenewResponseActionLease(ctx context.Context, id, workerID string, until time.Time) error
	CompleteResponseAction(ctx context.Context, id, workerID, output string) error
	FailResponseAction(ctx context.Context, id, workerID, message string) error

	// Ping reports whether the backing store is reachable (for readiness checks).
	Ping(ctx context.Context) error
}

// ErrNotFound is returned when a lookup misses.
type ErrNotFound struct{ Kind, ID string }

func (e ErrNotFound) Error() string { return e.Kind + " not found: " + e.ID }

// ErrSelfApproval is returned when the approver of a response action is also its
// requester. It is a distinct type because the API maps it to 409 Conflict — the
// request is well-formed and the action exists, only the actor is wrong.
type ErrSelfApproval struct{ ID, Actor string }

func (e ErrSelfApproval) Error() string {
	return "response action " + e.ID + " was requested by " + e.Actor +
		"; approval requires a different administrator"
}

// SelfApprovalPolicy is embedded by both store implementations. Two-person control
// is the default; BLADEDR_RESPONSE_ALLOW_SELF_APPROVAL relaxes it for deployments
// with a single administrator, which would otherwise never be able to run a
// response action. Both transitions are audited either way.
type SelfApprovalPolicy struct{ AllowSelfApproval bool }
