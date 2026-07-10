package store

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Memory is an in-memory Store for development and tests.
type Memory struct {
	mu        sync.RWMutex
	hosts     map[string]*Host
	creds     map[string]*Credential
	scans     map[string]*Scan
	obs       map[string]*Observation
	rules     map[string]*RuleRecord
	baselines map[string]*Baseline
	schedules map[string]*Schedule
	colls     map[string]*Collection
	collMem   map[string]map[string]bool // collectionID -> set of hostIDs (static)
	users     map[string]*User           // by id
	sessions  map[string]*Session        // by token
	audit     []*AuditEvent
	// dedup index: hostID -> dedupKey -> observation id
	dedup map[string]map[string]string
}

func NewMemory() *Memory {
	return &Memory{
		hosts:     map[string]*Host{},
		creds:     map[string]*Credential{},
		scans:     map[string]*Scan{},
		obs:       map[string]*Observation{},
		rules:     map[string]*RuleRecord{},
		baselines: map[string]*Baseline{},
		schedules: map[string]*Schedule{},
		colls:     map[string]*Collection{},
		collMem:   map[string]map[string]bool{},
		users:     map[string]*User{},
		sessions:  map[string]*Session{},
		audit:     []*AuditEvent{},
		dedup:     map[string]map[string]string{},
	}
}

func cloneCollection(c *Collection) *Collection {
	cp := *c
	if c.MatchTags != nil {
		cp.MatchTags = map[string]string{}
		for k, v := range c.MatchTags {
			cp.MatchTags[k] = v
		}
	}
	return &cp
}

func (m *Memory) CreateCollection(_ context.Context, c *Collection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.ID == "" {
		c.ID = uuid.NewString()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	m.colls[c.ID] = cloneCollection(c)
	if m.collMem[c.ID] == nil {
		m.collMem[c.ID] = map[string]bool{}
	}
	return nil
}

func (m *Memory) GetCollection(_ context.Context, id string) (*Collection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.colls[id]
	if !ok {
		return nil, ErrNotFound{"collection", id}
	}
	return cloneCollection(c), nil
}

func (m *Memory) ListCollections(_ context.Context) ([]*Collection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Collection, 0, len(m.colls))
	for _, c := range m.colls {
		out = append(out, cloneCollection(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) UpdateCollection(_ context.Context, c *Collection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.colls[c.ID]; !ok {
		return ErrNotFound{"collection", c.ID}
	}
	m.colls[c.ID] = cloneCollection(c)
	return nil
}

func (m *Memory) DeleteCollection(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.colls, id)
	delete(m.collMem, id)
	return nil
}

func (m *Memory) AddCollectionMember(_ context.Context, collectionID, hostID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.colls[collectionID]; !ok {
		return ErrNotFound{"collection", collectionID}
	}
	if m.collMem[collectionID] == nil {
		m.collMem[collectionID] = map[string]bool{}
	}
	m.collMem[collectionID][hostID] = true
	return nil
}

func (m *Memory) RemoveCollectionMember(_ context.Context, collectionID, hostID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mem := m.collMem[collectionID]; mem != nil {
		delete(mem, hostID)
	}
	return nil
}

func (m *Memory) CollectionHosts(_ context.Context, id string) ([]*Host, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.colls[id]
	if !ok {
		return nil, ErrNotFound{"collection", id}
	}
	var out []*Host
	if c.Dynamic {
		for _, h := range m.hosts {
			if tagsMatch(h.Tags, c.MatchTags) {
				out = append(out, cloneHost(h))
			}
		}
	} else {
		for hostID := range m.collMem[id] {
			if h, ok := m.hosts[hostID]; ok {
				out = append(out, cloneHost(h))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func cloneSchedule(s *Schedule) *Schedule {
	c := *s
	if s.LastRun != nil {
		t := *s.LastRun
		c.LastRun = &t
	}
	return &c
}

func (m *Memory) CreateSchedule(_ context.Context, s *Schedule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.ID == "" {
		s.ID = uuid.NewString()
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	m.schedules[s.ID] = cloneSchedule(s)
	return nil
}

func (m *Memory) GetSchedule(_ context.Context, id string) (*Schedule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.schedules[id]
	if !ok {
		return nil, ErrNotFound{"schedule", id}
	}
	return cloneSchedule(s), nil
}

func (m *Memory) ListSchedules(_ context.Context) ([]*Schedule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Schedule, 0, len(m.schedules))
	for _, s := range m.schedules {
		out = append(out, cloneSchedule(s))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) UpdateSchedule(_ context.Context, s *Schedule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.schedules[s.ID]; !ok {
		return ErrNotFound{"schedule", s.ID}
	}
	m.schedules[s.ID] = cloneSchedule(s)
	return nil
}

func (m *Memory) DeleteSchedule(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.schedules, id)
	return nil
}

func (m *Memory) GetBaseline(_ context.Context, hostID string) (*Baseline, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.baselines[hostID]
	if !ok {
		return nil, ErrNotFound{"baseline", hostID}
	}
	return cloneBaseline(b), nil
}

func (m *Memory) SaveBaseline(_ context.Context, b *Baseline) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now().UTC()
	}
	m.baselines[b.HostID] = cloneBaseline(b)
	return nil
}

func (m *Memory) DeleteBaseline(_ context.Context, hostID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.baselines, hostID)
	return nil
}

func (m *Memory) ListBaselines(_ context.Context) ([]*Baseline, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Baseline, 0, len(m.baselines))
	for _, b := range m.baselines {
		out = append(out, cloneBaseline(b))
	}
	return out, nil
}

func cloneBaseline(b *Baseline) *Baseline {
	c := *b
	c.Digest = make(map[string][]string, len(b.Digest))
	for k, v := range b.Digest {
		c.Digest[k] = append([]string(nil), v...)
	}
	return &c
}

func (m *Memory) UpsertRule(_ context.Context, r *RuleRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *r
	m.rules[r.ID] = &cp
	return nil
}

func (m *Memory) ListRules(_ context.Context) ([]*RuleRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*RuleRecord, 0, len(m.rules))
	for _, r := range m.rules {
		cp := *r
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) GetRule(_ context.Context, id string) (*RuleRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.rules[id]
	if !ok {
		return nil, ErrNotFound{"rule", id}
	}
	cp := *r
	return &cp, nil
}

func (m *Memory) DeleteRule(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rules[id]; !ok {
		return ErrNotFound{"rule", id}
	}
	delete(m.rules, id)
	return nil
}

func (m *Memory) SetRuleEnabled(_ context.Context, id string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rules[id]
	if !ok {
		return ErrNotFound{"rule", id}
	}
	r.Enabled = enabled
	return nil
}

func (m *Memory) CreateCredential(_ context.Context, c *Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.ID == "" {
		c.ID = uuid.NewString()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	m.creds[c.ID] = cloneCred(c)
	return nil
}

func (m *Memory) GetCredential(_ context.Context, id string) (*Credential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.creds[id]
	if !ok {
		return nil, ErrNotFound{"credential", id}
	}
	return cloneCred(c), nil
}

func (m *Memory) ListCredentials(_ context.Context) ([]*Credential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Credential, 0, len(m.creds))
	for _, c := range m.creds {
		out = append(out, cloneCred(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) DeleteCredential(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.creds[id]; !ok {
		return ErrNotFound{"credential", id}
	}
	delete(m.creds, id)
	return nil
}

func cloneCred(c *Credential) *Credential {
	cp := *c
	cp.SecretEnc = append([]byte(nil), c.SecretEnc...)
	return &cp
}

func (m *Memory) CreateHost(_ context.Context, h *Host) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if h.ID == "" {
		h.ID = uuid.NewString()
	}
	if h.CreatedAt.IsZero() {
		h.CreatedAt = time.Now().UTC()
	}
	m.hosts[h.ID] = cloneHost(h)
	return nil
}

func (m *Memory) GetHost(_ context.Context, id string) (*Host, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h, ok := m.hosts[id]
	if !ok {
		return nil, ErrNotFound{"host", id}
	}
	return cloneHost(h), nil
}

func (m *Memory) ListHosts(_ context.Context) ([]*Host, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Host, 0, len(m.hosts))
	for _, h := range m.hosts {
		out = append(out, cloneHost(h))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) UpdateHost(_ context.Context, h *Host) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.hosts[h.ID]; !ok {
		return ErrNotFound{"host", h.ID}
	}
	m.hosts[h.ID] = cloneHost(h)
	return nil
}

func (m *Memory) DeleteHost(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.hosts[id]; !ok {
		return ErrNotFound{"host", id}
	}
	delete(m.hosts, id)
	return nil
}

func (m *Memory) CreateScan(_ context.Context, s *Scan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.ID == "" {
		s.ID = uuid.NewString()
	}
	m.scans[s.ID] = cloneScan(s)
	return nil
}

func (m *Memory) UpdateScan(_ context.Context, s *Scan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.scans[s.ID]; !ok {
		return ErrNotFound{"scan", s.ID}
	}
	m.scans[s.ID] = cloneScan(s)
	return nil
}

func (m *Memory) GetScan(_ context.Context, id string) (*Scan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.scans[id]
	if !ok {
		return nil, ErrNotFound{"scan", id}
	}
	return cloneScan(s), nil
}

func (m *Memory) ListScansByHost(_ context.Context, hostID string) ([]*Scan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Scan
	for _, s := range m.scans {
		if s.HostID == hostID {
			out = append(out, cloneScan(s))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out, nil
}

func (m *Memory) UpsertObservation(_ context.Context, o *Observation) (*Observation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	if byKey, ok := m.dedup[o.HostID]; ok {
		if id, ok := byKey[o.DedupKey]; ok {
			ex := m.obs[id]
			ex.LastSeen = now
			ex.Count++
			ex.Score = o.Score
			ex.Severity = o.Severity
			ex.Evidence = o.Evidence
			ex.ScanID = o.ScanID
			return cloneObs(ex), nil
		}
	}
	if o.ID == "" {
		o.ID = uuid.NewString()
	}
	if o.FirstSeen.IsZero() {
		o.FirstSeen = now
	}
	o.LastSeen = now
	o.Count = 1
	if o.Status == "" {
		o.Status = ObsOpen
	}
	m.obs[o.ID] = cloneObs(o)
	if m.dedup[o.HostID] == nil {
		m.dedup[o.HostID] = map[string]string{}
	}
	m.dedup[o.HostID][o.DedupKey] = o.ID
	return cloneObs(o), nil
}

func (m *Memory) ListObservations(_ context.Context, f ObservationFilter) ([]*Observation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Observation
	for _, o := range m.obs {
		if f.HostID != "" && o.HostID != f.HostID {
			continue
		}
		if f.Severity != "" && o.Severity != f.Severity {
			continue
		}
		if f.Status != "" && o.Status != f.Status {
			continue
		}
		if f.Source != "" && o.Source != f.Source {
			continue
		}
		if f.RuleID != "" && o.RuleID != f.RuleID {
			continue
		}
		if f.Query != "" && !matchesQuery(o, f.Query) {
			continue
		}
		out = append(out, cloneObs(o))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (m *Memory) GetObservation(_ context.Context, id string) (*Observation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	o, ok := m.obs[id]
	if !ok {
		return nil, ErrNotFound{"observation", id}
	}
	return cloneObs(o), nil
}

func (m *Memory) SetObservationStatus(_ context.Context, id, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.obs[id]
	if !ok {
		return ErrNotFound{"observation", id}
	}
	o.Status = status
	return nil
}

// matchesQuery is a naive substring search standing in for BM25 (Postgres).
func matchesQuery(o *Observation, q string) bool {
	q = strings.ToLower(q)
	if strings.Contains(strings.ToLower(o.Title), q) ||
		strings.Contains(strings.ToLower(o.RuleID), q) {
		return true
	}
	for _, v := range o.Evidence {
		if s, ok := v.(string); ok && strings.Contains(strings.ToLower(s), q) {
			return true
		}
	}
	return false
}

func cloneHost(h *Host) *Host {
	c := *h
	if h.Tags != nil {
		c.Tags = make(map[string]string, len(h.Tags))
		for k, v := range h.Tags {
			c.Tags[k] = v
		}
	}
	return &c
}

func cloneScan(s *Scan) *Scan { c := *s; return &c }

func cloneObs(o *Observation) *Observation {
	c := *o
	if o.Mitre != nil {
		c.Mitre = append([]string(nil), o.Mitre...)
	}
	if o.Evidence != nil {
		c.Evidence = make(map[string]any, len(o.Evidence))
		for k, v := range o.Evidence {
			c.Evidence[k] = v
		}
	}
	return &c
}

// --- users + sessions ---

func (m *Memory) CreateUser(_ context.Context, u *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	for _, e := range m.users {
		if e.Username == u.Username {
			return ErrNotFound{"user (duplicate username)", u.Username}
		}
	}
	cp := *u
	m.users[u.ID] = &cp
	return nil
}

func (m *Memory) GetUser(_ context.Context, id string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if u, ok := m.users[id]; ok {
		cp := *u
		return &cp, nil
	}
	return nil, ErrNotFound{"user", id}
}

func (m *Memory) GetUserByName(_ context.Context, username string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, u := range m.users {
		if u.Username == username {
			cp := *u
			return &cp, nil
		}
	}
	return nil, ErrNotFound{"user", username}
}

func (m *Memory) ListUsers(_ context.Context) ([]*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*User, 0, len(m.users))
	for _, u := range m.users {
		cp := *u
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

func (m *Memory) UpdateUser(_ context.Context, u *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[u.ID]; !ok {
		return ErrNotFound{"user", u.ID}
	}
	cp := *u
	m.users[u.ID] = &cp
	return nil
}

func (m *Memory) DeleteUser(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.users, id)
	for tok, s := range m.sessions { // revoke the user's sessions
		if s.UserID == id {
			delete(m.sessions, tok)
		}
	}
	return nil
}

func (m *Memory) CountUsers(_ context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.users), nil
}

func (m *Memory) CreateSession(_ context.Context, s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *s
	m.sessions[s.Token] = &cp
	return nil
}

func (m *Memory) SessionUser(_ context.Context, token string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[token]
	if !ok || time.Now().After(s.ExpiresAt) {
		return nil, ErrNotFound{"session", ""}
	}
	if u, ok := m.users[s.UserID]; ok {
		cp := *u
		return &cp, nil
	}
	return nil, ErrNotFound{"session user", ""}
}

func (m *Memory) DeleteSession(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, token)
	return nil
}

// --- audit log ---

func (m *Memory) AppendAudit(_ context.Context, e *AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.ID == "" {
		e.ID = uuid.NewString()
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	cp := *e
	m.audit = append(m.audit, &cp)
	if len(m.audit) > 5000 { // cap the in-memory log
		m.audit = m.audit[len(m.audit)-5000:]
	}
	return nil
}

func (m *Memory) ListAudit(_ context.Context, limit int) ([]*AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > len(m.audit) {
		limit = len(m.audit)
	}
	out := make([]*AuditEvent, 0, limit)
	for i := len(m.audit) - 1; i >= 0 && len(out) < limit; i-- { // newest first
		cp := *m.audit[i]
		out = append(out, &cp)
	}
	return out, nil
}

// Ping always succeeds for the in-memory store.
func (m *Memory) Ping(_ context.Context) error { return nil }

// DeleteExpiredSessions removes sessions whose expiry has passed.
func (m *Memory) DeleteExpiredSessions(_ context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	n := 0
	for tok, s := range m.sessions {
		if now.After(s.ExpiresAt) {
			delete(m.sessions, tok)
			n++
		}
	}
	return n, nil
}
