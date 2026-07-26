package store

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Memory is an in-memory Store for development and tests.
type Memory struct {
	mu         sync.RWMutex
	hosts      map[string]*Host
	creds      map[string]*Credential
	scans      map[string]*Scan
	scanJobs   map[string]*ScanJob
	obs        map[string]*Observation
	exports    map[string]*ExportTarget
	deliveries map[string]*ExportDelivery
	rules      map[string]*RuleRecord
	baselines  map[string]*Baseline
	schedules  map[string]*Schedule
	colls      map[string]*Collection
	collMem    map[string]map[string]bool // collectionID -> set of hostIDs (static)
	users      map[string]*User           // by id
	sessions   map[string]*Session        // by token digest
	sensorTok  map[string]*SensorToken    // by token digest
	audit      []*AuditEvent
	archive    []*ArchivedRecord
	responses  map[string]*ResponseAction
	// dedup index: hostID -> dedupKey -> observation id
	dedup map[string]map[string]string
	SelfApprovalPolicy
}

func NewMemory() *Memory {
	return &Memory{
		hosts:      map[string]*Host{},
		creds:      map[string]*Credential{},
		scans:      map[string]*Scan{},
		scanJobs:   map[string]*ScanJob{},
		obs:        map[string]*Observation{},
		exports:    map[string]*ExportTarget{},
		deliveries: map[string]*ExportDelivery{},
		rules:      map[string]*RuleRecord{},
		baselines:  map[string]*Baseline{},
		schedules:  map[string]*Schedule{},
		colls:      map[string]*Collection{},
		collMem:    map[string]map[string]bool{},
		users:      map[string]*User{},
		sessions:   map[string]*Session{},
		sensorTok:  map[string]*SensorToken{},
		audit:      []*AuditEvent{},
		archive:    []*ArchivedRecord{},
		responses:  map[string]*ResponseAction{},
		dedup:      map[string]map[string]string{},
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

func cloneScanJob(j *ScanJob) *ScanJob {
	cp := *j
	if j.LeaseUntil != nil {
		t := *j.LeaseUntil
		cp.LeaseUntil = &t
	}
	return &cp
}

func (m *Memory) EnqueueScanJob(_ context.Context, job *ScanJob) (*ScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.hosts[job.HostID]; !ok {
		return nil, ErrNotFound{"host", job.HostID}
	}
	for _, existing := range m.scanJobs {
		if existing.HostID == job.HostID && (existing.Status == ScanJobQueued || existing.Status == ScanJobRunning) {
			return cloneScanJob(existing), nil
		}
	}
	now := time.Now().UTC()
	if job.ID == "" {
		job.ID = uuid.NewString()
	}
	if job.Status == "" {
		job.Status = ScanJobQueued
	}
	if job.MaxAttempts <= 0 {
		job.MaxAttempts = 3
	}
	if job.NextAttemptAt.IsZero() {
		job.NextAttemptAt = now
	}
	if job.CreatedAt.IsZero() {
		job.CreatedAt = now
	}
	job.UpdatedAt = now
	m.scanJobs[job.ID] = cloneScanJob(job)
	return cloneScanJob(job), nil
}

func (m *Memory) GetScanJob(_ context.Context, id string) (*ScanJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if j, ok := m.scanJobs[id]; ok {
		return cloneScanJob(j), nil
	}
	return nil, ErrNotFound{"scan job", id}
}

func (m *Memory) ListScanJobs(_ context.Context, hostID string, limit int) ([]*ScanJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*ScanJob
	for _, j := range m.scanJobs {
		if hostID == "" || j.HostID == hostID {
			out = append(out, cloneScanJob(j))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) ClaimScanJob(_ context.Context, workerID string, now time.Time, lease time.Duration) (*ScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var candidates []*ScanJob
	for _, j := range m.scanJobs {
		queued := j.Status == ScanJobQueued && !j.NextAttemptAt.After(now)
		expired := j.Status == ScanJobRunning && j.LeaseUntil != nil && !j.LeaseUntil.After(now)
		if queued || expired {
			candidates = append(candidates, j)
		}
	}
	if len(candidates) == 0 {
		return nil, ErrNotFound{"scan job", "claimable"}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].CreatedAt.Before(candidates[j].CreatedAt) })
	j := candidates[0]
	until := now.Add(lease)
	j.Status, j.WorkerID, j.LeaseUntil = ScanJobRunning, workerID, &until
	j.Attempts++
	j.UpdatedAt = now
	return cloneScanJob(j), nil
}

func (m *Memory) RenewScanJobLease(_ context.Context, id, workerID string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.scanJobs[id]
	if !ok || j.Status != ScanJobRunning || j.WorkerID != workerID {
		return ErrNotFound{"owned scan job", id}
	}
	j.LeaseUntil, j.UpdatedAt = &until, time.Now().UTC()
	return nil
}

func (m *Memory) CompleteScanJob(_ context.Context, id, workerID, scanID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.scanJobs[id]
	if !ok || j.Status != ScanJobRunning || j.WorkerID != workerID {
		return ErrNotFound{"owned scan job", id}
	}
	j.Status, j.ScanID, j.Error = ScanJobSucceeded, scanID, ""
	j.WorkerID, j.LeaseUntil, j.UpdatedAt = "", nil, time.Now().UTC()
	return nil
}

func (m *Memory) FailScanJob(_ context.Context, id, workerID, message string, retryAt time.Time, terminal bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.scanJobs[id]
	if !ok || j.Status != ScanJobRunning || j.WorkerID != workerID {
		return ErrNotFound{"owned scan job", id}
	}
	if terminal {
		j.Status = ScanJobFailed
	} else {
		j.Status = ScanJobQueued
		j.NextAttemptAt = retryAt
	}
	j.Error, j.WorkerID, j.LeaseUntil, j.UpdatedAt = message, "", nil, time.Now().UTC()
	return nil
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
			m.enqueueExportsLocked(ex.ID, now)
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
	m.enqueueExportsLocked(o.ID, now)
	return cloneObs(o), nil
}

func (m *Memory) enqueueExportsLocked(observationID string, now time.Time) {
	for _, target := range m.exports {
		if !target.Enabled {
			continue
		}
		d := &ExportDelivery{
			ID: uuid.NewString(), TargetID: target.ID, ObservationID: observationID,
			Status: DeliveryQueued, MaxAttempts: 10, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
		}
		m.deliveries[d.ID] = d
	}
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
		if !f.BeforeTime.IsZero() {
			if o.LastSeen.After(f.BeforeTime) || (o.LastSeen.Equal(f.BeforeTime) && o.ID >= f.BeforeID) {
				continue
			}
		}
		out = append(out, cloneObs(o))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].ID > out[j].ID
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
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

func cloneExportTarget(t *ExportTarget) *ExportTarget {
	cp := *t
	cp.SecretEnc = append([]byte(nil), t.SecretEnc...)
	cp.Config = map[string]string{}
	for k, v := range t.Config {
		cp.Config[k] = v
	}
	return &cp
}

func cloneDelivery(d *ExportDelivery) *ExportDelivery {
	cp := *d
	if d.LeaseUntil != nil {
		t := *d.LeaseUntil
		cp.LeaseUntil = &t
	}
	if d.DeliveredAt != nil {
		t := *d.DeliveredAt
		cp.DeliveredAt = &t
	}
	return &cp
}

func (m *Memory) CreateExportTarget(_ context.Context, t *ExportTarget) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
	m.exports[t.ID] = cloneExportTarget(t)
	return nil
}

func (m *Memory) GetExportTarget(_ context.Context, id string) (*ExportTarget, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if t, ok := m.exports[id]; ok {
		return cloneExportTarget(t), nil
	}
	return nil, ErrNotFound{"export target", id}
}

func (m *Memory) ListExportTargets(_ context.Context) ([]*ExportTarget, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*ExportTarget
	for _, t := range m.exports {
		out = append(out, cloneExportTarget(t))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Memory) UpdateExportTarget(_ context.Context, t *ExportTarget) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.exports[t.ID]; !ok {
		return ErrNotFound{"export target", t.ID}
	}
	t.UpdatedAt = time.Now().UTC()
	m.exports[t.ID] = cloneExportTarget(t)
	return nil
}

func (m *Memory) DeleteExportTarget(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.exports[id]; !ok {
		return ErrNotFound{"export target", id}
	}
	delete(m.exports, id)
	for deliveryID, d := range m.deliveries {
		if d.TargetID == id {
			delete(m.deliveries, deliveryID)
		}
	}
	return nil
}

func (m *Memory) ClaimExportDelivery(_ context.Context, workerID string, now time.Time, lease time.Duration) (*ExportDelivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var candidates []*ExportDelivery
	for _, d := range m.deliveries {
		target := m.exports[d.TargetID]
		if target == nil || !target.Enabled {
			continue
		}
		queued := d.Status == DeliveryQueued && !d.AvailableAt.After(now)
		expired := d.Status == DeliveryDelivering && d.LeaseUntil != nil && !d.LeaseUntil.After(now)
		if queued || expired {
			candidates = append(candidates, d)
		}
	}
	if len(candidates) == 0 {
		return nil, ErrNotFound{"export delivery", "claimable"}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].CreatedAt.Before(candidates[j].CreatedAt) })
	d := candidates[0]
	until := now.Add(lease)
	d.Status, d.WorkerID, d.LeaseUntil = DeliveryDelivering, workerID, &until
	d.Attempts++
	d.UpdatedAt = now
	return cloneDelivery(d), nil
}

func (m *Memory) RenewExportDeliveryLease(_ context.Context, id, workerID string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.deliveries[id]
	if !ok || d.Status != DeliveryDelivering || d.WorkerID != workerID {
		return ErrNotFound{"owned export delivery", id}
	}
	d.LeaseUntil, d.UpdatedAt = &until, time.Now().UTC()
	return nil
}

func (m *Memory) CompleteExportDelivery(_ context.Context, id, workerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.deliveries[id]
	if !ok || d.Status != DeliveryDelivering || d.WorkerID != workerID {
		return ErrNotFound{"owned export delivery", id}
	}
	now := time.Now().UTC()
	d.Status, d.WorkerID, d.LeaseUntil, d.LastError = DeliverySent, "", nil, ""
	d.DeliveredAt, d.UpdatedAt = &now, now
	return nil
}

func (m *Memory) FailExportDelivery(_ context.Context, id, workerID, message string, retryAt time.Time, terminal bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.deliveries[id]
	if !ok || d.Status != DeliveryDelivering || d.WorkerID != workerID {
		return ErrNotFound{"owned export delivery", id}
	}
	d.Status = DeliveryQueued
	if terminal {
		d.Status = DeliveryDead
	}
	d.LastError, d.AvailableAt, d.WorkerID, d.LeaseUntil, d.UpdatedAt = message, retryAt, "", nil, time.Now().UTC()
	return nil
}

func (m *Memory) ListDeadExportDeliveries(_ context.Context, limit int) ([]*ExportDelivery, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*ExportDelivery
	for _, d := range m.deliveries {
		if d.Status == DeliveryDead {
			out = append(out, cloneDelivery(d))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Memory) RetryExportDelivery(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.deliveries[id]
	if !ok || d.Status != DeliveryDead {
		return ErrNotFound{"dead export delivery", id}
	}
	d.Status, d.Attempts, d.LastError = DeliveryQueued, 0, ""
	d.AvailableAt, d.UpdatedAt = time.Now().UTC(), time.Now().UTC()
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
	cp := cloneUser(u)
	m.users[u.ID] = cp
	return nil
}

func cloneUser(u *User) *User {
	cp := *u
	cp.MFASecretEnc = append([]byte(nil), u.MFASecretEnc...)
	return &cp
}

func (m *Memory) GetUser(_ context.Context, id string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if u, ok := m.users[id]; ok {
		return cloneUser(u), nil
	}
	return nil, ErrNotFound{"user", id}
}

func (m *Memory) GetUserByName(_ context.Context, username string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, u := range m.users {
		if u.Username == username {
			return cloneUser(u), nil
		}
	}
	return nil, ErrNotFound{"user", username}
}

func (m *Memory) ListUsers(_ context.Context) ([]*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, cloneUser(u))
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
	m.users[u.ID] = cloneUser(u)
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
	m.sessions[s.TokenHash] = &cp
	return nil
}

func (m *Memory) SessionUser(_ context.Context, tokenHash string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[tokenHash]
	if !ok || time.Now().After(s.ExpiresAt) {
		return nil, ErrNotFound{"session", ""}
	}
	if u, ok := m.users[s.UserID]; ok {
		return cloneUser(u), nil
	}
	return nil, ErrNotFound{"session user", ""}
}

func (m *Memory) DeleteSession(_ context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, tokenHash)
	return nil
}

func (m *Memory) CreateSensorToken(_ context.Context, t *SensorToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.hosts[t.HostID]; !ok {
		return ErrNotFound{"host", t.HostID}
	}
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	cp := *t
	m.sensorTok[t.TokenHash] = &cp
	return nil
}

func (m *Memory) SensorTokenValid(_ context.Context, hostID, tokenHash string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.sensorTok[tokenHash]
	if !ok || t.HostID != hostID || t.RevokedAt != nil {
		return false, nil
	}
	return t.ExpiresAt == nil || time.Now().Before(*t.ExpiresAt), nil
}

func (m *Memory) ListSensorTokens(_ context.Context, hostID string) ([]*SensorToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*SensorToken
	for _, t := range m.sensorTok {
		if t.HostID == hostID {
			cp := *t
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *Memory) RevokeSensorToken(_ context.Context, hostID, tokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.sensorTok {
		if t.ID == tokenID && t.HostID == hostID {
			if t.RevokedAt == nil {
				now := time.Now().UTC()
				t.RevokedAt = &now
			}
			return nil
		}
	}
	return ErrNotFound{"sensor token", tokenID}
}

func (m *Memory) RevokeOtherSensorTokens(_ context.Context, hostID, keepTokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for _, t := range m.sensorTok {
		if t.HostID == hostID && t.ID != keepTokenID && t.RevokedAt == nil {
			t.RevokedAt = &now
		}
	}
	return nil
}

func (m *Memory) RevokeSensorTokens(_ context.Context, hostID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for _, t := range m.sensorTok {
		if t.HostID == hostID && t.RevokedAt == nil {
			t.RevokedAt = &now
		}
	}
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

func (m *Memory) ListAudit(ctx context.Context, limit int) ([]*AuditEvent, error) {
	return m.ListAuditPage(ctx, AuditFilter{Limit: limit})
}

func (m *Memory) ListAuditPage(_ context.Context, filter AuditFilter) ([]*AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit := filter.Limit
	if limit <= 0 || limit > len(m.audit) {
		limit = len(m.audit)
	}
	out := make([]*AuditEvent, 0, limit)
	for i := len(m.audit) - 1; i >= 0 && len(out) < limit; i-- { // newest first
		e := m.audit[i]
		if !filter.BeforeTime.IsZero() && (e.Time.After(filter.BeforeTime) || (e.Time.Equal(filter.BeforeTime) && e.ID >= filter.BeforeID)) {
			continue
		}
		cp := *e
		out = append(out, &cp)
	}
	return out, nil
}

func (m *Memory) archiveLocked(kind, originalID string, value any, now time.Time) {
	payload, _ := json.Marshal(value)
	m.archive = append(m.archive, &ArchivedRecord{
		ID: uuid.NewString(), Kind: kind, OriginalID: originalID, ArchivedAt: now, Payload: payload,
	})
}

func (m *Memory) ApplyRetention(_ context.Context, policy RetentionPolicy) (RetentionResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	var result RetentionResult
	if policy.ObservationAge > 0 {
		cutoff := now.Add(-policy.ObservationAge)
		for id, o := range m.obs {
			terminal := o.Status == ObsResolved || o.Status == ObsFalsePositive
			if terminal && o.LastSeen.Before(cutoff) {
				m.archiveLocked("observation", id, o, now)
				delete(m.obs, id)
				if byKey := m.dedup[o.HostID]; byKey != nil {
					delete(byKey, o.DedupKey)
				}
				result.Observations++
			}
		}
	}
	if policy.ScanAge > 0 {
		cutoff := now.Add(-policy.ScanAge)
		for id, scan := range m.scans {
			if scan.StartedAt.Before(cutoff) {
				m.archiveLocked("scan", id, scan, now)
				delete(m.scans, id)
				result.Scans++
			}
		}
	}
	if policy.AuditAge > 0 {
		cutoff := now.Add(-policy.AuditAge)
		kept := m.audit[:0]
		for _, event := range m.audit {
			if event.Time.Before(cutoff) {
				m.archiveLocked("audit", event.ID, event, now)
				result.Audit++
			} else {
				kept = append(kept, event)
			}
		}
		m.audit = kept
	}
	if policy.ArchiveAge > 0 {
		cutoff := now.Add(-policy.ArchiveAge)
		kept := m.archive[:0]
		for _, record := range m.archive {
			if record.ArchivedAt.Before(cutoff) {
				result.Archive++
			} else {
				kept = append(kept, record)
			}
		}
		m.archive = kept
	}
	return result, nil
}

func (m *Memory) ListArchive(_ context.Context, kind string, limit int) ([]*ArchivedRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []*ArchivedRecord
	for i := len(m.archive) - 1; i >= 0 && len(out) < limit; i-- {
		record := m.archive[i]
		if kind != "" && record.Kind != kind {
			continue
		}
		cp := *record
		cp.Payload = append(json.RawMessage(nil), record.Payload...)
		out = append(out, &cp)
	}
	return out, nil
}

func cloneResponseAction(action *ResponseAction) *ResponseAction {
	cp := *action
	cp.Params = map[string]string{}
	for key, value := range action.Params {
		cp.Params[key] = value
	}
	cp.LeaseUntil = cloneTime(action.LeaseUntil)
	cp.ApprovedAt = cloneTime(action.ApprovedAt)
	cp.StartedAt = cloneTime(action.StartedAt)
	cp.FinishedAt = cloneTime(action.FinishedAt)
	return &cp
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cp := *value
	return &cp
}

func (m *Memory) CreateResponseAction(_ context.Context, action *ResponseAction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.hosts[action.HostID]; !ok {
		return ErrNotFound{"host", action.HostID}
	}
	now := time.Now().UTC()
	if action.ID == "" {
		action.ID = uuid.NewString()
	}
	if action.Status == "" {
		action.Status = ResponsePending
	}
	if action.CreatedAt.IsZero() {
		action.CreatedAt = now
	}
	action.UpdatedAt = now
	m.responses[action.ID] = cloneResponseAction(action)
	return nil
}

func (m *Memory) GetResponseAction(_ context.Context, id string) (*ResponseAction, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if action, ok := m.responses[id]; ok {
		return cloneResponseAction(action), nil
	}
	return nil, ErrNotFound{"response action", id}
}

func (m *Memory) ListResponseActions(_ context.Context, hostID string, limit int) ([]*ResponseAction, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var out []*ResponseAction
	for _, action := range m.responses {
		if hostID == "" || action.HostID == hostID {
			out = append(out, cloneResponseAction(action))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ApproveResponseAction enforces two-person control: the approver must differ from
// the requester. The check lives in the store rather than the handler so every entry
// point — API, future CLI, background reconciliation — is covered by one rule.
func (m *Memory) ApproveResponseAction(_ context.Context, id, approver string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	action, ok := m.responses[id]
	if !ok || action.Status != ResponsePending {
		return ErrNotFound{"pending response action", id}
	}
	if action.RequestedBy == approver && !m.AllowSelfApproval {
		return ErrSelfApproval{ID: id, Actor: approver}
	}
	now := time.Now().UTC()
	action.Status, action.ApprovedBy, action.ApprovedAt, action.UpdatedAt = ResponseApproved, approver, &now, now
	return nil
}

// RejectResponseAction closes a pending request without touching the host. Unlike
// approval this is allowed for the requester, who may withdraw their own request.
func (m *Memory) RejectResponseAction(_ context.Context, id, rejector, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	action, ok := m.responses[id]
	if !ok || action.Status != ResponsePending {
		return ErrNotFound{"pending response action", id}
	}
	now := time.Now().UTC()
	action.Status, action.RejectedBy, action.RejectReason = ResponseRejected, rejector, reason
	action.RejectedAt, action.FinishedAt, action.UpdatedAt = &now, &now, now
	return nil
}

func (m *Memory) ClaimResponseAction(_ context.Context, workerID string, now time.Time, lease time.Duration) (*ResponseAction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var candidates []*ResponseAction
	for _, action := range m.responses {
		approved := action.Status == ResponseApproved
		expired := action.Status == ResponseRunning && action.LeaseUntil != nil && !action.LeaseUntil.After(now)
		if approved || expired {
			candidates = append(candidates, action)
		}
	}
	if len(candidates) == 0 {
		return nil, ErrNotFound{"response action", "claimable"}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].CreatedAt.Before(candidates[j].CreatedAt) })
	action := candidates[0]
	until := now.Add(lease)
	action.Status, action.WorkerID, action.LeaseUntil, action.UpdatedAt = ResponseRunning, workerID, &until, now
	if action.StartedAt == nil {
		action.StartedAt = &now
	}
	return cloneResponseAction(action), nil
}

func (m *Memory) RenewResponseActionLease(_ context.Context, id, workerID string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	action, ok := m.responses[id]
	if !ok || action.Status != ResponseRunning || action.WorkerID != workerID {
		return ErrNotFound{"owned response action", id}
	}
	action.LeaseUntil, action.UpdatedAt = &until, time.Now().UTC()
	return nil
}

func (m *Memory) CompleteResponseAction(_ context.Context, id, workerID, output string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	action, ok := m.responses[id]
	if !ok || action.Status != ResponseRunning || action.WorkerID != workerID {
		return ErrNotFound{"owned response action", id}
	}
	now := time.Now().UTC()
	action.Status, action.Output, action.Error = ResponseSucceeded, output, ""
	action.WorkerID, action.LeaseUntil, action.FinishedAt, action.UpdatedAt = "", nil, &now, now
	return nil
}

func (m *Memory) FailResponseAction(_ context.Context, id, workerID, message string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	action, ok := m.responses[id]
	if !ok || action.Status != ResponseRunning || action.WorkerID != workerID {
		return ErrNotFound{"owned response action", id}
	}
	now := time.Now().UTC()
	action.Status, action.Error = ResponseFailed, message
	action.WorkerID, action.LeaseUntil, action.FinishedAt, action.UpdatedAt = "", nil, &now, now
	return nil
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
