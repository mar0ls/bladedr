// Package api exposes the bladedr REST API (DESIGN section 6).
package api

import (
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"bladedr/internal/export"
	"bladedr/internal/risk"
	"bladedr/internal/rules"
	"bladedr/internal/scan"
	"bladedr/internal/secrets"
	"bladedr/internal/sensor"
	"bladedr/internal/store"
)

//go:embed openapi.yaml
var openAPIFS embed.FS

type API struct {
	Store     store.Store
	Runner    *scan.Runner
	Queue     *scan.Queue
	Responses *scan.ResponseQueue
	Crypto    *secrets.Crypto // seals credential secrets; nil disables credential writes
	// ActiveRules returns the merged active rule set (builtin ∪ dir ∪ DB).
	ActiveRules func(context.Context) ([]rules.Rule, error)
	// RiskDataset is an optional poligon dataset.jsonl of labelled lab examples (see
	// cmd/bladedr-lab); when set, the risk model trains on prod triage + lab data.
	RiskDataset string
	// RiskAugment, when true, class-balances the scorer's training set via synthetic
	// augmentation. Scoring only — never the Evaluate CV, which would leak.
	RiskAugment     bool
	RetentionPolicy store.RetentionPolicy
	// TrustedProxies contains the explicitly configured reverse-proxy networks whose
	// forwarding headers may influence audit attribution and login throttling.
	TrustedProxies []*net.IPNet
	// SecureCookies marks the session cookie Secure (HTTPS-only). Enable behind TLS.
	SecureCookies bool
	// Policies is the eBPF TracingPolicy catalog the sensor ships (from
	// BLADEDR_POLICY_DIR), shown in the UI so operators can see runtime coverage.
	Policies []sensor.PolicyMeta

	loginLimiter *loginLimiter // per-IP login throttle, initialised by Routes
	metrics      *metrics      // HTTP metrics collector, initialised by Routes
}

func (a *API) Routes() http.Handler {
	if a.loginLimiter == nil {
		a.loginLimiter = newLoginLimiter()
	}
	if a.metrics == nil {
		a.metrics = newMetrics()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /readyz", a.readyz)
	mux.HandleFunc("GET /metrics", a.serveMetrics)
	mux.HandleFunc("GET /openapi.yaml", a.serveOpenAPI)
	mux.HandleFunc("GET /api/v1/hosts", a.listHosts)
	mux.HandleFunc("POST /api/v1/hosts", a.createHost)
	mux.HandleFunc("GET /api/v1/hosts/{id}", a.getHost)
	mux.HandleFunc("PATCH /api/v1/hosts/{id}", a.patchHost)
	mux.HandleFunc("DELETE /api/v1/hosts/{id}", a.deleteHost)
	mux.HandleFunc("POST /api/v1/hosts/{id}/scans", a.triggerScan)
	mux.HandleFunc("GET /api/v1/hosts/{id}/scans", a.listScans)
	mux.HandleFunc("GET /api/v1/hosts/{id}/baseline", a.getBaseline)
	mux.HandleFunc("DELETE /api/v1/hosts/{id}/baseline", a.resetBaseline)
	mux.HandleFunc("GET /api/v1/scans/{id}", a.getScan)
	mux.HandleFunc("GET /api/v1/scan-jobs", a.listScanJobs)
	mux.HandleFunc("GET /api/v1/scan-jobs/{id}", a.getScanJob)
	mux.HandleFunc("GET /api/v1/credentials", a.listCredentials)
	mux.HandleFunc("POST /api/v1/credentials", a.createCredential)
	mux.HandleFunc("DELETE /api/v1/credentials/{id}", a.deleteCredential)
	mux.HandleFunc("GET /api/v1/rules", a.listRules)
	mux.HandleFunc("GET /api/v1/rules/active", a.listActiveRules)
	mux.HandleFunc("GET /api/v1/policies", a.listPolicies)
	mux.HandleFunc("POST /api/v1/rules", a.createRule)
	mux.HandleFunc("PATCH /api/v1/rules/{id}", a.patchRule)
	mux.HandleFunc("DELETE /api/v1/rules/{id}", a.deleteRule)
	mux.HandleFunc("GET /api/v1/schedules", a.listSchedules)
	mux.HandleFunc("POST /api/v1/schedules", a.createSchedule)
	mux.HandleFunc("GET /api/v1/schedules/{id}", a.getSchedule)
	mux.HandleFunc("PATCH /api/v1/schedules/{id}", a.patchSchedule)
	mux.HandleFunc("DELETE /api/v1/schedules/{id}", a.deleteSchedule)
	mux.HandleFunc("POST /api/v1/schedules/{id}/run", a.runSchedule)
	mux.HandleFunc("GET /api/v1/collections", a.listCollections)
	mux.HandleFunc("POST /api/v1/collections", a.createCollection)
	mux.HandleFunc("GET /api/v1/collections/{id}", a.getCollection)
	mux.HandleFunc("PATCH /api/v1/collections/{id}", a.patchCollection)
	mux.HandleFunc("DELETE /api/v1/collections/{id}", a.deleteCollection)
	mux.HandleFunc("GET /api/v1/collections/{id}/hosts", a.collectionHosts)
	mux.HandleFunc("PUT /api/v1/collections/{id}/members/{host}", a.addCollectionMember)
	mux.HandleFunc("DELETE /api/v1/collections/{id}/members/{host}", a.removeCollectionMember)
	mux.HandleFunc("GET /api/v1/observations", a.listObservations)
	mux.HandleFunc("GET /api/v1/observations/{id}", a.getObservation)
	mux.HandleFunc("PATCH /api/v1/observations/{id}", a.patchObservation)
	mux.HandleFunc("POST /api/v1/observations/bulk", a.bulkObservations)
	mux.HandleFunc("POST /api/v1/hosts/{id}/sensor", a.hostSensor)
	mux.HandleFunc("GET /api/v1/hosts/{id}/sensor-tokens", a.listSensorTokens)
	mux.HandleFunc("POST /api/v1/hosts/{id}/sensor-tokens", a.createSensorToken)
	mux.HandleFunc("DELETE /api/v1/hosts/{id}/sensor-tokens/{token}", a.revokeSensorToken)
	mux.HandleFunc("POST /api/v1/hosts/{id}/events", a.ingestEvents)
	mux.HandleFunc("GET /api/v1/export/ecs", a.exportECS)
	mux.HandleFunc("GET /api/v1/export-targets", a.listExportTargets)
	mux.HandleFunc("POST /api/v1/export-targets", a.createExportTarget)
	mux.HandleFunc("GET /api/v1/export-targets/{id}", a.getExportTarget)
	mux.HandleFunc("PATCH /api/v1/export-targets/{id}", a.patchExportTarget)
	mux.HandleFunc("DELETE /api/v1/export-targets/{id}", a.deleteExportTarget)
	mux.HandleFunc("GET /api/v1/export-dlq", a.listExportDLQ)
	mux.HandleFunc("POST /api/v1/export-dlq/{id}/retry", a.retryExportDelivery)
	mux.HandleFunc("GET /api/v1/archive", a.listArchive)
	mux.HandleFunc("GET /api/v1/retention", a.getRetentionPolicy)
	mux.HandleFunc("POST /api/v1/retention/run", a.runRetention)
	mux.HandleFunc("GET /api/v1/responses", a.listResponses)
	mux.HandleFunc("POST /api/v1/responses", a.createResponse)
	mux.HandleFunc("GET /api/v1/responses/{id}", a.getResponse)
	mux.HandleFunc("POST /api/v1/responses/{id}/approve", a.approveResponse)
	mux.HandleFunc("POST /api/v1/responses/{id}/reject", a.rejectResponse)
	mux.HandleFunc("GET /api/v1/risk/stats", a.riskStats)
	mux.HandleFunc("GET /api/v1/risk/observations", a.riskObservations)
	// auth + user management
	mux.HandleFunc("POST /api/v1/login", a.login)
	mux.HandleFunc("POST /api/v1/logout", a.logout)
	mux.HandleFunc("GET /api/v1/me", a.me)
	mux.HandleFunc("POST /api/v1/me/mfa/setup", a.setupMFA)
	mux.HandleFunc("POST /api/v1/me/mfa/confirm", a.confirmMFA)
	mux.HandleFunc("DELETE /api/v1/me/mfa", a.disableMFA)
	mux.HandleFunc("GET /api/v1/users", a.listUsers)
	mux.HandleFunc("POST /api/v1/users", a.createUser)
	mux.HandleFunc("PATCH /api/v1/users/{id}", a.patchUser)
	mux.HandleFunc("DELETE /api/v1/users/{id}", a.deleteUser)
	mux.HandleFunc("GET /api/v1/audit", a.listAudit)
	a.registerUI(mux)
	// Every route except the public ones (login, healthz, login page) requires an
	// authenticated session; mutations and admin areas are gated by role (RBAC). The
	// outer observe wrapper records metrics + access logs for all requests.
	return a.observe(a.authMiddleware(mux))
}

func (a *API) serveOpenAPI(w http.ResponseWriter, _ *http.Request) {
	spec, err := openAPIFS.ReadFile("openapi.yaml")
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	// static embedded asset, not user-controlled data
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	_, _ = w.Write(spec)
}

func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// listPolicies returns the eBPF TracingPolicy catalog the sensor ships.
func (a *API) listPolicies(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.Policies)
}

// --- hosts ---

func (a *API) listHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := a.Store.ListHosts(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	// Optional ?tag=key=value filter (repeatable; host must match all).
	if tags := r.URL.Query()["tag"]; len(tags) > 0 {
		want := map[string]string{}
		for _, t := range tags {
			if k, v, ok := strings.Cut(t, "="); ok {
				want[k] = v
			}
		}
		filtered := hosts[:0]
		for _, h := range hosts {
			if hostHasTags(h.Tags, want) {
				filtered = append(filtered, h)
			}
		}
		hosts = filtered
	}
	writeJSON(w, http.StatusOK, hosts)
}

func hostHasTags(have, want map[string]string) bool {
	for k, v := range want {
		if have[k] != v {
			return false
		}
	}
	return true
}

// patchHost merges tags (a tag with an empty value deletes that key) and lets a
// few mutable fields be updated (hostname, mode). Other fields are managed by scans.
func (a *API) patchHost(w http.ResponseWriter, r *http.Request) {
	h, err := a.Store.GetHost(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	var in struct {
		Hostname *string           `json:"hostname"`
		Mode     *string           `json:"mode"`
		Tags     map[string]string `json:"tags"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Hostname != nil {
		h.Hostname = *in.Hostname
	}
	if in.Mode != nil {
		if *in.Mode != store.ModeScanOnly && *in.Mode != store.ModeScanPlusSensor {
			writeError(w, http.StatusBadRequest, "invalid mode")
			return
		}
		h.Mode = *in.Mode
	}
	if in.Tags != nil {
		if h.Tags == nil {
			h.Tags = map[string]string{}
		}
		for k, v := range in.Tags {
			if v == "" {
				delete(h.Tags, k)
			} else {
				h.Tags[k] = v
			}
		}
	}
	if err := a.Store.UpdateHost(r.Context(), h); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (a *API) createHost(w http.ResponseWriter, r *http.Request) {
	var in store.Host
	if !decode(w, r, &in) {
		return
	}
	if in.Hostname == "" && in.PrimaryIP == "" {
		writeError(w, http.StatusBadRequest, "hostname or primary_ip required")
		return
	}
	if in.SSHPort == 0 {
		in.SSHPort = 22
	}
	if in.Mode == "" {
		in.Mode = store.ModeScanOnly
	}
	in.Status = store.StatusPending
	if err := a.Store.CreateHost(r.Context(), &in); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, in)
}

func (a *API) getHost(w http.ResponseWriter, r *http.Request) {
	h, err := a.Store.GetHost(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (a *API) deleteHost(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteHost(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- scans ---

func (a *API) triggerScan(w http.ResponseWriter, r *http.Request) {
	h, err := a.Store.GetHost(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	if a.Queue == nil {
		writeError(w, http.StatusServiceUnavailable, "scan queue unavailable")
		return
	}
	job, err := a.Queue.Enqueue(r.Context(), h, store.TriggerAPI)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Location", "/api/v1/scan-jobs/"+job.ID)
	writeJSON(w, http.StatusAccepted, job)
}

func (a *API) getScanJob(w http.ResponseWriter, r *http.Request) {
	job, err := a.Store.GetScanJob(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (a *API) listScanJobs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	jobs, err := a.Store.ListScanJobs(r.Context(), r.URL.Query().Get("host"), limit)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, jobs)
}

func (a *API) listScans(w http.ResponseWriter, r *http.Request) {
	scans, err := a.Store.ListScansByHost(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

func (a *API) getScan(w http.ResponseWriter, r *http.Request) {
	sc, err := a.Store.GetScan(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

// --- baseline (drift engine) ---

func (a *API) getBaseline(w http.ResponseWriter, r *http.Request) {
	b, err := a.Store.GetBaseline(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, b)
}

// resetBaseline clears the host baseline; the next scan re-establishes it.
func (a *API) resetBaseline(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteBaseline(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- credentials ---

func (a *API) listCredentials(w http.ResponseWriter, r *http.Request) {
	creds, err := a.Store.ListCredentials(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, creds) // SecretEnc is json:"-", never exposed
}

func (a *API) createCredential(w http.ResponseWriter, r *http.Request) {
	if a.Crypto == nil {
		writeError(w, http.StatusServiceUnavailable, "credential sealing disabled: no node key configured")
		return
	}
	var body struct {
		Name     string `json:"name"`
		Username string `json:"username"`
		AuthType string `json:"auth_type"`
		Secret   string `json:"secret"` // private key PEM or password; write-only
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Username == "" || body.Secret == "" {
		writeError(w, http.StatusBadRequest, "username and secret required")
		return
	}
	switch body.AuthType {
	case store.AuthSSHKey, store.AuthPassword, store.AuthSSHAgent:
	case "":
		body.AuthType = store.AuthSSHKey
	default:
		writeError(w, http.StatusBadRequest, "invalid auth_type")
		return
	}
	sealed, err := a.Crypto.Seal([]byte(body.Secret))
	if err != nil {
		writeErr(w, err)
		return
	}
	c := &store.Credential{Name: body.Name, Username: body.Username, AuthType: body.AuthType, SecretEnc: sealed}
	if err := a.Store.CreateCredential(r.Context(), c); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, c) // secret not echoed back
}

func (a *API) deleteCredential(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteCredential(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- rules (user/DB-managed; merged with builtin at scan time) ---

func (a *API) listRules(w http.ResponseWriter, r *http.Request) {
	rs, err := a.Store.ListRules(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rs)
}

func (a *API) listActiveRules(w http.ResponseWriter, r *http.Request) {
	if a.ActiveRules == nil {
		writeError(w, http.StatusNotImplemented, "active rule set not available")
		return
	}
	rs, err := a.ActiveRules(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	enabled := make([]rules.Rule, 0, len(rs))
	for _, rule := range rs {
		if rule.IsEnabled() {
			enabled = append(enabled, rule)
		}
	}
	writeJSON(w, http.StatusOK, enabled)
}

// createRule accepts a single rule as YAML or JSON (JSON is valid YAML), validates
// it (metadata + CEL compilation), and stores it. Active on the next scan.
func (a *API) createRule(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	parsed, err := rules.ParseRules(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(parsed) != 1 {
		writeError(w, http.StatusBadRequest, "expected exactly one rule")
		return
	}
	rule := parsed[0]
	if err := rules.ValidateRule(rule); err != nil {
		writeError(w, http.StatusBadRequest, "invalid rule: "+err.Error())
		return
	}
	def, err := json.Marshal(rule)
	if err != nil {
		writeErr(w, err)
		return
	}
	rec := &store.RuleRecord{
		ID:         rule.ID,
		Source:     "user",
		Category:   rule.Category,
		Severity:   rule.Severity,
		Mitre:      rule.Mitre,
		Enabled:    rule.IsEnabled(),
		Definition: def,
	}
	if err := a.Store.UpsertRule(r.Context(), rec); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, rec)
}

func (a *API) patchRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled required")
		return
	}
	id := r.PathValue("id")
	err := a.Store.SetRuleEnabled(r.Context(), id, *body.Enabled)
	var nf store.ErrNotFound
	if errors.As(err, &nf) {
		// Not a DB rule — if it's a builtin, materialise a DB override carrying the
		// builtin's definition + the requested enabled flag, so the dashboard can
		// disable/enable builtins (deleting the override later reverts to the builtin).
		if rule := a.activeRule(r.Context(), id); rule != nil {
			def, _ := json.Marshal(rule)
			err = a.Store.UpsertRule(r.Context(), &store.RuleRecord{
				ID: id, Source: "user", Category: rule.Category, Severity: rule.Severity,
				Mitre: rule.Mitre, Enabled: *body.Enabled, Definition: def,
			})
		}
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// activeRule returns the merged (builtin∪dir∪DB) rule with the given id, or nil.
func (a *API) activeRule(ctx context.Context, id string) *rules.Rule {
	if a.ActiveRules == nil {
		return nil
	}
	rs, err := a.ActiveRules(ctx)
	if err != nil {
		return nil
	}
	for i := range rs {
		if rs[i].ID == id {
			return &rs[i]
		}
	}
	return nil
}

func (a *API) deleteRule(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteRule(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- observations ---

func (a *API) listObservations(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.ObservationFilter{
		HostID:   q.Get("host"),
		Severity: q.Get("severity"),
		Status:   q.Get("status"),
		Source:   q.Get("source"),
		RuleID:   q.Get("rule"),
		Query:    q.Get("q"),
	}
	limit := pageLimit(q.Get("limit"), 100)
	if cursor := q.Get("cursor"); cursor != "" {
		var err error
		f.BeforeTime, f.BeforeID, err = decodeCursor(cursor)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid cursor")
			return
		}
	}
	f.Limit = limit + 1
	obs, err := a.Store.ListObservations(r.Context(), f)
	if err != nil {
		writeErr(w, err)
		return
	}
	if len(obs) > limit {
		obs = obs[:limit]
		last := obs[len(obs)-1]
		w.Header().Set("X-Next-Cursor", encodeCursor(last.LastSeen, last.ID))
	}
	writeJSON(w, http.StatusOK, obs)
}

func (a *API) getObservation(w http.ResponseWriter, r *http.Request) {
	o, err := a.Store.GetObservation(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, o)
}

// bulkObservations sets the same status on many observations at once (the UI's
// multi-select triage). Best-effort: it applies to every id it can and returns
// how many succeeded.
func (a *API) bulkObservations(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs    []string `json:"ids"`
		Status string   `json:"status"`
	}
	if !decode(w, r, &body) {
		return
	}
	switch body.Status {
	case store.ObsOpen, store.ObsAcknowledged, store.ObsResolved, store.ObsFalsePositive:
	default:
		writeError(w, http.StatusBadRequest, "invalid status")
		return
	}
	updated := 0
	for _, id := range body.IDs {
		if err := a.Store.SetObservationStatus(r.Context(), id, body.Status); err == nil {
			updated++
		}
	}
	writeJSON(w, http.StatusOK, map[string]int{"updated": updated})
}

func (a *API) patchObservation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Status string `json:"status"`
	}
	if !decode(w, r, &body) {
		return
	}
	switch body.Status {
	case store.ObsOpen, store.ObsAcknowledged, store.ObsResolved, store.ObsFalsePositive:
	default:
		writeError(w, http.StatusBadRequest, "invalid status")
		return
	}
	if err := a.Store.SetObservationStatus(r.Context(), r.PathValue("id"), body.Status); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- risk scoring (explainable ML prioritiser; see internal/risk) ---

const (
	riskLabelsPerClass = 5_000
	riskOpenLimit      = 10_000
)

// labDataset loads the optional poligon dataset of technique-labelled examples.
// Best-effort: a missing/unset file yields no records, so the risk model degrades to
// prod-triage-only training. A malformed file is an error, not silence — a dataset
// that half-loaded would train the model on an arbitrary prefix of the lab run.
func (a *API) labDataset() ([]*store.Observation, error) {
	lab, err := risk.LoadDataset(a.RiskDataset)
	if err != nil {
		slog.Warn("risk dataset unavailable", "path", a.RiskDataset, "error", err)
	}
	return lab, err
}

// productionRiskLabels fetches each supervised class independently. A large open
// backlog therefore cannot evict triaged observations from the training window.
func (a *API) productionRiskLabels(ctx context.Context) ([]*store.Observation, error) {
	labels := make([]*store.Observation, 0, 2*riskLabelsPerClass)
	for _, status := range []string{store.ObsAcknowledged, store.ObsFalsePositive} {
		observations, err := a.Store.ListObservations(ctx, store.ObservationFilter{
			Status: status,
			Limit:  riskLabelsPerClass,
		})
		if err != nil {
			return nil, fmt.Errorf("list %s observations: %w", status, err)
		}
		labels = append(labels, observations...)
	}
	return labels, nil
}

// riskStats trains on prod triage + lab data and reports whether there is enough
// labelled, balanced, separable data to trust the model — the evidence behind
// Stats.Trustworthy, not just a score.
func (a *API) riskStats(w http.ResponseWriter, r *http.Request) {
	prod, err := a.productionRiskLabels(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	lab, err := a.labDataset()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "risk dataset unavailable")
		return
	}
	combined := append(append([]*store.Observation{}, prod...), lab...)
	labPos, labNeg := 0, 0
	for _, o := range lab {
		switch risk.LabelOf(o.Status) {
		case risk.Positive:
			labPos++
		case risk.Negative:
			labNeg++
		}
	}
	resp := struct {
		risk.Stats
		ProdLabeled  int `json:"prod_labeled"`
		LabPositives int `json:"lab_positives"`
		LabNegatives int `json:"lab_negatives"`
	}{
		Stats:        risk.Evaluate(combined),
		ProdLabeled:  len(prod),
		LabPositives: labPos,
		LabNegatives: labNeg,
	}
	writeJSON(w, http.StatusOK, resp)
}

// riskObservations ranks open observations using production triage and lab labels.
func (a *API) riskObservations(w http.ResponseWriter, r *http.Request) {
	open, err := a.Store.ListObservations(r.Context(), store.ObservationFilter{
		Status: store.ObsOpen,
		Limit:  riskOpenLimit,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	prod, err := a.productionRiskLabels(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	lab, err := a.labDataset()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "risk dataset unavailable")
		return
	}
	train := append(append([]*store.Observation{}, prod...), lab...)
	if a.RiskAugment {
		train = risk.Augment(train, 1)
	}
	m := risk.Train(train)
	type scored struct {
		*store.Observation
		Risk risk.Result `json:"risk"`
	}
	out := make([]scored, 0, len(open))
	for _, o := range open {
		out = append(out, scored{Observation: o, Risk: m.Score(o)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Risk.Priority != out[j].Risk.Priority {
			return out[i].Risk.Priority > out[j].Risk.Priority
		}
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].ID > out[j].ID
	})
	writeJSON(w, http.StatusOK, out)
}

// hostSensor enables (deploys Tetragon + the sensor over SSH) or disables the eBPF
// sensor on a host, from the dashboard. POST /api/v1/hosts/{id}/sensor {action}.
func (a *API) hostSensor(w http.ResponseWriter, r *http.Request) {
	host, err := a.Store.GetHost(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	var body struct {
		Action string `json:"action"`
	}
	if !decode(w, r, &body) {
		return
	}
	// Deploy involves an SSH upload + a Tetragon container start (image pull on first
	// run), so allow a generous timeout independent of the request.
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	switch body.Action {
	case "enable":
		err = a.Runner.EnableSensor(ctx, host)
	case "disable":
		err = a.Runner.DisableSensor(ctx, host)
	default:
		writeError(w, http.StatusBadRequest, "action must be enable or disable")
		return
	}
	if err != nil {
		a.audit(r, "sensor."+body.Action, host.ID, "fail", err.Error())
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	a.audit(r, "sensor."+body.Action, host.ID, "ok", "")
	writeJSON(w, http.StatusOK, map[string]string{"mode": host.Mode})
}

// listAudit returns recent security-audit events (admin-only). GET /api/v1/audit.
func (a *API) listAudit(w http.ResponseWriter, r *http.Request) {
	limit := pageLimit(r.URL.Query().Get("limit"), 100)
	filter := store.AuditFilter{Limit: limit + 1}
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		var err error
		filter.BeforeTime, filter.BeforeID, err = decodeCursor(cursor)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid cursor")
			return
		}
	}
	evs, err := a.Store.ListAuditPage(r.Context(), filter)
	if err != nil {
		writeErr(w, err)
		return
	}
	if len(evs) > limit {
		evs = evs[:limit]
		last := evs[len(evs)-1]
		w.Header().Set("X-Next-Cursor", encodeCursor(last.Time, last.ID))
	}
	writeJSON(w, http.StatusOK, evs)
}

// ingestEvents accepts a batch of eBPF-sensor observations for a host (the
// bladedr-sensor Tetragon wrapper posts these). The server forces HostID, Source
// and an open status — it trusts the sensor for the detection metadata (which it
// derives from the loaded policies) the same way it trusts the probe for findings.
// POST /api/v1/hosts/{id}/events.
func (a *API) ingestEvents(w http.ResponseWriter, r *http.Request) {
	host, err := a.Store.GetHost(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	var evs []store.Observation
	if !decodeLimited(w, r, &evs, maxIngestBodyBytes) {
		return
	}
	if len(evs) > maxIngestBatch {
		writeError(w, http.StatusRequestEntityTooLarge, "event batch exceeds 500 items")
		return
	}
	n := 0
	for i := range evs {
		o := evs[i]
		o.HostID = host.ID
		o.Source = store.SourceEBPFSensor
		o.Status = store.ObsOpen
		if o.RuleID == "" || o.DedupKey == "" {
			continue
		}
		if _, err := a.Store.UpsertObservation(r.Context(), &o); err == nil {
			n++
		}
	}
	writeJSON(w, http.StatusOK, map[string]int{"ingested": n})
}

// scheduleReq is the create/patch body. Interval accepts a Go duration string
// ("15m", "1h"); interval_s (seconds) is an alternative. host_id empty = all hosts.
type scheduleReq struct {
	Name         string `json:"name"`
	HostID       string `json:"host_id"`
	CollectionID string `json:"collection_id"`
	Interval     string `json:"interval"`
	IntervalS    int64  `json:"interval_s"`
	Enabled      *bool  `json:"enabled"`
}

// minScheduleInterval guards against hammering hosts with too-frequent scans.
const minScheduleInterval = 300 // 5m floor: agentless SSH+probe-upload scans should not run more often

// resolveInterval turns the request's interval/interval_s into seconds, or 0 if
// neither is set, or -1 if the duration string is invalid.
func (req scheduleReq) resolveInterval() int64 {
	if req.IntervalS > 0 {
		return req.IntervalS
	}
	if req.Interval != "" {
		d, err := time.ParseDuration(req.Interval)
		if err != nil {
			return -1
		}
		return int64(d.Seconds())
	}
	return 0
}

func (a *API) listSchedules(w http.ResponseWriter, r *http.Request) {
	scheds, err := a.Store.ListSchedules(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, scheds)
}

func (a *API) createSchedule(w http.ResponseWriter, r *http.Request) {
	var req scheduleReq
	if !decode(w, r, &req) {
		return
	}
	intervalS := req.resolveInterval()
	switch {
	case intervalS == -1:
		writeError(w, http.StatusBadRequest, "invalid interval (use a duration like \"15m\" or interval_s seconds)")
		return
	case intervalS == 0:
		writeError(w, http.StatusBadRequest, "interval or interval_s required")
		return
	case intervalS < minScheduleInterval:
		writeError(w, http.StatusBadRequest, "interval must be at least 5m (recommended 15m-1h)")
		return
	}
	if req.HostID != "" && req.CollectionID != "" {
		writeError(w, http.StatusBadRequest, "set at most one of host_id / collection_id (empty = all hosts)")
		return
	}
	if req.HostID != "" {
		if _, err := a.Store.GetHost(r.Context(), req.HostID); err != nil {
			writeErr(w, err)
			return
		}
	}
	if req.CollectionID != "" {
		if _, err := a.Store.GetCollection(r.Context(), req.CollectionID); err != nil {
			writeErr(w, err)
			return
		}
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	s := &store.Schedule{
		Name:         req.Name,
		HostID:       req.HostID,
		CollectionID: req.CollectionID,
		IntervalS:    intervalS,
		Enabled:      enabled,
		NextRun:      time.Now().UTC(), // fire on the next scheduler tick
	}
	if err := a.Store.CreateSchedule(r.Context(), s); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, s)
}

func (a *API) getSchedule(w http.ResponseWriter, r *http.Request) {
	s, err := a.Store.GetSchedule(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (a *API) patchSchedule(w http.ResponseWriter, r *http.Request) {
	s, err := a.Store.GetSchedule(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	var req scheduleReq
	if !decode(w, r, &req) {
		return
	}
	if req.Name != "" {
		s.Name = req.Name
	}
	if iv := req.resolveInterval(); iv > 0 {
		if iv < minScheduleInterval {
			writeError(w, http.StatusBadRequest, "interval must be at least 5m (recommended 15m-1h)")
			return
		}
		s.IntervalS = iv
	} else if iv == -1 {
		writeError(w, http.StatusBadRequest, "invalid interval")
		return
	}
	if req.Enabled != nil {
		s.Enabled = *req.Enabled
	}
	if err := a.Store.UpdateSchedule(r.Context(), s); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (a *API) deleteSchedule(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteSchedule(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// runSchedule enqueues a schedule's target scan(s) immediately and returns jobs,
// without waiting for the next tick (and without advancing NextRun).
func (a *API) runSchedule(w http.ResponseWriter, r *http.Request) {
	s, err := a.Store.GetSchedule(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	var hosts []*store.Host
	switch {
	case s.HostID != "":
		var h *store.Host
		if h, err = a.Store.GetHost(r.Context(), s.HostID); err == nil {
			hosts = []*store.Host{h}
		}
	case s.CollectionID != "":
		hosts, err = a.Store.CollectionHosts(r.Context(), s.CollectionID)
	default:
		hosts, err = a.Store.ListHosts(r.Context())
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	if a.Queue == nil {
		writeError(w, http.StatusServiceUnavailable, "scan queue unavailable")
		return
	}
	jobs := make([]*store.ScanJob, 0, len(hosts))
	for _, h := range hosts {
		job, err := a.Queue.Enqueue(r.Context(), h, store.TriggerManual)
		if err != nil {
			continue
		}
		jobs = append(jobs, job)
	}
	writeJSON(w, http.StatusAccepted, jobs)
}

// exportECS streams matching observations as ECS NDJSON (one JSON doc per line),
// the format Elasticsearch/Filebeat/Logstash and most SIEMs ingest directly.
// Filters mirror the observations API (host, severity, status, source, rule, q).
func (a *API) exportECS(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.ObservationFilter{
		HostID:   q.Get("host"),
		Severity: q.Get("severity"),
		Status:   q.Get("status"),
		Source:   q.Get("source"),
		RuleID:   q.Get("rule"),
		Query:    q.Get("q"),
	}
	if l := q.Get("limit"); l != "" {
		f.Limit, _ = strconv.Atoi(l)
	}
	obs, err := a.Store.ListObservations(r.Context(), f)
	if err != nil {
		writeErr(w, err)
		return
	}
	hosts, _ := a.Store.ListHosts(r.Context())
	byID := map[string]*store.Host{}
	for _, h := range hosts {
		byID[h.ID] = h
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)
	for _, o := range obs {
		if err := enc.Encode(export.ToECS(o, byID[o.HostID])); err != nil {
			return // client gone
		}
	}
}

type exportTargetRequest struct {
	Name    string            `json:"name"`
	Type    string            `json:"type"`
	Config  map[string]string `json:"config"`
	Secret  *string           `json:"secret"`
	Enabled *bool             `json:"enabled"`
}

func validateExportTarget(req exportTargetRequest) error {
	if strings.TrimSpace(req.Name) == "" {
		return errors.New("name is required")
	}
	for key := range req.Config {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "api_key") {
			return fmt.Errorf("secret configuration must use the write-only secret field, not config.%s", key)
		}
	}
	switch req.Type {
	case store.ExportWebhook, store.ExportElasticsearch:
		u, err := url.ParseRequestURI(req.Config["url"])
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("config.url must be an absolute http or https URL")
		}
	case store.ExportSyslog:
		network := req.Config["network"]
		if network != "" && network != "tcp" && network != "udp" {
			return errors.New("config.network must be tcp or udp")
		}
		if _, _, err := net.SplitHostPort(req.Config["address"]); err != nil {
			return errors.New("config.address must be host:port")
		}
	default:
		return errors.New("type must be webhook, elasticsearch, or syslog")
	}
	return nil
}

func (a *API) sealExportSecret(secret *string, current []byte) ([]byte, error) {
	if secret == nil {
		return current, nil
	}
	if *secret == "" {
		return nil, nil
	}
	if a.Crypto == nil {
		return nil, errors.New("secret encryption unavailable")
	}
	return a.Crypto.Seal([]byte(*secret))
}

func (a *API) listExportTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := a.Store.ListExportTargets(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, targets)
}

func (a *API) getExportTarget(w http.ResponseWriter, r *http.Request) {
	target, err := a.Store.GetExportTarget(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, target)
}

func (a *API) createExportTarget(w http.ResponseWriter, r *http.Request) {
	var req exportTargetRequest
	if !decode(w, r, &req) {
		return
	}
	if err := validateExportTarget(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	secret, err := a.sealExportSecret(req.Secret, nil)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	target := &store.ExportTarget{Name: strings.TrimSpace(req.Name), Type: req.Type, Config: req.Config, SecretEnc: secret, Enabled: enabled}
	if err := a.Store.CreateExportTarget(r.Context(), target); err != nil {
		writeErr(w, err)
		return
	}
	a.audit(r, "export_target.create", target.ID, "ok", "type="+target.Type)
	writeJSON(w, http.StatusCreated, target)
}

func (a *API) patchExportTarget(w http.ResponseWriter, r *http.Request) {
	target, err := a.Store.GetExportTarget(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	var req exportTargetRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Name != "" {
		target.Name = strings.TrimSpace(req.Name)
	}
	if req.Type != "" {
		target.Type = req.Type
	}
	if req.Config != nil {
		target.Config = req.Config
	}
	if req.Enabled != nil {
		target.Enabled = *req.Enabled
	}
	check := exportTargetRequest{Name: target.Name, Type: target.Type, Config: target.Config}
	if err := validateExportTarget(check); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	target.SecretEnc, err = a.sealExportSecret(req.Secret, target.SecretEnc)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if err := a.Store.UpdateExportTarget(r.Context(), target); err != nil {
		writeErr(w, err)
		return
	}
	a.audit(r, "export_target.update", target.ID, "ok", "")
	writeJSON(w, http.StatusOK, target)
}

func (a *API) deleteExportTarget(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteExportTarget(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	a.audit(r, "export_target.delete", r.PathValue("id"), "ok", "")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listExportDLQ(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := a.Store.ListDeadExportDeliveries(r.Context(), limit)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (a *API) retryExportDelivery(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.RetryExportDelivery(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	a.audit(r, "export_delivery.retry", r.PathValue("id"), "ok", "")
	w.WriteHeader(http.StatusAccepted)
}

type pageCursor struct {
	Time time.Time `json:"time"`
	ID   string    `json:"id"`
}

func pageLimit(raw string, fallback int) int {
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return fallback
	}
	if n > 500 {
		return 500
	}
	return n
}

func encodeCursor(t time.Time, id string) string {
	b, _ := json.Marshal(pageCursor{Time: t.UTC(), ID: id})
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(raw string) (time.Time, string, error) {
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return time.Time{}, "", err
	}
	var cursor pageCursor
	if err := json.Unmarshal(b, &cursor); err != nil || cursor.Time.IsZero() || cursor.ID == "" {
		return time.Time{}, "", errors.New("invalid cursor")
	}
	return cursor.Time, cursor.ID, nil
}

func (a *API) listArchive(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	if kind != "" && kind != "observation" && kind != "scan" && kind != "audit" {
		writeError(w, http.StatusBadRequest, "kind must be observation, scan, or audit")
		return
	}
	records, err := a.Store.ListArchive(r.Context(), kind, pageLimit(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, records)
}

func (a *API) getRetentionPolicy(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"observations": a.RetentionPolicy.ObservationAge.String(),
		"scans":        a.RetentionPolicy.ScanAge.String(),
		"audit":        a.RetentionPolicy.AuditAge.String(),
		"archive":      a.RetentionPolicy.ArchiveAge.String(),
	})
}

func (a *API) runRetention(w http.ResponseWriter, r *http.Request) {
	result, err := a.Store.ApplyRetention(r.Context(), a.RetentionPolicy)
	if err != nil {
		writeErr(w, err)
		return
	}
	a.audit(r, "retention.run", "", "ok", fmt.Sprintf("observations=%d scans=%d audit=%d archive=%d", result.Observations, result.Scans, result.Audit, result.Archive))
	writeJSON(w, http.StatusOK, result)
}

func (a *API) listResponses(w http.ResponseWriter, r *http.Request) {
	actions, err := a.Store.ListResponseActions(r.Context(), r.URL.Query().Get("host"), pageLimit(r.URL.Query().Get("limit"), 100))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, actions)
}

func (a *API) getResponse(w http.ResponseWriter, r *http.Request) {
	action, err := a.Store.GetResponseAction(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, action)
}

func (a *API) createResponse(w http.ResponseWriter, r *http.Request) {
	var body struct {
		HostID   string            `json:"host_id"`
		Playbook string            `json:"playbook"`
		Params   map[string]string `json:"params"`
		DryRun   *bool             `json:"dry_run"`
	}
	if !decode(w, r, &body) {
		return
	}
	if _, err := a.Store.GetHost(r.Context(), body.HostID); err != nil {
		writeErr(w, err)
		return
	}
	if err := scan.ValidateResponseRequest(body.Playbook, body.Params); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	dryRun := true
	if body.DryRun != nil {
		dryRun = *body.DryRun
	}
	actor := currentUser(r)
	if actor == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	action := &store.ResponseAction{
		HostID: body.HostID, Playbook: body.Playbook, Params: body.Params,
		DryRun: dryRun, Status: store.ResponsePending, RequestedBy: actor.Username,
	}
	if err := a.Store.CreateResponseAction(r.Context(), action); err != nil {
		writeErr(w, err)
		return
	}
	a.audit(r, "response.request", action.ID, "ok", "playbook="+action.Playbook+" dry_run="+strconv.FormatBool(action.DryRun))
	writeJSON(w, http.StatusCreated, action)
}

// approveResponse releases a pending action to the worker queue. Two-person control
// is enforced in the store; a refusal is audited, since an admin approving their own
// containment request is worth seeing in the log.
func (a *API) approveResponse(w http.ResponseWriter, r *http.Request) {
	actor := currentUser(r)
	if actor == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	id := r.PathValue("id")
	if err := a.Store.ApproveResponseAction(r.Context(), id, actor.Username); err != nil {
		var self store.ErrSelfApproval
		if errors.As(err, &self) {
			a.audit(r, "response.approve", id, "denied", "self-approval blocked")
		}
		writeErr(w, err)
		return
	}
	a.audit(r, "response.approve", id, "ok", "")
	action, _ := a.Store.GetResponseAction(r.Context(), id)
	writeJSON(w, http.StatusAccepted, action)
}

// rejectResponse closes a pending action without contacting the host. The requester
// may reject their own request — withdrawing is not a privilege escalation, unlike
// approving.
func (a *API) rejectResponse(w http.ResponseWriter, r *http.Request) {
	actor := currentUser(r)
	if actor == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if r.ContentLength != 0 && !decode(w, r, &body) {
		return
	}
	if len(body.Reason) > 1000 {
		writeError(w, http.StatusBadRequest, "reason must be at most 1000 characters")
		return
	}
	id := r.PathValue("id")
	if err := a.Store.RejectResponseAction(r.Context(), id, actor.Username, body.Reason); err != nil {
		writeErr(w, err)
		return
	}
	a.audit(r, "response.reject", id, "ok", body.Reason)
	action, _ := a.Store.GetResponseAction(r.Context(), id)
	writeJSON(w, http.StatusOK, action)
}

// --- collections ---

func (a *API) listCollections(w http.ResponseWriter, r *http.Request) {
	cs, err := a.Store.ListCollections(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cs)
}

func (a *API) createCollection(w http.ResponseWriter, r *http.Request) {
	var in store.Collection
	if !decode(w, r, &in) {
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if in.Dynamic && len(in.MatchTags) == 0 {
		writeError(w, http.StatusBadRequest, "dynamic collection requires match_tags")
		return
	}
	if err := a.Store.CreateCollection(r.Context(), &in); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, in)
}

func (a *API) getCollection(w http.ResponseWriter, r *http.Request) {
	c, err := a.Store.GetCollection(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (a *API) patchCollection(w http.ResponseWriter, r *http.Request) {
	c, err := a.Store.GetCollection(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	var in struct {
		Name        *string           `json:"name"`
		Description *string           `json:"description"`
		MatchTags   map[string]string `json:"match_tags"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Name != nil {
		c.Name = *in.Name
	}
	if in.Description != nil {
		c.Description = *in.Description
	}
	if in.MatchTags != nil {
		c.MatchTags = in.MatchTags
	}
	if err := a.Store.UpdateCollection(r.Context(), c); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (a *API) deleteCollection(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.DeleteCollection(r.Context(), r.PathValue("id")); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) collectionHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := a.Store.CollectionHosts(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (a *API) addCollectionMember(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.AddCollectionMember(r.Context(), r.PathValue("id"), r.PathValue("host")); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) removeCollectionMember(w http.ResponseWriter, r *http.Request) {
	if err := a.Store.RemoveCollectionMember(r.Context(), r.PathValue("id"), r.PathValue("host")); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeErr(w http.ResponseWriter, err error) {
	var nf store.ErrNotFound
	if errors.As(err, &nf) {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	// Self-approval is a policy conflict, not a bad request or a missing object: the
	// action exists and the payload is valid, only the actor is wrong.
	var self store.ErrSelfApproval
	if errors.As(err, &self) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeError(w, http.StatusInternalServerError, err.Error())
}

const (
	maxJSONBodyBytes   = 1 << 20 // ordinary API request
	maxIngestBodyBytes = 4 << 20 // a sensor batch may contain evidence payloads
	maxIngestBatch     = 500
)

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeLimited(w, r, v, maxJSONBodyBytes)
}

func decodeLimited(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, "request body must contain one JSON value")
		return false
	}
	return true
}
