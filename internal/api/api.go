// Package api exposes the bladedr REST API (DESIGN section 6).
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
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

type API struct {
	Store  store.Store
	Runner *scan.Runner
	Crypto *secrets.Crypto // seals credential secrets; nil disables credential writes
	// ActiveRules returns the merged active rule set (builtin ∪ dir ∪ DB).
	ActiveRules func(context.Context) ([]rules.Rule, error)
	// RiskDataset is an optional poligon dataset.jsonl of technique-labelled positives
	// (see cmd/bladedr-lab); when set, the risk model trains on prod triage + lab data.
	RiskDataset string
	// RiskAugment, when true, class-balances the scorer's training set via synthetic
	// augmentation (scoring only — never the Evaluate CV, which would leak).
	RiskAugment bool
	// IngestToken is the machine-to-machine bearer token(s) the eBPF sensors use to
	// POST events (no user session). May be a comma-separated list so a token can be
	// rotated with no downtime. Empty disables token-based ingest (then an operator
	// session is required like any other write).
	IngestToken string
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
	mux.HandleFunc("POST /api/v1/hosts/{id}/events", a.ingestEvents)
	mux.HandleFunc("GET /api/v1/export/ecs", a.exportECS)
	mux.HandleFunc("GET /api/v1/risk/stats", a.riskStats)
	mux.HandleFunc("GET /api/v1/risk/observations", a.riskObservations)
	// auth + user management
	mux.HandleFunc("POST /api/v1/login", a.login)
	mux.HandleFunc("POST /api/v1/logout", a.logout)
	mux.HandleFunc("GET /api/v1/me", a.me)
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
	sc, err := a.Runner.Scan(r.Context(), h, store.TriggerAPI)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sc)
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
	if l := q.Get("limit"); l != "" {
		f.Limit, _ = strconv.Atoi(l)
	}
	obs, err := a.Store.ListObservations(r.Context(), f)
	if err != nil {
		writeErr(w, err)
		return
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

// labDataset loads the optional poligon dataset of technique-labelled positives.
// Best-effort: a missing/unset file yields no records, so the risk model degrades
// to prod-triage-only training.
func (a *API) labDataset() []*store.Observation {
	lab, err := risk.LoadDataset(a.RiskDataset)
	if err != nil {
		return nil
	}
	return lab
}

// riskStats trains on prod triage + lab data and reports whether there is enough
// labelled, balanced, separable data to trust the model — the evidence behind
// "should we use ML yet?". The response also splits the labelled counts into prod
// vs lab so an inflated CV from easy lab positives is visible. GET /api/v1/risk/stats.
func (a *API) riskStats(w http.ResponseWriter, r *http.Request) {
	prod, err := a.Store.ListObservations(r.Context(), store.ObservationFilter{Limit: 10000})
	if err != nil {
		writeErr(w, err)
		return
	}
	lab := a.labDataset()
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
		ProdLabeled:  countLabeled(prod),
		LabPositives: labPos,
		LabNegatives: labNeg,
	}
	writeJSON(w, http.StatusOK, resp)
}

// countLabeled returns how many observations carry a triage label (not open).
func countLabeled(obs []*store.Observation) int {
	n := 0
	for _, o := range obs {
		if risk.LabelOf(o.Status) != risk.Unlabeled {
			n++
		}
	}
	return n
}

// riskObservations returns the OPEN observations ranked by ML priority, each with
// the features that drove its score. Trains on prod triage + lab data. Falls back
// to the rule's static score until the model has both classes. GET /api/v1/risk/observations.
func (a *API) riskObservations(w http.ResponseWriter, r *http.Request) {
	all, err := a.Store.ListObservations(r.Context(), store.ObservationFilter{Limit: 10000})
	if err != nil {
		writeErr(w, err)
		return
	}
	// Train (for scoring) on prod triage + lab, optionally class-balanced by synthetic
	// augmentation. Augmentation is applied to TRAINING ONLY — never to the Evaluate
	// CV in riskStats, where it would leak — so the trust metric stays honest.
	train := append(append([]*store.Observation{}, all...), a.labDataset()...)
	if a.RiskAugment {
		train = risk.Augment(train, 1)
	}
	m := risk.Train(train)
	type scored struct {
		*store.Observation
		Risk risk.Result `json:"risk"`
	}
	out := make([]scored, 0)
	for _, o := range all {
		if o.Status != store.ObsOpen {
			continue
		}
		out = append(out, scored{Observation: o, Risk: m.Score(o)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Risk.Priority > out[j].Risk.Priority })
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
	limit := 500
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			limit = n
		}
	}
	evs, err := a.Store.ListAudit(r.Context(), limit)
	if err != nil {
		writeErr(w, err)
		return
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
	if !decode(w, r, &evs) {
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

// runSchedule fires a schedule's target scan(s) immediately and returns the scans,
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
	scans := make([]*store.Scan, 0, len(hosts))
	for _, h := range hosts {
		sc, err := a.Runner.Scan(r.Context(), h, store.TriggerManual)
		if err != nil {
			continue // best-effort: skip unreachable hosts
		}
		scans = append(scans, sc)
	}
	writeJSON(w, http.StatusOK, scans)
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
	writeError(w, http.StatusInternalServerError, err.Error())
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}
