package api

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"bladedr/internal/rules"
	"bladedr/internal/sensor"
	"bladedr/internal/store"
)

//go:embed templates/*.html
var uiFS embed.FS

//go:embed logo.png
var uiLogo []byte

var uiFuncs = template.FuncMap{
	// mitreURL builds the ATT&CK page URL, mapping sub-techniques T1543.002 ->
	// .../techniques/T1543/002/.
	"mitreURL": func(t string) string {
		return "https://attack.mitre.org/techniques/" + strings.Replace(t, ".", "/", 1) + "/"
	},
}

// uiTemplate parses the shared base layout together with one content page.
func uiTemplate(page string) *template.Template {
	return template.Must(template.New(page).Funcs(uiFuncs).ParseFS(uiFS, "templates/base.html", "templates/"+page))
}

var (
	tmplDashboard    = uiTemplate("dashboard.html")
	tmplObservations = uiTemplate("observations.html")
	tmplHosts        = uiTemplate("hosts.html")
	tmplEditHost     = uiTemplate("edit-host.html")
	tmplSchedules    = uiTemplate("schedules.html")
	tmplRules        = uiTemplate("rules.html")
	tmplUsers        = uiTemplate("users.html")
	tmplAudit        = uiTemplate("audit.html")
	tmplPolicies     = uiTemplate("policies.html")
	tmplLogin        = template.Must(template.New("login.html").ParseFS(uiFS, "templates/login.html"))
)

type bar struct {
	Label string
	Count int
	Pct   int    // width relative to the max bar
	Class string // optional severity class for colouring
}

// topBars turns a label→count map into the top-n bars sorted desc, with widths.
func topBars(m map[string]int, n int) []bar {
	bars := make([]bar, 0, len(m))
	for k, v := range m {
		bars = append(bars, bar{Label: k, Count: v})
	}
	sort.Slice(bars, func(i, j int) bool {
		if bars[i].Count != bars[j].Count {
			return bars[i].Count > bars[j].Count
		}
		return bars[i].Label < bars[j].Label
	})
	if n > 0 && len(bars) > n {
		bars = bars[:n]
	}
	max := 0
	for _, b := range bars {
		if b.Count > max {
			max = b.Count
		}
	}
	for i := range bars {
		if max > 0 {
			bars[i].Pct = bars[i].Count * 100 / max
		}
	}
	return bars
}

// uiDashboard renders the overview: KPI cards + severity / top-rule / top-MITRE /
// per-host bar charts, computed server-side from the store (no JS chart lib).
func (a *API) uiDashboard(w http.ResponseWriter, r *http.Request) {
	hosts, err := a.Store.ListHosts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hostName := map[string]string{}
	for _, h := range hosts {
		hostName[h.ID] = hostDisplay(h)
	}
	all, _ := a.Store.ListObservations(r.Context(), store.ObservationFilter{Limit: 10000})

	bySeverity := map[string]int{}
	byRule := map[string]int{}
	byMitre := map[string]int{}
	byHost := map[string]int{}
	byStatus := map[string]int{}
	openTotal, critHigh := 0, 0
	for _, o := range all {
		byStatus[o.Status]++
		if o.Status != store.ObsOpen {
			continue
		}
		openTotal++
		bySeverity[o.Severity]++
		byRule[o.RuleID]++
		byHost[hostName[o.HostID]]++
		if o.Severity == "critical" || o.Severity == "high" {
			critHigh++
		}
		for _, t := range o.Mitre {
			byMitre[t]++
		}
	}
	// Severity bars in fixed order with colour classes.
	sevBars := make([]bar, 0, 4)
	maxSev := 0
	for _, s := range []string{"critical", "high", "medium", "low"} {
		if bySeverity[s] > maxSev {
			maxSev = bySeverity[s]
		}
	}
	for _, s := range []string{"critical", "high", "medium", "low"} {
		pct := 0
		if maxSev > 0 {
			pct = bySeverity[s] * 100 / maxSev
		}
		sevBars = append(sevBars, bar{Label: s, Count: bySeverity[s], Pct: pct, Class: "sev-" + s})
	}

	render(w, r, tmplDashboard, map[string]any{
		"Title": "overview", "Nav": "dash",
		"Hosts": len(hosts), "OpenTotal": openTotal, "CritHigh": critHigh,
		"Resolved": byStatus[store.ObsResolved], "FalsePositive": byStatus[store.ObsFalsePositive],
		"Acknowledged": byStatus[store.ObsAcknowledged],
		"SevBars":      sevBars,
		"RuleBars":     topBars(byRule, 10),
		"MitreBars":    topBars(byMitre, 10),
		"HostBars":     topBars(byHost, 8),
	})
}

// RegisterUI mounts the server-rendered hunting UI on the mux. It reuses the
// store directly for reads; triage actions post back to the JSON API.
func (a *API) registerUI(mux *http.ServeMux) {
	mux.HandleFunc("GET /ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/dashboard", http.StatusFound)
	})
	mux.HandleFunc("GET /ui/dashboard", a.uiDashboard)
	mux.HandleFunc("GET /ui/observations", a.uiObservations)
	mux.HandleFunc("GET /ui/hosts", a.uiHosts)
	mux.HandleFunc("POST /ui/hosts", a.uiAddHost)
	mux.HandleFunc("GET /ui/hosts/{id}/edit", a.uiEditHostForm)
	mux.HandleFunc("POST /ui/hosts/{id}/edit", a.uiEditHost)
	mux.HandleFunc("GET /ui/schedules", a.uiSchedules)
	mux.HandleFunc("POST /ui/schedules", a.uiAddSchedule)
	mux.HandleFunc("GET /ui/rules", a.uiRules)
	mux.HandleFunc("GET /ui/policies", a.uiPolicies)
	mux.HandleFunc("GET /ui/login", a.uiLogin)
	mux.HandleFunc("GET /ui/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		// static embedded asset, not user-controlled data
		// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
		w.Write(uiLogo)
	})
	mux.HandleFunc("GET /ui/users", a.uiUsers)
	mux.HandleFunc("GET /ui/audit", a.uiAudit)
}

// uiAudit renders the security audit log (admin-only, enforced by middleware).
func (a *API) uiAudit(w http.ResponseWriter, r *http.Request) {
	evs, err := a.Store.ListAudit(r.Context(), 500)
	if err != nil {
		writeErr(w, err)
		return
	}
	render(w, r, tmplAudit, map[string]any{"Title": "audit", "Nav": "audit", "Events": evs})
}

// uiPolicies renders the eBPF TracingPolicy catalog the sensor ships.
func (a *API) uiPolicies(w http.ResponseWriter, r *http.Request) {
	sev := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	pols := append([]sensor.PolicyMeta(nil), a.Policies...)
	sort.Slice(pols, func(i, j int) bool {
		si, sj := sev[pols[i].Severity], sev[pols[j].Severity]
		if si != sj {
			return si < sj
		}
		return pols[i].Name < pols[j].Name
	})
	render(w, r, tmplPolicies, map[string]any{"Title": "policies", "Nav": "policies", "Policies": pols})
}

// uiLogin serves the standalone login page (public; posts to /api/v1/login).
func (a *API) uiLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmplLogin.Execute(w, nil)
}

// uiUsers renders the user-management page (admin-only, enforced by middleware).
func (a *API) uiUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.Store.ListUsers(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	cur := ""
	if u := currentUser(r); u != nil {
		cur = u.ID
	}
	render(w, r, tmplUsers, map[string]any{"Title": "users", "Nav": "users", "Users": users, "CurrentID": cur})
}

// uiEditHostForm renders the host edit page (hostname, mode, tags).
func (a *API) uiEditHostForm(w http.ResponseWriter, r *http.Request) {
	h, err := a.Store.GetHost(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	lines := make([]string, 0, len(h.Tags))
	for _, kv := range tagPairs(h.Tags) {
		lines = append(lines, kv)
	}
	username, authType := "", store.AuthPassword
	if h.CredentialID != "" {
		if c, err := a.Store.GetCredential(r.Context(), h.CredentialID); err == nil {
			username, authType = c.Username, c.AuthType
		}
	}
	render(w, r, tmplEditHost, map[string]any{
		"Title": "edit host", "Nav": "hosts", "Host": h, "TagsText": strings.Join(lines, "\n"),
		"Username": username, "AuthType": authType,
	})
}

// uiEditHost applies the host edit form: hostname, mode and a full tag replacement
// parsed from "key=value" lines.
func (a *API) uiEditHost(w http.ResponseWriter, r *http.Request) {
	h, err := a.Store.GetHost(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.Hostname = strings.TrimSpace(r.FormValue("hostname"))
	if m := r.FormValue("mode"); m == store.ModeScanOnly || m == store.ModeScanPlusSensor {
		h.Mode = m
	}
	if p, err := strconv.Atoi(strings.TrimSpace(r.FormValue("ssh_port"))); err == nil && p > 0 {
		h.SSHPort = p
	}
	h.Tags = parseTagLines(r.FormValue("tags"))
	// Credential change: only when a new secret is supplied (we can't re-seal
	// without it). Creates a fresh sealed credential and repoints the host.
	if secret := r.FormValue("secret"); strings.TrimSpace(secret) != "" {
		if a.Crypto == nil {
			http.Error(w, "credential sealing disabled: no node key configured", http.StatusServiceUnavailable)
			return
		}
		user := strings.TrimSpace(r.FormValue("username"))
		if user == "" {
			http.Error(w, "username required to set a new credential", http.StatusBadRequest)
			return
		}
		authType := r.FormValue("auth_type")
		if authType != store.AuthSSHKey && authType != store.AuthPassword {
			authType = store.AuthPassword
		}
		sealed, err := a.Crypto.Seal([]byte(secret))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cred := &store.Credential{Name: user + "@" + h.PrimaryIP, Username: user, AuthType: authType, SecretEnc: sealed}
		if err := a.Store.CreateCredential(r.Context(), cred); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.CredentialID = cred.ID
		h.SSHHostKey = "" // re-pin host key on next scan (new creds may target a rebuilt host)
		h.Status = store.StatusPending
	}
	if err := a.Store.UpdateHost(r.Context(), h); err != nil {
		writeErr(w, err)
		return
	}
	http.Redirect(w, r, "/ui/hosts", http.StatusSeeOther)
}

type schedRow struct {
	*store.Schedule
	Target      string
	IntervalStr string
	LastRunStr  string
	NextRunStr  string
}

// uiRules renders the merged active rule set (builtin ∪ dir ∪ DB) with enable
// state, and lets an analyst add a custom YAML rule, toggle any rule, or delete a
// user rule — all via the existing JSON /api/v1/rules API.
func (a *API) uiRules(w http.ResponseWriter, r *http.Request) {
	var rs []rules.Rule
	if a.ActiveRules != nil {
		rs, _ = a.ActiveRules(r.Context())
	}
	userRecs, _ := a.Store.ListRules(r.Context())
	isUser := map[string]bool{}
	for _, u := range userRecs {
		isUser[u.ID] = true
	}
	type ruleRow struct {
		ID, Title, Category, Severity string
		Mitre                         []string
		Enabled, IsUser               bool
	}
	rows := make([]ruleRow, 0, len(rs))
	enabled := 0
	for _, rl := range rs {
		if rl.IsEnabled() {
			enabled++
		}
		rows = append(rows, ruleRow{rl.ID, rl.Title, rl.Category, rl.Severity, rl.Mitre, rl.IsEnabled(), isUser[rl.ID]})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Category != rows[j].Category {
			return rows[i].Category < rows[j].Category
		}
		return rows[i].ID < rows[j].ID
	})
	render(w, r, tmplRules, map[string]any{
		"Title": "rules", "Nav": "rules", "Rows": rows, "Total": len(rs), "Enabled": enabled,
	})
}

func (a *API) uiSchedules(w http.ResponseWriter, r *http.Request) {
	scheds, err := a.Store.ListSchedules(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	hosts, _ := a.Store.ListHosts(r.Context())
	colls, _ := a.Store.ListCollections(r.Context())
	hostName := map[string]string{}
	for _, h := range hosts {
		hostName[h.ID] = hostDisplay(h)
	}
	collName := map[string]string{}
	for _, c := range colls {
		collName[c.ID] = c.Name
	}
	rows := make([]schedRow, 0, len(scheds))
	for _, s := range scheds {
		target := "all hosts"
		switch {
		case s.HostID != "":
			target = "host: " + hostName[s.HostID]
		case s.CollectionID != "":
			target = "collection: " + collName[s.CollectionID]
		}
		last := "never"
		if s.LastRun != nil {
			last = humanTime(*s.LastRun)
		}
		rows = append(rows, schedRow{
			Schedule: s, Target: target,
			IntervalStr: (time.Duration(s.IntervalS) * time.Second).String(),
			LastRunStr:  last, NextRunStr: humanTime(s.NextRun),
		})
	}
	type opt struct{ ID, Display, Name string }
	hostOpts := make([]opt, 0, len(hosts))
	for _, h := range hosts {
		hostOpts = append(hostOpts, opt{ID: h.ID, Display: hostDisplay(h)})
	}
	collOpts := make([]opt, 0, len(colls))
	for _, c := range colls {
		collOpts = append(collOpts, opt{ID: c.ID, Name: c.Name})
	}
	render(w, r, tmplSchedules, map[string]any{
		"Title": "schedules", "Nav": "sched", "Rows": rows,
		"HostList": hostOpts, "Collections": collOpts,
	})
}

func (a *API) uiAddSchedule(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	intervalS := int64(0)
	if d, err := time.ParseDuration(strings.TrimSpace(r.FormValue("interval"))); err == nil {
		intervalS = int64(d.Seconds())
	}
	if intervalS < minScheduleInterval {
		http.Error(w, "interval must be at least 5m (recommended 15m-1h; e.g. 30m)", http.StatusBadRequest)
		return
	}
	s := &store.Schedule{
		Name: strings.TrimSpace(r.FormValue("name")), IntervalS: intervalS,
		Enabled: true, NextRun: time.Now().UTC(),
	}
	switch r.FormValue("target") {
	case "host":
		s.HostID = r.FormValue("host_id")
	case "collection":
		s.CollectionID = r.FormValue("collection_id")
	}
	if err := a.Store.CreateSchedule(r.Context(), s); err != nil {
		writeErr(w, err)
		return
	}
	http.Redirect(w, r, "/ui/schedules", http.StatusSeeOther)
}

// parseTagLines parses "key=value" lines (or comma-separated) into a tag map.
func parseTagLines(s string) map[string]string {
	out := map[string]string{}
	s = strings.ReplaceAll(s, ",", "\n")
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if k != "" && v != "" {
				out[k] = v
			}
		}
	}
	return out
}

// uiAddHost handles the "Add host" form: it seals the SSH secret with the node
// key, creates a credential + host, and redirects back to the hosts page. This
// is the point-and-click equivalent of scripts/add-host.sh.
func (a *API) uiAddHost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ip := strings.TrimSpace(r.FormValue("primary_ip"))
	user := strings.TrimSpace(r.FormValue("username"))
	secret := r.FormValue("secret")
	if ip == "" || user == "" || secret == "" {
		http.Error(w, "primary_ip, username and secret are required", http.StatusBadRequest)
		return
	}
	if a.Crypto == nil {
		http.Error(w, "credential sealing disabled: no node key configured", http.StatusServiceUnavailable)
		return
	}
	authType := r.FormValue("auth_type")
	if authType != store.AuthSSHKey && authType != store.AuthPassword {
		authType = store.AuthPassword
	}
	port := 22
	if p, err := strconv.Atoi(strings.TrimSpace(r.FormValue("ssh_port"))); err == nil && p > 0 {
		port = p
	}
	arch := strings.TrimSpace(r.FormValue("arch"))
	if arch == "" {
		arch = "amd64"
	}
	sealed, err := a.Crypto.Seal([]byte(secret))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cred := &store.Credential{Name: user + "@" + ip, Username: user, AuthType: authType, SecretEnc: sealed}
	if err := a.Store.CreateCredential(r.Context(), cred); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	mode := r.FormValue("mode")
	if mode != store.ModeScanOnly && mode != store.ModeScanPlusSensor {
		mode = store.ModeScanOnly
	}
	host := &store.Host{
		Hostname: strings.TrimSpace(r.FormValue("hostname")), PrimaryIP: ip, SSHPort: port,
		CredentialID: cred.ID, Arch: arch, Mode: mode, Status: store.StatusPending,
	}
	if err := a.Store.CreateHost(r.Context(), host); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/ui/hosts", http.StatusSeeOther)
}

type obsRow struct {
	*store.Observation
	Hostname    string
	EvidenceStr string
	LastSeenStr string
}

func (a *API) uiObservations(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.ObservationFilter{
		HostID:   q.Get("host"),
		Severity: q.Get("severity"),
		Status:   q.Get("status"),
		Query:    q.Get("q"),
		Limit:    500,
	}
	obs, err := a.Store.ListObservations(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	hosts, _ := a.Store.ListHosts(r.Context())
	byID := map[string]*store.Host{}
	for _, h := range hosts {
		byID[h.ID] = h
	}
	rows := make([]obsRow, 0, len(obs))
	for _, o := range obs {
		rows = append(rows, obsRow{
			Observation: o,
			Hostname:    hostDisplay(byID[o.HostID]),
			EvidenceStr: evidenceString(o.Evidence),
			LastSeenStr: humanTime(o.LastSeen),
		})
	}
	type hostOpt struct {
		ID, Display string
	}
	hostOpts := make([]hostOpt, 0, len(hosts))
	for _, h := range hosts {
		hostOpts = append(hostOpts, hostOpt{ID: h.ID, Display: hostDisplay(h)})
	}
	data := map[string]any{
		"Title":      "observations",
		"Nav":        "obs",
		"Rows":       rows,
		"HostList":   hostOpts,
		"Severities": []string{"critical", "high", "medium", "low"},
		"Statuses":   []string{store.ObsOpen, store.ObsAcknowledged, store.ObsResolved, store.ObsFalsePositive},
		"Filter": map[string]string{
			"Q": f.Query, "Severity": f.Severity, "Status": f.Status, "Host": f.HostID,
		},
	}
	render(w, r, tmplObservations, data)
}

type hostRow struct {
	*store.Host
	TagPairs     []string
	OpenFindings int
	LastSeenStr  string
	SensorOn     bool // Mode == scan_plus_sensor
	EbpfCount    int  // eBPF observations seen (proxy for "sensor reporting")
}

func (a *API) uiHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := a.Store.ListHosts(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	tagFilter := r.URL.Query().Get("tag")
	wantK, wantV, hasFilter := strings.Cut(tagFilter, "=")
	rows := make([]hostRow, 0, len(hosts))
	for _, h := range hosts {
		if hasFilter && h.Tags[wantK] != wantV {
			continue
		}
		open, _ := a.Store.ListObservations(r.Context(), store.ObservationFilter{HostID: h.ID, Status: store.ObsOpen})
		ebpf, _ := a.Store.ListObservations(r.Context(), store.ObservationFilter{HostID: h.ID, Source: store.SourceEBPFSensor})
		rows = append(rows, hostRow{
			Host:         h,
			TagPairs:     tagPairs(h.Tags),
			OpenFindings: len(open),
			LastSeenStr:  lastSeen(h.LastSeen),
			SensorOn:     h.Mode == "scan_plus_sensor",
			EbpfCount:    len(ebpf),
		})
	}
	data := map[string]any{
		"Title":     "hosts",
		"Nav":       "hosts",
		"Rows":      rows,
		"TagFilter": tagFilter,
	}
	render(w, r, tmplHosts, data)
}

func render(w http.ResponseWriter, r *http.Request, t *template.Template, data any) {
	// Inject the authenticated user so the nav can show it + gate the admin link.
	if m, ok := data.(map[string]any); ok {
		if u := currentUser(r); u != nil {
			m["CurrentUser"] = u.Username
			m["Role"] = u.Role
			m["IsAdmin"] = u.Role == store.RoleAdmin
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func hostDisplay(h *store.Host) string {
	switch {
	case h == nil:
		return "(unknown)"
	case h.Hostname != "":
		return h.Hostname
	case h.PrimaryIP != "":
		return h.PrimaryIP
	default:
		return h.ID[:8]
	}
}

func evidenceString(ev map[string]any) string {
	if len(ev) == 0 {
		return ""
	}
	keys := make([]string, 0, len(ev))
	for k := range ev {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, ev[k]))
	}
	s := strings.Join(parts, ", ")
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}

func tagPairs(tags map[string]string) []string {
	if len(tags) == 0 {
		return nil
	}
	out := make([]string, 0, len(tags))
	for k, v := range tags {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

func humanTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04")
}

func lastSeen(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return humanTime(*t)
}
