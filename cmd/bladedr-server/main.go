// Command bladedr-server is the control plane: inventory, scan orchestration,
// rule engine, storage and the REST API.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"bladedr/internal/api"
	"bladedr/internal/auth"
	"bladedr/internal/rules"
	"bladedr/internal/scan"
	"bladedr/internal/secrets"
	"bladedr/internal/sensor"
	"bladedr/internal/store"
)

// version is overridden at release build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	setupLogging()
	keygen := flag.Bool("keygen", false, "generate a node keypair (for BLADEDR_NODE_KEY) and exit")
	dumpBundle := flag.Bool("dump-bundle", false, "print the builtin rule bundle (probe --rules input) and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *dumpBundle {
		rs, err := loadRules()
		if err != nil {
			log.Fatal(err)
		}
		b, _ := json.MarshalIndent(rules.BundleFrom(rs), "", "  ")
		fmt.Println(string(b))
		return
	}
	if *keygen {
		pub, priv, err := secrets.GenerateKeyPair()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("BLADEDR_NODE_KEY=%s   # private (node) — keep secret\npublic_key=%s   # seals credentials\n", priv, pub)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	addr := env("BLADEDR_ADDR", ":8080")
	localProbe := env("BLADEDR_PROBE_BIN", "bladedr-probe")

	baseRules, err := loadRules()
	if err != nil {
		log.Fatalf("load rules: %v", err)
	}
	log.Printf("loaded %d builtin/file detection rules", len(baseRules))

	st := openStore(ctx)
	bootstrapAdmin(ctx, st)
	crypto := openCrypto()
	probeBins := loadProbeBinaries()

	var extra []string
	if e := os.Getenv("BLADEDR_PROBE_EXTRA"); e != "" {
		extra = strings.Fields(e)
	}

	// Active rule set = builtin/file base merged with user rules from the store.
	loadActiveRules := func(ctx context.Context) ([]rules.Rule, error) {
		recs, err := st.ListRules(ctx)
		if err != nil {
			return nil, err
		}
		dbRules := make([]rules.Rule, 0, len(recs))
		for _, rec := range recs {
			var rr rules.Rule
			if err := json.Unmarshal(rec.Definition, &rr); err != nil {
				continue
			}
			enabled := rec.Enabled
			rr.Enabled = &enabled
			dbRules = append(dbRules, rr)
		}
		return rules.Merge(baseRules, dbRules), nil
	}

	// BLADEDR_INGEST_TOKEN may be a comma-separated list to rotate without downtime:
	// the API accepts any listed token, while sensors are deployed with the primary
	// (first) one.
	ingestTokens := os.Getenv("BLADEDR_INGEST_TOKEN")
	primaryIngestToken := ingestTokens
	if i := strings.IndexByte(ingestTokens, ','); i >= 0 {
		primaryIngestToken = strings.TrimSpace(ingestTokens[:i])
	}

	runner := &scan.Runner{
		Store:              st,
		LoadRules:          loadActiveRules,
		NewTransport:       transportFactory(ctx, st, crypto, probeBins, localProbe, extra),
		SensorBins:         loadSensorBinaries(),
		PolicyTar:          loadPolicyTar(),
		ServerURL:          os.Getenv("BLADEDR_SERVER_URL"),
		IngestToken:        primaryIngestToken,
		NewSensorTransport: sensorTransportFactory(ctx, st, crypto, loadProbeBinaries()),
	}

	// Background scheduler: fires due recurring scans from the store.
	scheduler := &scan.Scheduler{Store: st, Runner: runner, Tick: schedulerTick(), ScanTimeout: scanTimeout()}
	go scheduler.Run(ctx)

	// Session housekeeping: expired sessions are already rejected on use, but this
	// sweeps them so the store doesn't accumulate dead rows.
	go pruneSessions(ctx, st)

	riskDataset := os.Getenv("BLADEDR_RISK_DATASET")
	if riskDataset == "" {
		riskDataset = "poligon/dataset.jsonl"
	}
	tlsCert, tlsKey := os.Getenv("BLADEDR_TLS_CERT"), os.Getenv("BLADEDR_TLS_KEY")
	tlsOn := tlsCert != "" && tlsKey != ""
	// Serving over TLS implies the session cookie can carry the Secure flag; enable it
	// automatically so operators don't have to remember the separate env var (they can
	// still force it on a plaintext LAN with BLADEDR_SECURE_COOKIES).
	secureCookies := tlsOn || os.Getenv("BLADEDR_SECURE_COOKIES") == "1" || os.Getenv("BLADEDR_SECURE_COOKIES") == "true"

	a := &api.API{Store: st, Runner: runner, Crypto: crypto, ActiveRules: loadActiveRules, RiskDataset: riskDataset,
		RiskAugment:   os.Getenv("BLADEDR_RISK_AUGMENT") == "1" || os.Getenv("BLADEDR_RISK_AUGMENT") == "true",
		IngestToken:   ingestTokens,
		SecureCookies: secureCookies,
		Policies:      loadPolicyMeta()}
	srv := &http.Server{Addr: addr, Handler: a.Routes(), ReadHeaderTimeout: 10 * time.Second}
	if tlsOn {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	// Graceful shutdown: on SIGINT/SIGTERM stop accepting and drain in flight.
	go func() {
		<-ctx.Done()
		log.Printf("shutting down…")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	if tlsOn {
		log.Printf("bladedr-server %s listening on %s (TLS)", version, addr)
		err = srv.ListenAndServeTLS(tlsCert, tlsKey)
	} else {
		log.Printf("bladedr-server %s listening on %s (plaintext — set BLADEDR_TLS_CERT/KEY for HTTPS; do not expose beyond a trusted LAN)", version, addr)
		err = srv.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// pruneSessions periodically deletes expired sessions until ctx is cancelled.
func pruneSessions(ctx context.Context, st store.Store) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := st.DeleteExpiredSessions(ctx); err != nil {
				log.Printf("session prune: %v", err)
			} else if n > 0 {
				log.Printf("pruned %d expired session(s)", n)
			}
		}
	}
}

// setupLogging installs slog as the default logger (text by default, JSON with
// BLADEDR_LOG_FORMAT=json for log aggregators; debug via BLADEDR_LOG_LEVEL=debug).
// slog.SetDefault also routes the standard log package through the same handler, so
// existing log.Printf lifecycle messages come out structured too.
func setupLogging() {
	level := slog.LevelInfo
	if strings.EqualFold(os.Getenv("BLADEDR_LOG_LEVEL"), "debug") {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler = slog.NewTextHandler(os.Stderr, opts)
	if strings.EqualFold(os.Getenv("BLADEDR_LOG_FORMAT"), "json") {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}

// transportFactory picks SSH (when the host has a credential + IP) or the local
// probe (dev/self-scan). For SSH it loads and decrypts the credential, builds a
// signer, selects the probe binary for the host arch, and pins the host key (TOFU).
func transportFactory(ctx context.Context, st store.Store, crypto *secrets.Crypto, probeBins map[string][]byte, localProbe string, extra []string) func(*store.Host) (scan.Transport, error) {
	return func(h *store.Host) (scan.Transport, error) {
		if h.CredentialID == "" || h.PrimaryIP == "" {
			if localProbe == "" {
				return nil, fmt.Errorf("host has no credential/IP and local probe is disabled")
			}
			return scan.LocalTransport{ProbeBin: localProbe, ExtraArgs: extra}, nil
		}
		if crypto == nil || !crypto.CanOpen() {
			return nil, fmt.Errorf("cannot decrypt credential: no node key loaded")
		}
		cred, err := st.GetCredential(ctx, h.CredentialID)
		if err != nil {
			return nil, err
		}
		secret, err := crypto.Open(cred.SecretEnc)
		if err != nil {
			return nil, fmt.Errorf("decrypt credential: %w", err)
		}
		auth, err := scan.AuthFor(cred.AuthType, string(secret))
		if err != nil {
			return nil, err
		}
		arch := h.Arch
		if arch == "" {
			arch = "amd64" // unknown until first scan; default and refine afterwards
		}
		bin := probeBins[arch]
		if bin == nil {
			return nil, fmt.Errorf("no probe binary configured for arch %q (set BLADEDR_PROBE_LINUX_%s)", arch, strings.ToUpper(arch))
		}
		t := scan.NewSSHTransport(h.Hostname, net.JoinHostPort(h.PrimaryIP, strconv.Itoa(h.SSHPort)), cred.Username, auth, bin)
		t.ExpectedHostKey = h.SSHHostKey
		t.OnLearnHostKey = func(key string) { // TOFU: pin on first contact
			h.SSHHostKey = key
			_ = st.UpdateHost(ctx, h)
		}
		return t, nil
	}
}

// bootstrapAdmin creates the initial admin account on a fresh install (no users).
// The password comes from BLADEDR_ADMIN_PASSWORD, or is generated and logged once.
func bootstrapAdmin(ctx context.Context, st store.Store) {
	n, err := st.CountUsers(ctx)
	if err != nil {
		log.Printf("warning: could not count users: %v", err)
		return
	}
	if n > 0 {
		return
	}
	user := os.Getenv("BLADEDR_ADMIN_USER")
	if user == "" {
		user = "admin"
	}
	pw := os.Getenv("BLADEDR_ADMIN_PASSWORD")
	generated := pw == ""
	if generated {
		b := make([]byte, 12)
		_, _ = rand.Read(b)
		pw = base64.RawURLEncoding.EncodeToString(b)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		log.Fatalf("hash admin password: %v", err)
	}
	if err := st.CreateUser(ctx, &store.User{Username: user, PasswordHash: hash, Role: store.RoleAdmin}); err != nil {
		log.Fatalf("create admin user: %v", err)
	}
	if generated {
		log.Printf("created initial admin %q with GENERATED password: %s  (set BLADEDR_ADMIN_PASSWORD to choose one)", user, pw)
	} else {
		log.Printf("created initial admin user %q", user)
	}
}

func openStore(ctx context.Context) store.Store {
	if dsn := os.Getenv("BLADEDR_DATABASE_URL"); dsn != "" {
		pg, err := store.OpenPostgres(ctx, dsn)
		if err != nil {
			log.Fatalf("connect postgres: %v", err)
		}
		log.Printf("using PostgreSQL store")
		return pg
	}
	log.Printf("using in-memory store (set BLADEDR_DATABASE_URL for Postgres)")
	return store.NewMemory()
}

func openCrypto() *secrets.Crypto {
	if k := os.Getenv("BLADEDR_NODE_KEY"); k != "" {
		c, err := secrets.FromNodeKey(k)
		if err != nil {
			log.Fatalf("BLADEDR_NODE_KEY: %v", err)
		}
		return c
	}
	pub, priv, err := secrets.GenerateKeyPair()
	if err != nil {
		log.Fatalf("generate node key: %v", err)
	}
	c, _ := secrets.FromNodeKey(priv)
	log.Printf("warning: no BLADEDR_NODE_KEY set; generated an EPHEMERAL key (public=%s). Credentials will not survive a restart. Run with -keygen to mint a persistent key.", pub)
	return c
}

// loadProbeBinaries reads the per-arch Linux probe binaries used by SSHTransport.
func loadProbeBinaries() map[string][]byte {
	bins := map[string][]byte{}
	for arch, envKey := range map[string]string{"amd64": "BLADEDR_PROBE_LINUX_AMD64", "arm64": "BLADEDR_PROBE_LINUX_ARM64"} {
		if path := os.Getenv(envKey); path != "" {
			b, err := os.ReadFile(path)
			if err != nil {
				log.Fatalf("%s: %v", envKey, err)
			}
			bins[arch] = b
			log.Printf("loaded probe binary for linux/%s (%d bytes)", arch, len(b))
		}
	}
	return bins
}

// loadSensorBinaries reads the per-arch Linux eBPF-sensor binaries used by the
// server-push deploy (the dashboard "Enable sensor" action).
func loadSensorBinaries() map[string][]byte {
	bins := map[string][]byte{}
	for arch, envKey := range map[string]string{"amd64": "BLADEDR_SENSOR_LINUX_AMD64", "arm64": "BLADEDR_SENSOR_LINUX_ARM64"} {
		if path := os.Getenv(envKey); path != "" {
			b, err := os.ReadFile(path)
			if err != nil {
				log.Fatalf("%s: %v", envKey, err)
			}
			bins[arch] = b
			log.Printf("loaded sensor binary for linux/%s (%d bytes)", arch, len(b))
		}
	}
	return bins
}

// loadPolicyMeta parses the TracingPolicy catalog from BLADEDR_POLICY_DIR for the
// UI's Policies page. Nil when the dir is unset or unreadable — the page then shows
// an empty state instead of failing.
func loadPolicyMeta() []sensor.PolicyMeta {
	dir := os.Getenv("BLADEDR_POLICY_DIR")
	if dir == "" {
		return nil
	}
	meta, err := sensor.LoadPolicyMeta(dir)
	if err != nil {
		log.Printf("policy metadata: %v", err)
		return nil
	}
	out := make([]sensor.PolicyMeta, 0, len(meta))
	for _, m := range meta {
		out = append(out, m)
	}
	return out
}

// loadPolicyTar gzip-tars the TracingPolicy bundle from BLADEDR_POLICY_DIR so the
// server can push it to a host during sensor deploy. Empty when unset.
func loadPolicyTar() []byte {
	dir := os.Getenv("BLADEDR_POLICY_DIR")
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Fatalf("BLADEDR_POLICY_DIR: %v", err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	n := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "shield-") || (!strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))})
		_, _ = tw.Write(data)
		n++
	}
	tw.Close()
	gz.Close()
	log.Printf("loaded %d Tetragon policies for sensor deploy (%d bytes gz)", n, buf.Len())
	return buf.Bytes()
}

// sensorTransportFactory builds the SSH transport + sudo password for deploying the
// sensor on a host (mirrors transportFactory; the password is returned only for
// password-auth hosts so a non-root SSH user can escalate via sudo -S).
func sensorTransportFactory(ctx context.Context, st store.Store, crypto *secrets.Crypto, probeBins map[string][]byte) func(*store.Host) (*scan.SSHTransport, string, error) {
	return func(h *store.Host) (*scan.SSHTransport, string, error) {
		if h.CredentialID == "" || h.PrimaryIP == "" {
			return nil, "", fmt.Errorf("host has no SSH credential/IP")
		}
		if crypto == nil || !crypto.CanOpen() {
			return nil, "", fmt.Errorf("cannot decrypt credential: no node key loaded")
		}
		cred, err := st.GetCredential(ctx, h.CredentialID)
		if err != nil {
			return nil, "", err
		}
		secret, err := crypto.Open(cred.SecretEnc)
		if err != nil {
			return nil, "", fmt.Errorf("decrypt credential: %w", err)
		}
		auth, err := scan.AuthFor(cred.AuthType, string(secret))
		if err != nil {
			return nil, "", err
		}
		arch := h.Arch
		if arch == "" {
			arch = "amd64"
		}
		t := scan.NewSSHTransport(h.Hostname, net.JoinHostPort(h.PrimaryIP, strconv.Itoa(h.SSHPort)), cred.Username, auth, probeBins[arch])
		t.ExpectedHostKey = h.SSHHostKey
		t.OnLearnHostKey = func(key string) { h.SSHHostKey = key; _ = st.UpdateHost(ctx, h) }
		pw := ""
		if cred.AuthType == "password" {
			pw = string(secret)
		}
		return t, pw, nil
	}
}

func loadRules() ([]rules.Rule, error) {
	if dir := os.Getenv("BLADEDR_RULES_DIR"); dir != "" {
		return rules.LoadDir(dir)
	}
	return rules.Builtin()
}

// schedulerTick is how often the scheduler checks for due schedules; overridable
// via BLADEDR_SCHEDULER_TICK (a Go duration, e.g. "10s") for tests/tuning.
func schedulerTick() time.Duration {
	if v := os.Getenv("BLADEDR_SCHEDULER_TICK"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 30 * time.Second
}

// scanTimeout bounds a single host scan in the scheduler so a hung host can't
// stall the fleet; overridable via BLADEDR_SCAN_TIMEOUT (Go duration).
func scanTimeout() time.Duration {
	if v := os.Getenv("BLADEDR_SCAN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 5 * time.Minute
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
