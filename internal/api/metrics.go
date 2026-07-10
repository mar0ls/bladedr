package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// metrics is a tiny, dependency-free Prometheus-text collector: request counts by
// method + status code plus a duration summary. Enough to graph traffic, error rate
// and latency without pulling in a client library.
type metrics struct {
	mu       sync.Mutex
	requests map[string]int64 // "method\x00code" -> count
	durSum   float64
	durCount int64
}

func newMetrics() *metrics { return &metrics{requests: map[string]int64{}} }

func (m *metrics) observe(method string, code int, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[method+"\x00"+strconv.Itoa(code)]++
	m.durSum += d.Seconds()
	m.durCount++
}

func (m *metrics) write(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintln(w, "# HELP bladedr_http_requests_total HTTP requests by method and status code.")
	fmt.Fprintln(w, "# TYPE bladedr_http_requests_total counter")
	for k, v := range m.requests {
		method, code, _ := strings.Cut(k, "\x00")
		fmt.Fprintf(w, "bladedr_http_requests_total{method=%q,code=%q} %d\n", method, code, v)
	}
	fmt.Fprintln(w, "# HELP bladedr_http_request_duration_seconds HTTP request duration summary.")
	fmt.Fprintln(w, "# TYPE bladedr_http_request_duration_seconds summary")
	fmt.Fprintf(w, "bladedr_http_request_duration_seconds_sum %g\n", m.durSum)
	fmt.Fprintf(w, "bladedr_http_request_duration_seconds_count %d\n", m.durCount)
}

// statusRecorder captures the response status for metrics and access logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// observe wraps the router: it times each request, records metrics, and emits one
// structured access-log line. Health/metrics scrapes log at debug so they don't drown
// the normal log.
func (a *API) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		d := time.Since(start)
		a.metrics.observe(r.Method, rec.status, d)

		level := slog.LevelInfo
		switch r.URL.Path {
		case "/healthz", "/readyz", "/metrics":
			level = slog.LevelDebug
		}
		slog.LogAttrs(r.Context(), level, "http",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
			slog.Duration("dur", d),
			slog.String("ip", clientIP(r)),
		)
	})
}

func (a *API) serveMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	a.metrics.write(w)
}

// readyz reports readiness: distinct from healthz (liveness), it checks the backing
// store is reachable, so a load balancer can hold traffic until the DB is up.
func (a *API) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := a.Store.Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "store unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
