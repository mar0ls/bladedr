package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"bladedr/internal/secrets"
	"bladedr/internal/store"
	"github.com/google/uuid"
)

type permanentError struct{ error }

// Worker drains the transactional export outbox. Claim leases make delivery safe
// across multiple server instances. Delivery is at-least-once; HTTP targets receive
// a stable Idempotency-Key and should deduplicate when exactly-once effects matter.
type Worker struct {
	Store        store.Store
	Crypto       *secrets.Crypto
	Workers      int
	PollInterval time.Duration
	Lease        time.Duration
	Timeout      time.Duration
	HTTPClient   *http.Client
	WorkerID     string
	Logf         func(string, ...any)
}

func (w *Worker) defaults() {
	if w.Workers <= 0 {
		w.Workers = 2
	}
	if w.PollInterval <= 0 {
		w.PollInterval = time.Second
	}
	if w.Lease <= 0 {
		w.Lease = 30 * time.Second
	}
	if w.Timeout <= 0 {
		w.Timeout = 15 * time.Second
	}
	if w.HTTPClient == nil {
		w.HTTPClient = &http.Client{Timeout: w.Timeout}
	}
	if w.WorkerID == "" {
		w.WorkerID = uuid.NewString()
	}
}

func (w *Worker) logf(format string, args ...any) {
	if w.Logf != nil {
		w.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

func (w *Worker) Run(ctx context.Context) {
	w.defaults()
	done := make(chan struct{}, w.Workers)
	for i := 0; i < w.Workers; i++ {
		go func() {
			w.loop(ctx, w.WorkerID+"/"+uuid.NewString())
			done <- struct{}{}
		}()
	}
	<-ctx.Done()
	for i := 0; i < w.Workers; i++ {
		<-done
	}
}

func (w *Worker) loop(ctx context.Context, workerID string) {
	ticker := time.NewTicker(w.PollInterval)
	defer ticker.Stop()
	for {
		worked, err := w.runOne(ctx, workerID)
		if err != nil {
			w.logf("export worker: %v", err)
		}
		if worked {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (w *Worker) RunOne(ctx context.Context) (bool, error) {
	w.defaults()
	return w.runOne(ctx, w.WorkerID+"/manual")
}

func (w *Worker) runOne(ctx context.Context, workerID string) (bool, error) {
	delivery, err := w.Store.ClaimExportDelivery(ctx, workerID, time.Now().UTC(), w.Lease)
	if err != nil {
		var missing store.ErrNotFound
		if errors.As(err, &missing) {
			return false, nil
		}
		return false, err
	}
	sendCtx, cancel := context.WithTimeout(ctx, w.Timeout)
	err = w.deliver(sendCtx, delivery)
	cancel()
	if err == nil {
		return true, w.Store.CompleteExportDelivery(ctx, delivery.ID, workerID)
	}
	var permanent permanentError
	terminal := delivery.Attempts >= delivery.MaxAttempts || errors.As(err, &permanent)
	// 30s, 1m, 2m ... capped at an hour. Claim increments Attempts first, so the
	// exponent should never go negative; clamp anyway, since a negative shift panics
	// and this runs on a worker goroutine.
	shift := max(delivery.Attempts-1, 0)
	delay := 30 * time.Second * time.Duration(1<<min(shift, 7))
	if delay > time.Hour {
		delay = time.Hour
	}
	return true, w.Store.FailExportDelivery(ctx, delivery.ID, workerID, err.Error(), time.Now().UTC().Add(delay), terminal)
}

func (w *Worker) deliver(ctx context.Context, delivery *store.ExportDelivery) error {
	target, err := w.Store.GetExportTarget(ctx, delivery.TargetID)
	if err != nil {
		return permanentError{err}
	}
	observation, err := w.Store.GetObservation(ctx, delivery.ObservationID)
	if err != nil {
		return permanentError{err}
	}
	host, _ := w.Store.GetHost(ctx, observation.HostID)
	payload, err := json.Marshal(ToECS(observation, host))
	if err != nil {
		return permanentError{err}
	}
	secret := ""
	if len(target.SecretEnc) > 0 {
		if w.Crypto == nil || !w.Crypto.CanOpen() {
			return permanentError{fmt.Errorf("export target secret cannot be decrypted")}
		}
		plain, err := w.Crypto.Open(target.SecretEnc)
		if err != nil {
			return permanentError{fmt.Errorf("decrypt export target secret: %w", err)}
		}
		secret = string(plain)
	}
	switch target.Type {
	case store.ExportWebhook:
		return w.sendHTTP(ctx, http.MethodPost, target.Config["url"], "", secret, payload, delivery.ID)
	case store.ExportElasticsearch:
		base := strings.TrimRight(target.Config["url"], "/")
		index := target.Config["index"]
		if index == "" {
			index = "bladedr-observations"
		}
		endpoint := base + "/" + url.PathEscape(index) + "/_doc/" + url.PathEscape(observation.ID)
		return w.sendHTTP(ctx, http.MethodPut, endpoint, "ApiKey", secret, payload, delivery.ID)
	case store.ExportSyslog:
		return sendSyslog(ctx, target.Config, payload)
	default:
		return permanentError{fmt.Errorf("unsupported export target type %q", target.Type)}
	}
}

func (w *Worker) sendHTTP(ctx context.Context, method, endpoint, authScheme, secret string, payload []byte, deliveryID string) error {
	u, err := url.ParseRequestURI(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return permanentError{fmt.Errorf("invalid HTTP export URL")}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(payload))
	if err != nil {
		return permanentError{err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "bladedr-export/1")
	req.Header.Set("Idempotency-Key", deliveryID)
	if secret != "" {
		if authScheme == "" {
			authScheme = "Bearer"
		}
		req.Header.Set("Authorization", authScheme+" "+secret)
	}
	resp, err := w.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	err = fmt.Errorf("export endpoint returned HTTP %d", resp.StatusCode)
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
		return permanentError{err}
	}
	return err
}

func sendSyslog(ctx context.Context, config map[string]string, payload []byte) error {
	network := config["network"]
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" && network != "udp" {
		return permanentError{fmt.Errorf("syslog network must be tcp or udp")}
	}
	address := config["address"]
	if _, _, err := net.SplitHostPort(address); err != nil {
		return permanentError{fmt.Errorf("invalid syslog address: %w", err)}
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	message := append([]byte("<134>1 "+time.Now().UTC().Format(time.RFC3339)+" - bladedr - observation - "), payload...)
	message = append(message, '\n')
	_, err = conn.Write(message)
	return err
}
