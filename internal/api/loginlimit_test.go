package api

import (
	"net/http"
	"testing"
	"time"
)

func TestLoginLimiter_LocksOutAfterThreshold(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	ip := "10.0.0.1"

	// Below the threshold: never locked.
	for i := 0; i < loginMaxFails-1; i++ {
		l.fail(ip, now)
		if w := l.retryAfter(ip, now); w != 0 {
			t.Fatalf("locked out after %d fails, want none until %d", i+1, loginMaxFails)
		}
	}
	// The threshold failure arms the lockout.
	l.fail(ip, now)
	if w := l.retryAfter(ip, now); w <= 0 {
		t.Fatalf("expected lockout after %d fails, got %v", loginMaxFails, w)
	}
	// It lifts once the backoff elapses.
	if w := l.retryAfter(ip, now.Add(loginLockoutBase+time.Second)); w != 0 {
		t.Fatalf("still locked after backoff elapsed: %v", w)
	}
}

func TestLoginLimiter_BackoffGrowsAndCaps(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	ip := "10.0.0.2"
	for i := 0; i < loginMaxFails; i++ {
		l.fail(ip, now)
	}
	first := l.retryAfter(ip, now)
	l.fail(ip, now) // one more failure -> longer lockout
	second := l.retryAfter(ip, now)
	if second <= first {
		t.Fatalf("backoff did not grow: first=%v second=%v", first, second)
	}
	for i := 0; i < 40; i++ {
		l.fail(ip, now)
	}
	if w := l.retryAfter(ip, now); w > loginLockoutMax {
		t.Fatalf("backoff exceeded cap: %v > %v", w, loginLockoutMax)
	}
}

func TestLoginLimiter_ResetClearsLockout(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	ip := "10.0.0.3"
	for i := 0; i < loginMaxFails; i++ {
		l.fail(ip, now)
	}
	if l.retryAfter(ip, now) == 0 {
		t.Fatal("expected lockout")
	}
	l.reset(ip)
	if w := l.retryAfter(ip, now); w != 0 {
		t.Fatalf("reset did not clear lockout: %v", w)
	}
}

// TestLoginThrottleHTTP drives the throttle through the real router: a burst of bad
// passwords eventually returns 429, and even correct credentials are refused while
// the IP is locked out (the check runs before authentication).
func TestLoginThrottleHTTP(t *testing.T) {
	a, _ := newTestAPI(t)
	bad := map[string]string{"Username": "admin-user", "Password": "wrong"}
	for i := 0; i < loginMaxFails; i++ {
		if w := do(a, "POST", "/api/v1/login", "", bad); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, w.Code)
		}
	}
	w := do(a, "POST", "/api/v1/login", "", bad)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d failures: got %d, want 429", loginMaxFails, w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("429 response should set Retry-After")
	}
	good := map[string]string{"Username": "admin-user", "Password": "password123"}
	if w := do(a, "POST", "/api/v1/login", "", good); w.Code != http.StatusTooManyRequests {
		t.Fatalf("valid login during lockout: got %d, want 429", w.Code)
	}
}

func TestLoginLimiter_IdleResetsCounter(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	ip := "10.0.0.4"
	for i := 0; i < loginMaxFails-1; i++ {
		l.fail(ip, now)
	}
	// A long idle gap resets the counter, so the next failure starts fresh.
	later := now.Add(loginWindow + time.Minute)
	l.fail(ip, later)
	if w := l.retryAfter(ip, later); w != 0 {
		t.Fatalf("counter did not reset after idle window: %v", w)
	}
}
