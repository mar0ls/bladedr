package api

import (
	"sync"
	"time"
)

// loginLimiter applies a capped exponential lockout per client IP. State is local to
// one server process and is removed after a successful login or an idle window.
type loginLimiter struct {
	mu        sync.Mutex
	attempts  map[string]*loginAttempt
	nextPrune time.Time
}

type loginAttempt struct {
	fails int
	until time.Time // locked out until this instant
	last  time.Time // last attempt, for idle-reset and pruning
}

const (
	loginMaxFails    = 5                // failures allowed before the first lockout
	loginWindow      = 15 * time.Minute // idle period after which the counter resets
	loginLockoutBase = 30 * time.Second // first lockout; doubles per extra failure
	loginLockoutMax  = 15 * time.Minute // backoff cap
)

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{attempts: map[string]*loginAttempt{}}
}

// retryAfter returns the remaining lockout for ip, or 0 if it may attempt now.
func (l *loginLimiter) retryAfter(ip string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(now)
	if a := l.attempts[ip]; a != nil && now.Before(a.until) {
		return a.until.Sub(now)
	}
	return 0
}

// fail records a failed attempt and (re)arms the lockout once past the threshold.
func (l *loginLimiter) fail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(now)
	a := l.attempts[ip]
	if a == nil {
		a = &loginAttempt{}
		l.attempts[ip] = a
	}
	if now.Sub(a.last) > loginWindow {
		a.fails = 0
	}
	a.fails++
	a.last = now
	if a.fails >= loginMaxFails {
		n := min(a.fails-loginMaxFails, 20) // guard the shift; the cap below clamps the value
		d := loginLockoutBase << uint(n)
		if d <= 0 || d > loginLockoutMax {
			d = loginLockoutMax
		}
		a.until = now.Add(d)
	}
}

// reset clears an IP's history after a successful login.
func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, ip)
}

// prune removes stale entries at most once per login window. The caller holds l.mu.
func (l *loginLimiter) prune(now time.Time) {
	if now.Before(l.nextPrune) {
		return
	}
	l.nextPrune = now.Add(loginWindow)
	for ip, a := range l.attempts {
		if now.Sub(a.last) > loginWindow && now.After(a.until) {
			delete(l.attempts, ip)
		}
	}
}
