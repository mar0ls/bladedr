package api

import (
	"sync"
	"time"
)

// loginLimiter throttles password guessing per client IP. After a burst of failures
// an IP is locked out for a backoff that doubles with each further failure, capped.
// It is in-memory (per server process), self-pruning, and cleared on a successful
// login. Not a substitute for a WAF at scale, but it turns online brute force from
// "unbounded" into "a handful of tries per window".
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

// prune drops stale entries so the map can't grow unbounded. Caller holds the lock;
// it does real work at most once per window.
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
