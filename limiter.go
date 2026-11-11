package codepair

import (
	"sync"
	"time"
)

// Limiter bounds online guessing at the code. A caller charges it once per handshake run, before replying to the
// joiner's message, because each run lets an active attacker test exactly one guess. Two counts are kept: a
// per-remote one that locks one computer out after maxFailures, and a global one that reports burnFailures, at which
// the caller should drop the code.
type Limiter struct {
	mu           sync.Mutex
	maxFailures  int
	burnFailures int
	lockout      time.Duration
	locks        map[string]peerLock
	failures     int
}

type peerLock struct {
	failures int
	until    time.Time
	last     time.Time
}

// NewLimiter returns a limiter that locks one remote out for lockout once it has failed maxFailures guesses, and
// reports burned once burnFailures guesses have failed in all.
func NewLimiter(maxFailures, burnFailures int, lockout time.Duration) *Limiter {
	return &Limiter{
		maxFailures:  maxFailures,
		burnFailures: burnFailures,
		lockout:      lockout,
		locks:        map[string]peerLock{},
	}
}

// Charge records one guess from remote and reports whether the guess may be served. locked means remote is inside a
// lockout; burned means the guesses failed in all have spent burnFailures, and the caller should drop the code.
// Either way nothing is counted and the guess must be refused. Checking and counting happen under one lock, so
// concurrent runs cannot jointly pass the limit; the remote is whatever the caller keys on, so a limit per remote
// holds only as far as an attacker cannot choose it, and the global count is the bound that does not depend on that.
func (l *Limiter) Charge(remote string, now time.Time) (locked, burned bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// A lock that has been quiet for a whole lockout says nothing about a computer that comes back tomorrow.
	for peer, lock := range l.locks {
		if now.Sub(lock.last) > l.lockout {
			delete(l.locks, peer)
		}
	}
	lock := l.locks[remote]
	if now.Before(lock.until) {
		return true, false
	}
	if l.failures >= l.burnFailures {
		return false, true
	}
	lock.failures++
	lock.last = now
	if lock.failures >= l.maxFailures {
		lock = peerLock{failures: l.maxFailures, until: now.Add(l.lockout), last: now}
	}
	l.locks[remote] = lock
	l.failures++
	return false, false
}

// Refund gives back the guess a correct code spent, so a user who mistypes once and then succeeds still has the
// whole budget. It leaves a lockout in place, since a computer that just exhausted its guesses has not earned them
// back.
func (l *Limiter) Refund(remote string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lock, ok := l.locks[remote]; ok && lock.failures > 0 && !now.Before(lock.until) {
		lock.failures--
		l.locks[remote] = lock
	}
	l.failures = max(0, l.failures-1)
}
