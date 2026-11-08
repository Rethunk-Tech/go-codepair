package codepair

import (
	"sync"
	"time"
)

// Limiter bounds online guessing at the code. A caller charges it once per guess, before checking the guess, so
// guesses made side by side cannot outnumber the limit. Two counts are kept: a per-remote one that locks one computer
// out after maxFailures, and a global one that reports burnFailures, at which the caller should drop the code.
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

// Locked reports whether remote is inside a lockout at now.
func (l *Limiter) Locked(remote string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return now.Before(l.locks[remote].until)
}

// Charge records one guess from remote. It returns burned once the guesses failed in all have reached burnFailures,
// which is the caller's signal to stop honouring the code; further charges keep returning burned until Refund gives
// a guess back.
func (l *Limiter) Charge(remote string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	// A lock that has been quiet for a whole lockout says nothing about a computer that comes back tomorrow.
	for peer, lock := range l.locks {
		if now.Sub(lock.last) > l.lockout {
			delete(l.locks, peer)
		}
	}
	lock := l.locks[remote]
	lock.failures++
	lock.last = now
	if lock.failures >= l.maxFailures {
		lock = peerLock{failures: l.maxFailures, until: now.Add(l.lockout), last: now}
	}
	l.locks[remote] = lock
	l.failures++
	return l.failures >= l.burnFailures
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
