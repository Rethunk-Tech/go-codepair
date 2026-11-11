package codepair

import (
	"errors"
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
	charged  int
}

// NewLimiter returns a limiter that locks one remote out for lockout once it has failed maxFailures guesses, and
// reports burned once burnFailures guesses have failed in all. All three bounds must be positive: a zero lockout
// would never expire, and a zero failure cap would refuse or burn on the first charge without a usable budget.
func NewLimiter(maxFailures, burnFailures int, lockout time.Duration) (*Limiter, error) {
	if maxFailures < 1 || burnFailures < 1 || lockout < 1 {
		return nil, errors.New("codepair: maxFailures, burnFailures and lockout must be positive")
	}
	return &Limiter{
		maxFailures:  maxFailures,
		burnFailures: burnFailures,
		lockout:      lockout,
		locks:        map[string]peerLock{},
	}, nil
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
	lock.charged++
	lock.last = now
	if lock.failures >= l.maxFailures {
		lock = peerLock{failures: l.maxFailures, until: now.Add(l.lockout), last: now, charged: lock.charged}
	}
	l.locks[remote] = lock
	l.failures++
	return false, false
}

// Refund gives back the guess a correct code spent, so a user who mistypes once and then succeeds still has the
// whole budget. It leaves a lockout in place, since a computer that just exhausted its guesses has not earned them
// back. A remote with no outstanding charge is left unchanged, so a refund cannot un-burn a budget another guess
// spent.
func (l *Limiter) Refund(remote string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	lock, ok := l.locks[remote]
	if !ok || lock.charged < 1 {
		return
	}
	lock.charged--
	if lock.failures > 0 && !now.Before(lock.until) {
		lock.failures--
	}
	l.locks[remote] = lock
	l.failures = max(0, l.failures-1)
}
