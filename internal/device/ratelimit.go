package device

import (
	"sync"
	"time"
)

// Limiter is a token bucket keyed by caller (in practice, client IP).
//
// It exists because a user code is short enough to guess given enough
// attempts: RFC 8628 §5.1 requires rate limiting on the verification endpoint
// precisely so the code's entropy is not the only thing standing between an
// attacker and someone else's certificate.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket

	burst  int           // tokens available to an idle caller
	refill time.Duration // time to regain one token
	now    func() time.Time
	lastGC time.Time
}

type bucket struct {
	tokens float64
	seen   time.Time
}

// NewLimiter builds a Limiter allowing burst attempts up front, replenishing
// one token every refill. Zero values take modest defaults.
func NewLimiter(burst int, refill time.Duration, now func() time.Time) *Limiter {
	if burst <= 0 {
		burst = 10
	}
	if refill <= 0 {
		refill = 10 * time.Second
	}
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		buckets: make(map[string]*bucket),
		burst:   burst,
		refill:  refill,
		now:     now,
	}
}

// Allow consumes a token for key, reporting whether the attempt may proceed.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.gcLocked(now)

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(l.burst)}
		l.buckets[key] = b
	} else {
		b.tokens += float64(now.Sub(b.seen)) / float64(l.refill)
		if b.tokens > float64(l.burst) {
			b.tokens = float64(l.burst)
		}
	}
	b.seen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// gcLocked drops buckets that have sat idle long enough to have refilled
// completely, since they are indistinguishable from a fresh caller. Callers
// must hold l.mu.
func (l *Limiter) gcLocked(now time.Time) {
	// Sweeping on every call would make Allow O(n); once a minute is plenty
	// to keep the map proportional to active callers.
	if now.Sub(l.lastGC) < time.Minute {
		return
	}
	l.lastGC = now

	idle := time.Duration(l.burst) * l.refill
	for key, b := range l.buckets {
		if now.Sub(b.seen) >= idle {
			delete(l.buckets, key)
		}
	}
}
