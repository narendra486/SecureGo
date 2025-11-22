package middleware

import (
	"net/http"
	"sync"
	"time"
)

// RateLimiter is a simple token-bucket limiter per key (IP by default).
type RateLimiter struct {
	rate    time.Duration
	burst   int
	buckets map[string]*bucket
	mu      sync.Mutex
	keyFunc func(*http.Request) string
	now     func() time.Time
}

type bucket struct {
	tokens int
	last   time.Time
}

// NewIPRateLimit returns a limiter allowing burst tokens per rate interval.
func NewIPRateLimit(rate time.Duration, burst int) *RateLimiter {
	return &RateLimiter{
		rate:    rate,
		burst:   burst,
		buckets: make(map[string]*bucket),
		keyFunc: func(r *http.Request) string { return IPFromRequest(r) },
		now:     time.Now,
	}
}

// NewKeyRateLimit allows rate limiting on an arbitrary key (e.g., user ID).
func NewKeyRateLimit(rate time.Duration, burst int, keyFunc func(*http.Request) string) *RateLimiter {
	if keyFunc == nil {
		keyFunc = func(r *http.Request) string { return IPFromRequest(r) }
	}
	return &RateLimiter{
		rate:    rate,
		burst:   burst,
		buckets: make(map[string]*bucket),
		keyFunc: keyFunc,
		now:     time.Now,
	}
}

// Middleware enforces the limit and responds 429 when exceeded.
func (l *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := l.keyFunc(r)
		if !l.allow(key) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *RateLimiter) allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	elapsed := now.Sub(b.last)
	if elapsed > 0 {
		refill := int(elapsed / l.rate)
		if refill > 0 {
			b.tokens = min(l.burst, b.tokens+refill)
			b.last = now
		}
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
