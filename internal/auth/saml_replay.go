package auth

import (
	"sync"
	"time"
)

// ReplayCache is an in-memory TTL cache for SAML assertion digests.
type ReplayCache struct {
	seen map[string]time.Time
	ttl  time.Duration
	mu   sync.Mutex
}

// NewReplayCache creates a cache with the given TTL.
func NewReplayCache(ttl time.Duration) *ReplayCache {
	return &ReplayCache{
		seen: make(map[string]time.Time),
		ttl:  ttl,
	}
}

// Seen returns true if digest was already recorded within TTL, and records it otherwise.
func (c *ReplayCache) Seen(digest string) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, t := range c.seen {
		if now.Sub(t) > c.ttl {
			delete(c.seen, k)
		}
	}
	if _, ok := c.seen[digest]; ok {
		return true
	}
	c.seen[digest] = now
	return false
}
