package main

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/hashcache"
)

// SHA-256 scan-result cache moved to internal/hashcache (ADR-0002). It is a
// clean leaf (stdlib only); every consumer — SecurityScanner.cache plus the
// metrics/otlp/ui_security stats/clear/evict call sites — goes through the
// exported API, so package main keeps the unqualified names here to leave those
// call sites and the whole test suite unchanged. No new exported API.
type (
	HashCache       = hashcache.HashCache
	ScanCacheResult = hashcache.ScanCacheResult
)

// newHashCache and SHA256Hex are re-exposed unqualified (the package func is
// hashcache.New, renamed from newHashCache for idiomatic hashcache.New usage).
var (
	SHA256Hex = hashcache.SHA256Hex
)

func newHashCache(maxSize int, ttl time.Duration) *HashCache {
	return hashcache.New(maxSize, ttl)
}
