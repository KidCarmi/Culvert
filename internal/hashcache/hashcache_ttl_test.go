package hashcache

import (
	"testing"
	"time"
)

// TestSetTTL_ShortLivedEntryExpiresIndependently pins the property the scan
// orchestrator depends on: a verdict about the SCANNER (a fail-closed timeout
// refusal) can be remembered for seconds while verdicts about CONTENT keep the
// cache's own hour-long lifetime. Without it an infrastructure blip kept
// blocking one object for the rest of the content TTL.
func TestSetTTL_ShortLivedEntryExpiresIndependently(t *testing.T) {
	c := New(16, time.Hour)

	c.SetTTL("infra", ScanCacheResult{Clean: false, Source: "timeout"}, 40*time.Millisecond)
	c.Set("content", ScanCacheResult{Clean: true, Source: "clean"})

	if _, ok := c.Get("infra"); !ok {
		t.Fatal("short-lived entry must be served while it is fresh")
	}
	time.Sleep(80 * time.Millisecond)

	if _, ok := c.Get("infra"); ok {
		t.Fatal("short-lived entry outlived its own TTL — it inherited the cache TTL")
	}
	if _, ok := c.Get("content"); !ok {
		t.Fatal("an explicit short TTL must not affect entries stored with the cache TTL")
	}
}

// TestSetTTL_NonPositiveFallsBackToCacheTTL keeps Set and SetTTL(…, 0)
// interchangeable, which is what lets Set delegate rather than duplicate.
func TestSetTTL_NonPositiveFallsBackToCacheTTL(t *testing.T) {
	c := New(16, 50*time.Millisecond)
	c.SetTTL("k", ScanCacheResult{Clean: true}, 0)
	if _, ok := c.Get("k"); !ok {
		t.Fatal("entry must be fresh immediately after storing")
	}
	time.Sleep(90 * time.Millisecond)
	if _, ok := c.Get("k"); ok {
		t.Fatal("ttl<=0 must adopt the cache TTL, not become unbounded")
	}
}
