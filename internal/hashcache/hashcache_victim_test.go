package hashcache

import (
	"fmt"
	"testing"
	"time"
)

// The scan cache holds two kinds of entry with very different lifetimes:
// content verdicts at the configured TTL (1h by default), and SetTTL entries
// that describe the SCANNER — secscan's fail-closed scan-timeout cooldown, 30s.
// These tests pin the eviction policy that keeps the second kind usable, which
// a pure minimum-absolute-expiry victim rule silently removed: the cooldown was
// always the heap root, so at capacity the next insert of any new key destroyed
// it. See liveVictimLocked.
//
// shortTTL and contentTTL stand in for that ratio. They are long enough that
// nothing under test expires during the run — these are LIVE-eviction tests,
// and an expired entry would be reaped by the batch loop instead, which is a
// different (already pinned) branch.
const (
	contentTTL = time.Hour
	shortTTL   = 30 * time.Second
)

// TestLiveEviction_ShortLivedEntrySurvivesNewKeyChurn is the regression gate.
// A fail-closed cooldown must still be in the cache after enough new-key
// inserts to have replaced the whole cache, because every one of those inserts
// has a full-lifetime verdict available to evict instead.
func TestLiveEviction_ShortLivedEntrySurvivesNewKeyChurn(t *testing.T) {
	const capacity = 64
	c := New(capacity, contentTTL)

	// Fill with content verdicts, then install one scanner-state entry. The
	// cache is now at capacity, nothing is expired: every further new key must
	// evict a verdict.
	for i := 0; i < capacity-1; i++ {
		c.Set(fmt.Sprintf("verdict%d", i), ScanCacheResult{Clean: true, Source: "clamav"})
	}
	c.SetTTL("hot", ScanCacheResult{Clean: false, Reason: "scan timeout", Source: "timeout"}, shortTTL)
	if _, ok := c.Get("hot"); !ok {
		t.Fatal("precondition: the cooldown was not stored")
	}

	for i := 0; i < capacity*4; i++ {
		c.Set(fmt.Sprintf("churn%d", i), ScanCacheResult{Clean: true, Source: "clamav"})
		if _, ok := c.Get("hot"); !ok {
			t.Fatalf("the fail-closed scan-timeout cooldown was evicted after %d new-key insert(s); "+
				"it must outlive churn while full-lifetime verdicts are available to evict, or the "+
				"anti-stampede guard is inert at capacity", i+1)
		}
	}
	checkInvariants(t, c)
}

// TestLiveEviction_PrefersTheEarliestFullLifetimeEntry pins which verdict is
// chosen: still the one closest to expiry, so the policy for ordinary content
// is unchanged. Negative control for the test above — protecting short-lived
// entries must not degrade into "evict the newest" or "evict arbitrarily".
func TestLiveEviction_PrefersTheEarliestFullLifetimeEntry(t *testing.T) {
	const capacity = 8
	c := New(capacity, contentTTL)

	// Stored oldest-first, so "oldest" has the earliest expiry of the verdicts.
	c.Set("oldest", ScanCacheResult{Clean: true})
	for i := 0; i < capacity-2; i++ {
		c.Set(fmt.Sprintf("v%d", i), ScanCacheResult{Clean: true})
	}
	c.SetTTL("cooldown", ScanCacheResult{Clean: false, Source: "timeout"}, shortTTL)

	c.Set("newkey", ScanCacheResult{Clean: true})

	if _, ok := c.Get("oldest"); ok {
		t.Error("the earliest-expiring full-lifetime verdict should have been the victim")
	}
	if _, ok := c.Get("cooldown"); !ok {
		t.Error("the short-lived cooldown must not be the victim while a verdict is available")
	}
	checkInvariants(t, c)
}

// TestLiveEviction_AllShortLivedStillEvicts is the bound control: protecting
// short-lived entries must never let the cache grow past maxSize. With nothing
// but cooldowns in it, a cooldown has to go.
func TestLiveEviction_AllShortLivedStillEvicts(t *testing.T) {
	const capacity = 4
	c := New(capacity, contentTTL)

	for i := 0; i < capacity; i++ {
		c.SetTTL(fmt.Sprintf("cd%d", i), ScanCacheResult{Clean: false, Source: "timeout"}, shortTTL)
	}
	for i := 0; i < capacity*3; i++ {
		c.SetTTL(fmt.Sprintf("more%d", i), ScanCacheResult{Clean: false, Source: "timeout"}, shortTTL)
		if _, _, size := c.Stats(); size > capacity {
			t.Fatalf("size %d exceeded capacity %d", size, capacity)
		}
	}
	checkInvariants(t, c)
}

// TestLiveEviction_UniformTTLIsUnchanged pins that the common case — every
// entry at the configured TTL — keeps the plain closest-to-expiry behaviour,
// so this change is confined to caches that actually mix lifetimes.
func TestLiveEviction_UniformTTLIsUnchanged(t *testing.T) {
	const capacity = 16
	c := New(capacity, contentTTL)

	c.Set("first", ScanCacheResult{Clean: true})
	for i := 0; i < capacity-1; i++ {
		c.Set(fmt.Sprintf("k%d", i), ScanCacheResult{Clean: true})
	}
	c.Set("overflow", ScanCacheResult{Clean: true})

	if _, ok := c.Get("first"); ok {
		t.Error("with a uniform TTL the earliest-stored entry is the victim")
	}
	if _, ok := c.Get("overflow"); !ok {
		t.Error("the new key must be present")
	}
	if _, _, size := c.Stats(); size != capacity {
		t.Errorf("size = %d, want %d", size, capacity)
	}
	checkInvariants(t, c)
}
