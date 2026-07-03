package main

// admin_settings_upstream_test.go — persistence + circuit-breaker-parameter
// contracts for the GUI-configured upstream pool (the "upstream runtime
// durability gap" logged as an out-of-scope observation in
// roadmap/CATEGORY-B-PRIME-FINDING-10.3-SPEC.md §5).
//
// Contracts pinned here:
//  1. SetProxies keeps the circuit-breaker parameters from the last
//     Configure (the API path previously hardcoded 5/60s).
//  2. Entries() round-trips RAW entry URLs (inline credentials intact) while
//     List() stays redacted — persistence needs the former, display the latter.
//  3. SaveAdminSettings writes the pool with the UpstreamProxiesSaved
//     sentinel; applyAdminNetwork restores it (restart simulation).
//  4. Sentinel semantics mirror BlocklistFeedsSaved: unset → YAML seed kept;
//     set + empty → authoritative wipe.

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// snapshotUpstreamPool captures the global pool's entries and circuit-breaker
// parameters and restores them on cleanup, so tests that mutate the global
// pool stay order-independent under -count=N / -shuffle=on.
func snapshotUpstreamPool(t *testing.T) {
	t.Helper()
	upstreamPool.mu.RLock()
	prevEntries := append([]UpstreamEntry(nil), upstreamPool.entries...)
	prevThreshold := upstreamPool.cbThreshold
	prevTimeout := upstreamPool.cbTimeout
	upstreamPool.mu.RUnlock()
	t.Cleanup(func() {
		upstreamPool.Configure(prevEntries, prevThreshold, prevTimeout)
	})
}

func TestUpstreamPool_SetProxiesPreservesCBParams(t *testing.T) {
	pool := &UpstreamPool{}
	pool.Configure([]UpstreamEntry{{URL: "http://seed.test:3128"}}, 7, 90*time.Second)

	pool.SetProxies([]UpstreamEntry{{URL: "http://replaced.test:3128"}})

	pool.mu.RLock()
	defer pool.mu.RUnlock()
	if len(pool.proxies) != 1 {
		t.Fatalf("proxies = %d, want 1", len(pool.proxies))
	}
	cb := pool.proxies[0].CB
	if cb.threshold != 7 {
		t.Errorf("threshold = %d, want 7 (SetProxies must keep Configure's CB params)", cb.threshold)
	}
	if cb.timeout != 90*time.Second {
		t.Errorf("timeout = %v, want 90s (SetProxies must keep Configure's CB params)", cb.timeout)
	}
}

func TestUpstreamPool_SetProxiesOnZeroPoolUsesCBDefaults(t *testing.T) {
	// A pool that was never Configure'd (or Configure'd with zero params —
	// YAML with no circuit_breaker section) must fall back to the
	// newCircuitBreaker defaults, matching the API handler's old behavior.
	pool := &UpstreamPool{}
	pool.SetProxies([]UpstreamEntry{{URL: "http://gui-added.test:3128"}})

	pool.mu.RLock()
	defer pool.mu.RUnlock()
	if len(pool.proxies) != 1 {
		t.Fatalf("proxies = %d, want 1", len(pool.proxies))
	}
	cb := pool.proxies[0].CB
	if cb.threshold != 5 || cb.timeout != 60*time.Second {
		t.Errorf("CB params = %d/%v, want defaults 5/60s", cb.threshold, cb.timeout)
	}
}

func TestUpstreamPool_EntriesReturnsRawCredentialedURL(t *testing.T) {
	const raw = "http://user:sekret-cred@parent.test:3128"
	pool := &UpstreamPool{}
	pool.Configure([]UpstreamEntry{{URL: raw}}, 5, time.Minute)

	entries := pool.Entries()
	if len(entries) != 1 || entries[0].URL != raw {
		t.Fatalf("Entries() = %+v, want raw URL %q (persistence must round-trip credentials)", entries, raw)
	}
	list := pool.List()
	if len(list) != 1 {
		t.Fatalf("List() = %d entries, want 1", len(list))
	}
	if strings.Contains(list[0].URL, "sekret-cred") {
		t.Errorf("List() leaked the credential: %q (must stay redacted)", list[0].URL)
	}
}

func TestUpstreamPool_SkipsHostlessURL(t *testing.T) {
	pool := &UpstreamPool{}
	pool.SetProxies([]UpstreamEntry{
		{URL: "parent1.corp.com:3128"}, // no scheme — parses opaque, undialable
		{URL: ""},
		{URL: "http://ok.test:3128"},
	})
	entries := pool.Entries()
	if len(entries) != 1 || entries[0].URL != "http://ok.test:3128" {
		t.Fatalf("Entries() = %+v, want only the valid scheme://host URL", entries)
	}
	if got := len(pool.List()); got != 1 {
		t.Fatalf("List() = %d proxies, want 1", got)
	}
}

func TestAdminSettings_UpstreamRoundTrip(t *testing.T) {
	snapshotUpstreamPool(t)
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)

	const userinfoURL = "http://svc:rt-userinfo@parent-a.test:3128" // fake — reserved .test TLD
	upstreamPool.Configure([]UpstreamEntry{
		{URL: userinfoURL},
		{URL: "http://parent-b.test:3128"},
	}, 7, 90*time.Second)

	SaveAdminSettings()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("settings file not written: %v", err)
	}
	var s AdminSettings
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	if !s.UpstreamProxiesSaved {
		t.Error("upstream_proxies_saved = false; want true (sentinel must be set on save)")
	}
	if len(s.UpstreamProxies) != 2 || s.UpstreamProxies[0].URL != userinfoURL {
		t.Fatalf("persisted proxies = %+v; want 2 raw entries with credentials intact", s.UpstreamProxies)
	}

	// Restart simulation: wipe the pool, then restore from the parsed file.
	upstreamPool.SetProxies(nil)
	if upstreamPool.Enabled() {
		t.Fatal("pool should be empty before restore")
	}
	applyAdminNetwork(&AdminSettings{
		UpstreamProxiesSaved: s.UpstreamProxiesSaved,
		UpstreamProxies:      s.UpstreamProxies,
	})
	restored := upstreamPool.Entries()
	if len(restored) != 2 || restored[0].URL != userinfoURL {
		t.Fatalf("restored entries = %+v; want the 2 saved entries", restored)
	}

	// The restore path must keep the startup-configured CB params too.
	upstreamPool.mu.RLock()
	defer upstreamPool.mu.RUnlock()
	if cb := upstreamPool.proxies[0].CB; cb.threshold != 7 || cb.timeout != 90*time.Second {
		t.Errorf("restored CB params = %d/%v, want 7/90s (YAML-owned, not persisted)", cb.threshold, cb.timeout)
	}
}

func TestAdminSettings_UpstreamSentinelUnsetKeepsSeed(t *testing.T) {
	snapshotUpstreamPool(t)
	upstreamPool.Configure([]UpstreamEntry{{URL: "http://yaml-seed.test:3128"}}, 5, time.Minute)

	// Pre-feature settings file: no sentinel, no list → seed untouched.
	applyAdminNetwork(&AdminSettings{})

	entries := upstreamPool.Entries()
	if len(entries) != 1 || entries[0].URL != "http://yaml-seed.test:3128" {
		t.Fatalf("entries = %+v; want the YAML seed untouched (upgrade safety)", entries)
	}
}

func TestAdminSettings_UpstreamEmptyWipes(t *testing.T) {
	snapshotUpstreamPool(t)
	upstreamPool.Configure([]UpstreamEntry{{URL: "http://yaml-seed.test:3128"}}, 5, time.Minute)

	// Sentinel set with an empty list: the admin deleted every proxy in the
	// GUI — that decision must survive a restart.
	applyAdminNetwork(&AdminSettings{UpstreamProxiesSaved: true})

	if upstreamPool.Enabled() {
		t.Fatalf("entries = %+v; want empty (saved wipe is authoritative over the YAML seed)", upstreamPool.Entries())
	}
}

func TestAPIUpstream_PostKeepsCBParamsAndPersists(t *testing.T) {
	snapshotUpstreamPool(t)
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)

	// Startup-configured CB params the handler must not clobber.
	upstreamPool.Configure(nil, 9, 45*time.Second)

	r := jsonReq("POST", "/api/upstream", map[string]any{
		"proxies": []map[string]string{{"url": "http://api-added.test:3128"}},
	})
	w := httptest.NewRecorder()
	apiUpstream(w, r)
	assertStatus(t, w, 200)

	upstreamPool.mu.RLock()
	if len(upstreamPool.proxies) != 1 {
		upstreamPool.mu.RUnlock()
		t.Fatalf("pool has %d proxies, want 1", len(upstreamPool.proxies))
	}
	cb := upstreamPool.proxies[0].CB
	threshold, timeout := cb.threshold, cb.timeout
	upstreamPool.mu.RUnlock()
	if threshold != 9 || timeout != 45*time.Second {
		t.Errorf("CB params after POST = %d/%v, want 9/45s (handler must not hardcode 5/60s)", threshold, timeout)
	}

	// adminSettingsSave runs SaveAdminSettings in a goroutine — poll for the
	// file rather than assuming scheduling order.
	deadline := time.Now().Add(5 * time.Second)
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			var s AdminSettings
			if json.Unmarshal(data, &s) == nil && s.UpstreamProxiesSaved &&
				len(s.UpstreamProxies) == 1 && s.UpstreamProxies[0].URL == "http://api-added.test:3128" {
				return // persisted — contract met
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("settings file never persisted the POSTed upstream (err=%v)", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
