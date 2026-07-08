package main

// admin_settings_upstream_test.go — persistence contracts for the
// GUI-configured upstream pool (the "upstream runtime durability gap" logged
// as an out-of-scope observation in
// roadmap/CATEGORY-B-PRIME-FINDING-10.3-SPEC.md §5).
//
// Engine-level pool contracts (SetProxies keeps CB params, Entries() raw vs
// List() redacted, hostless-URL rejection) moved to internal/upstream with
// the ADR-0002 extraction. This file keeps the MAIN-side contracts:
//
//  1. SaveAdminSettings writes the pool with the UpstreamProxiesSaved
//     sentinel; applyAdminNetwork restores it (restart simulation) and keeps
//     the startup-configured circuit-breaker params (YAML-owned).
//  2. Sentinel semantics mirror BlocklistFeedsSaved: unset → YAML seed kept;
//     set + empty → authoritative wipe.
//  3. POST /api/upstream keeps CB params and persists via adminSettingsSave.
//
// CB params are asserted through the exported surface: Pool.Next() returns
// the sole *upstream.Proxy, whose CB exposes Params().

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// snapshotUpstreamPool captures the global pool's entries and circuit-breaker
// parameters and restores them on cleanup, so tests that mutate the global
// pool stay order-independent under -count=N / -shuffle=on.
func snapshotUpstreamPool(t *testing.T) {
	t.Helper()
	prevEntries := upstreamPool.Entries()
	prevThreshold, prevTimeout := upstreamPool.CBParams()
	t.Cleanup(func() {
		upstreamPool.Configure(prevEntries, prevThreshold, prevTimeout)
	})
}

// soleProxyCBParams returns the CB params of the pool's single healthy proxy.
func soleProxyCBParams(t *testing.T) (int, time.Duration) {
	t.Helper()
	up := upstreamPool.Next()
	if up == nil {
		t.Fatal("pool has no available proxy")
	}
	return up.CB.Params()
}

func TestAdminSettings_UpstreamRoundTrip(t *testing.T) {
	snapshotUpstreamPool(t)
	path := filepath.Join(t.TempDir(), "admin_settings.json")
	swapAdminSettingsPath(t, path)

	const userinfoURL = "http://svc:rt-userinfo@parent-a.test:3128" // #nosec G101 -- fake userinfo in a reserved .test URL; verifies raw credential round-trip through persistence
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
	if th, to := soleProxyCBParams(t); th != 7 || to != 90*time.Second {
		t.Errorf("restored CB params = %d/%v, want 7/90s (YAML-owned, not persisted)", th, to)
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

	if got := len(upstreamPool.List()); got != 1 {
		t.Fatalf("pool has %d proxies, want 1", got)
	}
	if th, to := soleProxyCBParams(t); th != 9 || to != 45*time.Second {
		t.Errorf("CB params after POST = %d/%v, want 9/45s (handler must not hardcode 5/60s)", th, to)
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
