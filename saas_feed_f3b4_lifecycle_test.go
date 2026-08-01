package main

// saas_feed_f3b4_lifecycle_test.go — F3b-4: startup lifecycle (offline-first, embedded
// baseline, no network), legacy-syncer retirement, and latched alerts.

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/saasfeed"
)

func swapFeedRuntimeGlobals(t *testing.T) {
	t.Helper()
	prevRT, prevSched, prevAuth := globalSaaSFeedRuntime, globalSaaSFeedScheduler, globalSaaSFeedAuthorityStore
	t.Cleanup(func() {
		globalSaaSFeedRuntime = prevRT
		globalSaaSFeedScheduler = prevSched
		globalSaaSFeedAuthorityStore = prevAuth
	})
}

// ─── startup lifecycle: offline-first, embedded baseline, no network ──────────────

func TestF3b4_Lifecycle_OfflineFirstEmbedded(t *testing.T) {
	f3a2ResetFeedDurable(t)
	f3a2SwapOverrides(t)
	swapClusterRole(t, "standalone")
	swapFeedStatus(t, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	swapFeedRuntimeGlobals(t)
	resetOwnership(t)
	// Disabled by default (no explicit management) ⇒ never fetches.
	setSaaSFeedDurable(saasFeedDurable{SchemaVersion: saasStoreSchemaVersion})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	feedDir := filepath.Join(t.TempDir(), "saas_feed")

	startSignedFeedLifecycle(feedDir, ctx)

	if globalSaaSFeedRuntime == nil {
		t.Fatal("lifecycle did not arm the runtime")
	}
	// Recovery installed the embedded baseline into the live store (offline; fresh dir).
	live := globalSaaSFeedRuntime.live.Current()
	if live == nil || live.Source != sourceEmbedded {
		t.Fatalf("expected embedded baseline installed, got %+v", live)
	}
	if live.HostCount() == 0 {
		t.Error("embedded baseline should carry compiled hosts")
	}
	// Status is truthful: enabled=false ⇒ disabled state (never never_succeeded churn).
	if st := globalSaaSFeedStatus.Snapshot().State; st != saasFeedStateDisabled {
		t.Errorf("state = %s, want disabled", st)
	}
	// The legacy raw syncer was NOT armed by the lifecycle (no fetch of the old URL).
	if url := globalSaaSFeed.FeedURL(); url != "" {
		t.Errorf("legacy syncer was armed (url=%q) — must stay retired", url)
	}
}

// ─── legacy-syncer retirement: cannot write under ownership; UT1 untouched ─────────

func TestF3b4_LegacySyncerRetired_NoWriteUnderOwnership(t *testing.T) {
	resetOwnership(t)
	// Under signed-feed ownership, the legacy merge is a hard no-op (single writer).
	setSignedFeedOwnsLiveStore(true)
	if n := mergeSaaSCategories([]saasfeed.Category{{Name: "TestCat", Hosts: []string{"legacy.example.com"}}}); n != 0 {
		t.Errorf("legacy syncer wrote %d hosts under signed-feed ownership — must be zero", n)
	}
}

func TestF3b4_UT1MetricsUnaffected(t *testing.T) {
	var sb strings.Builder
	urlcatWritePrometheus(&sb)
	s := sb.String()
	// UT1 category feed metrics remain; the retired legacy SaaS metrics are gone.
	if !strings.Contains(s, "culvert_category_feed_last_sync_timestamp_seconds") {
		t.Error("UT1 category feed metrics missing (must be unchanged)")
	}
	if strings.Contains(s, "culvert_saas_feed_entries") || strings.Contains(s, "culvert_saas_feed_sync_failures_total") {
		t.Error("retired legacy SaaS feed metrics still emitted")
	}
}

// ─── latched alerts: fire once per crossing, recovered on clear ────────────────────

func TestF3b4_Alerts_LatchedFireOnce(t *testing.T) {
	// Swap the alert sink for a recorder + reset the latches.
	var mu sync.Mutex
	var events []string
	prevFire := saasFeedAlertFire
	saasFeedAlertFire = func(event string, _ AlertPayload) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
	}
	globalSaaSFeedAlerts.mu.Lock()
	globalSaaSFeedAlerts.refreshFailing, globalSaaSFeedAlerts.stale, globalSaaSFeedAlerts.critical, globalSaaSFeedAlerts.waitingAuthority = false, false, false, false
	globalSaaSFeedAlerts.mu.Unlock()
	t.Cleanup(func() {
		saasFeedAlertFire = prevFire
		globalSaaSFeedAlerts.mu.Lock()
		globalSaaSFeedAlerts.refreshFailing, globalSaaSFeedAlerts.stale, globalSaaSFeedAlerts.critical, globalSaaSFeedAlerts.waitingAuthority = false, false, false, false
		globalSaaSFeedAlerts.mu.Unlock()
	})

	drain := func() []string { mu.Lock(); defer mu.Unlock(); out := events; events = nil; return out }

	// 3 consecutive failures ⇒ refresh_failing fires ONCE.
	evaluateSaaSFeedAlerts(saasFeedStatusSnapshot{ConsecutiveFailures: 3, LastErrorClass: "fetch"})
	evaluateSaaSFeedAlerts(saasFeedStatusSnapshot{ConsecutiveFailures: 4, LastErrorClass: "fetch"})
	got := drain()
	if len(got) != 1 || got[0] != "saas_feed_refresh_failing" {
		t.Fatalf("expected one refresh_failing, got %v", got)
	}
	// Recovery ⇒ recovered fires once.
	evaluateSaaSFeedAlerts(saasFeedStatusSnapshot{ConsecutiveFailures: 0})
	if got := drain(); len(got) != 1 || got[0] != "saas_feed_recovered" {
		t.Fatalf("expected one recovered, got %v", got)
	}

	// Stale crossing fires once.
	evaluateSaaSFeedAlerts(saasFeedStatusSnapshot{ActiveFeedVersion: 5, Stale: true})
	evaluateSaaSFeedAlerts(saasFeedStatusSnapshot{ActiveFeedVersion: 5, Stale: true})
	if got := drain(); len(got) != 1 || got[0] != "saas_feed_stale" {
		t.Fatalf("expected one stale, got %v", got)
	}

	// Waiting-for-authority crossing fires once.
	evaluateSaaSFeedAlerts(saasFeedStatusSnapshot{WaitingForAuthority: true})
	if got := drain(); len(got) != 1 || got[0] != "saas_feed_missing_authority" {
		t.Fatalf("expected one missing_authority, got %v", got)
	}

	// Critical crossing fires recovery_degraded once.
	evaluateSaaSFeedAlerts(saasFeedStatusSnapshot{Critical: true, CriticalReason: "equivocation"})
	if got := drain(); len(got) != 1 || got[0] != "saas_feed_recovery_degraded" {
		t.Fatalf("expected one recovery_degraded, got %v", got)
	}
}
