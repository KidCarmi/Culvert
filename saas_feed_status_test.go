package main

// saas_feed_status_test.go — F3b-4: runtime status model — state derivation, counters,
// null-delta, 304 provenance retention, cancellation exclusion, provenance transitions.

import (
	"testing"
	"time"
)

func f3b4Clock(t time.Time) func() time.Time { return func() time.Time { return t } }

func statusWithClock(now time.Time) *saasFeedStatus {
	return newSaaSFeedStatus(f3b4Clock(now))
}

func viewFor(src effectiveSource, version int64, gen, exp string) *effectiveCategoryView {
	return newEffectiveView(map[string]string{"a.example.com": "social"}, effectiveCategoryView{
		Source: src, FeedVersion: version, GeneratedAt: gen, ExpiresAt: exp, ConfigRevision: "none",
	})
}

func TestF3b4_Status_DerivedStatePrecedence(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

	t.Run("disabled", func(t *testing.T) {
		s := statusWithClock(base)
		s.noteConfig(feedAuthorityResolution{Authority: authorityStandalone, Config: SaaSFeedConfig{Enabled: false}})
		if got := s.Snapshot().State; got != saasFeedStateDisabled {
			t.Errorf("state = %s, want disabled", got)
		}
	})
	t.Run("waiting_for_authority", func(t *testing.T) {
		s := statusWithClock(base)
		s.noteConfig(feedAuthorityResolution{Authority: authorityManagedDP, WaitingForAuthority: true})
		if got := s.Snapshot().State; got != saasFeedStateWaitingForAuthority {
			t.Errorf("state = %s, want waiting_for_authority", got)
		}
	})
	t.Run("embedded (enabled, never succeeded)", func(t *testing.T) {
		s := statusWithClock(base)
		s.noteConfig(feedAuthorityResolution{Authority: authorityStandalone, Config: SaaSFeedConfig{Managed: true, Enabled: true}})
		snap := s.Snapshot()
		if snap.State != saasFeedStateEmbedded {
			t.Errorf("state = %s, want embedded", snap.State)
		}
		if !snap.NeverSucceeded || snap.LastActivationDelta != nil {
			t.Errorf("embedded/never_succeeded must have null delta: %+v", snap)
		}
		if snap.SignatureStatus != "compiled_trusted" || !snap.CompiledTrusted {
			t.Errorf("embedded must be compiled_trusted: %+v", snap)
		}
	})
	t.Run("fresh", func(t *testing.T) {
		s := statusWithClock(base)
		s.noteConfig(feedAuthorityResolution{Authority: authorityStandalone, Config: SaaSFeedConfig{Managed: true, Enabled: true}})
		s.noteActivation(viewFor(sourceDownloaded, 5, "2026-08-01T00:00:00Z", "2026-08-20T00:00:00Z"), saasFeedActivationDelta{HostsAdded: 3})
		snap := s.Snapshot()
		if snap.State != saasFeedStateFresh {
			t.Errorf("state = %s, want fresh", snap.State)
		}
		if snap.Provenance != "downloaded" || snap.SignatureStatus != "verified" {
			t.Errorf("fresh provenance/sig wrong: %+v", snap)
		}
		if snap.LastActivationDelta == nil || snap.LastActivationDelta.HostsAdded != 3 {
			t.Errorf("delta should be present after activation: %+v", snap.LastActivationDelta)
		}
		if snap.ExpiresInDays == nil || *snap.ExpiresInDays != 19 {
			t.Errorf("expires_in_days = %v, want 19", snap.ExpiresInDays)
		}
	})
}

// TestF3b4_Status_DerivedStateServing covers the serving/operational states (split from
// the precedence test to keep each function under the cognitive-complexity bound).
func TestF3b4_Status_DerivedStateServing(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	t.Run("stale", func(t *testing.T) {
		s := statusWithClock(base)
		s.noteConfig(feedAuthorityResolution{Authority: authorityStandalone, Config: SaaSFeedConfig{Managed: true, Enabled: true}})
		v := viewFor(sourceCached, 5, "2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z")
		v.Stale = true
		s.noteActivation(v, saasFeedActivationDelta{})
		if got := s.Snapshot().State; got != saasFeedStateStale {
			t.Errorf("state = %s, want stale", got)
		}
	})
	t.Run("degraded (active + recent failures)", func(t *testing.T) {
		s := statusWithClock(base)
		s.noteConfig(feedAuthorityResolution{Authority: authorityStandalone, Config: SaaSFeedConfig{Managed: true, Enabled: true}})
		s.noteActivation(viewFor(sourceDownloaded, 5, "2026-08-01T00:00:00Z", "2026-08-20T00:00:00Z"), saasFeedActivationDelta{})
		s.noteAttemptFailure(saasFeedErrFetch, 0, false, "dial timeout")
		if got := s.Snapshot().State; got != saasFeedStateDegraded {
			t.Errorf("state = %s, want degraded", got)
		}
	})
	t.Run("syncing (fresh + in-flight)", func(t *testing.T) {
		s := statusWithClock(base)
		s.noteConfig(feedAuthorityResolution{Authority: authorityStandalone, Config: SaaSFeedConfig{Managed: true, Enabled: true}})
		s.noteActivation(viewFor(sourceDownloaded, 5, "2026-08-01T00:00:00Z", "2026-08-20T00:00:00Z"), saasFeedActivationDelta{})
		s.noteSyncStart()
		if got := s.Snapshot().State; got != saasFeedStateSyncing {
			t.Errorf("state = %s, want syncing", got)
		}
		s.noteSyncEnd()
		if got := s.Snapshot().State; got != saasFeedStateFresh {
			t.Errorf("post-sync state = %s, want fresh", got)
		}
	})
	t.Run("critical overrides serving state", func(t *testing.T) {
		s := statusWithClock(base)
		s.noteConfig(feedAuthorityResolution{Authority: authorityStandalone, Config: SaaSFeedConfig{Managed: true, Enabled: true}})
		s.noteRecovery(recoveryResult{Class: recoveryEquivocation, Critical: true, Detail: "equivocation"})
		if got := s.Snapshot().State; got != saasFeedStateCritical {
			t.Errorf("state = %s, want critical", got)
		}
	})
}

func TestF3b4_Status_FailuresSinceStartAndCancellation(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	s := statusWithClock(base)
	s.noteConfig(feedAuthorityResolution{Authority: authorityStandalone, Config: SaaSFeedConfig{Managed: true, Enabled: true}})

	s.noteAttemptFailure(saasFeedErrFetch, 0, false, "x")
	s.noteAttemptFailure(saasFeedErrHTTP, 503, false, "y")
	snap := s.Snapshot()
	if snap.FailuresSinceStart != 2 || snap.ConsecutiveFailures != 2 {
		t.Fatalf("failures = %d / consecutive = %d, want 2/2", snap.FailuresSinceStart, snap.ConsecutiveFailures)
	}

	// Shutdown cancellation is NOT a failure — no counter change, never degraded.
	s.noteAttemptFailure(saasFeedErrFetch, 0, true, "canceled")
	snap = s.Snapshot()
	if snap.FailuresSinceStart != 2 || snap.ConsecutiveFailures != 2 {
		t.Errorf("cancellation counted as failure: %d/%d", snap.FailuresSinceStart, snap.ConsecutiveFailures)
	}
	if snap.LastOutcome != saasFeedOutcomeCanceled {
		t.Errorf("last outcome = %s, want canceled", snap.LastOutcome)
	}

	// A successful activation resets the consecutive streak but not the lifetime counter.
	s.noteActivation(viewFor(sourceDownloaded, 1, "2026-08-01T00:00:00Z", "2026-08-20T00:00:00Z"), saasFeedActivationDelta{HostsAdded: 1})
	snap = s.Snapshot()
	if snap.ConsecutiveFailures != 0 || snap.FailuresSinceStart != 2 {
		t.Errorf("post-success counters = %d/%d, want 0/2", snap.ConsecutiveFailures, snap.FailuresSinceStart)
	}
}

func TestF3b4_Status_304RetainsProvenance(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	s := statusWithClock(base)
	s.noteConfig(feedAuthorityResolution{Authority: authorityStandalone, Config: SaaSFeedConfig{Managed: true, Enabled: true}})
	s.noteActivation(viewFor(sourceDownloaded, 5, "2026-08-01T00:00:00Z", "2026-08-20T00:00:00Z"), saasFeedActivationDelta{HostsAdded: 2})

	// A 304 recomputes freshness, keeps provenance, resets the failure streak, no new activation.
	s.noteAttemptFailure(saasFeedErrFetch, 0, false, "blip") // streak = 1
	s.noteNoChange(f3b4Time("2026-08-20T00:00:00Z"), false)
	snap := s.Snapshot()
	if snap.Provenance != "downloaded" || snap.ActiveSource != "downloaded" {
		t.Errorf("304 changed provenance: %+v", snap)
	}
	if !snap.Last304 || snap.LastOutcome != saasFeedOutcomeNoChange || snap.ConsecutiveFailures != 0 {
		t.Errorf("304 bookkeeping wrong: %+v", snap)
	}
	if snap.ActiveFeedVersion != 5 {
		t.Errorf("304 must not change active version: %d", snap.ActiveFeedVersion)
	}
}

func TestF3b4_Status_ProvenanceTransitionRestartCached(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	// Restart: recovery of a durable committed generation reports `cached`.
	s := statusWithClock(base)
	s.noteConfig(feedAuthorityResolution{Authority: authorityStandalone, Config: SaaSFeedConfig{Managed: true, Enabled: true}})
	s.noteRecovery(recoveryResult{
		Class: recoveryActiveServed, ActiveVersion: 7, Source: sourceCached,
		View: viewFor(sourceCached, 7, "2026-08-01T00:00:00Z", "2026-08-20T00:00:00Z"),
	})
	snap := s.Snapshot()
	if snap.Provenance != "cached" || snap.State != saasFeedStateFresh {
		t.Errorf("restart should be cached/fresh: %+v", snap)
	}
	// A restart delta is meaningless ⇒ stays null even though a generation is active.
	if snap.LastActivationDelta != nil {
		t.Errorf("restart must not fabricate an activation delta: %+v", snap.LastActivationDelta)
	}
	if snap.NeverSucceeded {
		t.Error("serving a recovered generation is a prior-success witness")
	}
}

func f3b4Time(s string) time.Time {
	t, ok := canonicalUTCSecond(s)
	if !ok {
		panic("bad test time " + s)
	}
	return t
}
