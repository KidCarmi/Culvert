package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/threatfeed"
)

// ── apiSecFeedsSync audit emission ────────────────────────────────────────
//
// This test pins the C1.5 §3.2 fix: a successful manual threat-feed sync
// must record a "threatfeed.sync" audit entry. Before the fix, the
// admin-only POST mutated state (overwriting the URL / domain maps that
// drive every block decision) without producing an audit trail.
//
// We swap globalThreatFeed for a fresh *ThreatFeed in-memory instance so
// the test does not depend on outbound HTTP. The fresh feed's Sync()
// will attempt the real URLhaus / OpenPhish fetches but errors are
// logged and silently ignored — the audit call runs unconditionally
// after Sync returns, which is exactly the contract under test.

// TestSecFeedsSync_RecordsAuditEntry covers the positive path: an
// admin-role POST to apiSecFeedsSync with the feed enabled appends one
// "threatfeed.sync" entry to the audit ring buffer.
//
// Saturation-tolerant: the in-memory audit ring is bounded at
// maxAuditLogs (500). Under -count=2 -shuffle=on the cumulative
// audit emissions across the suite can saturate the ring before this
// test runs, in which case adding a new entry evicts the oldest and
// len() does NOT grow. Asserting len(after)==len(before)+1 is therefore
// brittle. Instead we scan the post-call snapshot for an entry that
// matches this test's unique discriminators (Actor IP from TEST-NET-2,
// Action, Object, and TS at or after the baseline) — that proves a
// new entry was recorded regardless of whether the ring was at
// capacity. Because tests in this package do not use t.Parallel, the
// scan is race-free.
func TestSecFeedsSync_RecordsAuditEntry(t *testing.T) {
	// Swap the global with a fresh, enabled, in-memory feed so we don't
	// pollute the production-configured instance and don't depend on
	// outbound network reachability.
	orig := globalThreatFeed
	t.Cleanup(func() { globalThreatFeed = orig })
	fresh := threatfeed.New()
	fresh.Init("", time.Hour) // enabled, no persistence
	globalThreatFeed = fresh

	// auditEvent stamps TS via time.Now().UnixMilli(); use the same
	// clock so the post-call entry's TS is guaranteed >= baselineTS.
	baselineTS := time.Now().UnixMilli()

	req := httptest.NewRequest(http.MethodPost, "/api/security-scan/feeds/sync", nil)
	req.RemoteAddr = "198.51.100.50:0" // unique TEST-NET-2 actor IP — see auditEntryMatches
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))

	rec := httptest.NewRecorder()
	apiSecFeedsSync(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("apiSecFeedsSync: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	// Scan the newest-first snapshot for our entry. Match on the full
	// (Actor, Action, Object, TS≥baseline) tuple so we cannot collide
	// with any entry written by another test or a prior invocation
	// under -count=2.
	if !hasMatchingAuditEntry(auditGet(), "198.51.100.50", "threatfeed.sync", "manual", baselineTS) {
		t.Fatalf("no audit entry recorded with Actor=198.51.100.50 Action=threatfeed.sync Object=manual TS>=%d", baselineTS)
	}
}

// TestSecFeedsSync_FeedDisabled_NoAuditEntry confirms the audit pipeline
// is reached ONLY on the success path. When the feed is disabled the
// handler returns 503 BEFORE Sync runs, so no audit entry is recorded —
// important so a misconfigured cluster doesn't generate noise.
//
// Saturation-tolerant for the same reason as the positive test above:
// instead of asserting len(after)==len(before), we scan for an entry
// matching this test's unique Actor IP and confirm none was written
// since the baseline timestamp.
func TestSecFeedsSync_FeedDisabled_NoAuditEntry(t *testing.T) {
	orig := globalThreatFeed
	t.Cleanup(func() { globalThreatFeed = orig })
	globalThreatFeed = threatfeed.New() // disabled until Init

	baselineTS := time.Now().UnixMilli()

	req := httptest.NewRequest(http.MethodPost, "/api/security-scan/feeds/sync", nil)
	req.RemoteAddr = "198.51.100.51:0" // distinct from the positive test
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))

	rec := httptest.NewRecorder()
	apiSecFeedsSync(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled feed: got %d, want 503 (body=%s)", rec.Code, rec.Body.String())
	}
	if hasMatchingAuditEntry(auditGet(), "198.51.100.51", "threatfeed.sync", "manual", baselineTS) {
		t.Errorf("audit entry recorded for disabled feed (Actor=198.51.100.51, since TS=%d)", baselineTS)
	}
}

// hasMatchingAuditEntry returns true when snap contains at least one
// entry whose (Actor, Action, Object) match the given strings AND whose
// TS is >= sinceTS. Used by both TestSecFeedsSync_* tests to avoid the
// brittle len()-based assertion that breaks under audit-ring saturation.
func hasMatchingAuditEntry(snap []AuditEntry, actor, action, object string, sinceTS int64) bool {
	for i := range snap {
		e := snap[i]
		if e.Actor == actor && e.Action == action && e.Object == object && e.TS >= sinceTS {
			return true
		}
	}
	return false
}
