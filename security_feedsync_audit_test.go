package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── apiSecFeedsSync audit emission ────────────────────────────────────────
//
// This test pins the C1.5 §3.2 fix: a successful manual threat-feed sync
// must record an "security.feeds_sync" audit entry. Before the fix, the
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
// "security.feeds_sync" entry to the audit ring buffer.
func TestSecFeedsSync_RecordsAuditEntry(t *testing.T) {
	// Swap the global with a fresh, enabled, in-memory feed so we don't
	// pollute the production-configured instance and don't depend on
	// outbound network reachability.
	orig := globalThreatFeed
	t.Cleanup(func() { globalThreatFeed = orig })
	globalThreatFeed = &ThreatFeed{enabled: true, syncInterval: time.Hour}

	// Snapshot the audit ring before the call so we can detect the new entry.
	before := len(auditGet())

	req := httptest.NewRequest(http.MethodPost, "/api/security-scan/feeds/sync", nil)
	req.RemoteAddr = "198.51.100.50:0"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))

	rec := httptest.NewRecorder()
	apiSecFeedsSync(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("apiSecFeedsSync: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	// auditGet returns newest-first. The new entry MUST be at index 0.
	after := auditGet()
	if got, want := len(after), before+1; got != want {
		t.Fatalf("audit ring length = %d, want %d (no entry recorded)", got, want)
	}
	entry := after[0]
	if entry.Action != "security.feeds_sync" {
		t.Errorf("audit Action = %q, want \"security.feeds_sync\"", entry.Action)
	}
	if entry.Object != "manual" {
		t.Errorf("audit Object = %q, want \"manual\"", entry.Object)
	}
}

// TestSecFeedsSync_FeedDisabled_NoAuditNo503EarlyReturn confirms the
// audit pipeline is reached ONLY on the success path. When the feed is
// disabled the handler returns 503 BEFORE Sync runs, so no audit entry
// is recorded — important so a misconfigured cluster doesn't generate
// noise.
func TestSecFeedsSync_FeedDisabled_NoAuditEntry(t *testing.T) {
	orig := globalThreatFeed
	t.Cleanup(func() { globalThreatFeed = orig })
	globalThreatFeed = &ThreatFeed{enabled: false}

	before := len(auditGet())

	req := httptest.NewRequest(http.MethodPost, "/api/security-scan/feeds/sync", nil)
	req.RemoteAddr = "198.51.100.51:0"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))

	rec := httptest.NewRecorder()
	apiSecFeedsSync(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled feed: got %d, want 503 (body=%s)", rec.Code, rec.Body.String())
	}
	if got, want := len(auditGet()), before; got != want {
		t.Errorf("audit ring length = %d, want %d (entry recorded for failed precondition)", got, want)
	}
}
