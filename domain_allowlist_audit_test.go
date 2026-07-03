package main

// domain_allowlist_audit_test.go — regression coverage for the
// apiDomainAllowlist audit gap closed in this PR.
//
// Before the fix, the PUT branch (admin-only, security-sensitive: edits
// the set of domains that bypass threat-feed blocking, threatfeed.go:236
// DomainAllowlisted) only emitted logger.Printf and produced no audit
// entry. ui_routes_meta.go:291 already acknowledged this with a
// "no direct auditEvent observed" Note, and
// roadmap/DOMAIN-ALLOWLIST-ROLLBACK-CLASSIFICATION.md §3.5 flagged it
// as a separate, audit-only follow-up.
//
// Tests follow the canonical TEST-NET-2 / baselineTS / hasMatchingAuditEntry
// pattern from security_feedsync_audit_test.go to stay tolerant of
// audit-ring saturation under -count=2 -shuffle=on.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/threatfeed"
)

// snapshotGlobalThreatFeedForAudit swaps globalThreatFeed for a fresh
// in-memory instance so SetDomainAllowlist's saveToDisk call is a no-op
// (Init with an empty dbPath disables persistence) and so other tests
// don't see the mutated state. The cleanup restores the original.
func snapshotGlobalThreatFeedForAudit(t *testing.T) {
	t.Helper()
	orig := globalThreatFeed
	t.Cleanup(func() { globalThreatFeed = orig })
	fresh := threatfeed.New()
	fresh.Init("", time.Hour)
	globalThreatFeed = fresh
}

// TestDomainAllowlist_PUT_RecordsAuditEntry pins the positive path: a
// successful admin PUT writes one threatfeed.allowlist.update entry to
// the audit ring. The test fails if the new auditEvent call is reverted.
func TestDomainAllowlist_PUT_RecordsAuditEntry(t *testing.T) {
	snapshotGlobalThreatFeedForAudit(t)

	// auditEvent stamps TS via time.Now().UnixMilli() (ui_helpers.go:46);
	// capturing the same clock guarantees the entry's TS >= baseline.
	baselineTS := time.Now().UnixMilli()

	body, _ := json.Marshal(map[string]any{"domains": []string{"github.com", "drive.google.com"}})
	req := httptest.NewRequest(http.MethodPut, "/api/security-scan/feeds/domain-allowlist", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.60:0" // unique TEST-NET-2 actor IP
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))

	rec := httptest.NewRecorder()
	apiDomainAllowlist(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("apiDomainAllowlist PUT: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	// Match on the full (Actor, Action, Object, TS>=baseline) tuple.
	// Object encodes the count: handler passes fmt.Sprintf("%d domain(s)", len(body.Domains)).
	if !hasMatchingAuditEntry(auditGet(), "198.51.100.60", "threatfeed.allowlist.update", "2 domain(s)", baselineTS) {
		t.Fatalf("no audit entry recorded with Actor=198.51.100.60 Action=threatfeed.allowlist.update Object=\"2 domain(s)\" TS>=%d — closed audit gap regressed", baselineTS)
	}
}

// TestDomainAllowlist_PUT_AuditCountIsNormalized pins the Codex P2 fix
// on PR #284: the audit object must reflect the count of domains actually
// stored after SetDomainAllowlist normalizes (trim, lowercase, empty-skip,
// map-dedupe), not the raw request slice length. Before the fix, an
// admin sending blanks / duplicates / case-or-whitespace variants would
// see e.g. "3 domain(s)" in the audit trail while only 1 was persisted,
// making the security audit misleading for the exact mutation being
// captured.
func TestDomainAllowlist_PUT_AuditCountIsNormalized(t *testing.T) {
	snapshotGlobalThreatFeedForAudit(t)
	baselineTS := time.Now().UnixMilli()

	// 4 raw entries → 1 unique after normalization:
	//   "github.com"     → "github.com"
	//   " github.com "   → "github.com" (trim collapses to same key)
	//   ""               → skipped (empty after trim)
	//   "GITHUB.COM"     → "github.com" (lowercase collapses to same key)
	body, _ := json.Marshal(map[string]any{
		"domains": []string{"github.com", " github.com ", "", "GITHUB.COM"},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/security-scan/feeds/domain-allowlist", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.63:0" // unique TEST-NET-2 actor IP
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))

	rec := httptest.NewRecorder()
	apiDomainAllowlist(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("PUT with dedupe-input: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	// The audit Object must report the NORMALIZED count (1), not the
	// raw input length (4). Pre-fix this would be "4 domain(s)" and the
	// match would miss.
	if !hasMatchingAuditEntry(auditGet(), "198.51.100.63", "threatfeed.allowlist.update", "1 domain(s)", baselineTS) {
		// Surface the actually-emitted object for diagnosis.
		var actualObject string
		for _, e := range auditGet() {
			if e.Actor == "198.51.100.63" && e.Action == "threatfeed.allowlist.update" && e.TS >= baselineTS {
				actualObject = e.Object
				break
			}
		}
		t.Fatalf("audit object did not reflect the normalized stored count; want \"1 domain(s)\", got %q — raw-length audit count regressed (Codex P2 on PR #284)", actualObject)
	}
}

// TestDomainAllowlist_PUT_InvalidJSON_NoAuditEntry pins that the audit
// emission is on the SUCCESS path only — invalid JSON returns 400
// before SetDomainAllowlist runs, so no audit entry should appear.
// Guards against over-auditing if the call ever gets moved earlier in
// the handler.
func TestDomainAllowlist_PUT_InvalidJSON_NoAuditEntry(t *testing.T) {
	snapshotGlobalThreatFeedForAudit(t)
	baselineTS := time.Now().UnixMilli()

	req := httptest.NewRequest(http.MethodPut, "/api/security-scan/feeds/domain-allowlist", bytes.NewReader([]byte("{not json")))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.61:0" // distinct from the positive test
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))

	rec := httptest.NewRecorder()
	apiDomainAllowlist(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON: got %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	// Match by Actor alone — any audit entry for this unique IP since
	// baseline indicates over-emission. We don't pin Action so we'd
	// catch a stray "threatfeed.allowlist.update" or anything else.
	for _, e := range auditGet() {
		if e.Actor == "198.51.100.61" && e.TS >= baselineTS {
			t.Errorf("audit entry recorded on the invalid-JSON 400 path: %+v", e)
		}
	}
}

// TestDomainAllowlist_GET_NoAuditEntry pins that the read-only GET
// branch does not audit. Defensive: prevents a future copy-paste from
// adding auditEvent to GET as well.
func TestDomainAllowlist_GET_NoAuditEntry(t *testing.T) {
	snapshotGlobalThreatFeedForAudit(t)
	baselineTS := time.Now().UnixMilli()

	req := httptest.NewRequest(http.MethodGet, "/api/security-scan/feeds/domain-allowlist", nil)
	req.RemoteAddr = "198.51.100.62:0"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleViewer))

	rec := httptest.NewRecorder()
	apiDomainAllowlist(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET: got %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	for _, e := range auditGet() {
		if e.Actor == "198.51.100.62" && e.TS >= baselineTS {
			t.Errorf("audit entry recorded for read-only GET: %+v", e)
		}
	}
}
