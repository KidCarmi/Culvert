package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileblock"

	"github.com/KidCarmi/Culvert/internal/ocsp"

	"github.com/KidCarmi/Culvert/internal/blocklist"
)

// ─── Finding 1.1: Blocklist.ClearAll ────────────────────────────────────────

func TestBlocklistClearAll(t *testing.T) {
	b := blocklist.New()
	b.Add("example.com")
	b.Add("test.org")
	b.Add("*.evil.com")
	b.AddManual("manual.net")
	b.AddException("safe.com")
	b.SetMode("block")

	b.ClearAll()
	if b.Count() != 0 {
		t.Errorf("Count after ClearAll = %d, want 0 (exact+wildcard+manual cleared)", b.Count())
	}
	if b.IsBlocked("example.com") || b.IsBlocked("sub.evil.com") || b.IsBlocked("manual.net") {
		t.Error("no entry should be blocked after ClearAll")
	}
	// Exceptions and mode survive ClearAll by contract.
	if got := b.ListExceptions(); len(got) != 1 || got[0] != "safe.com" {
		t.Errorf("exceptions after ClearAll = %v, want [safe.com]", got)
	}
	if b.Mode() != "block" {
		t.Errorf("mode after ClearAll = %q, want block", b.Mode())
	}
}

// ─── Finding 1.1: FileBlocker.ClearAll ──────────────────────────────────────

func TestFileBlockerClearAll(t *testing.T) {
	fb := fileblock.NewBlocker()
	fb.Add(".exe")
	fb.Add(".dll")
	fb.ClearAll()
	if fb.Count() != 0 {
		t.Errorf("expected 0 after ClearAll, got %d", fb.Count())
	}
}

// ─── Finding 1.1: IPFilter.ClearAll ─────────────────────────────────────────

func TestIPFilterClearAll(t *testing.T) {
	f := &IPFilter{single: map[string]bool{}}
	_ = f.Add("10.0.0.1")
	_ = f.Add("192.168.0.0/16")
	if len(f.List()) == 0 {
		t.Fatal("expected entries before ClearAll")
	}
	f.ClearAll()
	if len(f.List()) != 0 {
		t.Error("expected empty list after ClearAll")
	}
}

// ─── Finding 4.4: HashCache.Evict + Clear ───────────────────────────────────

func TestHashCacheEvictAndClear(t *testing.T) {
	c := newHashCache(100, 5*time.Minute)

	c.Set("abc123", ScanCacheResult{Clean: true})
	c.Set("def456", ScanCacheResult{Clean: false, Source: "test"})

	// Evict existing.
	if !c.Evict("abc123") {
		t.Error("Evict should return true for existing entry")
	}
	// Evict non-existing.
	if c.Evict("nonexistent") {
		t.Error("Evict should return false for non-existing entry")
	}
	// Verify abc123 is gone.
	if _, ok := c.Get("abc123"); ok {
		t.Error("abc123 should be evicted")
	}
	// def456 should still exist.
	if _, ok := c.Get("def456"); !ok {
		t.Error("def456 should still exist")
	}

	// Clear all.
	c.Clear()
	if _, ok := c.Get("def456"); ok {
		t.Error("def456 should be gone after Clear")
	}
	_, _, size := c.Stats()
	if size != 0 {
		t.Errorf("cache_size should be 0 after Clear, got %d", size)
	}
}

// ─── Finding 16.1: RateLimiter exemption ────────────────────────────────────

func TestRateLimiterExemption(t *testing.T) {
	r := newRateLimiter()
	r.Configure(1, time.Minute) // 1 req/min

	// Add exemptions.
	if err := r.AddExemption("10.0.0.5"); err != nil {
		t.Fatalf("AddExemption IP: %v", err)
	}
	if err := r.AddExemption("192.168.0.0/16"); err != nil {
		t.Fatalf("AddExemption CIDR: %v", err)
	}

	// Invalid entry.
	if err := r.AddExemption("not-an-ip"); err == nil {
		t.Error("expected error for invalid IP")
	}

	// Check exemption.
	if !r.IsExempt("10.0.0.5") {
		t.Error("10.0.0.5 should be exempt")
	}
	if !r.IsExempt("192.168.1.100") {
		t.Error("192.168.1.100 should be exempt (CIDR match)")
	}
	if r.IsExempt("8.8.8.8") {
		t.Error("8.8.8.8 should not be exempt")
	}
	if r.IsExempt("not-an-ip") {
		t.Error("invalid IP should not be exempt")
	}

	// Exempt IP should always be allowed even when rate limited.
	if !r.Allow("10.0.0.5") {
		t.Error("exempt IP should always be allowed")
	}
	if !r.Allow("10.0.0.5") {
		t.Error("exempt IP should always be allowed (2nd request)")
	}

	// List exemptions.
	list := r.ListExemptions()
	if len(list) != 2 {
		t.Errorf("expected 2 exemptions, got %d", len(list))
	}

	// Remove exemption.
	r.RemoveExemption("10.0.0.5")
	if r.IsExempt("10.0.0.5") {
		t.Error("10.0.0.5 should no longer be exempt")
	}
	r.RemoveExemption("192.168.0.0/16")
	if r.IsExempt("192.168.1.100") {
		t.Error("192.168.1.100 should no longer be exempt")
	}
}

// ─── Finding 3.1: SSLAction in LogEntry ─────────────────────────────────────

func TestRecordRequestSSLAction(t *testing.T) {
	// Clear logs.
	logsMu.Lock()
	logs = nil
	logsMu.Unlock()

	recordRequest("1.2.3.4", "CONNECT", "example.com:443", "OK", "rule1", "allow", "user@test", "inspect")

	entries := logGet()
	if len(entries) == 0 {
		t.Fatal("expected at least one log entry")
	}
	last := entries[len(entries)-1]
	if last.SSLAction != "inspect" {
		t.Errorf("expected SSLAction='inspect', got %q", last.SSLAction)
	}
}

// ─── Finding 6.2: auditGetMemory ────────────────────────────────────────────

func TestAuditGetMemory(t *testing.T) {
	// Seed some audit entries.
	auditMu.Lock()
	auditLog = nil
	auditMu.Unlock()

	now := time.Now().UnixMilli()
	for i := 0; i < 5; i++ {
		auditMu.Lock()
		auditLog = append(auditLog, AuditEntry{
			TS:     now + int64(i*1000),
			Time:   time.Now().Format("15:04:05"),
			Actor:  "admin",
			Action: "test",
		})
		auditMu.Unlock()
	}

	// No filter.
	entries, total := auditGetMemory(0, 100, 0, 0)
	if total != 5 {
		t.Errorf("expected total=5, got %d", total)
	}
	if len(entries) != 5 {
		t.Errorf("expected 5 entries, got %d", len(entries))
	}

	// With pagination.
	entries, total = auditGetMemory(2, 2, 0, 0)
	if total != 5 {
		t.Errorf("expected total=5, got %d", total)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}

	// Offset past end.
	entries, _ = auditGetMemory(10, 5, 0, 0)
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for offset past end, got %d", len(entries))
	}

	// With time filter.
	entries, _ = auditGetMemory(0, 100, now+1000, now+3000)
	if len(entries) == 0 {
		t.Error("expected some entries with time filter")
	}
	for _, e := range entries {
		if e.TS < now+1000 || e.TS > now+3000 {
			t.Errorf("entry TS %d outside filter range [%d, %d]", e.TS, now+1000, now+3000)
		}
	}
}

// ─── Finding 4.4: apiScanCache handler ──────────────────────────────────────

func TestAPIScanCache(t *testing.T) {
	// GET — should return stats or disabled.
	req := httptest.NewRequest(http.MethodGet, "/api/security-scan/cache", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rr := httptest.NewRecorder()
	apiScanCache(rr, req)
	if rr.Code != 200 {
		t.Errorf("GET expected 200, got %d", rr.Code)
	}

	// DELETE without hash — clear all (or return error if scanner not initialized).
	req = httptest.NewRequest(http.MethodDelete, "/api/security-scan/cache", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rr = httptest.NewRecorder()
	apiScanCache(rr, req)
	// Either 200 (cleared) or 503 (scanner not enabled) is acceptable.
	if rr.Code != 200 && rr.Code != 503 {
		t.Errorf("DELETE expected 200 or 503, got %d", rr.Code)
	}

	// Method not allowed.
	req = httptest.NewRequest(http.MethodPut, "/api/security-scan/cache", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rr = httptest.NewRecorder()
	apiScanCache(rr, req)
	if rr.Code != 405 {
		t.Errorf("PUT expected 405, got %d", rr.Code)
	}
}

// ─── Finding 1.1: Config import replace mode ────────────────────────────────

func TestConfigImportReplaceMode(t *testing.T) {
	// Seed some blocklist entries.
	bl.Add("old-entry.com")

	backup := configBackup{
		Version:   1,
		Blocklist: []string{"new-entry.com"},
	}
	body, _ := json.Marshal(backup)

	// Import with replace mode.
	req := httptest.NewRequest(http.MethodPost, "/api/config/import?mode=replace", strings.NewReader(string(body)))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), uiRoleKey{}, RoleAdmin))
	rr := httptest.NewRecorder()
	apiConfigImport(rr, req)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["mode"] != "replace" {
		t.Errorf("expected mode=replace in response, got %v", resp["mode"])
	}

	// In replace mode, old-entry.com should be gone.
	entries := bl.List()
	found := false
	for _, e := range entries {
		if e == "old-entry.com" {
			t.Error("old-entry.com should have been cleared in replace mode")
		}
		if e == "new-entry.com" {
			found = true
		}
	}
	if !found {
		t.Error("new-entry.com should have been imported")
	}

	// Clean up.
	bl.ClearAll()
}

// ─── Finding 5.2: User deletion revokes sessions ───────────────────────────

func TestRevokeUserSessions(t *testing.T) {
	// sessionRevoked is a package-global; under -count=2 or -shuffle=on this
	// test's own RevokeUser("deleteme") call leaks into the next run and
	// causes the "valid before revocation" assertion to fail. Tear down the
	// revocation entries we create, before AND after, so the test is
	// deterministic regardless of run order.
	sessionRevoked.mu.Lock()
	delete(sessionRevoked.users, "deleteme")
	delete(sessionRevoked.users, "otheruser")
	sessionRevoked.mu.Unlock()
	t.Cleanup(func() {
		sessionRevoked.mu.Lock()
		delete(sessionRevoked.users, "deleteme")
		delete(sessionRevoked.users, "otheruser")
		sessionRevoked.mu.Unlock()
	})

	// Create a valid session for a user.
	s := &Session{
		Sub:  "deleteme",
		Role: string(RoleOperator),
		Exp:  time.Now().Add(time.Hour).Unix(),
	}
	tok, err := encodeSession(s)
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}

	// Session should be valid before revocation.
	if _, err := decodeSession(tok); err != nil {
		t.Fatalf("session should be valid before revocation: %v", err)
	}

	// Revoke all sessions for this user.
	sessionRevoked.RevokeUser("deleteme")

	// Session should now be rejected.
	if _, err := decodeSession(tok); err == nil {
		t.Error("session should be rejected after user revocation")
	}

	// A different user's session should still work.
	s2 := &Session{
		Sub:  "otheruser",
		Role: string(RoleOperator),
		Exp:  time.Now().Add(time.Hour).Unix(),
	}
	tok2, _ := encodeSession(s2)
	if _, err := decodeSession(tok2); err != nil {
		t.Errorf("other user's session should still be valid: %v", err)
	}
}

// ─── Finding 8.1: AlertStore.DeliveryHistory ─────────────────────────────────

func TestDeliveryHistory(t *testing.T) {
	as := &AlertStore{}
	as.Init("")

	// Record some deliveries.
	as.RecordDelivery(AlertDelivery{Timestamp: "2026-01-01T00:00:01Z", WebhookID: "a", Success: true})
	as.RecordDelivery(AlertDelivery{Timestamp: "2026-01-01T00:00:02Z", WebhookID: "b", Success: false})
	as.RecordDelivery(AlertDelivery{Timestamp: "2026-01-01T00:00:03Z", WebhookID: "c", Success: true})

	hist := as.DeliveryHistory()
	if len(hist) != 3 {
		t.Fatalf("len(history) = %d, want 3", len(hist))
	}
	// Newest first.
	if hist[0].WebhookID != "c" {
		t.Errorf("history[0].WebhookID = %q, want c (newest)", hist[0].WebhookID)
	}
	if hist[2].WebhookID != "a" {
		t.Errorf("history[2].WebhookID = %q, want a (oldest)", hist[2].WebhookID)
	}
}

func TestDeliveryHistory_Empty(t *testing.T) {
	as := &AlertStore{}
	as.Init("")
	hist := as.DeliveryHistory()
	if len(hist) != 0 {
		t.Errorf("expected empty history, got %d entries", len(hist))
	}
}

// ─── Finding auth_idp: effectivePriority ─────────────────────────────────────

func TestEffectivePriority(t *testing.T) {
	// nil profile.
	var nilP *IdPProfile
	if got := nilP.effectivePriority(); got != 1<<31-1 {
		t.Errorf("nil.effectivePriority() = %d, want max int", got)
	}
	// Zero priority → max int.
	p := &IdPProfile{Priority: 0}
	if got := p.effectivePriority(); got != 1<<31-1 {
		t.Errorf("zero.effectivePriority() = %d, want max int", got)
	}
	// Normal priority.
	p2 := &IdPProfile{Priority: 5}
	if got := p2.effectivePriority(); got != 5 {
		t.Errorf("effectivePriority() = %d, want 5", got)
	}
}

// ─── blockpage: setBlockPageHTML / getBlockPageHTML ───────────────────────────

func TestSetBlockPageHTML(t *testing.T) {
	orig := getBlockPageHTML()
	defer setBlockPageHTML(orig) //nolint:errcheck // restore original

	custom := "<html><body>{{.Host}} blocked</body></html>"
	if err := setBlockPageHTML(custom); err != nil {
		t.Fatalf("setBlockPageHTML: %v", err)
	}
	if got := getBlockPageHTML(); got != custom {
		t.Errorf("getBlockPageHTML = %q, want %q", got, custom)
	}
}

func TestSetBlockPageHTML_InvalidTemplate(t *testing.T) {
	err := setBlockPageHTML("{{.Unclosed}")
	if err == nil {
		t.Error("expected error for invalid template, got nil")
	}
}

// ─── connlimit: Disable / MaxPerIP / ActiveIPs ──────────────────────────────

func TestConnLimiterDisable(t *testing.T) {
	cl := newConnLimiter()
	cl.Enable(100)
	if !cl.Enabled() {
		t.Fatal("expected enabled after Enable()")
	}
	cl.Disable()
	if cl.Enabled() {
		t.Error("expected disabled after Disable()")
	}
}

func TestConnLimiterMaxPerIP(t *testing.T) {
	cl := newConnLimiter()
	cl.Enable(50)
	if got := cl.MaxPerIP(); got != 50 {
		t.Errorf("MaxPerIP() = %d, want 50", got)
	}
}

// ─── ocsp: Disable / CacheLen ────────────────────────────────────────────────

func TestOCSPDisable(t *testing.T) {
	oc := ocsp.New()
	oc.Enable()
	if !oc.Enabled() {
		t.Fatal("expected enabled")
	}
	oc.Disable()
	if oc.Enabled() {
		t.Error("expected disabled after Disable()")
	}
}

// ─── logScanLimitExceeded (Finding 4.2) ──────────────────────────────────────

func TestLogScanLimitExceeded(_ *testing.T) {
	// Just ensure it doesn't panic. No need to swap globalAlertStore since
	// logScanLimitExceeded fires the alert via go fireAlert() which captures
	// the store pointer internally.
	logScanLimitExceeded("example.com", "10.0.0.1", 5<<20)
}
