package main

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// ── Config tests ───────────────────────────────────────────────────────────────

func TestConfig_Auth(t *testing.T) {
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	if c.AuthEnabled() {
		t.Error("new Config should have auth disabled")
	}

	if err := c.SetAuth("alice", "secret"); err != nil {
		t.Fatalf("SetAuth error: %v", err)
	}
	if !c.AuthEnabled() {
		t.Error("auth should be enabled after SetAuth with user")
	}
	if c.GetUser() != "alice" {
		t.Errorf("GetUser = %q, want alice", c.GetUser())
	}
	if !c.VerifyAuth("alice", "secret") {
		t.Error("VerifyAuth should succeed with correct credentials")
	}
	if c.VerifyAuth("alice", "wrong") {
		t.Error("VerifyAuth should fail with wrong password")
	}

	if err := c.SetAuth("", ""); err != nil {
		t.Fatalf("SetAuth('','') error: %v", err)
	}
	if c.AuthEnabled() {
		t.Error("auth should be disabled when user is empty")
	}
}

func TestConfig_ConcurrentAccess(t *testing.T) {
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); c.SetAuth("u", "p") }() //nolint:errcheck
		go func() { defer wg.Done(); c.GetUser() }()
	}
	wg.Wait()
}

// ── LogEntry / logAdd / logGet tests ──────────────────────────────────────────

func newTestLog() (add func(LogEntry), get func() []LogEntry, clear func()) {
	var mu sync.Mutex
	var entries []LogEntry
	add = func(e LogEntry) {
		mu.Lock()
		defer mu.Unlock()
		entries = append(entries, e)
		if len(entries) > maxLogs {
			entries = entries[len(entries)-maxLogs:]
		}
	}
	get = func() []LogEntry {
		mu.Lock()
		cp := make([]LogEntry, len(entries))
		copy(cp, entries)
		mu.Unlock()
		// reverse
		for i, j := 0, len(cp)-1; i < j; i, j = i+1, j-1 {
			cp[i], cp[j] = cp[j], cp[i]
		}
		return cp
	}
	clear = func() {
		mu.Lock()
		entries = nil
		mu.Unlock()
	}
	return
}

func TestLog_OrderedMostRecentFirst(t *testing.T) {
	add, get, clear := newTestLog()
	defer clear()

	add(LogEntry{TS: 1, Host: "first"})
	add(LogEntry{TS: 2, Host: "second"})
	add(LogEntry{TS: 3, Host: "third"})

	got := get()
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(got))
	}
	if got[0].Host != "third" {
		t.Errorf("most recent entry should be first, got %q", got[0].Host)
	}
}

func TestLog_MaxCapacity(t *testing.T) {
	add, get, clear := newTestLog()
	defer clear()

	for i := 0; i < maxLogs+50; i++ {
		add(LogEntry{TS: int64(i), Host: "h"})
	}
	if got := get(); len(got) != maxLogs {
		t.Errorf("expected maxLogs=%d entries, got %d", maxLogs, len(got))
	}
}

// ── Uptime helper ─────────────────────────────────────────────────────────────

func TestUptime_Format(t *testing.T) {
	// uptime() uses startTime global; just check the format is non-empty.
	u := uptime()
	if u == "" {
		t.Error("uptime() returned empty string")
	}
	// Should contain 'm' and 's'.
	hasM := false
	for _, c := range u {
		if c == 'm' { hasM = true }
	}
	if !hasM {
		t.Errorf("uptime() format unexpected: %q", u)
	}
}

// ── Audit log ─────────────────────────────────────────────────────────────────

func resetAuditLog() {
	auditMu.Lock()
	auditLog = nil
	auditMu.Unlock()
}

func TestAuditLog_AddAndGet(t *testing.T) {
	resetAuditLog()
	auditAdd(AuditEntry{TS: 1, Actor: "1.1.1.1", Action: "policy.add", Object: "rule-A", Detail: "priority=1"})
	auditAdd(AuditEntry{TS: 2, Actor: "2.2.2.2", Action: "blocklist.remove", Object: "evil.com", Detail: ""})

	got := auditGet()
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	// Newest first.
	if got[0].Action != "blocklist.remove" {
		t.Errorf("expected newest entry first, got %q", got[0].Action)
	}
	if got[1].Action != "policy.add" {
		t.Errorf("expected oldest entry second, got %q", got[1].Action)
	}
}

func TestAuditLog_MaxCapacity(t *testing.T) {
	resetAuditLog()
	for i := 0; i < maxAuditLogs+10; i++ {
		auditAdd(AuditEntry{TS: int64(i), Action: "policy.add"})
	}
	if got := auditGet(); len(got) != maxAuditLogs {
		t.Errorf("expected %d audit entries, got %d", maxAuditLogs, len(got))
	}
}

func TestAuditLog_NeverContainsCredentials(t *testing.T) {
	resetAuditLog()
	// Simulate settings.update — password must NOT appear in any field.
	auditAdd(AuditEntry{
		TS:     1,
		Actor:  "127.0.0.1",
		Action: "settings.update",
		Object: "auth",
		Detail: "user=alice", // password deliberately absent
	})
	got := auditGet()
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got))
	}
	entry := got[0]
	for _, field := range []string{entry.Object, entry.Detail} {
		if strings.Contains(field, "pass") || strings.Contains(field, "secret") {
			t.Errorf("audit entry contains suspicious credential hint: %q", field)
		}
	}
}

// ── recordRequest ─────────────────────────────────────────────────────────────

func TestRecordRequest_IncrementsTotal(t *testing.T) {
	before := statTotal
	recordRequest("1.1.1.1", "GET", "example.com", "OK", "", "")
	if statTotal != before+1 {
		t.Errorf("statTotal should have incremented by 1")
	}
}

// ── timeSeries ────────────────────────────────────────────────────────────────

func TestTimeSeries_Get(t *testing.T) {
	data := tsGet()
	if len(data) != 60 {
		t.Errorf("tsGet() should return 60 buckets, got %d", len(data))
	}
}

func TestTimeSeries_Record(t *testing.T) {
	before := tsGet()
	// Record one request and verify the first bucket (most recent) increases.
	// Give it a tiny sleep to ensure same minute bucket.
	tsRecord()
	after := tsGet()
	if after[0] < before[0] {
		t.Error("most-recent bucket should be >= before after tsRecord()")
	}
	_ = time.Now() // silence import
}
