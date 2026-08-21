package main

// Phase 1 (per-rule "log full URL") unit tests: the policyLogURI helper, the
// LogEntry.URI plumbing via recordRequestAuthURI, and JSON round-tripping of
// the new PolicyRule.LogFullURI flag and the omitempty LogEntry.URI field.

import (
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRuleLogsTraffic(t *testing.T) {
	if !ruleLogsTraffic(&PolicyRule{}) {
		t.Error("nil LogTraffic should log by default")
	}
	tr, fa := true, false
	if !ruleLogsTraffic(&PolicyRule{LogTraffic: &tr}) {
		t.Error("LogTraffic=true should log")
	}
	if ruleLogsTraffic(&PolicyRule{LogTraffic: &fa}) {
		t.Error("LogTraffic=false should NOT log")
	}
}

// TestRecordStats_NoLogEntry proves the "Log traffic off" path: stats are
// counted but no request-log entry is written.
func TestRecordStats_NoLogEntry(t *testing.T) {
	isolateLogRing(t)
	oldLS := globalLogStore.Load()
	globalLogStore.Store(nil)
	t.Cleanup(func() { globalLogStore.Store(oldLS) })

	before := atomic.LoadInt64(&statTotal)
	recordStats("1.2.3.4", "h.example.com", "OK", "rule", "Allow")
	if got := atomic.LoadInt64(&statTotal); got != before+1 {
		t.Errorf("statTotal delta = %d, want 1 (request still counted)", got-before)
	}
	if n := len(logGet()); n != 0 {
		t.Errorf("recordStats wrote %d log entries, want 0", n)
	}
}

// TestRecordRequestLogOnly_NoStatIncrement locks the inner-request double-count
// fix: the log-only recorder writes an entry but does NOT touch statTotal (the
// enclosing CONNECT already counted).
func TestRecordRequestLogOnly_NoStatIncrement(t *testing.T) {
	isolateLogRing(t)
	oldLS := globalLogStore.Load()
	globalLogStore.Store(nil)
	t.Cleanup(func() { globalLogStore.Store(oldLS) })

	before := atomic.LoadInt64(&statTotal)
	recordRequestLogOnly("1.2.3.4", "GET", "h.example.com", "OK", "rule", "Allow",
		"alice", "inspect", "h.example.com/p", AuthLogFields{})
	if got := atomic.LoadInt64(&statTotal); got != before {
		t.Errorf("recordRequestLogOnly changed statTotal by %d, want 0", got-before)
	}
	entries := logGet()
	if len(entries) != 1 || entries[0].URI != "h.example.com/p" {
		t.Fatalf("expected 1 logged entry with URI, got %d", len(entries))
	}
}

// TestLevelForStatus_BlockedTab moved to internal/reqlog (ADR-0002, store.go
// decomposition Phase C).

// TestRecordInspectBlock_URIGatedOnLogFullURI verifies inspected blocks carry
// the decrypted URL when the rule has LogFullURI (Codex review fix), and not
// otherwise — and that blocks are logged regardless.
func TestRecordInspectBlock_URIGatedOnLogFullURI(t *testing.T) {
	isolateLogRing(t)
	oldLS := globalLogStore.Load()
	globalLogStore.Store(nil)
	t.Cleanup(func() { globalLogStore.Store(oldLS) })

	recordInspectBlock(ProxyIdentity{ClientIP: "1.2.3.4"}, "FILE_BLOCKED", "exe", "", "h.example.com", "/d/app.exe",
		&PolicyMatch{Rule: &PolicyRule{Name: "r", LogFullURI: true}}, nil)
	recordInspectBlock(ProxyIdentity{ClientIP: "1.2.3.4"}, "SCAN_BLOCKED", "clam", "eicar", "h2.example.com", "/x",
		&PolicyMatch{Rule: &PolicyRule{Name: "r2"}}, nil) // LogFullURI off

	entries := logGet()
	var fileURI, scanURI string
	var sawFile, sawScan bool
	for i := range entries {
		switch entries[i].Status {
		case "FILE_BLOCKED":
			fileURI, sawFile = entries[i].URI, true
		case "SCAN_BLOCKED":
			scanURI, sawScan = entries[i].URI, true
		}
	}
	if !sawFile || fileURI != "h.example.com/d/app.exe" {
		t.Errorf("FILE_BLOCKED URI = %q (seen=%v), want h.example.com/d/app.exe", fileURI, sawFile)
	}
	if !sawScan || scanURI != "" {
		t.Errorf("SCAN_BLOCKED URI should be empty when LogFullURI off, got %q (seen=%v)", scanURI, sawScan)
	}
}

func TestPolicyRule_LogTrafficRoundTrip(t *testing.T) {
	fa := false
	b, err := json.Marshal(PolicyRule{Name: "r", LogTraffic: &fa})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"logTraffic":false`) {
		t.Errorf("marshaled rule missing logTraffic:false — %s", b)
	}
	// nil pointer is omitted (existing rules unchanged on the wire).
	b2, _ := json.Marshal(PolicyRule{Name: "r"})
	if strings.Contains(string(b2), "logTraffic") {
		t.Errorf("nil LogTraffic should be omitted — %s", b2)
	}
	var back PolicyRule
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.LogTraffic == nil || *back.LogTraffic != false {
		t.Error("LogTraffic=false did not round-trip")
	}
}

func TestPolicyLogURI(t *testing.T) {
	cases := []struct {
		host, path, want string
	}{
		{"example.com:443", "", "example.com:443"}, // CONNECT, no decrypted path
		{"example.com", "/a/b", "example.com/a/b"}, // plain path
		{"h.example.com", "/", "h.example.com/"},   // root path preserved
	}
	for _, c := range cases {
		if got := policyLogURI(c.host, c.path); got != c.want {
			t.Errorf("policyLogURI(%q,%q) = %q, want %q", c.host, c.path, got, c.want)
		}
	}
}

func TestRecordRequestAuthURI_SetsURI(t *testing.T) {
	isolateLogRing(t)

	recordRequestAuthURI("10.0.0.1", "GET", "h.example.com", "OK", "rule1", "Allow",
		"alice", "inspect", "h.example.com/secret/path", AuthLogFields{})

	entries := logGet()
	if len(entries) == 0 {
		t.Fatal("no log entry recorded")
	}
	if entries[0].URI != "h.example.com/secret/path" {
		t.Errorf("URI = %q, want h.example.com/secret/path", entries[0].URI)
	}
	if entries[0].SSLAction != "inspect" {
		t.Errorf("SSLAction = %q, want inspect", entries[0].SSLAction)
	}
}

func TestRecordRequestAuth_NoURI(t *testing.T) {
	// The non-URI recorder must leave URI empty so existing rules' wire output
	// stays byte-identical (omitempty).
	isolateLogRing(t)

	recordRequestAuth("10.0.0.2", "GET", "plain.example.com", "OK", "r", "Allow", "bob", AuthLogFields{})
	entries := logGet()
	if len(entries) == 0 {
		t.Fatal("no log entry recorded")
	}
	if entries[0].URI != "" {
		t.Errorf("URI = %q, want empty for recordRequestAuth", entries[0].URI)
	}
}

func TestPolicyRule_LogFullURIRoundTrip(t *testing.T) {
	b, err := json.Marshal(PolicyRule{Name: "r", LogFullURI: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"logFullUri":true`) {
		t.Errorf("marshaled rule missing logFullUri:true — %s", b)
	}
	var back PolicyRule
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !back.LogFullURI {
		t.Error("LogFullURI did not round-trip through JSON")
	}
}

func TestLogEntry_URIOmitEmpty(t *testing.T) {
	b, err := json.Marshal(LogEntry{Host: "h", Status: "OK"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "uri") {
		t.Errorf("empty URI should be omitted from wire output — %s", b)
	}
}
