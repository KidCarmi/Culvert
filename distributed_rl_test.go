package main

import (
	"strings"
	"testing"
	"time"
)

// ─── generateTraceparent ────────────────────────────────────────────────────

func TestGenerateTraceparent_Format(t *testing.T) {
	tp := generateTraceparent()
	// Format: "00-{32 hex}-{16 hex}-01"
	parts := strings.Split(tp, "-")
	if len(parts) != 4 {
		t.Fatalf("traceparent parts = %d, want 4: %q", len(parts), tp)
	}
	if parts[0] != "00" {
		t.Fatalf("version = %q, want 00", parts[0])
	}
	if len(parts[1]) != 32 {
		t.Fatalf("trace-id length = %d, want 32", len(parts[1]))
	}
	if len(parts[2]) != 16 {
		t.Fatalf("parent-id length = %d, want 16", len(parts[2]))
	}
	if parts[3] != "01" {
		t.Fatalf("flags = %q, want 01", parts[3])
	}
}

func TestGenerateTraceparent_Unique(t *testing.T) {
	a := generateTraceparent()
	b := generateTraceparent()
	if a == b {
		t.Fatal("two traceparents should differ")
	}
}

// ─── detectProtocolName ─────────────────────────────────────────────────────

func TestDetectProtocolName(t *testing.T) {
	tests := []struct {
		b    byte
		want string
	}{
		{0x16, "TLS"},
		{0x14, "TLS"}, // change_cipher_spec
		{0x15, "TLS"}, // alert
		{0x17, "TLS"}, // application_data
		{'S', "SSH"},
		{0x03, "RDP"},
		{'G', "HTTP"},
		{'P', "HTTP"},
		{'H', "HTTP"},
		{0x00, "unknown"},
		{0xFF, "unknown"},
	}
	for _, tc := range tests {
		got := detectProtocolName(tc.b)
		if got != tc.want {
			t.Errorf("detectProtocolName(0x%02x) = %q, want %q", tc.b, got, tc.want)
		}
	}
}

// ─── syslog formatMsg ───────────────────────────────────────────────────────

func TestSyslogFormatMsg_RFC3164(t *testing.T) {
	sw := &syslogWriter{
		host:   "testhost",
		tag:    "culvert",
		format: "rfc3164",
		pid:    "1234",
	}
	msg := sw.formatMsg(14, "hello world")
	if !strings.HasPrefix(msg, "<14>") {
		t.Fatalf("RFC3164 should start with <14>, got %q", msg)
	}
	if !strings.Contains(msg, "testhost") {
		t.Fatal("should contain hostname")
	}
	if !strings.Contains(msg, "culvert:") {
		t.Fatal("should contain tag with colon")
	}
	if !strings.Contains(msg, "hello world") {
		t.Fatal("should contain message body")
	}
}

func TestSyslogFormatMsg_RFC5424(t *testing.T) {
	sw := &syslogWriter{
		host:   "testhost",
		tag:    "culvert",
		format: "rfc5424",
		pid:    "5678",
	}
	msg := sw.formatMsg(13, "audit event")
	// RFC5424: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
	if !strings.HasPrefix(msg, "<13>1 ") {
		t.Fatalf("RFC5424 should start with <13>1, got %q", msg)
	}
	if !strings.Contains(msg, "testhost") {
		t.Fatal("should contain hostname")
	}
	if !strings.Contains(msg, "culvert") {
		t.Fatal("should contain app-name")
	}
	if !strings.Contains(msg, "5678") {
		t.Fatal("should contain PID")
	}
	if !strings.Contains(msg, "audit event") {
		t.Fatal("should contain message body")
	}
	// Should contain RFC3339 timestamp
	if !strings.Contains(msg, "T") {
		t.Fatal("RFC5424 timestamp should be RFC3339 format")
	}
}

func TestSyslogFormat_Getter(t *testing.T) {
	sw := &syslogWriter{format: "rfc5424"}
	if sw.Format() != "rfc5424" {
		t.Fatalf("Format() = %q, want rfc5424", sw.Format())
	}
}

// ─── clusterCountStore ──────────────────────────────────────────────────────

func TestClusterCountStore_GetApply(t *testing.T) {
	cs := &clusterCountStore{counts: map[string]int{}}

	// Empty store returns 0.
	if got := cs.Get("1.2.3.4"); got != 0 {
		t.Fatalf("empty store Get = %d, want 0", got)
	}

	// Apply remote counts.
	cs.Apply(map[string]int{"1.2.3.4": 50, "5.6.7.8": 30})
	if got := cs.Get("1.2.3.4"); got != 50 {
		t.Fatalf("Get(1.2.3.4) = %d, want 50", got)
	}
	if got := cs.Get("5.6.7.8"); got != 30 {
		t.Fatalf("Get(5.6.7.8) = %d, want 30", got)
	}
	if got := cs.Count(); got != 2 {
		t.Fatalf("Count() = %d, want 2", got)
	}

	// Apply replaces entirely.
	cs.Apply(map[string]int{"9.9.9.9": 10})
	if got := cs.Get("1.2.3.4"); got != 0 {
		t.Fatal("old key should be gone after Apply")
	}
	if got := cs.Count(); got != 1 {
		t.Fatalf("Count() = %d, want 1", got)
	}
}

// ─── ExportHotDeltas ────────────────────────────────────────────────────────

func TestExportHotDeltas_Disabled(t *testing.T) {
	r := newRateLimiter()
	// Not enabled — should return nil.
	deltas := r.ExportHotDeltas()
	if deltas != nil {
		t.Fatalf("disabled limiter should return nil, got %v", deltas)
	}
}

func TestExportHotDeltas_ThresholdFilter(t *testing.T) {
	r := newRateLimiter()
	r.Configure(100, time.Minute) // 100 RPM, threshold = 50

	// Add 49 requests for "cold" IP (below 50% threshold).
	for i := 0; i < 49; i++ {
		r.Allow("cold-ip")
	}
	// Add 51 requests for "hot" IP (above 50% threshold).
	for i := 0; i < 51; i++ {
		r.Allow("hot-ip")
	}

	deltas := r.ExportHotDeltas()
	found := false
	for _, d := range deltas {
		if d.IP == "cold-ip" {
			t.Fatal("cold-ip should NOT be exported (below threshold)")
		}
		if d.IP == "hot-ip" {
			found = true
			if d.Count != 51 {
				t.Fatalf("hot-ip count = %d, want 51", d.Count)
			}
		}
	}
	if !found {
		t.Fatal("hot-ip should be in exported deltas")
	}
}

// ─── AllowClusterAware ──────────────────────────────────────────────────────

func TestAllowClusterAware_CombinesRemote(t *testing.T) {
	r := newRateLimiter()
	r.Configure(10, time.Minute)

	// Simulate 7 remote requests from other nodes.
	oldCounts := clusterCounts
	clusterCounts = &clusterCountStore{counts: map[string]int{"test-ip": 7}}
	defer func() { clusterCounts = oldCounts }()

	// Local: should allow 3 more (7 remote + 3 local = 10 = limit).
	for i := 0; i < 3; i++ {
		if !r.AllowClusterAware("test-ip") {
			t.Fatalf("request %d should be allowed (7 remote + %d local < 10)", i+1, i)
		}
	}
	// 4th should be blocked (7 + 3 = 10 >= 10).
	if r.AllowClusterAware("test-ip") {
		t.Fatal("should be blocked: 7 remote + 3 local >= 10 limit")
	}
}

func TestAllowAuto_Standalone(t *testing.T) {
	r := newRateLimiter()
	r.Configure(5, time.Minute)

	// Standalone mode: clusterRateLimitEnabled is false.
	clusterRateLimitEnabled.Store(false)
	for i := 0; i < 5; i++ {
		if !r.AllowAuto("standalone-ip") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if r.AllowAuto("standalone-ip") {
		t.Fatal("6th request should be blocked")
	}
}

// ─── rateLimitAggregator ────────────────────────────────────────────────────

func TestRateLimitAggregator_Basics(t *testing.T) {
	agg := &rateLimitAggregator{
		perNode:  map[string]map[string]int{},
		expireAt: map[string]time.Time{},
	}

	agg.Update("node-a", []RateLimitDelta{
		{IP: "1.1.1.1", Count: 30},
		{IP: "2.2.2.2", Count: 20},
	})
	agg.Update("node-b", []RateLimitDelta{
		{IP: "1.1.1.1", Count: 10},
		{IP: "3.3.3.3", Count: 5},
	})

	// Exclude node-a: should get node-b counts only.
	totals := agg.ClusterTotalsExcluding("node-a")
	if totals["1.1.1.1"] != 10 {
		t.Fatalf("1.1.1.1 excluding node-a = %d, want 10", totals["1.1.1.1"])
	}
	if totals["3.3.3.3"] != 5 {
		t.Fatalf("3.3.3.3 excluding node-a = %d, want 5", totals["3.3.3.3"])
	}
	if _, ok := totals["2.2.2.2"]; ok {
		t.Fatal("2.2.2.2 is only on node-a and should be excluded")
	}

	// Exclude node-b: should get node-a counts.
	totals = agg.ClusterTotalsExcluding("node-b")
	if totals["1.1.1.1"] != 30 {
		t.Fatalf("1.1.1.1 excluding node-b = %d, want 30", totals["1.1.1.1"])
	}

	nodes, hotIPs := agg.Stats()
	if nodes != 2 {
		t.Fatalf("Stats nodes = %d, want 2", nodes)
	}
	if hotIPs != 3 {
		t.Fatalf("Stats hotIPs = %d, want 3", hotIPs)
	}
}

func TestRateLimitAggregator_StaleNodePruning(t *testing.T) {
	agg := &rateLimitAggregator{
		perNode:  map[string]map[string]int{},
		expireAt: map[string]time.Time{},
	}

	// Insert a node with a timestamp 3 minutes ago (beyond 2min cutoff).
	agg.perNode["stale-node"] = map[string]int{"x.x.x.x": 100}
	agg.expireAt["stale-node"] = time.Now().Add(-3 * time.Minute)

	agg.Update("fresh-node", []RateLimitDelta{{IP: "y.y.y.y", Count: 5}})

	totals := agg.ClusterTotalsExcluding("fresh-node")
	if _, ok := totals["x.x.x.x"]; ok {
		t.Fatal("stale node counts should be pruned")
	}

	nodes, _ := agg.Stats()
	if nodes != 1 {
		t.Fatalf("after pruning, nodes = %d, want 1", nodes)
	}
}

// ─── bodyNeedsBuffering / maxScanBufferBytes ────────────────────────────────

func TestBodyNeedsBuffering(t *testing.T) {
	// Reset global state for test.
	origDPI := dpiScanner
	origSec := globalSecScanner
	defer func() {
		dpiScanner = origDPI
		globalSecScanner = origSec
	}()

	// No scanners active.
	dpiScanner = &ContentScanner{maxBytes: 1 << 20}
	globalSecScanner = &SecurityScanner{cache: newHashCache(100, 0)}
	if bodyNeedsBuffering("text/html") {
		t.Fatal("should not buffer when no scanners active")
	}

	// DPI active with text content.
	dpiScanner.Add("test-pattern") //nolint:errcheck
	if !bodyNeedsBuffering("text/html") {
		t.Fatal("should buffer text when DPI active")
	}
	if bodyNeedsBuffering("image/png") {
		t.Fatal("should not buffer binary when only DPI active")
	}
}

func TestMaxScanBufferBytes_DPIvsSec(t *testing.T) {
	origDPI := dpiScanner
	origSec := globalSecScanner
	defer func() {
		dpiScanner = origDPI
		globalSecScanner = origSec
	}()

	dpiScanner = &ContentScanner{maxBytes: 2 << 20}
	globalSecScanner = &SecurityScanner{maxBytes: 5 << 20, cache: newHashCache(100, 0)}

	got := maxScanBufferBytes()
	if got != 5<<20 {
		t.Fatalf("maxScanBufferBytes = %d, want %d", got, 5<<20)
	}

	dpiScanner.maxBytes = 10 << 20
	got = maxScanBufferBytes()
	if got != 10<<20 {
		t.Fatalf("maxScanBufferBytes = %d, want %d (DPI larger)", got, 10<<20)
	}
}

// ─── safeScanBody / safeDPIScan panic recovery ──────────────────────────────

func TestSafeScanBody_NilOnEmpty(t *testing.T) {
	result := safeScanBody(nil)
	if result != nil {
		t.Fatal("safeScanBody(nil) should return nil")
	}
	result = safeScanBody([]byte{})
	if result != nil {
		t.Fatal("safeScanBody(empty) should return nil")
	}
}

func TestSafeDPIScan_NoPatterns(t *testing.T) {
	origDPI := dpiScanner
	defer func() { dpiScanner = origDPI }()
	dpiScanner = &ContentScanner{maxBytes: 1 << 20}

	pattern, matched := safeDPIScan([]byte("hello world"))
	if matched {
		t.Fatalf("should not match with no patterns, got %q", pattern)
	}
}
