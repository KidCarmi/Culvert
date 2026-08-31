package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/otlp"
	"github.com/KidCarmi/Culvert/internal/secscan"
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

// syslog formatMsg/Format tests moved to internal/syslog (ADR-0002) — they use
// the unexported formatMsg + struct fields, now in package syslog.

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
	dpiScanner = newContentScanner(1 << 20)
	globalSecScanner = secscan.New(secscan.Deps{Cache: newHashCache(100, 0)})
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

	dpiScanner = newContentScanner(2 << 20)
	globalSecScanner = secscan.New(secscan.Deps{MaxBytes: 5 << 20, Cache: newHashCache(100, 0)})

	got := maxScanBufferBytes()
	if got != 5<<20 {
		t.Fatalf("maxScanBufferBytes = %d, want %d", got, 5<<20)
	}

	dpiScanner = newContentScanner(10 << 20)
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
	dpiScanner = newContentScanner(1 << 20)

	pattern, matched := safeDPIScan([]byte("hello world"))
	if matched {
		t.Fatalf("should not match with no patterns, got %q", pattern)
	}
}

// ─── OTLP exporter ────────────────────────────────────────────────────────

func TestOTLPExporter_ConfigureAndStop(t *testing.T) {
	o := otlp.NewMetrics(nil)
	// Initially disabled.
	if o.Enabled() {
		t.Fatal("should be disabled initially")
	}
	if o.Endpoint() != "" {
		t.Fatalf("endpoint should be empty, got %q", o.Endpoint())
	}

	// Configure with an endpoint.
	o.Configure("http://collector.example.com:4318", nil)
	if !o.Enabled() {
		t.Fatal("should be enabled after Configure")
	}
	if o.Endpoint() != "http://collector.example.com:4318" {
		t.Fatalf("endpoint = %q", o.Endpoint())
	}

	// Stop.
	o.Stop()
	if o.Enabled() {
		t.Fatal("should be disabled after Stop")
	}
}

func TestOTLPExporter_ConfigureEmpty(t *testing.T) {
	o := otlp.NewMetrics(nil)
	// Empty endpoint should be a no-op.
	o.Configure("", nil)
	if o.Enabled() {
		t.Fatal("empty endpoint should not enable")
	}
}

// TestValidOTLPEndpoint_Regexp moved to internal/otlp (the endpoint
// validator is package-internal since the extraction).

func TestOTLPCounterMetrics(t *testing.T) {
	now := "1234567890"
	metrics := otlpCounterMetrics(now)
	if len(metrics) < 10 {
		t.Fatalf("expected at least 10 counter metrics, got %d", len(metrics))
	}
	for _, m := range metrics {
		if m.Sum == nil {
			t.Fatalf("counter metric %q missing Sum", m.Name)
		}
		if !m.Sum.IsMonotonic {
			t.Fatalf("counter metric %q should be monotonic", m.Name)
		}
		if len(m.Sum.DataPoints) != 1 {
			t.Fatalf("counter metric %q should have 1 data point", m.Name)
		}
		if m.Sum.DataPoints[0].TimeUnixNano != now {
			t.Fatalf("data point time = %q, want %q", m.Sum.DataPoints[0].TimeUnixNano, now)
		}
	}
}

func TestOTLPGaugeMetrics(t *testing.T) {
	now := "1234567890"
	metrics := otlpGaugeMetrics(now)
	if len(metrics) < 5 {
		t.Fatalf("expected at least 5 gauge metrics, got %d", len(metrics))
	}
	for _, m := range metrics {
		if m.Gauge == nil {
			t.Fatalf("gauge metric %q missing Gauge", m.Name)
		}
		if len(m.Gauge.DataPoints) != 1 {
			t.Fatalf("gauge metric %q should have 1 data point", m.Name)
		}
	}
}

func TestOTLPHistogramMetric(t *testing.T) {
	now := "1234567890"
	m := otlpHistogramMetric(now)
	if m.Histogram == nil {
		t.Fatal("histogram metric missing Histogram")
	}
	if m.Name != "culvert.request.duration" {
		t.Fatalf("name = %q, want culvert.request.duration", m.Name)
	}
	if m.Unit != "s" {
		t.Fatalf("unit = %q, want s", m.Unit)
	}
	if len(m.Histogram.DataPoints) != 1 {
		t.Fatal("should have 1 histogram data point")
	}
}

func TestOTLPRuleMetrics_Empty(t *testing.T) {
	// ruleMet is a package global populated by every test that exercises the
	// policy engine. Under -count>1 or -shuffle=on, a previously-registered
	// rule bleeds into this test and the "0 rules" assertion fires. Snapshot
	// and clear ruleMet for the duration of the test, then restore.
	ruleMet.mu.Lock()
	savedView := ruleMet.view()
	ruleMet.publishLocked(&ruleCounterView{hits: map[string]*int64{}, last: map[string]*int64{}})
	ruleMet.mu.Unlock()
	t.Cleanup(func() {
		ruleMet.mu.Lock()
		ruleMet.publishLocked(savedView)
		ruleMet.mu.Unlock()
	})

	now := "1234567890"
	metrics := otlpRuleMetrics(now)
	// With no rules registered, should return empty slice.
	if len(metrics) != 0 {
		t.Fatalf("expected 0 rule metrics with no rules, got %d", len(metrics))
	}
}

func TestOTLPBuildPayload(t *testing.T) {
	payload := otlp.Envelope(culvertMetricsSnapshot(fmt.Sprintf("%d", time.Now().UnixNano())))
	if len(payload.ResourceMetrics) != 1 {
		t.Fatalf("expected 1 resource metric, got %d", len(payload.ResourceMetrics))
	}
	rm := payload.ResourceMetrics[0]
	if len(rm.ScopeMetrics) != 1 {
		t.Fatalf("expected 1 scope metric, got %d", len(rm.ScopeMetrics))
	}
	// Should have counters + gauges + histogram at minimum.
	if len(rm.ScopeMetrics[0].Metrics) < 16 {
		t.Fatalf("expected at least 16 metrics, got %d", len(rm.ScopeMetrics[0].Metrics))
	}
}

// ─── Session revocation export/merge ───────────────────────────────────────
// (Moved to internal/session with the ADR-0002 extraction.)

// ─── clusterAuditLog ──────────────────────────────────────────────────────

func TestClusterAuditLog_AppendAndRecent(t *testing.T) {
	log := &clusterAuditLog{maxSize: 5}

	log.Append("node-a", []AuditEntry{{Action: "login"}, {Action: "logout"}})
	log.Append("node-b", []AuditEntry{{Action: "block"}})

	if log.Count() != 3 {
		t.Fatalf("count = %d, want 3", log.Count())
	}

	recent := log.Recent(2)
	if len(recent) != 2 {
		t.Fatalf("recent(2) len = %d, want 2", len(recent))
	}
	// Most recent should be last appended.
	if recent[1].Entry.Action != "block" {
		t.Fatalf("last entry action = %q, want block", recent[1].Entry.Action)
	}
	if recent[1].NodeID != "node-b" {
		t.Fatalf("last entry node = %q, want node-b", recent[1].NodeID)
	}

	// Request more than available.
	recent = log.Recent(100)
	if len(recent) != 3 {
		t.Fatalf("recent(100) should return all 3, got %d", len(recent))
	}

	// Zero/negative returns nil.
	if log.Recent(0) != nil {
		t.Fatal("recent(0) should return nil")
	}
}

func TestClusterAuditLog_RingBuffer(t *testing.T) {
	log := &clusterAuditLog{maxSize: 3}

	// Add 5 entries — only last 3 should survive.
	for i := 0; i < 5; i++ {
		log.Append("node", []AuditEntry{{Action: string(rune('a' + i))}})
	}
	if log.Count() != 3 {
		t.Fatalf("count = %d, want 3 (ring buffer)", log.Count())
	}
	recent := log.Recent(3)
	if recent[0].Entry.Action != "c" {
		t.Fatalf("oldest surviving = %q, want c", recent[0].Entry.Action)
	}
}

// ─── revocationAggregator ──────────────────────────────────────────────────

func TestRevocationAggregator_MergedExcluding(t *testing.T) {
	agg := &revocationAggregator{perNode: map[string][]RevocationEntry{}}

	future := time.Now().Add(1 * time.Hour).Unix()
	past := time.Now().Add(-1 * time.Hour).Unix()

	agg.Update("node-a", []RevocationEntry{
		{Token: "tok-a1", Expiry: future},
		{Token: "tok-expired", Expiry: past},
	})
	agg.Update("node-b", []RevocationEntry{
		{Token: "tok-b1", Expiry: future},
		{Token: "tok-a1", Expiry: future}, // duplicate across nodes
	})

	merged := agg.MergedExcluding("node-a")
	if len(merged) != 2 {
		t.Fatalf("expected 2 merged entries (node-b only), got %d", len(merged))
	}

	// Should not include node-a's entries.
	merged = agg.MergedExcluding("node-b")
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged entry (node-a, non-expired), got %d", len(merged))
	}
	if merged[0].Token != "tok-a1" {
		t.Fatalf("expected tok-a1, got %q", merged[0].Token)
	}
}
