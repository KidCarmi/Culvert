package main

import (
	"net/http"
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

// ─── OTLP exporter ────────────────────────────────────────────────────────

func TestOTLPExporter_ConfigureAndStop(t *testing.T) {
	o := &OTLPExporter{
		interval: 1 * time.Hour, // long interval to avoid push
		client:   &http.Client{Timeout: 1 * time.Second},
	}
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
	o := &OTLPExporter{
		interval: 1 * time.Hour,
		client:   &http.Client{Timeout: 1 * time.Second},
	}
	// Empty endpoint should be a no-op.
	o.Configure("", nil)
	if o.Enabled() {
		t.Fatal("empty endpoint should not enable")
	}
}

func TestValidOTLPEndpoint_Regexp(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"http://collector:4318", true},
		{"https://otel.example.com", true},
		{"http://10.0.0.1:4318", true},
		{"ftp://bad.example.com", false},
		{"", false},
		{"not-a-url", false},
		{"http://", false},
	}
	for _, tc := range tests {
		got := validOTLPEndpoint.MatchString(tc.url)
		if got != tc.want {
			t.Errorf("validOTLPEndpoint(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

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
	savedHits := ruleMet.hits
	savedOrder := ruleMet.order
	ruleMet.hits = map[string]*int64{}
	ruleMet.order = nil
	ruleMet.mu.Unlock()
	t.Cleanup(func() {
		ruleMet.mu.Lock()
		ruleMet.hits = savedHits
		ruleMet.order = savedOrder
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
	o := &OTLPExporter{
		interval: 1 * time.Hour,
		client:   &http.Client{Timeout: 1 * time.Second},
	}
	payload := o.buildPayload()
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

func TestExportRevocations_FiltersExpired(t *testing.T) {
	rl := &revocationList{tokens: map[string]time.Time{}}
	// Add one valid and one expired token.
	rl.tokens["valid-token"] = time.Now().Add(1 * time.Hour)
	rl.tokens["expired-token"] = time.Now().Add(-1 * time.Hour)

	entries := rl.ExportRevocations()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry (expired filtered), got %d", len(entries))
	}
	if entries[0].Token != "valid-token" {
		t.Fatalf("expected valid-token, got %q", entries[0].Token)
	}
	// Expired token should have been cleaned up.
	if _, exists := rl.tokens["expired-token"]; exists {
		t.Fatal("expired token should be removed from map")
	}
}

func TestMergeRevocations(t *testing.T) {
	rl := &revocationList{tokens: map[string]time.Time{}}
	// Pre-existing token.
	rl.tokens["existing"] = time.Now().Add(1 * time.Hour)

	entries := []RevocationEntry{
		{Token: "new-token", Expiry: time.Now().Add(1 * time.Hour).Unix()},
		{Token: "existing", Expiry: time.Now().Add(2 * time.Hour).Unix()}, // duplicate
		{Token: "expired", Expiry: time.Now().Add(-1 * time.Hour).Unix()}, // expired
	}
	added := rl.MergeRevocations(entries)
	if added != 1 {
		t.Fatalf("expected 1 added, got %d", added)
	}
	if rl.Count() != 2 {
		t.Fatalf("expected 2 total, got %d", rl.Count())
	}
}

// ─── Audit event queue ─────────────────────────────────────────────────────

func TestAuditEventQueue(t *testing.T) {
	// Drain any existing events.
	drainPendingAuditEvents()

	// Queue some events.
	queueAuditForCluster(AuditEntry{Action: "test1"})
	queueAuditForCluster(AuditEntry{Action: "test2"})

	events := drainPendingAuditEvents()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Action != "test1" || events[1].Action != "test2" {
		t.Fatal("events out of order")
	}

	// Second drain should be empty.
	events = drainPendingAuditEvents()
	if events != nil {
		t.Fatalf("expected nil after drain, got %d events", len(events))
	}
}

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
