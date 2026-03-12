package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── SSE hub (events.go) ─────────────────────────────────────────────────────

func TestSSEHub_RegisterUnregister(t *testing.T) {
	h := &sseHub{clients: make(map[chan []byte]struct{})}
	ch := make(chan []byte, 4)

	if h.ClientCount() != 0 {
		t.Error("fresh hub should have 0 clients")
	}
	h.register(ch)
	if h.ClientCount() != 1 {
		t.Errorf("ClientCount = %d, want 1 after register", h.ClientCount())
	}
	h.unregister(ch)
	if h.ClientCount() != 0 {
		t.Errorf("ClientCount = %d, want 0 after unregister", h.ClientCount())
	}
}

func TestSSEHub_Broadcast(t *testing.T) {
	h := &sseHub{clients: make(map[chan []byte]struct{})}
	ch := make(chan []byte, 4)
	h.register(ch)

	msg := []byte(`{"test":1}`)
	h.broadcast(msg)

	select {
	case received := <-ch:
		if !bytes.Equal(received, msg) {
			t.Errorf("broadcast received %q, want %q", received, msg)
		}
	default:
		t.Error("broadcast message not received")
	}
	h.unregister(ch)
}

func TestSSEHub_Broadcast_SlowClient(t *testing.T) {
	// A full channel (no buffer space) should be skipped gracefully.
	h := &sseHub{clients: make(map[chan []byte]struct{})}
	ch := make(chan []byte) // unbuffered — will always be "full"
	h.register(ch)
	// broadcast should not block
	done := make(chan struct{})
	go func() {
		h.broadcast([]byte("msg"))
		close(done)
	}()
	<-done
	h.unregister(ch)
}

// ─── SecurityScanner (security_scan.go) ──────────────────────────────────────

func TestSecurityScanner_Enabled(t *testing.T) {
	ss := &SecurityScanner{cache: newHashCache(100, 0)}
	if ss.Enabled() {
		t.Error("uninitialized scanner should not be enabled")
	}
	ss.enabled = true
	if !ss.Enabled() {
		t.Error("enabled scanner should report enabled")
	}
}

func TestSecurityScanner_MaxBytes(t *testing.T) {
	ss := &SecurityScanner{cache: newHashCache(100, 0), maxBytes: 5 << 20}
	if got := ss.MaxBytes(); got != 5<<20 {
		t.Errorf("MaxBytes() = %d, want 5MiB", got)
	}
}

func TestSecurityScanner_BodyScanEnabled_Disabled(t *testing.T) {
	ss := &SecurityScanner{cache: newHashCache(100, 0)}
	if ss.BodyScanEnabled() {
		t.Error("disabled scanner should report BodyScanEnabled=false")
	}
}

func TestSecurityScanner_CheckURL_NoFeed(t *testing.T) {
	ss := &SecurityScanner{cache: newHashCache(100, 0)}
	// globalThreatFeed not enabled — should return nil
	result := ss.CheckURL("http://malware.example.com/bad")
	if result != nil {
		t.Error("CheckURL should return nil when threat feed is not enabled")
	}
}

func TestSecurityScanner_CheckDomain_NoFeed(t *testing.T) {
	ss := &SecurityScanner{cache: newHashCache(100, 0)}
	result := ss.CheckDomain("malware.example.com")
	if result != nil {
		t.Error("CheckDomain should return nil when threat feed is not enabled")
	}
}

func TestSecurityScanner_ScanBody_Empty(t *testing.T) {
	ss := &SecurityScanner{cache: newHashCache(100, 0), enabled: true}
	// empty data → should return nil
	if result := ss.ScanBody(nil); result != nil {
		t.Error("ScanBody with nil data should return nil")
	}
	if result := ss.ScanBody([]byte{}); result != nil {
		t.Error("ScanBody with empty data should return nil")
	}
}

func TestSecurityScanner_ScanBody_NotEnabled(t *testing.T) {
	ss := &SecurityScanner{cache: newHashCache(100, 0)}
	result := ss.ScanBody([]byte("some data"))
	if result != nil {
		t.Error("ScanBody with disabled scanner should return nil")
	}
}

func TestSecurityScanner_ClamAVStatus_Nil(t *testing.T) {
	ss := &SecurityScanner{cache: newHashCache(100, 0)}
	if got := ss.ClamAVStatus(); got != "disabled" {
		t.Errorf("ClamAVStatus with nil clam = %q, want disabled", got)
	}
}

func TestMaxScanBufferBytes(t *testing.T) {
	// Just verify it returns a positive value and doesn't panic
	n := maxScanBufferBytes()
	if n <= 0 {
		t.Errorf("maxScanBufferBytes() = %d, want > 0", n)
	}
}

func TestBodyNeedsBuffering_Disabled(t *testing.T) {
	// Both scanners disabled — should return false
	if bodyNeedsBuffering("text/html") {
		t.Error("bodyNeedsBuffering should be false when scanners are disabled")
	}
}

func TestSecScanStatusMap(t *testing.T) {
	m := secScanStatusMap()
	if _, ok := m["enabled"]; !ok {
		t.Error("secScanStatusMap should contain 'enabled' key")
	}
	if _, ok := m["clamav_status"]; !ok {
		t.Error("secScanStatusMap should contain 'clamav_status' key")
	}
	if _, ok := m["yara_rules"]; !ok {
		t.Error("secScanStatusMap should contain 'yara_rules' key")
	}
}

func TestScanBlock(t *testing.T) {
	w := httptest.NewRecorder()
	scanBlock(w, "evil.com", "EICAR", "clamav")
	if w.Code != http.StatusForbidden {
		t.Errorf("scanBlock status = %d, want 403", w.Code)
	}
	if !strings.Contains(w.Body.String(), "CLAMAV") {
		t.Errorf("scanBlock body should mention source, got: %q", w.Body.String())
	}
}

func TestScanBlockConn(t *testing.T) {
	var buf bytes.Buffer
	scanBlockConn(&buf, "evil.com", "EICAR", "clamav")
	if !strings.Contains(buf.String(), "403") {
		t.Errorf("scanBlockConn should write 403, got: %q", buf.String())
	}
}


func TestServePACFile(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/proxy.pac", nil)
	r.RemoteAddr = "127.0.0.1:9000"
	servePACFile(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("servePACFile status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "javascript") &&
		!strings.Contains(w.Header().Get("Content-Type"), "pac") &&
		!strings.Contains(w.Body.String(), "FindProxyForURL") {
		t.Error("servePACFile should return PAC content with FindProxyForURL")
	}
}

func TestServePACFile_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/proxy.pac", nil)
	r.RemoteAddr = "127.0.0.1:9000"
	servePACFile(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("servePACFile POST status = %d, want 405", w.Code)
	}
}

// ─── proxy.go helpers ────────────────────────────────────────────────────────


func TestRemoveHopHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "keep-alive")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Content-Type", "application/json")
	removeHopHeaders(h)
	if h.Get("Connection") != "" {
		t.Error("removeHopHeaders should remove Connection header")
	}
	if h.Get("Transfer-Encoding") != "" {
		t.Error("removeHopHeaders should remove Transfer-Encoding header")
	}
	if h.Get("Content-Type") == "" {
		t.Error("removeHopHeaders should NOT remove Content-Type header")
	}
}

func TestCopyHeaders(t *testing.T) {
	dst := http.Header{}
	src := http.Header{}
	src.Set("X-Custom", "value1")
	src.Add("X-Multi", "a")
	src.Add("X-Multi", "b")
	copyHeaders(dst, src)
	if dst.Get("X-Custom") != "value1" {
		t.Errorf("copyHeaders should copy X-Custom, got %q", dst.Get("X-Custom"))
	}
	if len(dst["X-Multi"]) != 2 {
		t.Errorf("copyHeaders should copy all values for X-Multi, got %d", len(dst["X-Multi"]))
	}
}

func TestScrubForwardedHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// Private IPs should be stripped from X-Forwarded-For
	r.Header.Set("X-Forwarded-For", "192.168.1.1, 8.8.8.8, 10.0.0.1")
	r.Header.Set("X-Real-IP", "192.168.1.5") // private — should be removed
	r.Header.Set("X-User-Identity", "should-be-removed")

	scrubForwardedHeaders(r)

	xff := r.Header.Get("X-Forwarded-For")
	if strings.Contains(xff, "192.168.1.1") || strings.Contains(xff, "10.0.0.1") {
		t.Errorf("private IPs should be stripped from X-Forwarded-For, got %q", xff)
	}
	if !strings.Contains(xff, "8.8.8.8") {
		t.Errorf("public IPs should remain in X-Forwarded-For, got %q", xff)
	}
	if r.Header.Get("X-Real-IP") != "" {
		t.Error("private X-Real-IP should be removed")
	}
	if r.Header.Get("X-User-Identity") != "" {
		t.Error("X-User-Identity should always be removed")
	}
}

func TestScrubForwardedHeaders_AllPrivate(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1")
	scrubForwardedHeaders(r)
	if r.Header.Get("X-Forwarded-For") != "" {
		t.Error("X-Forwarded-For should be deleted when all IPs are private")
	}
}


func TestDefaultPolicyAction(t *testing.T) {
	// Should return one of "allow" or "deny"
	action := defaultPolicyAction()
	if action != "allow" && action != "deny" {
		t.Errorf("defaultPolicyAction() = %q, want 'allow' or 'deny'", action)
	}
}

// ─── Metrics (metrics.go) ────────────────────────────────────────────────────

func TestHandleMetrics_NoToken(t *testing.T) {
	old := metricsToken
	metricsToken = ""
	defer func() { metricsToken = old }()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	handleMetrics(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("handleMetrics status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "proxyshield_requests_total") {
		t.Error("handleMetrics should return Prometheus metrics")
	}
}

func TestHandleMetrics_WithToken_Authorized(t *testing.T) {
	old := metricsToken
	metricsToken = "secret123"
	defer func() { metricsToken = old }()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Header.Set("Authorization", "Bearer secret123")
	handleMetrics(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("handleMetrics with valid token status = %d, want 200", w.Code)
	}
}

func TestHandleMetrics_WithToken_Unauthorized(t *testing.T) {
	old := metricsToken
	metricsToken = "secret123"
	defer func() { metricsToken = old }()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	r.Header.Set("Authorization", "Bearer wrongtoken")
	handleMetrics(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("handleMetrics with wrong token status = %d, want 401", w.Code)
	}
}

func TestHandleMetrics_NoBearer(t *testing.T) {
	old := metricsToken
	metricsToken = "secret123"
	defer func() { metricsToken = old }()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	handleMetrics(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("handleMetrics with no token status = %d, want 401", w.Code)
	}
}

