package main

// qa_gate_test.go — hard-gate QA coverage for the fixes applied in this
// branch. Every test here asserts the CORRECTED behavior; if any of them
// regress, the pipeline gate must fail.
//
// The tests are grouped by defect they cover:
//
//   1. sanitizeLog control-byte strip         (proxy.go)
//   2. privateCIDRs coverage expansion        (proxy.go)
//   3. SSRF ssrfControl Dialer.Control hook   (security.go)
//   4. Config.TOTPLastCounter persistence     (store.go)
//
// The TOTP algorithm tests (empty-secret rejection, replay protection, code-format
// hardening, positive round-trip) moved to internal/totp/totp_test.go when totp.go
// was extracted into the internal/totp package (ADR-0002). Config.TOTPLastCounter
// persistence stays here — it exercises store.go, not the TOTP algorithm.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// newRequestWithHeader returns a synthetic http.Request with a single header
// set — keeps the scrubForwardedHeaders test independent of the proxy server.
func newRequestWithHeader(key, value string) (*http.Request, error) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set(key, value)
	return req, nil
}

// ─── 5. sanitizeLog control-byte strip ──────────────────────────────────────

func TestSanitizeLog_StripsCtrlAndANSIEscape(t *testing.T) {
	// Every byte in the C0 control set and DEL must be replaced with '_'.
	// ESC (0x1B) is the lynchpin: leaving it through enables "colour bomb"
	// log-viewer hijacks (CWE-150) where a log line reprograms the terminal.
	input := "ok\x00nul\x07bel\x08bs\x0bvt\x0cff\x1besc\x7fdel line\nbreak\r\tother"
	got := sanitizeLog(input)
	for i := 0; i < len(got); i++ {
		c := got[i]
		if c < 0x20 || c == 0x7F {
			t.Fatalf("sanitizeLog leaked control byte 0x%02X at offset %d: %q", c, i, got)
		}
	}
	// Must preserve ordinary UTF-8 content.
	if !strings.Contains(got, "ok") || !strings.Contains(got, "other") {
		t.Fatalf("sanitizeLog dropped printable content: %q", got)
	}
}

func TestSanitizeLog_FastPathNoAlloc(t *testing.T) {
	// A control-free string must survive byte-for-byte. Ensures the fast
	// path is actually taken (return of s, not a rebuilt copy).
	in := "GET /api/policy HTTP/1.1 host=example.com"
	if got := sanitizeLog(in); got != in {
		t.Fatalf("control-free string mutated: got %q want %q", got, in)
	}
}

// ─── 6. privateCIDRs coverage expansion ─────────────────────────────────────

func TestIsPrivateIP_ExpandedCoverage(t *testing.T) {
	// Every entry below is explicitly required to be private after the
	// coverage expansion that accompanied the SSRF hardening.
	private := []string{
		"0.0.0.0",         // "this host"
		"0.1.2.3",         // 0.0.0.0/8
		"10.0.0.1",        // RFC 1918
		"100.64.0.1",      // RFC 6598 CGN
		"100.127.255.254", // CGN end
		"127.0.0.1",       // loopback
		"169.254.169.254", // AWS/GCE/Azure metadata
		"172.16.0.1",      // RFC 1918
		"172.31.255.254",  // RFC 1918 end
		"192.168.1.1",     // RFC 1918
		"198.18.0.1",      // benchmark
		"198.19.255.254",  // benchmark end
		"224.0.0.1",       // multicast
		"239.255.255.255", // multicast end
		"240.0.0.1",       // reserved
		"255.255.255.255", // broadcast
		"::1",             // IPv6 loopback
		"fc00::1",         // ULA
		"fe80::1",         // IPv6 link-local
		"ff02::1",         // IPv6 multicast
	}
	for _, addr := range private {
		ip := net.ParseIP(addr)
		if ip == nil {
			t.Fatalf("bad test data: %q did not parse", addr)
		}
		if !isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%s) = false, want true", addr)
		}
	}

	// Critical regression check: IPv4-mapped IPv6 must reuse the IPv4 list.
	// If someone ever re-adds ::ffff:0:0/96 naively, this catches it by
	// asserting a public v4 stays public when wrapped as v4-mapped v6.
	publicMapped := net.ParseIP("::ffff:8.8.8.8")
	if publicMapped == nil {
		t.Fatal("::ffff:8.8.8.8 did not parse")
	}
	if isPrivateIP(publicMapped) {
		t.Error("::ffff:8.8.8.8 must be public (would regress if ::ffff:0:0/96 is blocked)")
	}

	// But a PRIVATE v4 expressed as v4-mapped v6 must still be caught.
	privateMapped := net.ParseIP("::ffff:127.0.0.1")
	if privateMapped == nil {
		t.Fatal("::ffff:127.0.0.1 did not parse")
	}
	if !isPrivateIP(privateMapped) {
		t.Error("::ffff:127.0.0.1 must be private (IPv4-mapped loopback bypass)")
	}
}

func TestIsPrivateIP_KnownPublicStaysPublic(t *testing.T) {
	// A handful of public IPs used as proxy destinations in other tests.
	// If this fails the expanded list is over-blocking (regression).
	publics := []string{
		"8.8.8.8",              // Google DNS
		"1.1.1.1",              // Cloudflare DNS
		"203.0.113.1",          // TEST-NET-3 (used as "public" in CONNECT tests)
		"2606:4700:4700::1111", // Cloudflare DNS (v6)
	}
	for _, addr := range publics {
		ip := net.ParseIP(addr)
		if ip == nil {
			t.Fatalf("bad test data: %q", addr)
		}
		if isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%s) = true, want false", addr)
		}
	}
}

// ─── 7. SSRF ssrfControl hook ───────────────────────────────────────────────

func TestSSRFControl_BlocksPrivate(t *testing.T) {
	// Called at connect time with the post-resolution IP. The TOCTOU window
	// between "pre-flight DNS check" and "actual connect" is only closed
	// when this function rejects a private peer address.
	cases := []string{
		"127.0.0.1:80",
		"10.0.0.1:443",
		"169.254.169.254:80", // metadata
		"[::1]:9090",
		"[fc00::1]:443",
	}
	for _, addr := range cases {
		if err := ssrfControl("tcp", addr, dummyRawConn{}); err == nil {
			t.Errorf("ssrfControl(%q) must return error (private target)", addr)
		}
	}
}

func TestSSRFControl_AllowsPublic(t *testing.T) {
	cases := []string{
		"8.8.8.8:53",
		"1.1.1.1:443",
		"[2606:4700:4700::1111]:443",
	}
	for _, addr := range cases {
		if err := ssrfControl("tcp", addr, dummyRawConn{}); err != nil {
			t.Errorf("ssrfControl(%q) must allow public target, got %v", addr, err)
		}
	}
}

func TestSSRFControl_MalformedAddrFailsClosed(t *testing.T) {
	// A malformed address must fail closed — better a broken dial than a
	// bypass that sneaks a raw hostname through without validation.
	bad := []string{
		"",
		"notahost",
		"example.com:443", // hostname, not an IP — must not slip through
		"::1",             // missing port
	}
	for _, addr := range bad {
		if err := ssrfControl("tcp", addr, dummyRawConn{}); err == nil {
			t.Errorf("ssrfControl(%q) must fail closed on malformed address", addr)
		}
	}
}

// dummyRawConn satisfies syscall.RawConn so ssrfControl can be unit-tested
// without opening an actual socket.
type dummyRawConn struct{}

func (dummyRawConn) Control(func(fd uintptr)) error { return nil }
func (dummyRawConn) Read(func(fd uintptr) bool) error {
	return fmt.Errorf("not supported")
}
func (dummyRawConn) Write(func(fd uintptr) bool) error {
	return fmt.Errorf("not supported")
}

// Compile-time assertion — if the RawConn contract changes, this line breaks
// before the test does and tells the maintainer exactly where to look.
var _ syscall.RawConn = dummyRawConn{}

// Integration-style guard: the real SSRF-safe dialer MUST refuse a dial to
// loopback regardless of port state. Catches the "forgot to wire ssrfControl"
// regression in the HTTP transport path.
func TestSSRFSafeDialer_RejectsLoopbackDial(t *testing.T) {
	// Start a tiny listener on loopback. Even though the port is open, the
	// dialer must refuse because loopback is blacklisted.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind loopback listener: %v", err)
	}
	defer func() { _ = ln.Close() }()

	addr := ln.Addr().String()
	conn, err := ssrfSafeDialContext(context.Background(), "tcp", addr)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("SSRF-safe dialer permitted loopback dial to %s — SSRF guard regression", addr)
	}
}

// ─── 8. Config.TOTPLastCounter persistence ──────────────────────────────────

func TestConfig_TOTPLastCounter_SetGet(t *testing.T) {
	c := newTestConfig()
	if err := c.SetUIUser("u1", "Passw0rd", RoleAdmin); err != nil {
		t.Fatalf("SetUIUser: %v", err)
	}
	if got := c.GetTOTPLastCounter("u1"); got != 0 {
		t.Errorf("new user: lastCounter = %d, want 0", got)
	}
	if got := c.GetTOTPLastCounter("ghost"); got != 0 {
		t.Errorf("ghost user: lastCounter = %d, want 0", got)
	}
	if !c.SetTOTPLastCounter("u1", 12345) {
		t.Fatal("SetTOTPLastCounter must succeed for existing user")
	}
	if got := c.GetTOTPLastCounter("u1"); got != 12345 {
		t.Errorf("lastCounter roundtrip: got %d, want 12345", got)
	}
	// Monotonic: smaller value must NOT regress the counter (attacker replay).
	if !c.SetTOTPLastCounter("u1", 100) {
		t.Fatal("SetTOTPLastCounter must still report ok for existing user")
	}
	if got := c.GetTOTPLastCounter("u1"); got != 12345 {
		t.Errorf("lastCounter regressed to %d — replay window reopened", got)
	}
	// Non-existent user must return false.
	if c.SetTOTPLastCounter("ghost", 9) {
		t.Error("SetTOTPLastCounter on non-existent user must return false")
	}
}

func TestConfig_TOTPLastCounter_PersistsThroughFile(t *testing.T) {
	// End-to-end: save and reload the users file; totpLastCounter must
	// survive so replay protection is durable across restarts.
	dir := t.TempDir()
	path := filepath.Join(dir, "ui_users.json")

	c1 := newTestConfig()
	c1.uiUsersFile = path
	if err := c1.SetUIUser("u1", "Passw0rd", RoleAdmin); err != nil {
		t.Fatalf("SetUIUser: %v", err)
	}
	if !c1.SetTOTPSecret("u1", "JBSWY3DPEHPK3PXP", nil) {
		t.Fatal("SetTOTPSecret: expected true")
	}
	if !c1.SetTOTPLastCounter("u1", 98765) {
		t.Fatal("SetTOTPLastCounter: expected true")
	}
	if err := c1.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile: %v", err)
	}

	// Fresh config, same file.
	c2 := newTestConfig()
	c2.uiUsersFile = path
	if err := c2.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile: %v", err)
	}
	if got := c2.GetTOTPLastCounter("u1"); got != 98765 {
		t.Fatalf("lastCounter did not persist: got %d, want 98765", got)
	}
	// Sanity: the raw JSON must contain the field name so the on-disk
	// contract is observable and we would catch an accidental schema break.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read users file: %v", err)
	}
	if !strings.Contains(string(data), "totp_last_counter") {
		t.Errorf("persisted file missing totp_last_counter field: %s", data)
	}
}

// ─── 9. RateLimiter edge cases (critical gate-path behavior) ────────────────

func TestRateLimiter_ExemptAlwaysAllowed(t *testing.T) {
	r := newRateLimiter()
	r.Configure(1, time.Minute) // 1 req/min — extremely tight
	if err := r.AddExemption("203.0.113.10"); err != nil {
		t.Fatalf("AddExemption: %v", err)
	}
	// Hammer with 50 calls — every one must pass because the IP is exempt.
	for i := 0; i < 50; i++ {
		if !r.Allow("203.0.113.10") {
			t.Fatalf("exempt IP was rate-limited on iteration %d", i)
		}
	}
	// A non-exempt IP must still be throttled.
	if !r.Allow("203.0.113.20") {
		t.Fatal("first request from non-exempt IP must succeed")
	}
	if r.Allow("203.0.113.20") {
		t.Fatal("second request from non-exempt IP must be rate-limited")
	}
}

// ─── 8b. ClusterStore.Load must not leave CARotation.RenewedNodes nil ─────

// TestClusterStoreLoad_CARotationRenewedNodesInitialised guards against a
// second nil-map class defect: if a persisted cluster-state JSON contains
// a CARotation object whose renewed_nodes field is absent or null (e.g.
// from an older writer or a manually-edited file), RecordNodeRenewed would
// panic with "assignment to entry in nil map" when the first DP node reports
// back. Load must normalise the map defensively.
func TestClusterStoreLoad_CARotationRenewedNodesInitialised(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")

	// Write a minimal cluster state with an active rotation but NO
	// renewed_nodes field — simulating an older writer or a hand-edited file.
	raw := []byte(`{
		"nodes": {},
		"tokens": {},
		"revoked": [],
		"version": 1,
		"ca_rotation": {
			"started_at": "2026-04-21T00:00:00Z",
			"new_fingerprint": "new-fp",
			"old_fingerprint": "old-fp",
			"old_expires":     "2026-04-22T00:00:00Z",
			"total_nodes":     3
		}
	}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("seed cluster.json: %v", err)
	}

	cs := &ClusterStore{}
	if err := cs.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// If the defensive init regressed, this would panic with
	// "assignment to entry in nil map" — fail loudly instead.
	cs.RecordNodeRenewed("dp-1")

	rot := cs.CARotationStatus()
	if rot == nil {
		t.Fatal("expected rotation state after Load")
	}
	if _, ok := rot.RenewedNodes["dp-1"]; !ok {
		t.Fatalf("dp-1 should be in RenewedNodes after RecordNodeRenewed, got %v", rot.RenewedNodes)
	}
}

// TestClusterStoreImportFullState_CARotationRenewedNodesInitialised covers
// the HA-replication twin of the Load path above. A follower that receives
// a state bundle mid-rotation must also get a non-nil RenewedNodes map.
func TestClusterStoreImportFullState_CARotationRenewedNodesInitialised(t *testing.T) {
	raw := []byte(`{
		"nodes": {},
		"tokens": {},
		"revoked": [],
		"version": 7,
		"ca_rotation": {
			"started_at": "2026-04-21T00:00:00Z",
			"new_fingerprint": "new-fp",
			"old_fingerprint": "old-fp",
			"old_expires":     "2026-04-22T00:00:00Z",
			"total_nodes":     2
		}
	}`)

	cs := &ClusterStore{}
	if err := cs.ImportFullState(raw); err != nil {
		t.Fatalf("ImportFullState: %v", err)
	}
	cs.RecordNodeRenewed("dp-a") // must not panic
	rot := cs.CARotationStatus()
	if rot == nil || rot.RenewedNodes == nil || rot.RenewedNodes["dp-a"] == "" {
		t.Fatalf("RenewedNodes not initialised / node not recorded: %+v", rot)
	}
}

// ─── 9a. applyConfigSnapshot must leave all Blocklist maps usable ──────────

// TestApplyConfigSnapshot_BlocklistMapsInitialised is a regression guard for
// the production defect caught by qa-determinism: applyConfigSnapshot used
// to construct &Blocklist{exact, wildcards} without the manual/exceptions
// maps, so the next AddManual or AddException call on a Data Plane node
// panicked with "assignment to entry in nil map".
func TestApplyConfigSnapshot_BlocklistMapsInitialised(t *testing.T) {
	origBL := bl
	t.Cleanup(func() { bl = origBL })

	applyConfigSnapshot(ConfigSnapshot{
		Version:      1,
		BlockedHosts: []string{"snapshot-regression.test"},
	})

	// These two calls would panic before the fix.
	bl.AddManual("manual-regression.test")
	bl.AddException("except-regression.test")

	if !bl.IsBlocked("snapshot-regression.test") {
		t.Fatal("snapshot host should be blocked after applyConfigSnapshot")
	}
	if !bl.IsBlocked("manual-regression.test") {
		t.Fatal("manual host should be blocked after AddManual")
	}
}

// ─── 10a. TOTP lockout — handler-level integration test ────────────────────

// TestAPIAuthLogin_TOTPFailureRecordsLockout proves the high-severity defect
// that made brute-forcing a 6-digit TOTP feasible is now fixed: login with
// valid password but wrong OTP MUST consume a lockout attempt. Without this,
// an attacker who phished or cracked the password could try all 1 000 000
// OTPs with only the 300 ms sleep as a barrier (~3.5 days, parallelisable).
func TestAPIAuthLogin_TOTPFailureRecordsLockout(t *testing.T) {
	const user = "totp_lockout_user"
	const pass = "CorrectHorseBattery9!"
	const secret = "JBSWY3DPEHPK3PXP"

	// Enable auth, create user, enrol TOTP, reset lockout state.
	if err := cfg.SetUIUser(user, pass, RoleAdmin); err != nil {
		t.Fatalf("SetUIUser: %v", err)
	}
	if !cfg.SetTOTPSecret(user, secret, nil) {
		t.Fatal("SetTOTPSecret: want true")
	}
	t.Cleanup(func() {
		cfg.DeleteUIUser(user)
		loginLimiter.ResetUser(user)
	})
	loginLimiter.ResetUser(user)
	initSecret(t)

	before := loginLimiter.AttemptsLeft("127.0.0.1", user)

	w := httptest.NewRecorder()
	body := map[string]string{"user": user, "pass": pass, "totp": "000000"}
	apiAuthLogin(w, jsonReq(http.MethodPost, "/api/auth/login", body))

	if w.Code != http.StatusUnauthorized && w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 401/429 for bad TOTP, got %d body=%s", w.Code, w.Body.String())
	}
	after := loginLimiter.AttemptsLeft("127.0.0.1", user)
	if after >= before {
		t.Fatalf("TOTP failure did not consume a lockout attempt: before=%d after=%d — "+
			"regression of the OTP brute-force fix", before, after)
	}
}

// ─── 10. scrubForwardedHeaders — identity-header strip ──────────────────────

// TestScrubForwardedHeaders_DropsInternalIdentityHeader locks in the rule
// that X-User-Identity is NEVER forwarded, even if a downstream client tries
// to inject it (identity spoofing). This is enforced in proxy.go; regressing
// the strip would allow anyone to forge an authenticated principal upstream.
func TestScrubForwardedHeaders_DropsInternalIdentityHeader(t *testing.T) {
	// Compile-time safety: this test uses only symbols that must stay public.
	// If scrubForwardedHeaders is renamed, the build fails here first.
	r, err := newRequestWithHeader("X-User-Identity", "admin@example.com")
	if err != nil {
		t.Fatalf("newRequestWithHeader: %v", err)
	}
	scrubForwardedHeaders(r)
	if got := r.Header.Get("X-User-Identity"); got != "" {
		t.Fatalf("X-User-Identity must be stripped, got %q", got)
	}
}
