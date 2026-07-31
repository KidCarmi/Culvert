package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/blocklist"
	"github.com/KidCarmi/Culvert/internal/session"
)

// ── ConfigStore Tests ──────────────────────────────────────────────────────

func TestConfigStore_UpdateAndGet(t *testing.T) {
	cs := &ConfigStore{}
	cs.Update(ConfigSnapshot{
		BlockedHosts: []string{"evil.com"},
		RateLimitRPM: 100,
	})

	snap := cs.Get()
	if snap.Version != 1 {
		t.Fatalf("version = %d, want 1", snap.Version)
	}
	if len(snap.BlockedHosts) != 1 || snap.BlockedHosts[0] != "evil.com" {
		t.Fatalf("blocked hosts = %v, want [evil.com]", snap.BlockedHosts)
	}
	if snap.RateLimitRPM != 100 {
		t.Fatalf("rate = %d, want 100", snap.RateLimitRPM)
	}
	if snap.UpdatedAt == "" {
		t.Fatal("updated_at should be set")
	}
}

func TestConfigStore_VersionIncrement(t *testing.T) {
	cs := &ConfigStore{}
	cs.Update(ConfigSnapshot{BlockedHosts: []string{"a.com"}})
	cs.Update(ConfigSnapshot{BlockedHosts: []string{"b.com"}})
	cs.Update(ConfigSnapshot{BlockedHosts: []string{"c.com"}})

	snap := cs.Get()
	if snap.Version != 3 {
		t.Fatalf("version = %d, want 3", snap.Version)
	}
}

func TestConfigStore_Subscribe(t *testing.T) {
	cs := &ConfigStore{}
	ch := cs.Subscribe()

	cs.Update(ConfigSnapshot{BlockedHosts: []string{"test.com"}})

	select {
	case <-ch:
		// Got notification
	case <-time.After(time.Second):
		t.Fatal("subscriber should have been notified")
	}
}

func TestConfigStore_MultipleSubscribers(t *testing.T) {
	cs := &ConfigStore{}
	ch1 := cs.Subscribe()
	ch2 := cs.Subscribe()

	cs.Update(ConfigSnapshot{BlockedHosts: []string{"test.com"}})

	for i, ch := range []chan struct{}{ch1, ch2} {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d not notified", i)
		}
	}
}

// ── tokenExpired Tests ─────────────────────────────────────────────────────

func TestTokenExpired_UsedRecent(t *testing.T) {
	tok := &EnrollToken{Used: true, UsedAt: time.Now().Add(-time.Hour)}
	if tokenExpired(tok, time.Now()) {
		t.Fatal("recently used token should not be expired")
	}
}

func TestTokenExpired_UsedOld(t *testing.T) {
	tok := &EnrollToken{Used: true, UsedAt: time.Now().Add(-8 * 24 * time.Hour)}
	if !tokenExpired(tok, time.Now()) {
		t.Fatal("token used 8 days ago should be expired for GC")
	}
}

func TestTokenExpired_UnusedNotYetExpired(t *testing.T) {
	tok := &EnrollToken{Used: false, ExpiresAt: time.Now().Add(time.Hour)}
	if tokenExpired(tok, time.Now()) {
		t.Fatal("unused token with future expiry should not be expired")
	}
}

func TestTokenExpired_UnusedRecentlyExpired(t *testing.T) {
	tok := &EnrollToken{Used: false, ExpiresAt: time.Now().Add(-time.Hour)}
	if tokenExpired(tok, time.Now()) {
		t.Fatal("unused token expired 1 hour ago should not be GC'd yet (24h grace)")
	}
}

func TestTokenExpired_UnusedLongExpired(t *testing.T) {
	tok := &EnrollToken{Used: false, ExpiresAt: time.Now().Add(-48 * time.Hour)}
	if !tokenExpired(tok, time.Now()) {
		t.Fatal("unused token expired 48h ago should be GC'd")
	}
}

// ── gcExpiredTokens Tests ──────────────────────────────────────────────────

func TestGCExpiredTokens(t *testing.T) {
	cs := newTestClusterStore(t)

	// Add a recently used token (should survive GC).
	cs.st.Tokens["fresh"] = &EnrollToken{
		TokenHash: "fresh", Used: true, UsedAt: time.Now(),
	}
	// Add an old used token (should be GC'd).
	cs.st.Tokens["old"] = &EnrollToken{
		TokenHash: "old", Used: true, UsedAt: time.Now().Add(-10 * 24 * time.Hour),
	}

	changed := cs.gcExpiredTokens(time.Now())
	if !changed {
		t.Fatal("should have changed (removed old token)")
	}
	if _, ok := cs.st.Tokens["fresh"]; !ok {
		t.Fatal("fresh token should survive GC")
	}
	if _, ok := cs.st.Tokens["old"]; ok {
		t.Fatal("old token should have been removed")
	}
}

func TestGCExpiredTokens_NoneToRemove(t *testing.T) {
	cs := newTestClusterStore(t)
	cs.st.Tokens["recent"] = &EnrollToken{
		TokenHash: "recent", Used: true, UsedAt: time.Now(),
	}
	changed := cs.gcExpiredTokens(time.Now())
	if changed {
		t.Fatal("should not report changes when nothing to GC")
	}
}

// ── gcOldRevocations Tests ─────────────────────────────────────────────────

func TestGCOldRevocations(t *testing.T) {
	cs := newTestClusterStore(t)
	cs.st.Revoked = []RevokedCert{
		{CertSerial: "recent", RevokedAt: time.Now()},
		{CertSerial: "old", RevokedAt: time.Now().Add(-400 * 24 * time.Hour)},
	}

	changed := cs.gcOldRevocations(time.Now())
	if !changed {
		t.Fatal("should have changed (removed old revocation)")
	}
	if len(cs.st.Revoked) != 1 {
		t.Fatalf("expected 1 revocation, got %d", len(cs.st.Revoked))
	}
	if cs.st.Revoked[0].CertSerial != "recent" {
		t.Fatalf("surviving revocation = %q, want recent", cs.st.Revoked[0].CertSerial)
	}
}

func TestGCOldRevocations_Empty(t *testing.T) {
	cs := newTestClusterStore(t)
	changed := cs.gcOldRevocations(time.Now())
	if changed {
		t.Fatal("should not report changes when empty")
	}
}

func TestGCOldRevocations_AllFresh(t *testing.T) {
	cs := newTestClusterStore(t)
	cs.st.Revoked = []RevokedCert{
		{CertSerial: "a", RevokedAt: time.Now()},
		{CertSerial: "b", RevokedAt: time.Now().Add(-30 * 24 * time.Hour)},
	}
	changed := cs.gcOldRevocations(time.Now())
	if changed {
		t.Fatal("no revocations should be removed")
	}
	if len(cs.st.Revoked) != 2 {
		t.Fatalf("expected 2 revocations, got %d", len(cs.st.Revoked))
	}
}

// ── verifyNode Tests ───────────────────────────────────────────────────────

func TestVerifyNode_EmptyNodeID(t *testing.T) {
	origStore := globalClusterStore
	defer func() { globalClusterStore = origStore }()
	globalClusterStore = newTestClusterStore(t)

	err := verifyNode(testBGCtx(), "")
	if err == nil {
		t.Fatal("expected error for empty node ID")
	}
}

func TestVerifyNode_RevokedNode(t *testing.T) {
	origStore := globalClusterStore
	defer func() { globalClusterStore = origStore }()
	globalClusterStore = newTestClusterStore(t)
	globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected", CertSerial: "s1"})
	_ = globalClusterStore.RevokeNode("dp-1", "admin", "test")

	err := verifyNode(testBGCtx(), "dp-1")
	if err == nil {
		t.Fatal("expected error for revoked node")
	}
}

func TestVerifyNode_ValidNode(t *testing.T) {
	origStore := globalClusterStore
	defer func() { globalClusterStore = origStore }()
	globalClusterStore = newTestClusterStore(t)
	globalClusterStore.RegisterNode(&EnrolledNode{NodeID: "dp-1", Status: "connected", CertSerial: "s1"})

	// H3: no TLS peer info now fails closed by default; this test
	// exercises the explicit dev-mode opt-in.
	origInsecure := clusterInsecure
	defer func() { clusterInsecure = origInsecure }()
	clusterInsecure = true

	err := verifyNode(testBGCtx(), "dp-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func testBGCtx() context.Context { //nolint:unused // used by tests
	return context.Background()
}

// ensure context import is used
var _ = context.Background

// ── Session secret startup shim tests ──────────────────────────────────────
// (Revocation-list persistence tests moved to internal/session with the
// ADR-0002 extraction; these stay because initSessionSecretFromConfig is the
// main-side env/config wiring.)

func TestInitSessionSecretFromConfig_Empty(t *testing.T) {
	origSecret := session.SigningKey()
	defer session.SetSigningKey(origSecret)

	// Empty string should be no-op.
	initSessionSecretFromConfig("")
}

func TestInitSessionSecretFromConfig_Valid(t *testing.T) {
	origSecret := session.SigningKey()
	defer session.SetSigningKey(origSecret)

	// 32 bytes = 64 hex chars (test-only, not a real key)
	hexKey := "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff0000000011111111" //nolint:gosec // test value
	initSessionSecretFromConfig(hexKey)
	if len(session.SigningKey()) != 32 {
		t.Fatalf("session secret length = %d, want 32", len(session.SigningKey()))
	}
}

func TestInitSessionSecretFromConfig_InvalidHex(t *testing.T) {
	origSecret := session.SigningKey()
	defer session.SetSigningKey(origSecret)

	initSessionSecretFromConfig("not-valid-hex!")
	// Should keep the original secret (warning logged).
}

func TestInitSessionSecretFromConfig_TooShort(t *testing.T) {
	origSecret := session.SigningKey()
	defer session.SetSigningKey(origSecret)

	initSessionSecretFromConfig("aabb") // only 2 bytes
	// Should keep the original secret.
}

// TestInitSessionSecretFromConfig_TrailingNewline covers a session_secret
// value sourced from a file (e.g. a YAML value populated via a shell
// `$(cat secret-file)`-style step, or hand-edited with a trailing newline
// left in place by an editor). hex.DecodeString rejects the embedded
// newline outright, so a byte-for-byte-valid secret was silently discarded
// in favor of a random key — defeating shared-signing-key clustering with
// no error surfaced beyond a log line.
func TestInitSessionSecretFromConfig_TrailingNewline(t *testing.T) {
	origSecret := session.SigningKey()
	defer session.SetSigningKey(origSecret)

	const hexKey = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff0000000011111111" //nolint:gosec // test value
	initSessionSecretFromConfig(hexKey + "\n")

	got := session.SigningKey()
	if len(got) != 32 {
		t.Fatalf("session secret length = %d, want 32 (trailing newline should be trimmed, not treated as invalid hex)", len(got))
	}
	want, _ := hex.DecodeString(hexKey)
	if !bytes.Equal(got, want) {
		t.Fatalf("session secret = %x, want %x", got, want)
	}
}

// ── cpServerOption Tests ───────────────────────────────────────────────────

func TestCPServerOption_NoTLS_NoInsecure(t *testing.T) {
	origInsecure := clusterInsecure
	defer func() { clusterInsecure = origInsecure }()
	clusterInsecure = false

	_, err := cpServerOption(":50051", "", "", "")
	if err == nil {
		t.Fatal("expected error when no TLS and not insecure")
	}
}

func TestCPServerOption_Insecure(t *testing.T) {
	origInsecure := clusterInsecure
	defer func() { clusterInsecure = origInsecure }()
	clusterInsecure = true

	opt, err := cpServerOption(":50051", "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opt == nil {
		t.Fatal("option should not be nil")
	}
}

// ── applyConfigSnapshot Tests ──────────────────────────────────────────────

func TestApplyConfigSnapshot(t *testing.T) {
	// Save and restore global state.
	origBL := bl
	origIPF := ipf
	origRL := rl
	defer func() {
		bl = origBL
		ipf = origIPF
		rl = origRL
	}()

	// Initialize required globals.
	bl = blocklist.New()
	ipf = &IPFilter{single: map[string]bool{}}
	rl = &RateLimiter{}

	snap := ConfigSnapshot{
		Version:      5,
		BlockedHosts: []string{"evil.com", "*.bad.org"},
		IPFilterMode: "allow",
		IPList:       []string{"10.0.0.1"},
		RateLimitRPM: 500,
	}

	applyConfigSnapshot(snap)

	if !bl.IsBlocked("evil.com") {
		t.Fatal("evil.com should be blocked")
	}
	if ipf.Mode() != "allow" {
		t.Fatalf("IP filter mode = %q, want allow", ipf.Mode())
	}
	if rl.Limit() != 500 {
		t.Fatalf("rate limit = %d, want 500", rl.Limit())
	}
}

// ── CurrentConfigSnapshot Tests ────────────────────────────────────────────

func TestCurrentConfigSnapshot(t *testing.T) {
	origBL := bl
	origIPF := ipf
	origRL := rl
	origCfg := cfg
	defer func() {
		bl = origBL
		ipf = origIPF
		rl = origRL
		cfg = origCfg
	}()

	bl = blocklist.New()
	bl.Add("test.com")
	ipf = &IPFilter{single: map[string]bool{}}
	ipf.SetMode("block") // valid mode; snapshot must round-trip it
	rl = &RateLimiter{}
	rl.Configure(200, time.Minute)

	snap := CurrentConfigSnapshot()
	if len(snap.BlockedHosts) != 1 || snap.BlockedHosts[0] != "test.com" {
		t.Fatalf("blocked hosts = %v", snap.BlockedHosts)
	}
	if snap.IPFilterMode != "block" {
		t.Fatalf("IP filter mode = %q", snap.IPFilterMode)
	}
	if snap.RateLimitRPM != 200 {
		t.Fatalf("rate = %d", snap.RateLimitRPM)
	}
}

// ── Cluster CA additional tests ────────────────────────────────────────────

func TestClusterCA_SecondaryActive_NoSecondary(t *testing.T) {
	ca := &clusterCA{}
	if ca.SecondaryActive() {
		t.Fatal("should be false when no secondary")
	}
}

func TestClusterCA_AllCACertsPEM_PrimaryOnly(t *testing.T) {
	dir := t.TempDir()
	ca := &clusterCA{}
	_ = ca.InitOrLoad(dir)

	pems := ca.AllCACertsPEM()
	if len(pems) == 0 {
		t.Fatal("should return primary CA PEM")
	}
}

func TestClusterCA_CleanupSecondary_NoOp(t *testing.T) {
	ca := &clusterCA{}
	// Should not panic when no secondary.
	ca.CleanupSecondary()
}
