package session

// Engine tests moved from package main (session_test.go, session_extra_test.go,
// session_jti_test.go) with the ADR-0002 extraction. Cookie-helper and
// Session→Identity tests stay in main (they need isSecureRequest / Identity).

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// initSecret initialises the signing key if it hasn't been set yet.
func initSecret(t *testing.T) {
	t.Helper()
	if !HasSigningKey() {
		InitRandomKey()
	}
}

// withFreshSigningKey installs a deterministic 32-byte key for the duration
// of t and restores the previous value on cleanup.
func withFreshSigningKey(t *testing.T) {
	t.Helper()
	prev := SigningKey()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1) // deterministic, non-zero
	}
	SetSigningKey(key)
	t.Cleanup(func() { SetSigningKey(prev) })
}

// withFreshRevocationList empties the package singleton for the duration of t.
func withFreshRevocationList(t *testing.T) {
	t.Helper()
	t.Cleanup(Revoked.SwapForTest())
}

// ─── Encode / Decode roundtrip ────────────────────────────────────────────────

func TestSessionRoundtrip(t *testing.T) {
	initSecret(t)

	s := &Session{
		Sub:      "user-123",
		Email:    "alice@example.com",
		Name:     "Alice",
		Groups:   []string{"admins", "users"},
		Provider: "local",
		Role:     "admin",
		Exp:      time.Now().Add(time.Hour).Unix(),
	}

	token, err := Encode(s)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if token == "" {
		t.Fatal("encoded token should not be empty")
	}

	got, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if got.Sub != s.Sub {
		t.Errorf("Sub = %q, want %q", got.Sub, s.Sub)
	}
	if got.Email != s.Email {
		t.Errorf("Email = %q, want %q", got.Email, s.Email)
	}
	if got.Name != s.Name {
		t.Errorf("Name = %q, want %q", got.Name, s.Name)
	}
	if got.Role != s.Role {
		t.Errorf("Role = %q, want %q", got.Role, s.Role)
	}
	if len(got.Groups) != len(s.Groups) {
		t.Errorf("Groups = %v, want %v", got.Groups, s.Groups)
	}
}

// ─── Decode error cases ───────────────────────────────────────────────────────

func TestDecode_MalformedNoDot(t *testing.T) {
	initSecret(t)
	_, err := Decode("nodothere")
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("expected malformed error, got %v", err)
	}
}

func TestDecode_InvalidSignature(t *testing.T) {
	initSecret(t)

	s := &Session{
		Sub: "user",
		Exp: time.Now().Add(time.Hour).Unix(),
	}
	token, _ := Encode(s)

	// Corrupt the signature part.
	dot := strings.LastIndex(token, ".")
	corrupted := token[:dot] + ".invalidsig"
	_, err := Decode(corrupted)
	if err == nil || !strings.Contains(err.Error(), "invalid signature") {
		t.Errorf("expected invalid signature error, got %v", err)
	}
}

func TestDecode_Expired(t *testing.T) {
	initSecret(t)

	s := &Session{
		Sub: "user",
		Exp: time.Now().Add(-time.Hour).Unix(), // expired 1 hour ago
	}
	token, _ := Encode(s)

	_, err := Decode(token)
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected expired error, got %v", err)
	}
}

func TestDecode_InvalidBase64(t *testing.T) {
	initSecret(t)

	// payload.sig where payload is not valid base64url.
	// Sign the garbage payload so the MAC check passes, then we get a base64 error.
	badPayload := "!!!notbase64!!!"
	token := badPayload + "." + MAC(badPayload)

	_, err := Decode(token)
	if err == nil {
		t.Error("expected error for invalid base64 payload")
	}
}

func TestDecode_Tampered(t *testing.T) {
	initSecret(t)

	s := &Session{Sub: "alice", Exp: time.Now().Add(time.Hour).Unix()}
	token, _ := Encode(s)

	// Tamper with the token (flip a byte in the middle).
	bs := []byte(token)
	if len(bs) > 10 {
		bs[10] ^= 0xFF
	}
	if _, err := Decode(string(bs)); err == nil {
		t.Error("tampered token should fail Decode")
	}
}

func TestDecode_Invalid(t *testing.T) {
	initSecret(t)
	if _, err := Decode("not.a.valid.token"); err == nil {
		t.Error("invalid token should fail Decode")
	}
	if _, err := Decode(""); err == nil {
		t.Error("empty token should fail Decode")
	}
}

// ─── Revocation list ──────────────────────────────────────────────────────────

func TestRevocationList_RevokeAndIsRevoked(t *testing.T) {
	rl := NewRevocationList()

	token := "sometoken"
	exp := time.Now().Add(time.Hour)

	if rl.IsRevoked(token) {
		t.Error("token should not be revoked before Revoke is called")
	}

	rl.Revoke(token, exp)

	if !rl.IsRevoked(token) {
		t.Error("token should be revoked after Revoke is called")
	}
}

func TestRevocationList_LazyEviction(t *testing.T) {
	rl := NewRevocationList()

	token := "expired-token"
	// Set expiry in the past so it evicts on next IsRevoked check.
	rl.Revoke(token, time.Now().Add(-time.Minute))

	// IsRevoked should evict and return false.
	if rl.IsRevoked(token) {
		t.Error("expired revocation entry should be evicted and return false")
	}

	// Entry should be gone from the map.
	rl.mu.Lock()
	_, exists := rl.tokens[token]
	rl.mu.Unlock()
	if exists {
		t.Error("evicted entry should not remain in the map")
	}
}

func TestRevocationList_UnknownToken(t *testing.T) {
	rl := NewRevocationList()
	if rl.IsRevoked("never-revoked-token") {
		t.Error("unknown token should not be revoked")
	}
}

func TestRevocationList_PastExpiryEvicts(t *testing.T) {
	rl := NewRevocationList()

	// Not revoked initially.
	if rl.IsRevoked("token1") {
		t.Error("token1 should not be revoked")
	}

	// Revoke with future expiry.
	rl.Revoke("token1", time.Now().Add(time.Hour))
	if !rl.IsRevoked("token1") {
		t.Error("token1 should be revoked")
	}

	// Revoke with past expiry — lazy eviction, should return false.
	rl.Revoke("token2", time.Now().Add(-time.Millisecond))
	if rl.IsRevoked("token2") {
		t.Error("expired revocation should be evicted and return false")
	}
}

func TestDecode_Revoked(t *testing.T) {
	initSecret(t)
	withFreshRevocationList(t)

	s := &Session{
		Sub: "victim",
		Exp: time.Now().Add(time.Hour).Unix(),
	}
	token, _ := Encode(s)

	// Revoke by extracting the b64 part.
	dot := strings.LastIndex(token, ".")
	b64part := token[:dot]
	Revoked.Revoke(b64part, time.Unix(s.Exp, 0))

	_, err := Decode(token)
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Errorf("expected revoked error, got %v", err)
	}
}

// ─── SetTTL clamping ──────────────────────────────────────────────────────────

func TestSetTTL_Clamping(t *testing.T) {
	// Save and restore original TTL.
	origTTL := TTL()
	defer SetTTL(origTTL)

	cases := []struct {
		input time.Duration
		want  time.Duration
	}{
		{time.Second, 15 * time.Minute},          // below min → clamped to 15min
		{15 * time.Minute, 15 * time.Minute},     // exactly min → unchanged
		{8 * time.Hour, 8 * time.Hour},           // normal value
		{7 * 24 * time.Hour, 7 * 24 * time.Hour}, // exactly max → unchanged
		{8 * 24 * time.Hour, 7 * 24 * time.Hour}, // above max → clamped to 7d
	}
	for _, c := range cases {
		SetTTL(c.input)
		got := TTL()
		if got != c.want {
			t.Errorf("SetTTL(%v): got %v, want %v", c.input, got, c.want)
		}
	}
}

// ─── MAC consistency ──────────────────────────────────────────────────────────

func TestMAC_Deterministic(t *testing.T) {
	initSecret(t)

	data := "test-payload"
	mac1 := MAC(data)
	mac2 := MAC(data)

	if mac1 != mac2 {
		t.Error("MAC should produce deterministic output for same input")
	}
	if mac1 == "" {
		t.Error("MAC should produce non-empty output")
	}
}

func TestMAC_DifferentInputs(t *testing.T) {
	initSecret(t)

	if MAC("aaa") == MAC("bbb") {
		t.Error("different inputs should produce different MACs")
	}
}

// ── Phase C5.1 — Session Jti tests ────────────────────────────────────────
//
// Pins the C5.1 contract:
//
//   • Every newly issued Session carries a 128-bit random Jti
//     (hex-encoded; 32 chars). Two same-second logins for the same
//     user produce DIFFERENT cookie values.
//   • Encode/decode round-trip preserves Jti.
//   • Legacy cookies (no jti field) decode cleanly with Jti="" and
//     remain revocable via the existing b64 token map.
//   • Jti is bound by the HMAC envelope; tampering with it without
//     resigning fails the signature check.
//
// (The "Jti not in Identity" half of the contract is pinned in package
// main — Identity is a main hub type.)

func TestJti_GenerateUnique(t *testing.T) {
	a := NewJti()
	b := NewJti()
	if a == b {
		t.Errorf("NewJti returned the same value twice: %q", a)
	}
	if want := 32; len(a) != want {
		t.Errorf("jti length = %d, want %d (16 bytes hex)", len(a), want)
	}
	// Must be lowercase hex.
	for _, c := range a {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("jti contains non-hex char %q in %q", c, a)
			break
		}
	}
}

func TestJti_UniqueAcrossEncodes(t *testing.T) {
	withFreshSigningKey(t)

	exp := time.Now().Add(time.Hour).Unix()
	makeCookie := func() string {
		s := &Session{Sub: "alice", Provider: "local", Role: "viewer", Exp: exp, Jti: NewJti()}
		v, err := Encode(s)
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		return v
	}
	a := makeCookie()
	b := makeCookie()
	if a == b {
		t.Errorf("two encodes for the same (sub, role, exp) tuple produced identical cookies — Jti not in payload?\n  got: %q", a)
	}
	// Sanity: both must decode and verify.
	if _, err := Decode(a); err != nil {
		t.Errorf("Decode(a): %v", err)
	}
	if _, err := Decode(b); err != nil {
		t.Errorf("Decode(b): %v", err)
	}
}

func TestJti_RoundTrip(t *testing.T) {
	withFreshSigningKey(t)

	want := NewJti()
	s := &Session{Sub: "bob", Provider: "local", Role: "admin", Exp: time.Now().Add(time.Hour).Unix(), Jti: want}
	cookie, err := Encode(s)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := Decode(cookie)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Jti != want {
		t.Errorf("round-trip Jti = %q, want %q", got.Jti, want)
	}
}

func TestJti_BackwardCompat_LegacyDecodes(t *testing.T) {
	withFreshSigningKey(t)

	cookie := craftLegacyCookie(t, "carol", "viewer", time.Now().Add(time.Hour).Unix())
	s, err := Decode(cookie)
	if err != nil {
		t.Fatalf("Decode(legacy cookie): %v", err)
	}
	if s.Jti != "" {
		t.Errorf("legacy cookie decoded with Jti = %q, want \"\" (field absent on wire)", s.Jti)
	}
	if s.Sub != "carol" || s.Role != "viewer" {
		t.Errorf("legacy cookie payload mismatch: %+v", s)
	}
}

func TestJti_BackwardCompat_LegacyRevoke(t *testing.T) {
	withFreshSigningKey(t)
	withFreshRevocationList(t)

	cookie := craftLegacyCookie(t, "dan", "viewer", time.Now().Add(time.Hour).Unix())
	// Sanity: it decodes before revocation.
	if _, err := Decode(cookie); err != nil {
		t.Fatalf("pre-revoke decode: %v", err)
	}

	b64 := cookie[:strings.LastIndex(cookie, ".")]
	Revoked.Revoke(b64, time.Now().Add(time.Hour))

	if _, err := Decode(cookie); err == nil {
		t.Errorf("post-revoke decode succeeded; expected \"session: revoked\"")
	} else if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("post-revoke error = %v, want contain \"revoked\"", err)
	}
}

func TestLoginLogoutLogin_NoRevocationCollision(t *testing.T) {
	withFreshSigningKey(t)
	withFreshRevocationList(t)

	exp := time.Now().Add(time.Hour).Unix()
	first := &Session{Sub: "eve", Provider: "local", Role: "viewer", Exp: exp, Jti: NewJti()}
	firstCookie, err := Encode(first)
	if err != nil {
		t.Fatalf("Encode first: %v", err)
	}
	// Logout-style revocation of the first cookie's b64.
	firstB64 := firstCookie[:strings.LastIndex(firstCookie, ".")]
	Revoked.Revoke(firstB64, time.Unix(exp, 0))

	// Second login in the same second — Jti must be different.
	second := &Session{Sub: "eve", Provider: "local", Role: "viewer", Exp: exp, Jti: NewJti()}
	if second.Jti == first.Jti {
		t.Fatalf("two NewJti calls returned the same value: %q", first.Jti)
	}
	secondCookie, err := Encode(second)
	if err != nil {
		t.Fatalf("Encode second: %v", err)
	}
	if secondCookie == firstCookie {
		t.Fatalf("second cookie equals revoked first cookie; C5.1 fix did not take effect")
	}
	if _, err := Decode(secondCookie); err != nil {
		t.Errorf("second cookie decode: %v (must NOT be \"session: revoked\")", err)
	}
}

func TestJti_TamperingFailsMAC(t *testing.T) {
	withFreshSigningKey(t)

	s := &Session{Sub: "grace", Provider: "local", Role: "viewer", Exp: time.Now().Add(time.Hour).Unix(), Jti: NewJti()}
	cookie, err := Encode(s)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	dot := strings.LastIndex(cookie, ".")
	b64, sig := cookie[:dot], cookie[dot+1:]

	// Decode the b64 payload, mutate Jti to a different valid value,
	// re-encode without recomputing the MAC.
	payload, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	var mut Session
	if err := json.Unmarshal(payload, &mut); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	mut.Jti = NewJti() // attacker-controlled new Jti
	mutPayload, err := json.Marshal(&mut)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	tampered := base64.RawURLEncoding.EncodeToString(mutPayload) + "." + sig

	if _, err := Decode(tampered); err == nil {
		t.Errorf("tampered cookie decoded successfully; Jti not bound by MAC")
	} else if !strings.Contains(err.Error(), "invalid signature") {
		t.Errorf("tampered cookie error = %v, want \"invalid signature\"", err)
	}
}

// ── Revocation export/merge (moved from distributed_rl_test.go) ────────────

func TestExportRevocations_FiltersExpired(t *testing.T) {
	rl := NewRevocationList()
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
	rl := NewRevocationList()
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

// ── Revocation persistence (moved from controlplane_extra_test.go) ─────────

// withRevocationsPath points persistence at p for the duration of t.
func withRevocationsPath(t *testing.T, p string) {
	t.Helper()
	orig := RevocationsPath()
	SetRevocationsPath(p)
	t.Cleanup(func() { SetRevocationsPath(orig) })
}

func TestRevocationList_SaveAndLoad(t *testing.T) {
	withRevocationsPath(t, filepath.Join(t.TempDir(), "revocations.json"))

	rl := NewRevocationList()
	rl.Revoke("token-1", time.Now().Add(time.Hour))
	rl.Revoke("token-2", time.Now().Add(2*time.Hour))

	if err := rl.SaveRevocations(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Load into fresh list.
	rl2 := NewRevocationList()
	if err := rl2.LoadRevocations(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if !rl2.IsRevoked("token-1") {
		t.Fatal("token-1 should be revoked after load")
	}
	if !rl2.IsRevoked("token-2") {
		t.Fatal("token-2 should be revoked after load")
	}
}

func TestRevocationList_SaveEmptyPath(t *testing.T) {
	withRevocationsPath(t, "")

	rl := NewRevocationList()
	if err := rl.SaveRevocations(); err != nil {
		t.Fatalf("save with empty path should be no-op: %v", err)
	}
}

func TestRevocationList_LoadEmptyPath(t *testing.T) {
	withRevocationsPath(t, "")

	rl := NewRevocationList()
	if err := rl.LoadRevocations(); err != nil {
		t.Fatalf("load with empty path should be no-op: %v", err)
	}
}

func TestRevocationList_LoadMissingFile(t *testing.T) {
	withRevocationsPath(t, "/nonexistent/revocations.json")

	rl := NewRevocationList()
	if err := rl.LoadRevocations(); err != nil {
		t.Fatalf("load of missing file should succeed (no-op): %v", err)
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────

// craftLegacyCookie builds a session cookie that lacks the jti field
// entirely (mimicking pre-C5.1 cookies). Bypasses Encode to avoid the
// omitempty/empty-string ambiguity — we want the field SHAPE to differ,
// i.e. the JSON to literally lack a "jti" key.
func craftLegacyCookie(t *testing.T, sub, role string, exp int64) string {
	t.Helper()
	// legacySession mirrors the pre-C5.1 Session shape — no Jti
	// field at all. JSON-marshaling this struct produces output
	// indistinguishable from a Session minted before C5.1.
	type legacySession struct {
		Sub      string   `json:"sub"`
		Email    string   `json:"email"`
		Name     string   `json:"name"`
		Groups   []string `json:"grp,omitempty"`
		Provider string   `json:"pvd"`
		Role     string   `json:"role,omitempty"`
		Exp      int64    `json:"exp"`
	}
	payload, err := json.Marshal(&legacySession{Sub: sub, Provider: "local", Role: role, Exp: exp})
	if err != nil {
		t.Fatalf("marshal legacy session: %v", err)
	}
	if strings.Contains(string(payload), `"jti"`) {
		t.Fatalf("legacy payload unexpectedly contains jti: %s", string(payload))
	}
	b64 := base64.RawURLEncoding.EncodeToString(payload)
	return b64 + "." + MAC(b64)
}
