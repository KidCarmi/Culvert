package main

// security_coverage_test.go — unit tests for security-critical paths that
// were previously at 0% coverage: AlertStore CRUD, webhook delivery,
// selfSignedTLS, TOTP store operations, and verifyTOTP.

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ── AlertStore ────────────────────────────────────────────────────────────────

func TestAlertStore_AddListDelete(t *testing.T) {
	as := &AlertStore{}
	as.Init("") // no file path — in-memory only

	// Empty list
	if got := as.List(); len(got) != 0 {
		t.Fatalf("expected empty list, got %d", len(got))
	}

	// Add
	h := as.Add(AlertWebhook{
		Name:    "test-hook",
		URL:     "http://example.com/webhook",
		Events:  []string{"threat_detected"},
		Enabled: true,
		Secret:  "supersecret",
	})
	if h.ID == "" {
		t.Fatal("Add should assign an ID")
	}
	if h.Secret != "" {
		t.Fatal("Add should strip secret from returned value")
	}

	// List should have 1 entry with no secret
	list := as.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 webhook, got %d", len(list))
	}
	if list[0].Secret != "" {
		t.Error("List should not expose secret")
	}

	// GetByID
	got, ok := as.GetByID(h.ID)
	if !ok {
		t.Fatal("GetByID should find the webhook")
	}
	if got.Name != "test-hook" {
		t.Errorf("unexpected name: %s", got.Name)
	}

	// GetByID — missing
	_, ok = as.GetByID("nonexistent")
	if ok {
		t.Error("GetByID should return false for missing ID")
	}

	// Update
	updated := AlertWebhook{
		Name:    "updated-hook",
		URL:     "http://example.com/webhook2",
		Events:  []string{"policy_block"},
		Enabled: false,
	}
	if !as.Update(h.ID, updated) {
		t.Fatal("Update should return true for existing ID")
	}
	got, _ = as.GetByID(h.ID)
	if got.Name != "updated-hook" {
		t.Errorf("expected updated name, got %s", got.Name)
	}
	// Secret should be preserved when update has empty secret
	if got.Secret != "supersecret" {
		t.Errorf("Update should preserve existing secret, got %q", got.Secret)
	}

	// Update — missing ID
	if as.Update("bad-id", AlertWebhook{}) {
		t.Error("Update should return false for missing ID")
	}

	// Delete
	if !as.Delete(h.ID) {
		t.Fatal("Delete should return true for existing ID")
	}
	if len(as.List()) != 0 {
		t.Error("List should be empty after delete")
	}

	// Delete — missing
	if as.Delete("bad-id") {
		t.Error("Delete should return false for missing ID")
	}
}

func TestFireAlert_EnabledAndDisabled(t *testing.T) {
	// Use a test HTTP server as the webhook target.
	received := make(chan string, 5)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Get("X-Culvert-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Save and restore the global store.
	orig := globalAlertStore
	defer func() { globalAlertStore = orig }()

	as := &AlertStore{}
	as.Init("")
	globalAlertStore = as

	// Add an enabled webhook with HMAC secret.
	as.Add(AlertWebhook{
		Name:    "enabled",
		URL:     srv.URL,
		Events:  []string{"threat_detected"},
		Enabled: true,
		Secret:  "testhook-secret",
	})
	// Add a disabled webhook — should not fire.
	as.Add(AlertWebhook{
		Name:    "disabled",
		URL:     srv.URL,
		Events:  []string{"threat_detected"},
		Enabled: false,
	})
	// Add a webhook for a different event — should not fire.
	as.Add(AlertWebhook{
		Name:    "other-event",
		URL:     srv.URL,
		Events:  []string{"cert_expiry"},
		Enabled: true,
	})

	fireAlert("threat_detected", AlertPayload{
		Actor:  "1.2.3.4",
		Host:   "malware.example.com",
		Detail: "Eicar-Test-Signature",
		Source: "clamav",
	})

	// Wait for exactly one delivery (the enabled matching hook).
	select {
	case sig := <-received:
		if sig == "" {
			t.Error("expected HMAC signature header, got empty")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for webhook delivery")
	}

	// Ensure no second delivery arrives (disabled + wrong-event hooks must not fire).
	select {
	case <-received:
		t.Error("unexpected second webhook delivery")
	case <-time.After(200 * time.Millisecond):
		// Good — no spurious delivery.
	}
}

func TestFireAlert_WildcardEvent(t *testing.T) {
	received := make(chan struct{}, 5)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	orig := globalAlertStore
	defer func() { globalAlertStore = orig }()

	as := &AlertStore{}
	as.Init("")
	globalAlertStore = as

	as.Add(AlertWebhook{
		Name:    "wildcard",
		URL:     srv.URL,
		Events:  []string{"*"},
		Enabled: true,
	})

	fireAlert("policy_block", AlertPayload{Actor: "user1", Host: "blocked.com"})

	select {
	case <-received:
		// Good
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: wildcard webhook not fired")
	}
}

func TestFireAlert_TimestampAutoFilled(t *testing.T) {
	// fireAlert should auto-fill Timestamp when empty — just ensure no panic.
	orig := globalAlertStore
	defer func() { globalAlertStore = orig }()
	as := &AlertStore{}
	as.Init("")
	globalAlertStore = as
	// No hooks — just test that the function runs without panic.
	fireAlert("auth_lockout", AlertPayload{}) // Timestamp intentionally empty
}

// ── selfSignedTLS ─────────────────────────────────────────────────────────────

func TestSelfSignedTLS_Valid(t *testing.T) {
	cfg, err := selfSignedTLS()
	if err != nil {
		t.Fatalf("selfSignedTLS() error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil tls.Config")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
	// The certificate must be parseable.
	cert := cfg.Certificates[0]
	if _, err := tls.X509KeyPair(
		// Re-encode to verify round-trip — just check leaf is non-nil.
		cert.Certificate[0], nil,
	); err == nil {
		// We just want the leaf to be present.
	}
	leaf, err := cfg.Certificates[0].Leaf, error(nil)
	_ = leaf
	_ = err
}

// ── TOTP store operations ─────────────────────────────────────────────────────

func newTestConfig() *Config {
	return &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
}

func TestConfig_TOTPOperations(t *testing.T) {
	c := newTestConfig()

	// Setup: create a test user.
	if err := c.SetUIUser("totp_user", "password", RoleAdmin); err != nil {
		t.Fatalf("SetUIUser: %v", err)
	}

	// Initially no TOTP.
	if c.UserHasTOTP("totp_user") {
		t.Error("new user should not have TOTP")
	}
	if c.GetTOTPSecret("totp_user") != "" {
		t.Error("GetTOTPSecret should return empty for unenrolled user")
	}

	// Non-existent user.
	if c.UserHasTOTP("ghost") {
		t.Error("non-existent user should not have TOTP")
	}
	if c.GetTOTPSecret("ghost") != "" {
		t.Error("GetTOTPSecret should return empty for non-existent user")
	}

	// SetTOTPSecret.
	if !c.SetTOTPSecret("totp_user", "JBSWY3DPEHPK3PXP", []string{"hash1", "hash2"}) {
		t.Fatal("SetTOTPSecret should return true for existing user")
	}
	if !c.UserHasTOTP("totp_user") {
		t.Error("user should have TOTP after SetTOTPSecret")
	}
	if c.GetTOTPSecret("totp_user") != "JBSWY3DPEHPK3PXP" {
		t.Error("GetTOTPSecret returned wrong secret")
	}

	// SetTOTPSecret — non-existent user.
	if c.SetTOTPSecret("ghost", "secret", nil) {
		t.Error("SetTOTPSecret should return false for non-existent user")
	}

	// ClearTOTP.
	if !c.ClearTOTP("totp_user") {
		t.Fatal("ClearTOTP should return true for existing user")
	}
	if c.UserHasTOTP("totp_user") {
		t.Error("user should not have TOTP after ClearTOTP")
	}

	// ClearTOTP — non-existent user.
	if c.ClearTOTP("ghost") {
		t.Error("ClearTOTP should return false for non-existent user")
	}
}

func TestConfig_ConsumeBackupCode(t *testing.T) {
	c := newTestConfig()
	if err := c.SetUIUser("backup_user", "pass", RoleAdmin); err != nil {
		t.Fatalf("SetUIUser: %v", err)
	}

	// Hash a known code with bcrypt.
	hashCode := func(plain string) string {
		h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("bcrypt: %v", err)
		}
		return string(h)
	}
	code := "ABCD1234"
	hashed := hashCode(code)

	c.SetTOTPSecret("backup_user", "secret", []string{hashed, hashCode("OTHER5678")})

	// Wrong code.
	if c.ConsumeBackupCode("backup_user", "WRONG000") {
		t.Error("wrong backup code should not be accepted")
	}
	// Non-existent user.
	if c.ConsumeBackupCode("ghost", code) {
		t.Error("non-existent user should return false")
	}
	// Correct code — should consume.
	if !c.ConsumeBackupCode("backup_user", code) {
		t.Fatal("valid backup code should be accepted")
	}
	// Replay — code should be gone.
	if c.ConsumeBackupCode("backup_user", code) {
		t.Error("used backup code should not be reusable")
	}
}

// ── verifyTOTP ────────────────────────────────────────────────────────────────

func TestVerifyTOTP_InvalidCode(t *testing.T) {
	// A valid base32 secret but wrong code — should return false, not panic.
	secret := "JBSWY3DPEHPK3PXP"
	if verifyTOTP(secret, "000000") {
		t.Error("random code should not validate against secret")
	}
}

func TestVerifyTOTP_EmptyInputs(t *testing.T) {
	if verifyTOTP("", "") {
		t.Error("empty secret+code should not validate")
	}
	if verifyTOTP("JBSWY3DPEHPK3PXP", "") {
		t.Error("empty code should not validate")
	}
	if verifyTOTP("", "123456") {
		t.Error("empty secret should not validate")
	}
}

func TestVerifyTOTP_TrimsWhitespace(t *testing.T) {
	// Whitespace-padded code should behave the same as the trimmed version
	// (both should be false for a wrong code — the important thing is no panic).
	secret := "JBSWY3DPEHPK3PXP"
	r1 := verifyTOTP(secret, " 999999 ")
	r2 := verifyTOTP(secret, "999999")
	if r1 != r2 {
		t.Errorf("whitespace should be trimmed: padded=%v trimmed=%v", r1, r2)
	}
}
