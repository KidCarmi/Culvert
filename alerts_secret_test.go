package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWebhookSecret_EncryptDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()

	enc, err := encryptWebhookSecret("supersecret", dir)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !strings.HasPrefix(enc, webhookSecretEncPrefix) {
		t.Errorf("encrypted value missing prefix: %q", enc)
	}
	if strings.Contains(enc, "supersecret") {
		t.Error("ciphertext should not contain the cleartext")
	}
	got, err := decryptWebhookSecret(enc, dir)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != "supersecret" {
		t.Errorf("round-trip = %q, want supersecret", got)
	}

	// Empty stays empty; legacy cleartext (no prefix) passes through.
	if v, _ := encryptWebhookSecret("", dir); v != "" {
		t.Errorf("encrypt(\"\") = %q, want empty", v)
	}
	if v, _ := decryptWebhookSecret("legacy-plain", dir); v != "legacy-plain" {
		t.Errorf("decrypt(legacy) = %q, want passthrough", v)
	}
}

func TestWebhookSecret_EncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alert_webhooks.json")

	as := &AlertStore{}
	as.Init(path) // file does not exist yet → in-memory, path set
	h := as.Add(AlertWebhook{
		Name:    "hook",
		URL:     "https://example.invalid/hook",
		Events:  []string{"*"},
		Enabled: true,
		Secret:  "supersecret-hmac-key",
	})

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read store file: %v", err)
	}
	if bytes.Contains(raw, []byte("supersecret-hmac-key")) {
		t.Error("RISK-003: cleartext secret found in alert_webhooks.json")
	}
	if !bytes.Contains(raw, []byte(webhookSecretEncPrefix)) {
		t.Errorf("expected encrypted-secret marker in store file:\n%s", raw)
	}
	// The key lives in a separate hidden file, not the store JSON.
	if _, err := os.Stat(filepath.Join(dir, webhookKeyFileName)); err != nil {
		t.Errorf("expected webhook key file: %v", err)
	}

	// A fresh store reading the same file decrypts back to cleartext for signing.
	as2 := &AlertStore{}
	as2.Init(path)
	got, ok := as2.GetByID(h.ID)
	if !ok {
		t.Fatal("webhook not found after reload")
	}
	if got.Secret != "supersecret-hmac-key" {
		t.Errorf("decrypted secret = %q, want supersecret-hmac-key", got.Secret)
	}
}

func TestWebhookSecret_LegacyCleartextMigratedOnSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alert_webhooks.json")

	// Simulate a pre-RISK-003 store file with a cleartext secret.
	legacy := `[{"id":"1","name":"old","url":"https://x.invalid","events":["*"],"enabled":true,"secret":"legacy-cleartext"}]`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	as := &AlertStore{}
	as.Init(path)
	got, ok := as.GetByID("1")
	if !ok || got.Secret != "legacy-cleartext" {
		t.Fatalf("legacy cleartext secret should load unchanged, got ok=%v secret=%q", ok, got.Secret)
	}

	// Any mutation triggers save(), which re-encrypts the whole set.
	as.Add(AlertWebhook{Name: "new", Secret: "another"})

	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("legacy-cleartext")) {
		t.Error("legacy secret still cleartext on disk after re-save")
	}
	if bytes.Contains(raw, []byte("another")) {
		t.Error("new secret written cleartext on disk")
	}
}
