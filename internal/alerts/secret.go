package alerts

// secret.go — encryption-at-rest for webhook HMAC signing secrets
// (RISK-003, moved from package main per ADR-0002). Webhook.Secret is the HMAC-SHA256 signing key; persisting it
// as cleartext in alert_webhooks.json let a file read or a copied data dir forge
// signed alert payloads. Secrets are now AES-256-GCM encrypted on disk under a
// per-data-dir key file; the in-memory value stays cleartext so signing works.
//
// Key handling: a random 32-byte key is generated on first use and stored as a
// 0600 hidden file next to the alert store (`.alert_webhook_key`). It is NOT in
// alert_webhooks.json (so reading that file alone cannot decrypt) and NOT part
// of a config export (which already redacts secrets via AlertStore.List).
//
// Threat model: protects against reading the webhook JSON file or an exported
// config bundle. It does not protect against an attacker who can read the whole
// data dir including the hidden key file — that is inherent to local-key
// encryption-at-rest and a far higher bar than cleartext in a 0600 JSON file.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// webhookSecretEncPrefix tags an encrypted secret on disk so legacy cleartext
// (no prefix) is distinguishable and migrated transparently on the next save.
const webhookSecretEncPrefix = "enc:v1:"

const webhookKeyFileName = ".alert_webhook_key"

var (
	webhookKeyMu    sync.Mutex
	webhookKeyCache = map[string][]byte{} // keyPath → 32-byte AES key
)

// webhookSecretKey loads (or creates) the AES-256 key in dir used to encrypt
// webhook secrets at rest. The key is cached per path.
func webhookSecretKey(dir string) ([]byte, error) {
	keyPath := filepath.Join(dir, webhookKeyFileName)

	webhookKeyMu.Lock()
	defer webhookKeyMu.Unlock()
	if k, ok := webhookKeyCache[keyPath]; ok {
		return k, nil
	}
	if data, err := os.ReadFile(keyPath); err == nil { // #nosec G304 -- derived from the operator-configured store path
		if len(data) != 32 {
			return nil, fmt.Errorf("webhook key %s: unexpected length %d (want 32)", filepath.Base(keyPath), len(data))
		}
		webhookKeyCache[keyPath] = data
		return data, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read webhook key: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate webhook key: %w", err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil { // #nosec G306 -- 0600 is intentional for a secret key
		return nil, fmt.Errorf("write webhook key: %w", err)
	}
	webhookKeyCache[keyPath] = key
	return key, nil
}

// encryptWebhookSecret encrypts a cleartext HMAC secret for on-disk storage.
// Empty stays empty. Output is webhookSecretEncPrefix + base64(nonce||ciphertext).
func encryptWebhookSecret(plaintext, dir string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	// Already encrypted (defensive — callers pass the in-memory cleartext).
	if strings.HasPrefix(plaintext, webhookSecretEncPrefix) {
		return plaintext, nil
	}
	gcm, err := webhookGCM(dir)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return webhookSecretEncPrefix + base64.StdEncoding.EncodeToString(ct), nil
}

// decryptWebhookSecret reverses encryptWebhookSecret. A value without the
// encryption prefix is legacy cleartext, returned unchanged (migrated to
// ciphertext on the next save).
func decryptWebhookSecret(stored, dir string) (string, error) {
	if stored == "" || !strings.HasPrefix(stored, webhookSecretEncPrefix) {
		return stored, nil // empty or legacy cleartext
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, webhookSecretEncPrefix))
	if err != nil {
		return "", fmt.Errorf("decode webhook secret: %w", err)
	}
	gcm, err := webhookGCM(dir)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("webhook secret ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt webhook secret: %w", err)
	}
	return string(pt), nil
}

// webhookGCM builds an AES-GCM cipher from the per-dir webhook key.
func webhookGCM(dir string) (cipher.AEAD, error) {
	key, err := webhookSecretKey(dir)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
