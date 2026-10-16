package alerts

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// SEC-SECRETWRITE-1 — the node-local webhook KEK unwraps every stored webhook
// HMAC secret (RISK-003). webhookSecretKey mints only on the encrypt path and
// only when the read answered fs.ErrNotExist; a DANGLING SYMLINK at the key
// path produces that same answer, so the mint must not follow it. Verified
// failing against the pre-fix os.WriteFile shape.
func TestWebhookSecretKey_MintDoesNotFollowAPlantedSymlink(t *testing.T) {
	clearWebhookKeyCacheForTest()
	t.Cleanup(clearWebhookKeyCacheForTest)

	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "attacker-chosen")
	path := filepath.Join(dir, webhookKeyFileName)
	if err := os.Symlink(outside, path); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}
	if _, err := os.ReadFile(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dangling symlink should read as ErrNotExist, got %v", err)
	}

	key, err := webhookSecretKey(dir, true)
	if err != nil {
		t.Fatalf("webhookSecretKey mint: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
	if _, err := os.Lstat(outside); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the webhook KEK escaped the data directory to %s", outside)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat key: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("key path is still a symlink — the KEK was written through it")
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("KEK mode = %v, want 0600", perm)
	}

	// The operator's documented recovery ("restore the original key file")
	// depends on the key actually being AT this path and re-readable.
	clearWebhookKeyCacheForTest()
	again, err := webhookSecretKey(dir, false)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(key, again) {
		t.Fatal("the minted key did not survive at the key path")
	}
}

// CONTROL: SEC-WHSIGN-1's rule is unchanged — the READ path never mints, so a
// failed decrypt still cannot create a second key generation behind the
// operator's back.
func TestWebhookSecretKey_ReadPathStillNeverMints(t *testing.T) {
	clearWebhookKeyCacheForTest()
	t.Cleanup(clearWebhookKeyCacheForTest)

	dir := t.TempDir()
	if _, err := webhookSecretKey(dir, false); err == nil {
		t.Fatal("read path on an empty dir must fail, not mint")
	}
	if _, err := os.Stat(filepath.Join(dir, webhookKeyFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the read path created a key file: %v", err)
	}
}

// A wrong-length key file is refused rather than overwritten, and no temp
// artifact survives a successful mint.
func TestWebhookSecretKey_RefusesShortKeyAndLeavesNoTempArtifact(t *testing.T) {
	clearWebhookKeyCacheForTest()
	t.Cleanup(clearWebhookKeyCacheForTest)

	short := t.TempDir()
	if err := os.WriteFile(filepath.Join(short, webhookKeyFileName), make([]byte, 16), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := webhookSecretKey(short, true); err == nil {
		t.Fatal("expected a refusal for a wrong-length key file")
	}

	clean := t.TempDir()
	if _, err := webhookSecretKey(clean, true); err != nil {
		t.Fatalf("mint: %v", err)
	}
	entries, err := os.ReadDir(clean)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != webhookKeyFileName {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected only %s, got %v", webhookKeyFileName, names)
	}
}
