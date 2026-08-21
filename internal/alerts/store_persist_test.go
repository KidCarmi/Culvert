package alerts

// store_persist_test.go — RISK-017 closure coverage: the webhook store's
// save path is live in production for the first time (Init is now wired in
// the persistent-admin-state startup slice), so pin the durability
// properties: file exists with mode 0600, no atomic-writer tmp leftovers,
// and a restart (fresh Store + Init on the same path) restores the webhook.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStore_Persist_RestartRoundTripAndDurability(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alert_webhooks.json")

	as := &Store{}
	as.Init(path)
	created := as.Add(Webhook{
		Name:    "persist-hook",
		URL:     "https://example.invalid/hook",
		Events:  []string{"threat_detected"},
		Enabled: true,
		Secret:  "persist-secret",
	})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("store file missing after Add: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("store file mode = %o, want 0600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("orphaned tmp file: %s", e.Name())
		}
	}

	// Restart: a fresh store on the same path restores the webhook with its
	// decrypted secret (the RISK-017 pre-fix behavior was an empty store).
	as2 := &Store{}
	as2.Init(path)
	got, ok := as2.GetByID(created.ID)
	if !ok {
		t.Fatal("webhook did not survive restart — RISK-017 regressed")
	}
	if got.Secret != "persist-secret" {
		t.Errorf("restored secret = %q, want persist-secret", got.Secret)
	}
	if got.Name != "persist-hook" || !got.Enabled {
		t.Errorf("restored webhook mismatch: %+v", got)
	}
}

// TestStore_Init_MigratesLegacyEventNames pins the CHAOS-47 rename
// (idp_unreachable -> identity_backend_unreachable): a webhook persisted
// under the retired name before the rename must keep firing under the new
// name after an upgrade, not silently lose its subscription.
func TestStore_Init_MigratesLegacyEventNames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alert_webhooks.json")

	legacy := `[{"id":"1","name":"pre-rename-hook","url":"https://example.invalid/hook",` +
		`"events":["threat_detected","idp_unreachable"],"enabled":true}]`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatalf("seed legacy store file: %v", err)
	}

	as := &Store{}
	as.Init(path)

	if !as.HasSubscriber("identity_backend_unreachable") {
		t.Error("webhook persisted under the retired idp_unreachable name did not migrate to identity_backend_unreachable")
	}
	if as.HasSubscriber("idp_unreachable") {
		t.Error("HasSubscriber still matches the retired event name after migration")
	}
	if !as.HasSubscriber("threat_detected") {
		t.Error("migration must not disturb an unrelated, already-current event name")
	}
}
