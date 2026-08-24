package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SEC-WHSIGN-1 — the appliance-side half of the webhook signing-degradation
// surface. The engine mechanics (ciphertext preservation, the derived status)
// are pinned in internal/alerts/webhook_signing_degraded_test.go; these tests
// pin what an OPERATOR can see, and that the node-local signing key can never
// travel in a backup.

// seedRestoredWebhookStore reproduces the reachable production path: a store
// whose alert_webhooks.json was restored from a backup onto a volume that has
// no .alert_webhook_key, so its secrets cannot be decrypted.
func seedRestoredWebhookStore(t *testing.T) *AlertStore {
	t.Helper()

	origDir := t.TempDir()
	origPath := filepath.Join(origDir, "alert_webhooks.json")
	src := &AlertStore{}
	src.Init(origPath)
	src.Add(AlertWebhook{
		Name:    "siem",
		URL:     "https://siem.example.com/hook",
		Events:  []string{"threat_detected"},
		Enabled: true,
		Secret:  "hmac-signing-key",
	})

	body, err := os.ReadFile(origPath) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("read seeded store: %v", err)
	}
	restoredPath := filepath.Join(t.TempDir(), "alert_webhooks.json")
	if err := os.WriteFile(restoredPath, body, 0o600); err != nil {
		t.Fatalf("write restored store: %v", err)
	}
	restored := &AlertStore{}
	restored.Init(restoredPath)
	if restored.SigningDegradedCount() != 1 {
		t.Fatalf("fixture did not reach the degraded state (count=%d)", restored.SigningDegradedCount())
	}
	return restored
}

func withAlertStore(t *testing.T, as *AlertStore) {
	t.Helper()
	orig := globalAlertStore
	t.Cleanup(func() { globalAlertStore = orig })
	globalAlertStore = as
}

// TestDiagnostics_AlertWebhookSigningRow_OKWhenHealthy is the negative control:
// a node whose webhook secrets decrypt reports nothing to act on.
func TestDiagnostics_AlertWebhookSigningRow_OKWhenHealthy(t *testing.T) {
	as := &AlertStore{}
	as.Init(filepath.Join(t.TempDir(), "alert_webhooks.json"))
	as.Add(AlertWebhook{Name: "ok", URL: "https://ok.example.com/h", Enabled: true, Secret: "k"})
	withAlertStore(t, as)

	ck := checkAlertWebhookSigning()
	if ck.Code != "alert_webhook_signing" {
		t.Fatalf("code = %q", ck.Code)
	}
	if ck.Status != diagOK {
		t.Errorf("status = %q, want %q (message: %s)", ck.Status, diagOK, ck.Message)
	}
	if ck.OperatorAction != "" {
		t.Errorf("healthy row carries an operator action: %q", ck.OperatorAction)
	}
}

// TestDiagnostics_AlertWebhookSigningRow_WarnsWhenDegraded: the state that used
// to be a single boot-time log line now reaches the operator contract.
func TestDiagnostics_AlertWebhookSigningRow_WarnsWhenDegraded(t *testing.T) {
	withAlertStore(t, seedRestoredWebhookStore(t))

	ck := checkAlertWebhookSigning()
	if ck.Status != diagWarn {
		t.Fatalf("status = %q, want %q", ck.Status, diagWarn)
	}
	if !strings.Contains(ck.Message, "UNSIGNED") {
		t.Errorf("message does not say deliveries are unsigned: %q", ck.Message)
	}
	if ck.OperatorAction == "" {
		t.Error("degraded row carries no operator action")
	}
	// VIEWER-role surface: counts only. No webhook name, URL or secret material.
	for _, forbidden := range []string{"siem", "siem.example.com", "hmac-signing-key", "enc:v1:"} {
		if strings.Contains(ck.Message+ck.OperatorAction, forbidden) {
			t.Errorf("row leaked %q into a viewer-role surface: %q / %q", forbidden, ck.Message, ck.OperatorAction)
		}
	}
}

// TestDiagnostics_AlertWebhookSigningRow_InDefaultReport pins the row into the
// operator contract, so it cannot be dropped silently.
func TestDiagnostics_AlertWebhookSigningRow_InDefaultReport(t *testing.T) {
	withAlertStore(t, seedRestoredWebhookStore(t))

	c := buildOperatorContract()
	for i := range c.Checks {
		if c.Checks[i].Code == "alert_webhook_signing" {
			if c.Checks[i].Status != diagWarn {
				t.Errorf("status = %q, want %q", c.Checks[i].Status, diagWarn)
			}
			return
		}
	}
	t.Fatal("alert_webhook_signing row missing from the default operator contract")
}

// TestAlertWebhookList_ExposesSigningDegradedWithoutSecrets: the admin API's
// list is the surface the GUI badges off. It must carry the status and nothing
// else — the secret stays redacted, in both states.
func TestAlertWebhookList_ExposesSigningDegradedWithoutSecrets(t *testing.T) {
	as := seedRestoredWebhookStore(t)
	as.Add(AlertWebhook{Name: "healthy", URL: "https://healthy.example.com/h", Enabled: true, Secret: "fresh-key"})

	blob, err := json.Marshal(map[string]any{"webhooks": as.List()})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(blob)
	if !strings.Contains(body, `"signing_degraded":true`) {
		t.Errorf("list response does not surface signing_degraded: %s", body)
	}
	if strings.Count(body, `"signing_degraded":true`) != 1 {
		t.Errorf("healthy webhook was also flagged: %s", body)
	}
	for _, forbidden := range []string{"hmac-signing-key", "fresh-key", "enc:v1:"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("list response leaked %q: %s", forbidden, body)
		}
	}
}

// TestBackup_NeverPacksTheWebhookSigningKey: alert_webhooks.json is archived and
// its secrets are ciphertext, so the key that unwraps them must never share the
// archive — the same ADR §9 rule that excludes .kek files. Defense-in-depth
// against a future dataDir walk, pinned here because the named artifact list is
// not the only way a file can reach packOne.
func TestBackup_NeverPacksTheWebhookSigningKey(t *testing.T) {
	dataDir := t.TempDir()
	seedFile(t, dataDir, "ui_users.json", []byte(`{}`), 0o600)
	seedFile(t, dataDir, "alert_webhooks.json", []byte(`[{"id":"1","name":"siem","url":"https://siem.example.com/h","enabled":true,"secret":"enc:v1:AAAA"}]`), 0o600)
	seedFile(t, dataDir, ".alert_webhook_key", []byte(strings.Repeat("k", 32)), 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, dataDir); err != nil {
		t.Fatalf("runBackup: %v", err)
	}
	_, files, _ := readBackupTarball(t, out)
	if _, ok := files["data/alert_webhooks.json"]; !ok {
		t.Fatalf("alert_webhooks.json missing from the archive: %v", sortedNames(files))
	}
	for name, body := range files {
		if strings.HasSuffix(name, webhookSigningKeyFileName) {
			t.Errorf("backup packed the webhook signing key at %q", name)
		}
		if strings.Contains(string(body), strings.Repeat("k", 32)) && name != "backup-manifest.json" {
			t.Errorf("backup entry %q carries the webhook signing key material", name)
		}
	}
}

// TestIsNodeLocalKeyArtifactPath: the exclusion recognises both classes of
// node-local key material and nothing else.
func TestIsNodeLocalKeyArtifactPath(t *testing.T) {
	excluded := []string{
		"data/cluster-ca.kek",
		"data/dp-node.kek",
		"data/.alert_webhook_key",
		".alert_webhook_key",
		"/data/config_versions/.alert_webhook_key",
	}
	kept := []string{
		"data/alert_webhooks.json",
		"data/cluster-ca.key",
		"data/ca.bundle",
		"data/alert_webhook_key.json",
		"data/.alert_webhook_key.bak",
	}
	for _, p := range excluded {
		if !isNodeLocalKeyArtifactPath(p) {
			t.Errorf("isNodeLocalKeyArtifactPath(%q) = false, want true", p)
		}
	}
	for _, p := range kept {
		if isNodeLocalKeyArtifactPath(p) {
			t.Errorf("isNodeLocalKeyArtifactPath(%q) = true, want false", p)
		}
	}
}
