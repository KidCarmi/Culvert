package alerts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Webhook signing-secret degradation (SEC-WHSIGN-1).
//
// A webhook's HMAC secret is AES-GCM encrypted at rest under a NODE-LOCAL key
// file (.alert_webhook_key) that is deliberately never archived: shipping it in
// the same tarball as the ciphertext it unwraps would defeat encryption at rest
// (the same rule that excludes .kek files). alert_webhooks.json IS archived, so
// restoring a backup onto a fresh volume is the reachable way to end up holding
// a secret that cannot be unwrapped.
//
// Two properties are pinned here, and both are security properties:
//
//  1. The undecryptable ciphertext SURVIVES. It used to be blanked in memory and
//     then written back as "" by the next save of ANY webhook (save rewrites the
//     whole list), so an unrelated admin edit permanently destroyed key material
//     that restoring the key file would otherwise have recovered.
//
//  2. The state is VISIBLE. Secret is redacted in List, so "no secret was ever
//     configured" and "the secret is unusable and deliveries are now UNSIGNED"
//     rendered identically in the admin UI. A receiver that verifies the HMAC
//     silently stops trusting this node's alerts; the operator had one log line
//     at boot as the only signal.

// seedEncryptedStore writes one webhook with an encrypted secret and returns the
// directory holding both alert_webhooks.json and its key file.
func seedEncryptedStore(t *testing.T, secret string) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "alert_webhooks.json")
	src := &Store{}
	src.Init(path)
	src.Add(Webhook{
		Name:    "siem",
		URL:     "https://siem.example.com/hook",
		Events:  []string{"threat_detected"},
		Enabled: true,
		Secret:  secret,
	})
	return dir, path
}

// restoreWithoutKey copies ONLY alert_webhooks.json into a fresh directory —
// exactly what `culvert --restore` does, since the key file is not in the
// archive — and loads a store over it.
func restoreWithoutKey(t *testing.T, srcPath string) (dir, path string, st *Store) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "alert_webhooks.json")
	body, err := os.ReadFile(srcPath) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("read source store: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write restored store: %v", err)
	}
	st = &Store{}
	st.Init(path)
	return dir, path, st
}

func onDiskHooks(t *testing.T, path string) []Webhook {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var hooks []Webhook
	if err := json.Unmarshal(body, &hooks); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return hooks
}

// TestSigningDegraded_UndecryptableCiphertextSurvivesUnrelatedSave is the
// regression test for the destructive half. It fails against the pre-fix tree.
func TestSigningDegraded_UndecryptableCiphertextSurvivesUnrelatedSave(t *testing.T) {
	_, origPath := seedEncryptedStore(t, "super-secret-hmac-key")
	original := onDiskHooks(t, origPath)
	if len(original) != 1 || !strings.HasPrefix(original[0].Secret, webhookSecretEncPrefix) {
		t.Fatalf("expected one encrypted secret on disk, got %+v", original)
	}

	_, newPath, st := restoreWithoutKey(t, origPath)

	// An UNRELATED mutation rewrites the whole file.
	st.Add(Webhook{Name: "pager", URL: "https://pager.example.com/hook", Events: []string{"policy_block"}, Enabled: true})

	after := onDiskHooks(t, newPath)
	if len(after) != 2 {
		t.Fatalf("want 2 hooks on disk, got %d", len(after))
	}
	if after[0].Secret != original[0].Secret {
		t.Errorf("ciphertext for the restored webhook changed on save:\n got  %q\n want %q (verbatim)", after[0].Secret, original[0].Secret)
	}
	// The unrelated new webhook carries no secret and must stay empty.
	if after[1].Secret != "" {
		t.Errorf("second webhook secret = %q, want empty", after[1].Secret)
	}
	// The status flag is derived at load and must never reach the file.
	for i := range after {
		if after[i].SigningDegraded {
			t.Errorf("hook %d persisted signing_degraded=true; the status must be derived, never stored", i)
		}
	}
}

// TestSigningDegraded_DeleteOfAnotherHookDoesNotDestroyTheCiphertext covers the
// other whole-list rewrite paths.
func TestSigningDegraded_DeleteOfAnotherHookDoesNotDestroyTheCiphertext(t *testing.T) {
	_, origPath := seedEncryptedStore(t, "hmac-key")
	original := onDiskHooks(t, origPath)

	_, newPath, st := restoreWithoutKey(t, origPath)
	added := st.Add(Webhook{Name: "temp", URL: "https://temp.example.com/hook", Enabled: true})
	if !st.Delete(added.ID) {
		t.Fatal("delete of the added webhook failed")
	}

	after := onDiskHooks(t, newPath)
	if len(after) != 1 || after[0].Secret != original[0].Secret {
		t.Errorf("ciphertext did not survive add+delete of an unrelated webhook: %+v", after)
	}
}

// TestSigningDegraded_UpdateWithoutSecretPreservesCiphertext: editing the
// degraded webhook's own name/events (the API sends an empty secret to mean
// "leave it alone") must not destroy it either.
func TestSigningDegraded_UpdateWithoutSecretPreservesCiphertext(t *testing.T) {
	_, origPath := seedEncryptedStore(t, "hmac-key")
	original := onDiskHooks(t, origPath)

	_, newPath, st := restoreWithoutKey(t, origPath)
	id := st.List()[0].ID
	if !st.Update(id, Webhook{Name: "siem-renamed", URL: "https://siem.example.com/hook", Events: []string{"policy_block"}, Enabled: true}) {
		t.Fatal("update failed")
	}

	after := onDiskHooks(t, newPath)
	if after[0].Secret != original[0].Secret {
		t.Errorf("ciphertext lost on a secret-less update: got %q want %q", after[0].Secret, original[0].Secret)
	}
	if after[0].Name != "siem-renamed" {
		t.Errorf("update did not apply: name = %q", after[0].Name)
	}
	if !st.List()[0].SigningDegraded {
		t.Error("webhook should still report SigningDegraded after a secret-less update")
	}
}

// TestSigningDegraded_ListReportsItWithoutLeaking is the visibility half: the
// flag is set, and no ciphertext or cleartext rides along with it.
func TestSigningDegraded_ListReportsItWithoutLeaking(t *testing.T) {
	_, origPath := seedEncryptedStore(t, "hmac-key")
	original := onDiskHooks(t, origPath)
	_, _, st := restoreWithoutKey(t, origPath)

	listed := st.List()
	if len(listed) != 1 {
		t.Fatalf("want 1 webhook, got %d", len(listed))
	}
	if !listed[0].SigningDegraded {
		t.Error("SigningDegraded = false; an operator cannot tell that deliveries are unsigned")
	}
	if listed[0].Secret != "" {
		t.Errorf("List leaked a secret: %q", listed[0].Secret)
	}
	blob, err := json.Marshal(listed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), original[0].Secret) {
		t.Error("the serialised list carries the stored ciphertext")
	}
	if n := st.SigningDegradedCount(); n != 1 {
		t.Errorf("SigningDegradedCount = %d, want 1", n)
	}

	// The delivery path keys on Secret, so signing is genuinely off — pinned so
	// the flag can never drift away from the behaviour it describes.
	h, ok := st.GetByID(listed[0].ID)
	if !ok || h.Secret != "" {
		t.Errorf("GetByID secret = %q, want empty (never sign with a secret we could not decrypt)", h.Secret)
	}
}

// TestSigningDegraded_HealthyStoreIsNotDegraded is the negative control: a
// store that CAN decrypt its secrets reports nothing, and a webhook that never
// had a secret is not mislabelled.
func TestSigningDegraded_HealthyStoreIsNotDegraded(t *testing.T) {
	dir, path := seedEncryptedStore(t, "hmac-key")
	reloaded := &Store{}
	reloaded.Init(path)
	if n := reloaded.SigningDegradedCount(); n != 0 {
		t.Errorf("SigningDegradedCount = %d on a healthy store, want 0", n)
	}
	if reloaded.List()[0].SigningDegraded {
		t.Error("healthy webhook reported as degraded")
	}
	h, _ := reloaded.GetByID(reloaded.List()[0].ID)
	if h.Secret != "hmac-key" {
		t.Errorf("secret did not round-trip: %q", h.Secret)
	}

	// A webhook with no secret at all.
	reloaded.Add(Webhook{Name: "nosecret", URL: "https://nosecret.example.com/h", Enabled: true})
	for _, w := range reloaded.List() {
		if w.Name == "nosecret" && w.SigningDegraded {
			t.Error("a webhook that never had a secret must not report SigningDegraded")
		}
	}
	on := onDiskHooks(t, filepath.Join(dir, "alert_webhooks.json"))
	for i := range on {
		if on[i].Name == "nosecret" && on[i].Secret != "" {
			t.Errorf("empty secret did not stay empty on disk: %q", on[i].Secret)
		}
	}
}

// TestSigningDegraded_ReEnteringTheSecretRecovers: the documented remedy works
// and clears the flag.
func TestSigningDegraded_ReEnteringTheSecretRecovers(t *testing.T) {
	_, origPath := seedEncryptedStore(t, "old-key")
	_, newPath, st := restoreWithoutKey(t, origPath)

	id := st.List()[0].ID
	if !st.Update(id, Webhook{Name: "siem", URL: "https://siem.example.com/hook", Events: []string{"threat_detected"}, Enabled: true, Secret: "re-entered-key"}) {
		t.Fatal("update failed")
	}
	if st.List()[0].SigningDegraded {
		t.Error("SigningDegraded still set after the secret was re-entered")
	}
	if n := st.SigningDegradedCount(); n != 0 {
		t.Errorf("SigningDegradedCount = %d after recovery, want 0", n)
	}
	h, _ := st.GetByID(id)
	if h.Secret != "re-entered-key" {
		t.Errorf("in-memory secret = %q, want the re-entered one", h.Secret)
	}

	// And it round-trips through disk under the NEW node's own key.
	reloaded := &Store{}
	reloaded.Init(newPath)
	rh, _ := reloaded.GetByID(id)
	if rh.Secret != "re-entered-key" {
		t.Errorf("re-entered secret did not persist: %q", rh.Secret)
	}
	if reloaded.SigningDegradedCount() != 0 {
		t.Error("still degraded after a reload")
	}
}

// TestSigningDegraded_RestoringTheKeyFileRecoversSigning: because the
// ciphertext survives, putting the node-local key back is enough — no secret
// re-entry needed. This is the property the destructive save had removed.
func TestSigningDegraded_RestoringTheKeyFileRecoversSigning(t *testing.T) {
	origDir, origPath := seedEncryptedStore(t, "hmac-key")

	newDir, newPath, st := restoreWithoutKey(t, origPath)
	if st.SigningDegradedCount() != 1 {
		t.Fatal("expected the restored store to be degraded")
	}
	// An unrelated edit happens before anyone notices (the destructive case).
	st.Add(Webhook{Name: "pager", URL: "https://pager.example.com/hook", Enabled: true})

	// Operator copies the node-local key across and restarts.
	key, err := os.ReadFile(filepath.Join(origDir, webhookKeyFileName)) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(newDir, webhookKeyFileName), key, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	clearWebhookKeyCacheForTest()

	recovered := &Store{}
	recovered.Init(newPath)
	if n := recovered.SigningDegradedCount(); n != 0 {
		t.Fatalf("SigningDegradedCount = %d after restoring the key file, want 0", n)
	}
	h, ok := recovered.GetByID(recovered.List()[0].ID)
	if !ok || h.Secret != "hmac-key" {
		t.Errorf("secret did not recover: %q", h.Secret)
	}
}

// TestSigningDegraded_MalformedStoredSecret: a corrupt/garbage stored value is
// treated the same way — signing off, value preserved, state visible. Malformed
// input must never be silently "fixed" by overwriting it.
func TestSigningDegraded_MalformedStoredSecret(t *testing.T) {
	for _, stored := range []string{
		webhookSecretEncPrefix + "not-base64!!",
		webhookSecretEncPrefix + "",
		webhookSecretEncPrefix + "AAAA",
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "alert_webhooks.json")
		body, err := json.Marshal([]Webhook{{ID: "1", Name: "h", URL: "https://h.example.com/x", Enabled: true, Secret: stored}})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		st := &Store{}
		st.Init(path)

		if !st.List()[0].SigningDegraded {
			t.Errorf("stored=%q: not reported as degraded", stored)
		}
		if h, _ := st.GetByID("1"); h.Secret != "" {
			t.Errorf("stored=%q: cleartext secret = %q, want empty", stored, h.Secret)
		}
		st.Add(Webhook{Name: "other", URL: "https://other.example.com/x", Enabled: true})
		if after := onDiskHooks(t, path); after[0].Secret != stored {
			t.Errorf("stored=%q: value was rewritten as %q", stored, after[0].Secret)
		}
	}
}

// TestSigningDegraded_StatusIsNeverAcceptedFromACaller: signing_degraded is a
// server-derived status. A client that asserts it (create, update, or a
// hand-edited/imported store file) must not be believed.
func TestSigningDegraded_StatusIsNeverAcceptedFromACaller(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alert_webhooks.json")
	st := &Store{}
	st.Init(path)

	created := st.Add(Webhook{Name: "a", URL: "https://a.example.com/x", Enabled: true, Secret: "k", SigningDegraded: true})
	if created.SigningDegraded {
		t.Error("Add echoed a caller-asserted SigningDegraded")
	}
	if st.List()[0].SigningDegraded || st.SigningDegradedCount() != 0 {
		t.Error("a caller-asserted SigningDegraded reached the store via Add")
	}
	if !st.Update(created.ID, Webhook{Name: "a", URL: "https://a.example.com/x", Enabled: true, SigningDegraded: true}) {
		t.Fatal("update failed")
	}
	if st.List()[0].SigningDegraded {
		t.Error("a caller-asserted SigningDegraded reached the store via Update")
	}

	// Straight from the file.
	path2 := filepath.Join(t.TempDir(), "alert_webhooks.json")
	body, err := json.Marshal([]Webhook{{ID: "1", Name: "h", URL: "https://h.example.com/x", Enabled: true, SigningDegraded: true}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path2, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	st2 := &Store{}
	st2.Init(path2)
	if st2.List()[0].SigningDegraded || st2.SigningDegradedCount() != 0 {
		t.Error("a stored signing_degraded=true was believed on load")
	}
}

// TestSigningDegraded_ConcurrentReadersAndWriters is the race-detector gate for
// the new field: List/SigningDegradedCount read it while Update/Add write it.
func TestSigningDegraded_ConcurrentReadersAndWriters(t *testing.T) {
	_, origPath := seedEncryptedStore(t, "hmac-key")
	_, _, st := restoreWithoutKey(t, origPath)
	id := st.List()[0].ID

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = st.List()
				_ = st.SigningDegradedCount()
				_, _ = st.GetByID(id)
			}
		}()
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				st.Update(id, Webhook{Name: "siem", URL: "https://siem.example.com/hook", Events: []string{"threat_detected"}, Enabled: true})
				h := st.Add(Webhook{Name: "churn", URL: "https://churn.example.com/x", Enabled: true})
				st.Delete(h.ID)
			}
		}(i)
	}
	wg.Wait()

	if n := st.SigningDegradedCount(); n != 1 {
		t.Errorf("SigningDegradedCount = %d after concurrent churn, want 1 (the degraded hook must not be lost or duplicated)", n)
	}
}
