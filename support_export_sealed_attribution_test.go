package main

// support_export_sealed_attribution_test.go — regression guard for the security
// fix that records the RECIPIENT of a sealed support-bundle export.
//
// The sealed-export path is the governed exfiltration channel. Before the fix its
// audit event recorded only the bundle id and format — not to whose key the bundle
// was sealed — so "sealed to tac-prod" and "sealed to an attacker's own key" left
// an identical trail, defeating the point of the admin-gated recipient registry.
// The fix records recipient name (or "(unregistered)" for a raw key) plus the full
// key fingerprint, and records old→new on recipient-key rotation.

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/sealbox"
)

func fingerprintOf(t *testing.T, pub *[sealbox.KeyLen]byte) string {
	t.Helper()
	return recipientFingerprint(pub)
}

// findAudit returns the newest audit entry matching action+object, or false.
func findAudit(action, object string) (AuditEntry, bool) {
	snap := auditGet()
	for i := len(snap) - 1; i >= 0; i-- {
		if snap[i].Action == action && snap[i].Object == object {
			return snap[i], true
		}
	}
	return AuditEntry{}, false
}

// TestSupportExportSealed_AuditRecordsRegisteredRecipient: a seal-by-name export
// records the recipient name and fingerprint in the audit detail.
func TestSupportExportSealed_AuditRecordsRegisteredRecipient(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	id := makeReadyBundle(t)

	pub, _, err := sealbox.GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub[:])
	rec, err := addSupportRecipient("tac-prod", pubB64, "1.2.3.4")
	if err != nil {
		t.Fatalf("register recipient: %v", err)
	}

	r := roleReq(RoleOperator, http.MethodPost, "/api/support/bundles/"+id+"/download-sealed",
		map[string]any{"recipient_name": "tac-prod"})
	r.SetPathValue("id", id)
	w := httptest.NewRecorder()
	apiSupportBundleExportSealed(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("sealed export code=%d want 200 (body=%q)", w.Code, w.Body.String())
	}

	e, ok := findAudit("support.bundle.download_sealed", id)
	if !ok {
		t.Fatal("no download_sealed audit entry for the bundle")
	}
	if !strings.Contains(e.Detail, "recipient=tac-prod") {
		t.Errorf("audit detail must name the recipient; got %q", e.Detail)
	}
	if !strings.Contains(e.Detail, "fp="+rec.Fingerprint) {
		t.Errorf("audit detail must carry the recipient fingerprint %s; got %q", rec.Fingerprint, e.Detail)
	}
}

// TestSupportExportSealed_AuditFlagsRawKey: a seal to a raw pasted key records the
// fingerprint and marks the recipient unregistered, so a raw-key exfil is
// distinguishable from a registered-recipient one in the trail.
func TestSupportExportSealed_AuditFlagsRawKey(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	id := makeReadyBundle(t)
	pub, _, _ := sealbox.GenerateKey()
	pubB64 := base64.StdEncoding.EncodeToString(pub[:])

	r := roleReq(RoleOperator, http.MethodPost, "/api/support/bundles/"+id+"/download-sealed",
		map[string]any{"recipient_public_key": pubB64})
	r.SetPathValue("id", id)
	w := httptest.NewRecorder()
	apiSupportBundleExportSealed(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("sealed export code=%d want 200 (body=%q)", w.Code, w.Body.String())
	}

	e, ok := findAudit("support.bundle.download_sealed", id)
	if !ok {
		t.Fatal("no download_sealed audit entry for the bundle")
	}
	if !strings.Contains(e.Detail, "recipient=(unregistered)") {
		t.Errorf("raw-key export must be flagged unregistered; got %q", e.Detail)
	}
	if !strings.Contains(e.Detail, "fp=") {
		t.Errorf("raw-key export must still record the fingerprint; got %q", e.Detail)
	}
}

// TestSupportRecipientRotate_AuditRecordsOldAndNew: rotating a recipient's key
// records both the replaced and the new fingerprint, so a compromised-admin
// key-swap is reconstructable from a single entry.
func TestSupportRecipientRotate_AuditRecordsOldAndNew(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	pub1, _, _ := sealbox.GenerateKey()
	rec1, err := addSupportRecipient("tac", base64.StdEncoding.EncodeToString(pub1[:]), "1.2.3.4")
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	pub2, _, _ := sealbox.GenerateKey()
	newB64 := base64.StdEncoding.EncodeToString(pub2[:])

	r := roleReq(RoleAdmin, http.MethodPut, "/api/support/recipients/tac",
		map[string]any{"public_key": newB64})
	r.SetPathValue("name", "tac")
	w := httptest.NewRecorder()
	apiSupportRecipientItem(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("rotate code=%d want 200 (body=%q)", w.Code, w.Body.String())
	}

	e, ok := findAudit("support.recipient.rotate", "tac")
	if !ok {
		t.Fatal("no recipient.rotate audit entry")
	}
	newFP := fingerprintOf(t, pub2)
	if !strings.Contains(e.Detail, rec1.Fingerprint) {
		t.Errorf("rotate audit must record the OLD fingerprint %s; got %q", rec1.Fingerprint, e.Detail)
	}
	if !strings.Contains(e.Detail, newFP) {
		t.Errorf("rotate audit must record the NEW fingerprint %s; got %q", newFP, e.Detail)
	}
	// old→new ordering: the replaced fingerprint precedes the replacement.
	if strings.Index(e.Detail, rec1.Fingerprint) >= strings.Index(e.Detail, newFP) {
		t.Errorf("rotate audit must record old→new order; got %q", e.Detail)
	}
}
