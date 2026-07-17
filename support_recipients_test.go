package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/sealbox"
)

func genRecipientKey(t *testing.T) (pubB64 string, pub *[sealbox.KeyLen]byte) {
	t.Helper()
	p, _, err := sealbox.GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return base64.StdEncoding.EncodeToString(p[:]), p
}

// TestRecipientRegistry_RoundTrip covers add → list → lookup → delete plus the
// fingerprint contract.
func TestRecipientRegistry_RoundTrip(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	pubB64, pub := genRecipientKey(t)
	rec, err := addSupportRecipient("tac-prod", pubB64, "1.2.3.4")
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	// Fingerprint is the lowercase-hex SHA-256 of the RAW key bytes.
	sum := sha256.Sum256(pub[:])
	if rec.Fingerprint != hex.EncodeToString(sum[:]) {
		t.Fatalf("fingerprint mismatch: %s", rec.Fingerprint)
	}

	list := listSupportRecipients()
	if len(list) != 1 || list[0].Name != "tac-prod" {
		t.Fatalf("list = %+v", list)
	}

	// lookup resolves to the exact registered key.
	got, err := lookupSupportRecipientKey("tac-prod")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if *got != *pub {
		t.Fatal("lookup returned a different key")
	}

	if err := deleteSupportRecipient("tac-prod"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(listSupportRecipients()) != 0 {
		t.Fatal("recipient not removed")
	}
	if err := deleteSupportRecipient("tac-prod"); err == nil {
		t.Fatal("deleting a missing recipient should error")
	}
}

// TestRecipientRegistry_Validation covers the guardrails: low-order key, bad name,
// and duplicate name.
func TestRecipientRegistry_Validation(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	// Low-order (all-zero) key must be refused — same guard as the seal path.
	zero := base64.StdEncoding.EncodeToString(make([]byte, sealbox.KeyLen))
	if _, err := addSupportRecipient("low", zero, ""); err == nil {
		t.Fatal("registered a low-order recipient key")
	}
	// Bad names.
	good, _ := genRecipientKey(t)
	for _, bad := range []string{"", " ", "-leading", "has space", "bad/slash", "..dots"} {
		if _, err := addSupportRecipient(bad, good, ""); err == nil {
			t.Fatalf("accepted invalid name %q", bad)
		}
	}
	// Duplicate name.
	if _, err := addSupportRecipient("dup", good, ""); err != nil {
		t.Fatalf("first add: %v", err)
	}
	other, _ := genRecipientKey(t)
	if _, err := addSupportRecipient("dup", other, ""); err == nil {
		t.Fatal("accepted a duplicate name")
	}
}

// TestRecipientRegistry_API covers method + RBAC on both handlers.
func TestRecipientRegistry_API(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	pubB64, _ := genRecipientKey(t)

	// POST as viewer → 403.
	vRec := httptest.NewRecorder()
	apiSupportRecipients(vRec, roleReq(RoleViewer, http.MethodPost, "/api/support/recipients",
		map[string]any{"name": "x", "public_key": pubB64}))
	if vRec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST code=%d want 403", vRec.Code)
	}
	// POST as admin → 200 and persisted.
	aRec := httptest.NewRecorder()
	apiSupportRecipients(aRec, roleReq(RoleAdmin, http.MethodPost, "/api/support/recipients",
		map[string]any{"name": "tac", "public_key": pubB64}))
	if aRec.Code != http.StatusOK {
		t.Fatalf("admin POST code=%d want 200 (body=%q)", aRec.Code, aRec.Body.String())
	}
	// GET as viewer lists it.
	gRec := httptest.NewRecorder()
	apiSupportRecipients(gRec, roleReq(RoleViewer, http.MethodGet, "/api/support/recipients", nil))
	if gRec.Code != http.StatusOK {
		t.Fatalf("viewer GET code=%d want 200", gRec.Code)
	}
	var body struct {
		Recipients []supportRecipient `json:"recipients"`
	}
	if err := json.Unmarshal(gRec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if len(body.Recipients) != 1 || body.Recipients[0].Name != "tac" {
		t.Fatalf("list = %+v", body.Recipients)
	}

	// DELETE as viewer → 403; as operator → 200.
	dv := httptest.NewRecorder()
	drv := roleReq(RoleViewer, http.MethodDelete, "/api/support/recipients/tac", nil)
	drv.SetPathValue("name", "tac")
	apiSupportRecipientItem(dv, drv)
	if dv.Code != http.StatusForbidden {
		t.Fatalf("viewer DELETE code=%d want 403", dv.Code)
	}
	do := httptest.NewRecorder()
	dro := roleReq(RoleOperator, http.MethodDelete, "/api/support/recipients/tac", nil)
	dro.SetPathValue("name", "tac")
	apiSupportRecipientItem(do, dro)
	if do.Code != http.StatusOK {
		t.Fatalf("operator DELETE code=%d want 200", do.Code)
	}
	// Deleting again → 404.
	dn := httptest.NewRecorder()
	drn := roleReq(RoleOperator, http.MethodDelete, "/api/support/recipients/tac", nil)
	drn.SetPathValue("name", "tac")
	apiSupportRecipientItem(dn, drn)
	if dn.Code != http.StatusNotFound {
		t.Fatalf("missing DELETE code=%d want 404", dn.Code)
	}
}

// TestSealByRegisteredRecipient proves the sealed-export handler can seal to a
// registered recipient by NAME, and the recipient opens it.
func TestSealByRegisteredRecipient(t *testing.T) {
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })

	pub, priv, err := sealbox.GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub[:])
	if _, err := addSupportRecipient("tac", pubB64, ""); err != nil {
		t.Fatalf("add recipient: %v", err)
	}

	id := makeReadyBundle(t)
	r := roleReq(RoleOperator, http.MethodPost, "/api/support/bundles/"+id+"/download-sealed",
		map[string]any{"recipient_name": "tac"})
	r.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	apiSupportBundleExportSealed(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("seal-by-name code=%d want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	blob := rec.Body.Bytes()
	if !sealbox.IsSealed(blob) {
		t.Fatal("output is not a sealbox envelope")
	}
	if _, err := sealbox.Open(blob, pub, priv); err != nil {
		t.Fatalf("recipient could not open the sealed bundle: %v", err)
	}

	// An unknown recipient name → 404.
	r2 := roleReq(RoleOperator, http.MethodPost, "/api/support/bundles/"+id+"/download-sealed",
		map[string]any{"recipient_name": "nope"})
	r2.SetPathValue("id", id)
	rec2 := httptest.NewRecorder()
	apiSupportBundleExportSealed(rec2, r2)
	if rec2.Code != http.StatusNotFound {
		t.Fatalf("unknown recipient code=%d want 404", rec2.Code)
	}

	// Both selectors present → 400 (never silently prefer one).
	r3 := roleReq(RoleOperator, http.MethodPost, "/api/support/bundles/"+id+"/download-sealed",
		map[string]any{"recipient_name": "tac", "recipient_public_key": pubB64})
	r3.SetPathValue("id", id)
	rec3 := httptest.NewRecorder()
	apiSupportBundleExportSealed(rec3, r3)
	if rec3.Code != http.StatusBadRequest {
		t.Fatalf("both-selectors code=%d want 400", rec3.Code)
	}
}
