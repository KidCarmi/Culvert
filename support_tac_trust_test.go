package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/sealbox"
)

// tacKeyJSON builds a one-key CULVERT_TAC_TRUST_KEYS array for a generated pub key.
func tacKeyJSON(id, pubB64 string) string {
	return `[{"key_id":"` + id + `","alg":"x25519","public_key":"` + pubB64 + `"}]`
}

// newTACKey returns a fresh X25519 pair and the std-base64 of the public key.
func newTACKey(t *testing.T) (pub, priv *[sealbox.KeyLen]byte, pubB64 string) {
	t.Helper()
	pub, priv, err := sealbox.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv, base64.StdEncoding.EncodeToString(pub[:])
}

// withBakedTACKeys swaps the linker-injected baked set for the duration of a test.
func withBakedTACKeys(t *testing.T, jsonVal string) {
	t.Helper()
	prev := bakedTACTrustKeysJSON
	bakedTACTrustKeysJSON = jsonVal
	t.Cleanup(func() { bakedTACTrustKeysJSON = prev })
}

func TestParseTACTrustKeys_ValidatesAlgAndKey(t *testing.T) {
	_, _, pubB64 := newTACKey(t)

	// Good key parses with the computed fingerprint.
	keys, err := parseTACTrustKeys(tacKeyJSON("tac-2026", pubB64), "test")
	if err != nil {
		t.Fatalf("valid key: %v", err)
	}
	if len(keys) != 1 || keys[0].KeyID != "tac-2026" || keys[0].Fingerprint == "" {
		t.Fatalf("parsed = %+v", keys)
	}

	// Wrong algorithm is refused.
	if _, err := parseTACTrustKeys(`[{"key_id":"k","alg":"ed25519","public_key":"`+pubB64+`"}]`, "test"); err == nil {
		t.Fatal("non-x25519 alg must be rejected")
	}
	// Bad key id grammar is refused.
	if _, err := parseTACTrustKeys(`[{"key_id":"bad id!","alg":"x25519","public_key":"`+pubB64+`"}]`, "test"); err == nil {
		t.Fatal("invalid key_id must be rejected")
	}
	// Not-32-bytes / not-base64 key is refused.
	if _, err := parseTACTrustKeys(`[{"key_id":"k","alg":"x25519","public_key":"not-base64!!"}]`, "test"); err == nil {
		t.Fatal("invalid public key must be rejected")
	}
	// A low-order point is refused (decodeX25519PubKey's guard).
	lowOrder := base64.StdEncoding.EncodeToString(make([]byte, sealbox.KeyLen)) // all-zero = low order
	if _, err := parseTACTrustKeys(tacKeyJSON("k", lowOrder), "test"); err == nil {
		t.Fatal("low-order recipient key must be rejected")
	}
	// Blank input yields no keys, no error.
	if keys, err := parseTACTrustKeys("  ", "test"); err != nil || keys != nil {
		t.Fatalf("blank input = (%+v, %v)", keys, err)
	}
}

func TestResolveTACTrustKeys_ConfiguredExtendBaked(t *testing.T) {
	_, _, bakedPub := newTACKey(t)
	_, _, cfgPub := newTACKey(t)
	withBakedTACKeys(t, tacKeyJSON("tac-baked", bakedPub))
	t.Setenv(envTACTrustKeys, tacKeyJSON("tac-region", cfgPub))
	t.Setenv(envTACActiveKeyID, "")

	keys, err := resolveTACTrustKeys()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("resolved %d keys, want baked+configured=2", len(keys))
	}
	// Baked comes first and is the default active key.
	if keys[0].KeyID != "tac-baked" || keys[0].Source != "baked" || !keys[0].Active {
		t.Fatalf("first key = %+v, want active baked", keys[0])
	}
	if keys[1].KeyID != "tac-region" || keys[1].Source != "configured" || keys[1].Active {
		t.Fatalf("second key = %+v, want inactive configured", keys[1])
	}
}

func TestResolveTACTrustKeys_DuplicateIDCollisionKeepsBaked(t *testing.T) {
	_, _, bakedPub := newTACKey(t)
	_, _, otherPub := newTACKey(t)
	withBakedTACKeys(t, tacKeyJSON("tac", bakedPub))
	// A configured key reusing the baked id with a DIFFERENT fingerprint is dropped.
	t.Setenv(envTACTrustKeys, tacKeyJSON("tac", otherPub))
	t.Setenv(envTACActiveKeyID, "")

	keys, err := resolveTACTrustKeys()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(keys) != 1 || keys[0].Source != "baked" || keys[0].PublicKey != bakedPub {
		t.Fatalf("collision resolution = %+v, want only the baked key", keys)
	}
}

func TestActiveTACKey_ExplicitIDAndUnknownFailsClosed(t *testing.T) {
	_, _, p1 := newTACKey(t)
	_, _, p2 := newTACKey(t)
	withBakedTACKeys(t, `[{"key_id":"k1","alg":"x25519","public_key":"`+p1+`"},{"key_id":"k2","alg":"x25519","public_key":"`+p2+`"}]`)

	// Explicit active id selects the named (non-first) key.
	t.Setenv(envTACActiveKeyID, "k2")
	key, _, err := activeTACTrustKey()
	if err != nil || key.KeyID != "k2" {
		t.Fatalf("active = (%q, %v), want k2", key.KeyID, err)
	}

	// An active id that names no resolved key fails closed.
	t.Setenv(envTACActiveKeyID, "nope")
	if _, _, err := activeTACTrustKey(); err == nil {
		t.Fatal("unknown active key id must fail closed")
	}
}

func TestSealBundleToTAC_RoundTripAndKeyID(t *testing.T) {
	pub, priv, pubB64 := newTACKey(t)
	withBakedTACKeys(t, tacKeyJSON("tac-active", pubB64))
	t.Setenv(envTACTrustKeys, "")
	t.Setenv(envTACActiveKeyID, "")

	plaintext := []byte("redacted support bundle bytes")
	sealed, keyID, err := sealBundleToTAC(plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if keyID != "tac-active" {
		t.Fatalf("key_id = %q, want tac-active", keyID)
	}
	if !sealbox.IsSealed(sealed) {
		t.Fatal("output is not a sealbox envelope")
	}
	// The appliance holds no private key; only TAC's private key opens it.
	opened, err := sealbox.Open(sealed, pub, priv)
	if err != nil {
		t.Fatalf("open with TAC key: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("round-trip mismatch: %q", opened)
	}
}

func TestSealBundleToTAC_NoKeyFailsClosed(t *testing.T) {
	withBakedTACKeys(t, "")
	t.Setenv(envTACTrustKeys, "")
	t.Setenv(envTACActiveKeyID, "")
	if _, _, err := sealBundleToTAC([]byte("x")); err == nil {
		t.Fatal("seal with no trust key must fail closed (errNoTACTrustKey)")
	}
	if tacTrustConfigured() {
		t.Fatal("tacTrustConfigured must be false with no key")
	}
}

func TestAPISupportTACTrust_ShapeAndRBAC(t *testing.T) {
	_, _, pubB64 := newTACKey(t)
	withBakedTACKeys(t, tacKeyJSON("tac-2026", pubB64))
	t.Setenv(envTACTrustKeys, "")
	t.Setenv(envTACActiveKeyID, "")

	// GET viewer → 200 with the resolved set; public key present, no secret fields.
	rec := httptest.NewRecorder()
	apiSupportTACTrust(rec, roleReq(RoleViewer, http.MethodGet, "/api/support/tac-trust", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET viewer = %d, want 200", rec.Code)
	}
	var body struct {
		Configured bool          `json:"configured"`
		ActiveKey  string        `json:"active_key"`
		Keys       []tacTrustKey `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Configured || body.ActiveKey != "tac-2026" || len(body.Keys) != 1 {
		t.Fatalf("body = %+v", body)
	}
	if body.Keys[0].Fingerprint == "" {
		t.Fatal("fingerprint should be surfaced for out-of-band verification")
	}

	// A non-GET verb is 405 (read-only surface).
	rec2 := httptest.NewRecorder()
	apiSupportTACTrust(rec2, roleReq(RoleAdmin, http.MethodPost, "/api/support/tac-trust", nil))
	if rec2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", rec2.Code)
	}
}
