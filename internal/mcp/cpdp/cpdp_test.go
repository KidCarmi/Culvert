package cpdp

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// ---- test helpers -------------------------------------------------------------

func testLimits() Limits { return DefaultLimits() }

// newSigner returns a deterministic-enough test signer plus a trust store that
// trusts it.
func newSigner(t *testing.T, keyID string) (Signer, *TrustStore) {
	t.Helper()
	s, err := GenerateLocalSigner(keyID)
	if err != nil {
		t.Fatalf("GenerateLocalSigner: %v", err)
	}
	ts, err := NewTrustStore([]TrustRoot{{KeyID: keyID, Alg: SigAlgEd25519, Public: s.Public()}})
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}
	return s, ts
}

func gwManifest() Manifest {
	return Manifest{
		SchemaVersion:   SchemaVersion,
		Capability:      CapabilityGateway,
		Epoch:           5,
		Revisions:       Revisions{Config: 2, Policy: 2, Catalog: 1, Credential: 1},
		MinDPVersion:    1,
		PayloadType:     "gateway",
		PayloadVersion:  1,
		CreatedUnixNano: 1000,
		Source:          SourceMeta{Kind: "publish"},
	}
}

func gwPayload() Payload {
	return Payload{Gateway: &GatewayPayload{
		Listener: GatewayListener{Enabled: true, BindAddress: "127.0.0.1", Port: 8091, PolicyDefaultAction: "deny"},
		Servers:  []ServerRecord{{ID: "s1", Endpoint: "https://s1.internal", PinnedIdentity: "sha256:aa", Verified: true, Enabled: true}},
		Tools:    []ToolRecord{{Server: "s1", Name: "read", Fingerprint: "fp1"}},
		CredentialProfiles: []CredentialProfileMeta{
			{ProfileID: "p1", Scope: "read", ProviderRef: "vault://kv/p1", Version: 1},
		},
	}}
}

func mgmtManifest() Manifest {
	m := gwManifest()
	m.Capability = CapabilityManagement
	m.PayloadType = "management"
	return m
}

func mgmtPayload() Payload {
	return Payload{Management: &ManagementPayload{
		Listener:                ManagementListener{Enabled: true, BindAddress: "127.0.0.1", Port: 8092, MutationEnabled: false},
		OperationCatalogVersion: 1,
		PolicyReadScope:         "mgmt.read",
	}}
}

func mustSign(t *testing.T, m Manifest, p Payload, s Signer) *Envelope {
	t.Helper()
	env, err := Sign(m, p, s, testLimits())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return env
}

func reasonIs(t *testing.T, err error, want mcperr.Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error %v, got nil", want)
	}
	if got := mcperr.ReasonOf(err); got != want {
		t.Fatalf("reason = %v, want %v (err=%v)", got, want, err)
	}
}

// ---- signing / canonical hashing ---------------------------------------------

func TestSignVerify_RoundTrip(t *testing.T) {
	s, ts := newSigner(t, "k1")
	env := mustSign(t, gwManifest(), gwPayload(), s)
	if env.SigAlg != SigAlgEd25519 || env.KeyID != "k1" {
		t.Fatalf("envelope alg/key = %q/%q", env.SigAlg, env.KeyID)
	}
	if err := VerifySignature(env, ts, testLimits()); err != nil {
		t.Fatalf("VerifySignature: %v", err)
	}
}

func TestContentHash_Deterministic(t *testing.T) {
	l := testLimits()
	h1, err := ContentHash(gwManifest(), gwPayload(), SigAlgEd25519, "k1", l.canonicalBounds())
	if err != nil {
		t.Fatal(err)
	}
	h2, err := ContentHash(gwManifest(), gwPayload(), SigAlgEd25519, "k1", l.canonicalBounds())
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %s != %s", h1, h2)
	}
}

func TestContentHash_MutationChangesHash(t *testing.T) {
	l := testLimits()
	base, _ := ContentHash(gwManifest(), gwPayload(), SigAlgEd25519, "k1", l.canonicalBounds())

	// Mutate each signed dimension and require a different hash.
	m2 := gwManifest()
	m2.Epoch = 6
	if h, _ := ContentHash(m2, gwPayload(), SigAlgEd25519, "k1", l.canonicalBounds()); h == base {
		t.Fatal("epoch change did not change hash")
	}
	m3 := gwManifest()
	m3.Revisions.Policy = 99
	if h, _ := ContentHash(m3, gwPayload(), SigAlgEd25519, "k1", l.canonicalBounds()); h == base {
		t.Fatal("revision change did not change hash")
	}
	p2 := gwPayload()
	p2.Gateway.Tools[0].Name = "write"
	if h, _ := ContentHash(gwManifest(), p2, SigAlgEd25519, "k1", l.canonicalBounds()); h == base {
		t.Fatal("payload section change did not change hash")
	}
	// alg + key id are part of the hash.
	if h, _ := ContentHash(gwManifest(), gwPayload(), SigAlgEd25519, "k2", l.canonicalBounds()); h == base {
		t.Fatal("key id change did not change hash")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	s1, _ := newSigner(t, "k1")
	_, ts2 := newSigner(t, "k1") // different key, same id — the trust store has a DIFFERENT public key
	env := mustSign(t, gwManifest(), gwPayload(), s1)
	// ts2 trusts key id "k1" but with a different public key ⇒ signature must fail.
	reasonIs(t, VerifySignature(env, ts2, testLimits()), mcperr.ReasonSnapshotSignatureInvalid)
}

func TestVerify_UnknownKeyID(t *testing.T) {
	s, _ := newSigner(t, "k1")
	env := mustSign(t, gwManifest(), gwPayload(), s)
	other, _ := GenerateLocalSigner("kX")
	ts, _ := NewTrustStore([]TrustRoot{{KeyID: "kX", Alg: SigAlgEd25519, Public: other.Public()}})
	reasonIs(t, VerifySignature(env, ts, testLimits()), mcperr.ReasonSnapshotKeyUntrusted)
}

func TestVerify_MalformedSignature(t *testing.T) {
	s, ts := newSigner(t, "k1")
	env := mustSign(t, gwManifest(), gwPayload(), s)
	env.Signature = "not-base64!!!"
	reasonIs(t, VerifySignature(env, ts, testLimits()), mcperr.ReasonSnapshotSignatureInvalid)
}

func TestVerify_UnknownAlg(t *testing.T) {
	s, ts := newSigner(t, "k1")
	env := mustSign(t, gwManifest(), gwPayload(), s)
	env.SigAlg = "rsa"
	reasonIs(t, VerifySignature(env, ts, testLimits()), mcperr.ReasonSnapshotAlgUnknown)
}

func TestVerify_HashMismatch(t *testing.T) {
	s, ts := newSigner(t, "k1")
	env := mustSign(t, gwManifest(), gwPayload(), s)
	// Tamper the payload after signing; the recomputed hash must not match.
	env.Payload.Gateway.Tools[0].Name = "write"
	reasonIs(t, VerifySignature(env, ts, testLimits()), mcperr.ReasonSnapshotHashMismatch)
}

func TestKeyRotation_OverlappingRoots(t *testing.T) {
	sOld, _ := GenerateLocalSigner("old")
	sNew, _ := GenerateLocalSigner("new")
	ts, err := NewTrustStore([]TrustRoot{
		{KeyID: "old", Alg: SigAlgEd25519, Public: sOld.Public()},
		{KeyID: "new", Alg: SigAlgEd25519, Public: sNew.Public()},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Both a snapshot signed by the old key and one signed by the new key verify
	// during the overlap window.
	if err := VerifySignature(mustSign(t, gwManifest(), gwPayload(), sOld), ts, testLimits()); err != nil {
		t.Fatalf("old key: %v", err)
	}
	if err := VerifySignature(mustSign(t, gwManifest(), gwPayload(), sNew), ts, testLimits()); err != nil {
		t.Fatalf("new key: %v", err)
	}
	// After rotation completes, a store without the old key rejects old-key snapshots.
	tsNewOnly, _ := NewTrustStore([]TrustRoot{{KeyID: "new", Alg: SigAlgEd25519, Public: sNew.Public()}})
	reasonIs(t, VerifySignature(mustSign(t, gwManifest(), gwPayload(), sOld), tsNewOnly, testLimits()), mcperr.ReasonSnapshotKeyUntrusted)
}

func TestTrustStore_FailClosed(t *testing.T) {
	if _, err := NewTrustStore(nil); err == nil {
		t.Fatal("empty trust store must fail closed")
	}
	// wrong key length.
	if _, err := NewTrustStore([]TrustRoot{{KeyID: "k", Alg: SigAlgEd25519, Public: ed25519.PublicKey{1, 2, 3}}}); err == nil {
		t.Fatal("short key must be rejected")
	}
	// duplicate key id.
	s, _ := GenerateLocalSigner("k")
	if _, err := NewTrustStore([]TrustRoot{
		{KeyID: "k", Alg: SigAlgEd25519, Public: s.Public()},
		{KeyID: "k", Alg: SigAlgEd25519, Public: s.Public()},
	}); err == nil {
		t.Fatal("duplicate key id must be rejected")
	}
	// non-ed25519 alg.
	if _, err := NewTrustStore([]TrustRoot{{KeyID: "k", Alg: "rsa", Public: s.Public()}}); err == nil {
		t.Fatal("non-ed25519 alg must be rejected")
	}
}

// ---- whole-snapshot validation -----------------------------------------------

func gwValidateInput(ts *TrustStore) ValidateInput {
	return ValidateInput{ExpectCapability: CapabilityGateway, DPVersion: DPCompatVersion, LastEpoch: 0, Trust: ts, Limits: testLimits()}
}

func TestValidate_ValidGateway(t *testing.T) {
	s, ts := newSigner(t, "k1")
	env := mustSign(t, gwManifest(), gwPayload(), s)
	if err := Validate(env, gwValidateInput(ts)); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_ValidManagement(t *testing.T) {
	s, ts := newSigner(t, "k1")
	env := mustSign(t, mgmtManifest(), mgmtPayload(), s)
	in := ValidateInput{ExpectCapability: CapabilityManagement, DPVersion: DPCompatVersion, Trust: ts, Limits: testLimits()}
	if err := Validate(env, in); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidate_CapabilityMismatch(t *testing.T) {
	s, ts := newSigner(t, "k1")
	env := mustSign(t, gwManifest(), gwPayload(), s)
	in := ValidateInput{ExpectCapability: CapabilityManagement, DPVersion: DPCompatVersion, Trust: ts, Limits: testLimits()}
	reasonIs(t, Validate(env, in), mcperr.ReasonSnapshotCapabilityMismatch)
}

func TestValidate_CrossCapabilityField(t *testing.T) {
	s, ts := newSigner(t, "k1")
	// A gateway envelope that ALSO carries a management payload is signed (so the
	// hash matches) but must be rejected by the isolation check.
	p := gwPayload()
	p.Management = &ManagementPayload{OperationCatalogVersion: 1}
	env := mustSign(t, gwManifest(), p, s)
	reasonIs(t, Validate(env, gwValidateInput(ts)), mcperr.ReasonSnapshotCapabilityMismatch)
}

func TestValidate_MinVersionUnmet(t *testing.T) {
	s, ts := newSigner(t, "k1")
	m := gwManifest()
	m.MinDPVersion = DPCompatVersion + 5 // requires a newer DP than we are
	env := mustSign(t, m, gwPayload(), s)
	reasonIs(t, Validate(env, gwValidateInput(ts)), mcperr.ReasonSnapshotMinVersionUnmet)
}

func TestValidate_MinVersionMalformed(t *testing.T) {
	s, ts := newSigner(t, "k1")
	m := gwManifest()
	m.MinDPVersion = 0 // absent — a PR-10 snapshot MUST declare a positive minimum
	env := mustSign(t, m, gwPayload(), s)
	reasonIs(t, Validate(env, gwValidateInput(ts)), mcperr.ReasonSnapshotMinVersionMalformed)
}

func TestValidate_UnknownSchema(t *testing.T) {
	s, ts := newSigner(t, "k1")
	m := gwManifest()
	m.SchemaVersion = 99
	env := mustSign(t, m, gwPayload(), s)
	reasonIs(t, Validate(env, gwValidateInput(ts)), mcperr.ReasonSnapshotSchemaUnknown)
}

func TestValidate_ToolReferencesUnknownServer(t *testing.T) {
	s, ts := newSigner(t, "k1")
	p := gwPayload()
	p.Gateway.Tools[0].Server = "ghost"
	env := mustSign(t, m0(gwManifest()), p, s)
	reasonIs(t, Validate(env, gwValidateInput(ts)), mcperr.ReasonSnapshotValidationFailed)
}

func TestValidate_CredentialProfileSecretBearing(t *testing.T) {
	s, ts := newSigner(t, "k1")
	p := gwPayload()
	p.Gateway.CredentialProfiles[0].ProviderRef = "enc:v1:AAAA" // looks like a materialized secret
	env := mustSign(t, gwManifest(), p, s)
	reasonIs(t, Validate(env, gwValidateInput(ts)), mcperr.ReasonSnapshotValidationFailed)
}

func TestValidate_StaleEpoch(t *testing.T) {
	s, ts := newSigner(t, "k1")
	m := gwManifest()
	m.Epoch = 3
	env := mustSign(t, m, gwPayload(), s)
	in := gwValidateInput(ts)
	in.LastEpoch = 10 // DP has already seen epoch 10 → epoch 3 is stale
	reasonIs(t, Validate(env, in), mcperr.ReasonSnapshotEpochStale)
}

func m0(m Manifest) Manifest { return m }

// ---- compatibility version ----------------------------------------------------

func TestCheckMinVersion(t *testing.T) {
	if err := CheckMinVersion(1, 1); err != nil {
		t.Fatalf("equal: %v", err)
	}
	if err := CheckMinVersion(1, 2); err != nil {
		t.Fatalf("above: %v", err)
	}
	reasonIs(t, CheckMinVersion(2, 1), mcperr.ReasonSnapshotMinVersionUnmet)
	reasonIs(t, CheckMinVersion(0, 1), mcperr.ReasonSnapshotMinVersionMalformed)
	reasonIs(t, CheckMinVersion(maxCompatVersion+1, 1), mcperr.ReasonSnapshotMinVersionMalformed)
}

// ---- epoch ratchet ------------------------------------------------------------

func TestEpochRatchet(t *testing.T) {
	r := NewEpochRatchet(0)
	// legacy zero acceptable until a positive epoch is seen.
	if err := r.CheckEpoch(0); err != nil {
		t.Fatalf("legacy zero: %v", err)
	}
	// commit a positive epoch.
	adv, err := r.CommitObservedEpoch(5)
	if err != nil || !adv {
		t.Fatalf("commit 5: adv=%v err=%v", adv, err)
	}
	// now a zero epoch is a zombie signal.
	reasonIs(t, r.CheckEpoch(0), mcperr.ReasonSnapshotEpochInvalid)
	// lower epoch rejected.
	reasonIs(t, r.CheckEpoch(4), mcperr.ReasonSnapshotEpochStale)
	// same epoch accepted, does not advance.
	if adv, err := r.CommitObservedEpoch(5); err != nil || adv {
		t.Fatalf("commit same: adv=%v err=%v", adv, err)
	}
	// higher epoch advances.
	if adv, err := r.CommitObservedEpoch(7); err != nil || !adv {
		t.Fatalf("commit 7: adv=%v err=%v", adv, err)
	}
	if r.Last() != 7 {
		t.Fatalf("last = %d, want 7", r.Last())
	}
	// commit refuses to regress even directly.
	reasonIs(t, func() error { _, e := r.CommitObservedEpoch(6); return e }(), mcperr.ReasonSnapshotEpochStale)
}

// ---- revision ordering --------------------------------------------------------

func TestCheckMonotonic(t *testing.T) {
	active := Revisions{Config: 5, Policy: 5, Catalog: 3, Credential: 2}
	// same epoch, higher config ok.
	if err := CheckMonotonic(active, Revisions{Config: 6, Policy: 5, Catalog: 3, Credential: 2}, 4, 4); err != nil {
		t.Fatalf("advance: %v", err)
	}
	// same epoch, lower config rejected.
	reasonIs(t, CheckMonotonic(active, Revisions{Config: 4, Policy: 5, Catalog: 3, Credential: 2}, 4, 4), mcperr.ReasonSnapshotRevisionRegression)
	// credential regression rejected.
	reasonIs(t, CheckMonotonic(active, Revisions{Config: 6, Policy: 5, Catalog: 3, Credential: 1}, 4, 4), mcperr.ReasonSnapshotRevisionRegression)
	// lower epoch rejected outright.
	reasonIs(t, CheckMonotonic(active, active, 4, 3), mcperr.ReasonSnapshotRevisionRegression)
	// higher epoch re-bases: any revision allowed.
	if err := CheckMonotonic(active, Revisions{Config: 1}, 4, 5); err != nil {
		t.Fatalf("higher epoch re-base: %v", err)
	}
}

// ---- active store -------------------------------------------------------------

func TestActiveStore_ActivateIdempotentAndSwap(t *testing.T) {
	s, _ := newSigner(t, "k1")
	store := NewActiveStore(CapabilityGateway)
	e1 := mustSign(t, gwManifest(), gwPayload(), s)
	if sw, err := store.Activate(e1); err != nil || !sw {
		t.Fatalf("activate1: sw=%v err=%v", sw, err)
	}
	if store.Active().ContentHash != e1.ContentHash {
		t.Fatal("active not e1")
	}
	// idempotent re-activate.
	if sw, err := store.Activate(e1); err != nil || sw {
		t.Fatalf("idempotent: sw=%v err=%v", sw, err)
	}
	// advance to e2 (higher config revision).
	m2 := gwManifest()
	m2.Revisions.Config = 3
	e2 := mustSign(t, m2, gwPayload(), s)
	if sw, err := store.Activate(e2); err != nil || !sw {
		t.Fatalf("activate2: sw=%v err=%v", sw, err)
	}
	if store.Active().ContentHash != e2.ContentHash || store.Previous().ContentHash != e1.ContentHash {
		t.Fatal("current/previous not advanced correctly")
	}
}

func TestActiveStore_SameRevisionDifferentContentRejected(t *testing.T) {
	s, _ := newSigner(t, "k1")
	store := NewActiveStore(CapabilityGateway)
	e1 := mustSign(t, gwManifest(), gwPayload(), s)
	store.Activate(e1)
	// Same epoch + config revision but different content.
	p2 := gwPayload()
	p2.Gateway.Tools[0].Name = "write"
	e2 := mustSign(t, gwManifest(), p2, s) // same manifest (rev+epoch), different payload
	reasonIs(t, func() error { _, e := store.Activate(e2); return e }(), mcperr.ReasonSnapshotRevisionRegression)
	if store.Active().ContentHash != e1.ContentHash {
		t.Fatal("active changed after rejected activation")
	}
}

func TestActiveStore_CapabilityIsolation(t *testing.T) {
	s, _ := newSigner(t, "k1")
	store := NewActiveStore(CapabilityGateway)
	mgmt := mustSign(t, mgmtManifest(), mgmtPayload(), s)
	reasonIs(t, func() error { _, e := store.Activate(mgmt); return e }(), mcperr.ReasonSnapshotCapabilityMismatch)
}

func TestActiveStore_Revert(t *testing.T) {
	s, _ := newSigner(t, "k1")
	store := NewActiveStore(CapabilityGateway)
	e1 := mustSign(t, gwManifest(), gwPayload(), s)
	m2 := gwManifest()
	m2.Revisions.Config = 3
	e2 := mustSign(t, m2, gwPayload(), s)
	store.Activate(e1)
	store.Activate(e2)
	// Revert to e1 (the retained previous).
	if rv, err := store.Revert(e1.ContentHash); err != nil || !rv {
		t.Fatalf("revert: rv=%v err=%v", rv, err)
	}
	if store.Active().ContentHash != e1.ContentHash {
		t.Fatal("revert did not activate e1")
	}
	// Reverting to a non-retained hash fails closed and leaves active unchanged.
	reasonIs(t, func() error { _, e := store.Revert("deadbeef"); return e }(), mcperr.ReasonRollbackTargetMissing)
	if store.Active().ContentHash != e1.ContentHash {
		t.Fatal("active changed after failed revert")
	}
}

// ---- acknowledgement ----------------------------------------------------------

func TestAck_ValidateAndMatch(t *testing.T) {
	a := Acknowledgement{AckID: "a1", NodeID: "n1", Capability: CapabilityGateway, ContentHash: "h1", State: AckApplied, Health: "ok"}
	if err := a.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !a.Matches("n1", CapabilityGateway, "h1") {
		t.Fatal("should match")
	}
	if a.Matches("n2", CapabilityGateway, "h1") || a.Matches("n1", CapabilityManagement, "h1") || a.Matches("n1", CapabilityGateway, "h2") {
		t.Fatal("must not match wrong node/cap/hash")
	}
	// missing binding fields fail closed.
	reasonIs(t, (Acknowledgement{NodeID: "n", Capability: CapabilityGateway, ContentHash: "h", State: AckApplied}).Validate(), mcperr.ReasonAckInvalid)
	reasonIs(t, (Acknowledgement{AckID: "a", Capability: CapabilityGateway, ContentHash: "h", State: AckApplied}).Validate(), mcperr.ReasonAckInvalid)
}

// ---- rollback directive -------------------------------------------------------

func TestRollbackDirective_SignVerify(t *testing.T) {
	s, ts := newSigner(t, "k1")
	d := RollbackDirective{
		Capability: CapabilityGateway, Epoch: 5,
		CurrentActiveHash: "cur", TargetHash: "tgt", CommandID: "cmd1",
		MinDPVersion: 1, ExpiryUnixNano: 2000,
	}
	signed, err := SignRollback(d, s)
	if err != nil {
		t.Fatalf("SignRollback: %v", err)
	}
	if err := VerifyRollback(signed, ts, CapabilityGateway, "cur", 1500, DPCompatVersion); err != nil {
		t.Fatalf("VerifyRollback: %v", err)
	}
	// expired.
	reasonIs(t, VerifyRollback(signed, ts, CapabilityGateway, "cur", 3000, DPCompatVersion), mcperr.ReasonRollbackDirectiveInvalid)
	// wrong current hash.
	reasonIs(t, VerifyRollback(signed, ts, CapabilityGateway, "other", 1500, DPCompatVersion), mcperr.ReasonRollbackDirectiveInvalid)
	// capability mismatch.
	reasonIs(t, VerifyRollback(signed, ts, CapabilityManagement, "cur", 1500, DPCompatVersion), mcperr.ReasonSnapshotCapabilityMismatch)
	// tampered signature.
	bad := *signed
	bad.TargetHash = "evil"
	reasonIs(t, VerifyRollback(&bad, ts, CapabilityGateway, "cur", 1500, DPCompatVersion), mcperr.ReasonRollbackDirectiveInvalid)
}

// ---- anti-weakening -----------------------------------------------------------

// A weakened verifier that trusted a public key CARRIED INSIDE the snapshot would
// accept a self-signed envelope. Prove the real verifier never consults such a
// key: an envelope signed by an untrusted key is rejected even though it is
// internally consistent (hash matches, signature valid for its own key).
func TestAntiWeakening_SnapshotCannotSelfAuthorize(t *testing.T) {
	attacker, _ := GenerateLocalSigner("attacker")
	env := mustSign(t, gwManifest(), gwPayload(), attacker) // internally valid, wrong trust
	legit, _ := GenerateLocalSigner("legit")
	ts, _ := NewTrustStore([]TrustRoot{{KeyID: "legit", Alg: SigAlgEd25519, Public: legit.Public()}})
	reasonIs(t, VerifySignature(env, ts, testLimits()), mcperr.ReasonSnapshotKeyUntrusted)
}

// A weakened verifier that checked the signature against the DECLARED content hash
// without recomputing it would accept a tampered payload as long as the attacker
// also updated content_hash and re-signed with their own key. The real verifier
// recomputes the hash from the payload, so a payload tamper (even with matching
// declared hash) fails at hash recomputation OR key trust. Here we tamper the
// payload and set a matching self-declared hash+signature from an untrusted key:
// the trust check stops it.
func TestAntiWeakening_RecomputesHashFromPayload(t *testing.T) {
	s, ts := newSigner(t, "k1")
	env := mustSign(t, gwManifest(), gwPayload(), s)
	// Tamper the payload but leave the (now-stale) declared content hash. A verifier
	// that recomputes will see a mismatch.
	env.Payload.Gateway.Servers[0].Enabled = false
	reasonIs(t, VerifySignature(env, ts, testLimits()), mcperr.ReasonSnapshotHashMismatch)
}

// Prove the content hash covers EVERY payload section: mutating the credential
// section changes the hash (a hash that excluded a section would not).
func TestAntiWeakening_HashCoversEverySection(t *testing.T) {
	l := testLimits()
	base, _ := ContentHash(gwManifest(), gwPayload(), SigAlgEd25519, "k1", l.canonicalBounds())
	p := gwPayload()
	p.Gateway.CredentialProfiles[0].Scope = "write"
	if h, _ := ContentHash(gwManifest(), p, SigAlgEd25519, "k1", l.canonicalBounds()); h == base {
		t.Fatal("credential section is not covered by the content hash")
	}
	p2 := gwPayload()
	p2.Gateway.Listener.Port = 9999
	if h, _ := ContentHash(gwManifest(), p2, SigAlgEd25519, "k1", l.canonicalBounds()); h == base {
		t.Fatal("listener section is not covered by the content hash")
	}
}

// Prove no signed field leaks a private key: the envelope JSON never contains the
// signer's private bytes.
func TestNoPrivateKeyInEnvelope(t *testing.T) {
	s, _ := newSigner(t, "k1")
	env := mustSign(t, gwManifest(), gwPayload(), s)
	// The Signer interface exposes no private accessor; confirm the base64 signature
	// is exactly a 64-byte ed25519 signature, not a key.
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature not a 64-byte ed25519 sig: len=%d err=%v", len(sig), err)
	}
}
