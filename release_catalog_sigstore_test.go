package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

// ─── test harness ─────────────────────────────────────────────────────────────

// matchingIdentity is a SAN that satisfies officialSigstoreSANRegex (a tagged
// release run of THIS repo's pinned signing workflow, ci.yml). Used to mint a
// leaf cert in the virtual CA.
const matchingIdentity = "https://github.com/KidCarmi/Culvert/.github/workflows/ci.yml@refs/tags/v1.2.3"

// wrongWorkflowIdentity is a tagged release of THIS repo but a DIFFERENT workflow
// file (release.yml) — it must be REJECTED now that the SAN is pinned to ci.yml
// (P2b-2 security review P0-1: narrow the signing surface to one workflow).
const wrongWorkflowIdentity = "https://github.com/KidCarmi/Culvert/.github/workflows/release.yml@refs/tags/v1.2.3"

// newTestSigstore builds a VirtualSigstore (offline Fulcio + Rekor + CT) and a
// verifier pinned to the official identity, both backed by the SAME trust
// material so a signature minted by the CA verifies against the verifier.
func newTestSigstore(t *testing.T) (*ca.VirtualSigstore, *sigstoreVerifier) {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	sv, err := newSigstoreVerifierFromMaterial(vs, officialSigstoreIdentity())
	if err != nil {
		t.Fatalf("newSigstoreVerifierFromMaterial: %v", err)
	}
	return vs, sv
}

// ─── identity verification (the security kernel) ──────────────────────────────

// A signature minted by the pinned workflow identity over the exact index bytes
// verifies. This exercises the REAL sigstore path: Fulcio chain → identity policy
// → Rekor inclusion proof → integrated-timestamp validity → artifact binding.
func TestSigstore_AcceptsPinnedIdentity(t *testing.T) {
	vs, sv := newTestSigstore(t)
	idx := []byte(`{"schema_version":1,"releases":[]}`)
	entity, err := vs.Sign(matchingIdentity, officialSigstoreIssuer, idx)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sv.verifyIndexEntity(idx, entity); err != nil {
		t.Fatalf("verifyIndexEntity: unexpected error: %v", err)
	}
}

// A signature over different bytes than the index is rejected (artifact binding).
func TestSigstore_RejectsTamperedArtifact(t *testing.T) {
	vs, sv := newTestSigstore(t)
	idx := []byte(`{"schema_version":1,"releases":[]}`)
	entity, err := vs.Sign(matchingIdentity, officialSigstoreIssuer, idx)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tampered := append(append([]byte(nil), idx...), ' ')
	if err := sv.verifyIndexEntity(tampered, entity); !errors.Is(err, errSigstoreVerify) {
		t.Fatalf("tampered artifact: err = %v; want errSigstoreVerify", err)
	}
}

// A signature from a DIFFERENT SAN (not the pinned workflow) is rejected even
// though the cert chains to the trusted Fulcio root — identity is enforced.
func TestSigstore_RejectsWrongSAN(t *testing.T) {
	vs, sv := newTestSigstore(t)
	idx := []byte(`{"schema_version":1,"releases":[]}`)
	// A SAN for the WRONG repo / a branch ref — fails the anchored regex.
	entity, err := vs.Sign("https://github.com/attacker/evil/.github/workflows/release.yml@refs/heads/main", officialSigstoreIssuer, idx)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sv.verifyIndexEntity(idx, entity); !errors.Is(err, errSigstoreVerify) {
		t.Fatalf("wrong SAN: err = %v; want errSigstoreVerify", err)
	}
}

// A signature with the right SAN but a DIFFERENT OIDC issuer is rejected.
func TestSigstore_RejectsWrongIssuer(t *testing.T) {
	vs, sv := newTestSigstore(t)
	idx := []byte(`{"schema_version":1,"releases":[]}`)
	entity, err := vs.Sign(matchingIdentity, "https://accounts.google.com", idx)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sv.verifyIndexEntity(idx, entity); !errors.Is(err, errSigstoreVerify) {
		t.Fatalf("wrong issuer: err = %v; want errSigstoreVerify", err)
	}
}

// A signature from a DIFFERENT workflow file of THIS repo, on a tag, is rejected:
// the SAN is pinned to ci.yml, so release.yml@refs/tags/v* must not verify.
func TestSigstore_RejectsWrongWorkflowFile(t *testing.T) {
	vs, sv := newTestSigstore(t)
	idx := []byte(`{"schema_version":1,"releases":[]}`)
	entity, err := vs.Sign(wrongWorkflowIdentity, officialSigstoreIssuer, idx)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sv.verifyIndexEntity(idx, entity); !errors.Is(err, errSigstoreVerify) {
		t.Fatalf("wrong workflow file: err = %v; want errSigstoreVerify", err)
	}
}

// The baked embed is the real Sigstore public-good trusted_root.json (P2b-2a):
// it must be non-empty and parse via the same path the verifier uses, with
// Fulcio + Rekor + CT material present (guards against baking the wrong artifact,
// e.g. TUF root.json metadata).
func TestSigstore_BakedRootCanBeParsed(t *testing.T) {
	if len(bytes.TrimSpace(bakedSigstoreTrustedRootJSON)) == 0 {
		t.Fatal("baked trusted_root.json is empty; P2b-2a must bake the official root")
	}
	tr, err := root.NewTrustedRootFromJSON(bakedSigstoreTrustedRootJSON)
	if err != nil {
		t.Fatalf("baked trusted_root.json does not parse via root.NewTrustedRootFromJSON: %v", err)
	}
	if len(tr.FulcioCertificateAuthorities()) == 0 {
		t.Error("baked root has no Fulcio certificate authorities")
	}
	if len(tr.RekorLogs()) == 0 {
		t.Error("baked root has no Rekor transparency logs")
	}
	// The baked root must also drive a usable verifier under the official identity.
	if _, err := newSigstoreVerifier(bakedSigstoreTrustedRootJSON, officialSigstoreIdentity()); err != nil {
		t.Fatalf("newSigstoreVerifier with the baked root failed: %v", err)
	}
}

// Malformed bundle JSON is a clean malformed error, not a panic or a bypass.
func TestSigstore_MalformedBundle(t *testing.T) {
	_, sv := newTestSigstore(t)
	if err := sv.verifyIndexBundle([]byte("idx"), []byte("this is not a bundle")); !errors.Is(err, errSigstoreMalformed) {
		t.Fatalf("malformed bundle: err = %v; want errSigstoreMalformed", err)
	}
}

// The verifier constructor rejects an incomplete identity policy (fail-closed).
func TestSigstore_RequiresFullIdentity(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	for _, id := range []sigstoreIdentity{
		{Issuer: "", SANRegex: officialSigstoreSANRegex},
		{Issuer: officialSigstoreIssuer, SANRegex: ""},
	} {
		if _, err := newSigstoreVerifierFromMaterial(vs, id); !errors.Is(err, errSigstoreConfig) {
			t.Fatalf("identity %+v: err = %v; want errSigstoreConfig", id, err)
		}
	}
}

// ─── scheme selection (downgrade-safe composition) ────────────────────────────

// memDualSource is an in-memory SignatureSource + sigstoreSource that can supply
// BOTH sidecars (ed25519 .sig and the .sigstore bundle) with independently
// injectable read errors, so verifyIndexSignature's tri-state precedence rule can
// be exercised exhaustively. It deliberately implements ONLY the two sidecar reads
// (not ReadIndex/ReadManifest) — verifyIndexSignature takes a SignatureSource and
// type-asserts sigstoreSource, nothing more.
type memDualSource struct {
	sig       []byte
	sigErr    error
	bundle    []byte
	bundleErr error
}

func (m *memDualSource) ReadSignature() ([]byte, error)      { return m.sig, m.sigErr }
func (m *memDualSource) ReadSigstoreBundle() ([]byte, error) { return m.bundle, m.bundleErr }

// dualTrust builds a TrustStore carrying BOTH a (valid) ed25519 key for idx and a
// Sigstore verifier, plus the matching ed25519 signature envelope bytes.
func dualTrust(t *testing.T, idx []byte, mode VerifyMode) (TrustStore, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sigEnv := sigEnvelopeBytes(t, catalogSigAlg, "k1", ed25519.Sign(priv, idx))
	_, sv := newTestSigstore(t)
	ts, err := NewTrustStoreWithSigstore([]TrustKey{{KeyID: "k1", Alg: catalogSigAlg, PublicKey: pub}}, mode, sv)
	if err != nil {
		t.Fatalf("NewTrustStoreWithSigstore: %v", err)
	}
	return ts, sigEnv
}

// .sigstore absent (fs.ErrNotExist) ⇒ fall through to a VALID ed25519 sig ⇒ accept.
func TestScheme_SigstoreAbsentFallsThroughToEd25519(t *testing.T) {
	idx := []byte("the-index")
	ts, sigEnv := dualTrust(t, idx, VerifyEnforce)
	src := &memDualSource{sig: sigEnv, bundleErr: fs.ErrNotExist}
	if err := verifyIndexSignature(idx, src, ts); err != nil {
		t.Fatalf("sigstore-absent + valid ed25519: err = %v; want accept", err)
	}
}

// .sigstore PRESENT but invalid ⇒ REJECT even though the ed25519 sig is valid.
// This is the artifact-owns-outcome / strip-one-sig downgrade guard.
func TestScheme_SigstorePresentInvalidNoEd25519Fallback(t *testing.T) {
	idx := []byte("the-index")
	ts, sigEnv := dualTrust(t, idx, VerifyEnforce)
	src := &memDualSource{sig: sigEnv, bundle: []byte("garbage-not-a-bundle")}
	err := verifyIndexSignature(idx, src, ts)
	if err == nil {
		t.Fatal("present-but-invalid .sigstore with a valid ed25519 sig was ACCEPTED; downgrade vector open")
	}
	if errors.Is(err, errSigVerify) {
		t.Fatalf("rejection came from the ed25519 path (%v); the sigstore artifact must own the outcome", err)
	}
}

// .sigstore unreadable (non-ErrNotExist) ⇒ REJECT, no fall-through.
func TestScheme_SigstoreUnreadableNoFallback(t *testing.T) {
	idx := []byte("the-index")
	ts, sigEnv := dualTrust(t, idx, VerifyEnforce)
	src := &memDualSource{sig: sigEnv, bundleErr: errors.New("permission denied")}
	if err := verifyIndexSignature(idx, src, ts); err == nil {
		t.Fatal("unreadable .sigstore was accepted via ed25519 fall-through; want reject")
	}
}

// Both sidecars absent + enforce ⇒ reject as unsigned.
func TestScheme_BothAbsentEnforceRejects(t *testing.T) {
	idx := []byte("the-index")
	ts, _ := dualTrust(t, idx, VerifyEnforce)
	src := &memDualSource{sigErr: fs.ErrNotExist, bundleErr: fs.ErrNotExist}
	if err := verifyIndexSignature(idx, src, ts); !errors.Is(err, errSigMissing) {
		t.Fatalf("both absent + enforce: err = %v; want errSigMissing", err)
	}
}

// Both sidecars absent + permissive ⇒ load with warning (break-glass).
func TestScheme_BothAbsentPermissiveLoads(t *testing.T) {
	idx := []byte("the-index")
	ts, _ := dualTrust(t, idx, VerifyPermissive)
	src := &memDualSource{sigErr: fs.ErrNotExist, bundleErr: fs.ErrNotExist}
	if err := verifyIndexSignature(idx, src, ts); err != nil {
		t.Fatalf("both absent + permissive: err = %v; want load", err)
	}
}

// A source that cannot supply a .sigstore (no sigstoreSource impl) is treated as
// sigstore-absent and falls through to a valid ed25519 sig ⇒ accept.
func TestScheme_NonSigstoreSourceFallsThrough(t *testing.T) {
	idx := []byte("the-index")
	ts, sigEnv := dualTrust(t, idx, VerifyEnforce)
	// memSignedSource (release_catalog_verify_test.go) implements ReadSignature
	// but NOT ReadSigstoreBundle.
	src := &memSignedSource{index: idx, sig: sigEnv}
	if err := verifyIndexSignature(idx, src, ts); err != nil {
		t.Fatalf("non-sigstore source + valid ed25519: err = %v; want accept", err)
	}
}

// ─── enforce-mode composition (either scheme satisfies non-emptiness) ──────────

// A Sigstore-only trust store (no ed25519 keys) is valid in enforce mode.
func TestTrustStore_SigstoreOnlyEnforceOK(t *testing.T) {
	_, sv := newTestSigstore(t)
	if _, err := NewTrustStoreWithSigstore(nil, VerifyEnforce, sv); err != nil {
		t.Fatalf("sigstore-only enforce store: %v", err)
	}
}

// No scheme at all in enforce mode still fails closed.
func TestTrustStore_NoSchemeEnforceFails(t *testing.T) {
	if _, err := NewTrustStoreWithSigstore(nil, VerifyEnforce, nil); err == nil {
		t.Fatal("empty enforce store (no ed25519, no sigstore) must fail closed")
	}
}

// ─── wiring resolution ─────────────────────────────────────────────────────────

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// Default build (baked official root, no override) ⇒ scheme ACTIVE, no warn/error
// (P2b-2a — the embed is no longer empty).
func TestResolveSigstoreWiring_BakedRootActive(t *testing.T) {
	w := resolveSigstoreWiring(env(nil))
	if !w.active || w.verifier == nil || w.err != nil || w.warn != "" {
		t.Fatalf("baked root should activate the scheme silently; got %+v", w)
	}
}

// Identity override set WITHOUT a trusted root ⇒ inactive + a visible warning.
// With the official root now baked, "no root" is reachable only by overriding the
// trusted-root path with an EMPTY file (deactivation).
func TestResolveSigstoreWiring_IdentityWithoutRootWarns(t *testing.T) {
	emptyRoot := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(emptyRoot, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w := resolveSigstoreWiring(env(map[string]string{
		envReleaseSigstoreIdentity:    `{"issuer":"https://x","san_regex":"^https://y$"}`,
		envReleaseSigstoreTrustedRoot: emptyRoot,
	}))
	if w.active || w.verifier != nil {
		t.Fatalf("identity without root must stay inactive; got %+v", w)
	}
	if w.warn == "" {
		t.Fatal("identity without root should warn (not silently dormant)")
	}
}

// Malformed identity override ⇒ fatal config error (Release Management disabled).
func TestResolveSigstoreWiring_BadIdentityErrors(t *testing.T) {
	w := resolveSigstoreWiring(env(map[string]string{
		envReleaseSigstoreIdentity: `{"issuer":"only-issuer"}`,
	}))
	if w.err == nil {
		t.Fatal("identity missing san_regex should error")
	}
}

// A trusted-root override path that cannot be read ⇒ fatal config error.
func TestResolveSigstoreWiring_BadRootPathErrors(t *testing.T) {
	w := resolveSigstoreWiring(env(map[string]string{
		envReleaseSigstoreTrustedRoot: filepath.Join(t.TempDir(), "does-not-exist.json"),
	}))
	if w.err == nil {
		t.Fatal("unreadable trusted-root path should error")
	}
}

// An empty trusted-root override file is treated as no-root (dormant) — the
// supported way to DEACTIVATE the keyless scheme now that the official root is
// baked.
func TestResolveSigstoreWiring_EmptyRootPathDormant(t *testing.T) {
	p := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w := resolveSigstoreWiring(env(map[string]string{envReleaseSigstoreTrustedRoot: p}))
	if w.active || w.err != nil {
		t.Fatalf("empty root file should be dormant; got %+v", w)
	}
}
