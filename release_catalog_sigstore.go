// Release Catalog Keyless Trust — P2b-1 (Sigstore-identity verifier).
//
// Adds a SECOND catalog-signature scheme that coexists with the ed25519 scheme
// (release_catalog_verify.go): a cosign "keyless" bundle (Fulcio cert + signature
// + Rekor inclusion proof) over the RAW index.json bytes, verified offline against
// a baked Sigstore TUF trusted root plus a PINNED workflow identity (issuer + SAN
// regex). Because the index binds every manifest by manifest_sha256, one signature
// over one document authenticates the whole catalog — same kernel as ed25519.
//
// Trust model: NO private key exists anywhere (keyless). Trust is "this exact
// GitHub Actions workflow, on a release tag, signed via Fulcio". Verification is
// fully offline: the bundle carries its own Rekor inclusion proof + integrated
// timestamp, and the trusted root is baked, so nothing reaches sigstore.dev at
// runtime (air-gap safe).
//
// Scope (roadmap/D1.6d-P2b-sigstore-identity-trust-plan.md): P2b-1 shipped the
// verifier, the .sigstore sidecar source, scheme selection, and wiring resolution.
// As of P2b-2a the official Sigstore public-good trusted root is BAKED into the
// embed below, so the scheme is ACTIVE by default (an operator can override or
// deactivate it via CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT). NO release-side signing
// yet — CI keyless signing + the end-to-end/image-sig gates are P2b-2b. Verifying
// identity (cert chain + SAN + issuer) happens BEFORE any other bundle content is
// trusted.
package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"
)

// bakedSigstoreTrustedRootJSON is the BAKED Sigstore trusted root (Fulcio CA +
// Rekor/CT log keys + TSA) used for OFFLINE keyless verification. It is the
// Sigstore public-good `trusted_root.json` (P2b-2a), so the Sigstore scheme is
// ACTIVE by default — an operator may override it via
// CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT (e.g. a fresher root after key rotation,
// or an empty file to deactivate). PUBLIC trust material only — never private
// keys. Provenance + refresh procedure: trusted_root.provenance.txt and
// docs/operator/sigstore-trusted-root-lifecycle.md.
//
//go:embed trusted_root.json
var bakedSigstoreTrustedRootJSON []byte

// sigstoreSigAlg labels the Sigstore scheme in logs/metadata (parallels
// catalogSigAlg for ed25519). It is not a wire value.
const sigstoreSigAlg = "sigstore"

// officialSigstoreIssuer / officialSigstoreSANRegex are the PINNED identity of the
// official release-signing workflow (plan §"Identity-policy specificity"):
//   - issuer EXACTLY the GitHub Actions OIDC issuer (no regex — exact match),
//   - SAN anchored to the full repo slug AND the EXACT signing workflow file
//     (`ci.yml`) AND a release TAG ref, so ONLY a tagged release run of this repo's
//     `ci.yml` can mint a catalog-valid identity (P2b-2 security review P0-1).
//
// The `ci\.yml` pin (vs a `[^@]+` workflow wildcard) keeps the signing surface to
// the one intended workflow. Cost: renaming the signing workflow file needs a
// coordinated identity update + overlap window — see
// docs/operator/sigstore-trusted-root-lifecycle.md.
const (
	officialSigstoreIssuer   = "https://token.actions.githubusercontent.com"
	officialSigstoreSANRegex = `^https://github\.com/KidCarmi/Culvert/\.github/workflows/ci\.yml@refs/tags/v.*$`
)

// Distinct sigstore error kinds (parallel to the ed25519 errSig* set) so callers/
// tests/alerting can tell a keyless-authenticity failure apart from the others.
var (
	errSigstoreMalformed = errors.New("release catalog: sigstore bundle malformed")
	errSigstoreOversize  = errors.New("release catalog: sigstore bundle exceeds size bound")
	errSigstoreVerify    = errors.New("release catalog: sigstore verification failed")
	errSigstoreConfig    = errors.New("release catalog: sigstore verifier config")
)

// sigstoreIdentity is the pinned certificate identity a keyless catalog signature
// must carry: an EXACT OIDC issuer and an anchored SAN regex. Both are required.
type sigstoreIdentity struct {
	Issuer   string `json:"issuer"`
	SANRegex string `json:"san_regex"`
}

// officialSigstoreIdentity returns the baked default identity policy. It is only
// ACTIVE when a trusted root is present (baked in P2b-2 or operator-supplied).
func officialSigstoreIdentity() sigstoreIdentity {
	return sigstoreIdentity{Issuer: officialSigstoreIssuer, SANRegex: officialSigstoreSANRegex}
}

// sigstoreVerifier verifies a cosign keyless bundle over the raw index bytes
// against a fixed TrustedMaterial (Fulcio/Rekor/CT roots) and a pinned identity.
// It is immutable after construction and safe for concurrent use.
type sigstoreVerifier struct {
	v  *verify.Verifier
	id verify.CertificateIdentity
}

// newSigstoreVerifier builds a verifier from a Sigstore TUF trusted-root JSON
// snapshot (baked or operator-supplied) and a pinned identity policy. The trusted
// root carries the Fulcio CA + Rekor log keys needed for offline verification.
func newSigstoreVerifier(trustedRootJSON []byte, id sigstoreIdentity) (*sigstoreVerifier, error) {
	tm, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: trusted root: %v", errSigstoreConfig, err)
	}
	return newSigstoreVerifierFromMaterial(tm, id)
}

// newSigstoreVerifierFromMaterial is the test-friendly core: it takes any
// root.TrustedMaterial (production passes a parsed trusted root; tests pass a
// VirtualSigstore) and the identity policy. The verifier is configured for OFFLINE
// keyless verification: it requires a Rekor transparency-log entry and uses the
// bundle's INTEGRATED (log-embedded) timestamp — never wall-clock — so a checked-in
// fixture bundle verifies indefinitely and no network is contacted at runtime.
func newSigstoreVerifierFromMaterial(tm root.TrustedMaterial, id sigstoreIdentity) (*sigstoreVerifier, error) {
	if strings.TrimSpace(id.Issuer) == "" || strings.TrimSpace(id.SANRegex) == "" {
		return nil, fmt.Errorf("%w: identity requires both issuer and san_regex", errSigstoreConfig)
	}
	v, err := verify.NewVerifier(tm,
		verify.WithTransparencyLog(1),
		verify.WithIntegratedTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: build verifier: %v", errSigstoreConfig, err)
	}
	// Exact issuer (issuerRegex empty), anchored SAN regex (sanValue empty).
	certID, err := verify.NewShortCertificateIdentity(id.Issuer, "", "", id.SANRegex)
	if err != nil {
		return nil, fmt.Errorf("%w: identity policy: %v", errSigstoreConfig, err)
	}
	return &sigstoreVerifier{v: v, id: certID}, nil
}

// verifyIndexBundle parses an UNTRUSTED cosign bundle JSON and verifies it over the
// exact index bytes. It returns nil only if the bundle's Fulcio cert chains to the
// trusted root, the cert identity matches the pinned issuer+SAN, the Rekor proof is
// valid, and the signature covers idxBytes. The identity is enforced as part of the
// policy, so a bundle from a DIFFERENT identity is rejected even if otherwise valid.
func (s *sigstoreVerifier) verifyIndexBundle(idxBytes, bundleJSON []byte) error {
	pb := new(protobundle.Bundle)
	if err := protojson.Unmarshal(bundleJSON, pb); err != nil {
		return fmt.Errorf("%w: %v", errSigstoreMalformed, err)
	}
	b, err := sgbundle.NewBundle(pb)
	if err != nil {
		return fmt.Errorf("%w: %v", errSigstoreMalformed, err)
	}
	return s.verifyIndexEntity(idxBytes, b)
}

// verifyIndexEntity is the parsed-entity core (production passes a *bundle.Bundle;
// tests pass a VirtualSigstore TestEntity). It binds the artifact (raw index bytes)
// and the pinned certificate identity into a single policy so the verify call
// proves authenticity AND identity together.
func (s *sigstoreVerifier) verifyIndexEntity(idxBytes []byte, entity verify.SignedEntity) error {
	_, err := s.v.Verify(entity, verify.NewPolicy(
		verify.WithArtifact(bytes.NewReader(idxBytes)),
		verify.WithCertificateIdentity(s.id),
	))
	if err != nil {
		return fmt.Errorf("%w: %v", errSigstoreVerify, err)
	}
	return nil
}

// ─── .sigstore sidecar source ────────────────────────────────────────────────

// sigstoreSource yields the detached cosign bundle for the index. It is OPTIONAL:
// a source that does not implement it is treated as "no .sigstore present" (the
// scheme falls through to ed25519), never as a bypass.
type sigstoreSource interface {
	// ReadSigstoreBundle returns the raw index.json.sigstore bytes (bounded). A
	// MISSING bundle MUST satisfy errors.Is(err, fs.ErrNotExist) so scheme
	// selection can tell "absent" (fall through) apart from "unreadable" (reject).
	ReadSigstoreBundle() ([]byte, error)
}

// ReadSigstoreBundle reads <dir>/index.json.sigstore with the same symlink-
// refusing, size-bounded discipline as every other dir-source read.
func (s *dirCatalogSource) ReadSigstoreBundle() ([]byte, error) {
	return catalogReadBounded(filepath.Join(s.dir, "index.json.sigstore"))
}

// ─── wiring config resolution ─────────────────────────────────────────────────

// parseSigstoreIdentity parses the operator override JSON ({"issuer","san_regex"}).
// Empty input ⇒ no override (caller uses the baked default).
func parseSigstoreIdentity(raw string) (sigstoreIdentity, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return sigstoreIdentity{}, false, nil
	}
	var id sigstoreIdentity
	if err := json.Unmarshal([]byte(raw), &id); err != nil {
		return sigstoreIdentity{}, false, fmt.Errorf("%s must be JSON {\"issuer\",\"san_regex\"}: %w", envReleaseSigstoreIdentity, err)
	}
	if strings.TrimSpace(id.Issuer) == "" || strings.TrimSpace(id.SANRegex) == "" {
		return sigstoreIdentity{}, false, fmt.Errorf("%s requires both issuer and san_regex", envReleaseSigstoreIdentity)
	}
	return id, true, nil
}

// sigstoreWiring is the resolved Sigstore trust configuration for startup.
type sigstoreWiring struct {
	verifier *sigstoreVerifier // nil ⇒ scheme not active
	active   bool              // true ⇒ a trusted root is present and a verifier was built
	warn     string            // loud one-line startup note ("" ⇒ none)
	err      error             // fatal config error ⇒ Release Management disabled
}

// resolveSigstoreWiring builds the Sigstore verifier from the trusted root (baked
// embed, or an operator-supplied path via CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT)
// and the identity policy (baked official default, or an operator override via
// CULVERT_RELEASE_SIGSTORE_IDENTITY). With no root present the scheme is INACTIVE
// (verifier nil) — and if an identity override was set without a root, it warns so
// the misconfiguration is visible rather than silently dormant.
func resolveSigstoreWiring(getenv func(string) string) sigstoreWiring {
	rootJSON, err := loadSigstoreTrustedRoot(getenv)
	if err != nil {
		return sigstoreWiring{err: err}
	}
	id, overridden, err := parseSigstoreIdentity(getenv(envReleaseSigstoreIdentity))
	if err != nil {
		return sigstoreWiring{err: err}
	}
	if !overridden {
		id = officialSigstoreIdentity()
	}

	if len(bytes.TrimSpace(rootJSON)) == 0 {
		if overridden {
			return sigstoreWiring{warn: "release catalog: " + envReleaseSigstoreIdentity +
				" is set but the Sigstore trusted root is empty; the keyless scheme is INACTIVE " +
				"(restore the baked root or set " + envReleaseSigstoreTrustedRoot + " to a valid root)"}
		}
		// Reached only when an operator OVERRIDES the (now baked, non-empty) root
		// with an empty file — the supported deactivation path. Dormant, no warning.
		return sigstoreWiring{}
	}

	sv, err := newSigstoreVerifier(rootJSON, id)
	if err != nil {
		return sigstoreWiring{err: err}
	}
	return sigstoreWiring{verifier: sv, active: true}
}

// loadSigstoreTrustedRoot returns the trusted-root JSON: the operator override file
// (if CULVERT_RELEASE_SIGSTORE_TRUSTED_ROOT is set) else the baked embed.
func loadSigstoreTrustedRoot(getenv func(string) string) ([]byte, error) {
	path := strings.TrimSpace(getenv(envReleaseSigstoreTrustedRoot))
	if path == "" {
		return bakedSigstoreTrustedRootJSON, nil
	}
	// #nosec G304 -- operator-provided trusted-root path (break-glass, host-trusted env var)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: read trusted root: %w", envReleaseSigstoreTrustedRoot, err)
	}
	return b, nil
}
