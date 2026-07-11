package main

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// parseReleaseIdentityEnv reads the KEY=VALUE lines of release_identity.env
// (ignoring blanks/comments). Values are taken verbatim (no quote stripping) so
// the SAN regex compares byte-for-byte with the Go constant.
func parseReleaseIdentityEnv(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open("release_identity.env")
	if err != nil {
		t.Fatalf("open release_identity.env: %v", err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = v
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan release_identity.env: %v", err)
	}
	return out
}

// TestReleaseIdentitySSOT pins the single-source-of-truth invariant (P2b-2b): the
// issuer + SAN regex that CI feeds to the image-signature `cosign verify` gate
// (release_identity.env) MUST be byte-identical to the in-binary catalog verifier's
// pinned identity (officialSigstore* constants). If they ever drift, an image could
// verify under one identity while the catalog verifier pins another.
func TestReleaseIdentitySSOT(t *testing.T) {
	env := parseReleaseIdentityEnv(t)
	if got := env["CULVERT_RELEASE_SIGSTORE_ISSUER"]; got != officialSigstoreIssuer {
		t.Errorf("issuer drift: release_identity.env=%q officialSigstoreIssuer=%q", got, officialSigstoreIssuer)
	}
	if got := env["CULVERT_RELEASE_SIGSTORE_SAN_REGEX"]; got != officialSigstoreSANRegex {
		t.Errorf("SAN regex drift:\n  release_identity.env=%q\n  officialSigstoreSANRegex=%q", got, officialSigstoreSANRegex)
	}
}

// TestInstallScriptPinsSameReleaseIdentity extends the SSOT wall to the
// quick-start installer: scripts/install.sh hardcodes the issuer + SAN regex
// (verify_pinned_image_signature) to cosign-verify the proxy image before it
// trusts the host-root maintenance-agent binary in the /app/deploy bundle. That
// copy MUST equal release_identity.env / the Go constants, or the installer
// could trust an image the in-binary verifier would reject (or vice versa). The
// identity is hardcoded (not read from the image) on purpose — the image must
// not be able to forge the identity it is verified against.
func TestInstallScriptPinsSameReleaseIdentity(t *testing.T) {
	env := parseReleaseIdentityEnv(t)
	b, err := os.ReadFile("scripts/install.sh")
	if err != nil {
		t.Fatalf("read scripts/install.sh: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, "verify_pinned_image_signature") {
		t.Skip("scripts/install.sh no longer verifies the pinned image signature; contract not applicable")
	}
	// The installer assigns the issuer as a plain double-quoted string and the
	// SAN regex as a single-quoted literal (backslashes must survive verbatim).
	wantIssuer := `MAINT_SIGSTORE_ISSUER="` + env["CULVERT_RELEASE_SIGSTORE_ISSUER"] + `"`
	if !strings.Contains(s, wantIssuer) {
		t.Errorf("scripts/install.sh missing/!= pinned issuer; want line containing %q", wantIssuer)
	}
	wantSAN := `MAINT_SIGSTORE_SAN_REGEX='` + env["CULVERT_RELEASE_SIGSTORE_SAN_REGEX"] + `'`
	if !strings.Contains(s, wantSAN) {
		t.Errorf("scripts/install.sh missing/!= pinned SAN regex; want line containing %q", wantSAN)
	}
}

// TestReleaseCatalogKeylessVerify is the CI end-to-end gate (tag path): after
// `cosign sign-blob --bundle` writes index.json.sigstore into CULVERT_RELEASE_GEN_OUT,
// this loads that dir through the REAL in-binary path — the BAKED Sigstore root +
// the pinned official identity — and asserts the freshly keyless-signed catalog
// verifies. It proves the shipped verifier accepts what the pipeline produced (no
// gate/runtime drift) AND that the natural OIDC SAN actually matches the pinned
// regex. Verification is offline (the bundle carries its Rekor inclusion proof +
// integrated timestamp).
//
// Skipped unless CULVERT_RELEASE_GEN_VERIFY_SIGSTORE is set, because it needs a real
// cosign-produced index.json.sigstore that only exists on the CI tag path.
func TestReleaseCatalogKeylessVerify(t *testing.T) {
	if os.Getenv("CULVERT_RELEASE_GEN_VERIFY_SIGSTORE") == "" {
		t.Skip("set CULVERT_RELEASE_GEN_VERIFY_SIGSTORE=1 (CI tag path, after cosign sign-blob) to run")
	}
	out := os.Getenv("CULVERT_RELEASE_GEN_OUT")
	if out == "" {
		t.Fatal("CULVERT_RELEASE_GEN_OUT must point at the signed bundle dir")
	}
	sv, err := newSigstoreVerifier(bakedSigstoreTrustedRootJSON, officialSigstoreIdentity())
	if err != nil {
		t.Fatalf("build verifier from baked root: %v", err)
	}
	// Sigstore-only enforce store: the bundle MUST verify keyless (no ed25519).
	ts, err := NewTrustStoreWithSigstore(nil, VerifyEnforce, sv)
	if err != nil {
		t.Fatalf("NewTrustStoreWithSigstore: %v", err)
	}
	cat, err := LoadVerifiedCatalog(&dirCatalogSource{dir: out}, ts)
	if err != nil {
		t.Fatalf("keyless verification of the signed catalog failed: %v", err)
	}
	if cat == nil || len(cat.List()) == 0 {
		t.Fatal("verified catalog is empty")
	}
}
