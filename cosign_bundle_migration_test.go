package main

// Phase A — cosign 2.x→3.x Sigstore-bundle migration contract.
//
// The release binary/SBOM signing path (ci.yml) and the operator install/verify
// path (packaging/culvert-maint/install.sh) have NO CI lane that runs a real
// keyless cosign verify — keyless signing/verification needs GitHub OIDC, which
// is only present on the tag path. These string contracts are therefore the
// regression guard that the migration OFF cosign detached signatures (.sig/.pem,
// removed from cosign 3.x sign-blob/attest-blob) TO the new-format Sigstore
// bundle (--bundle *.sigstore.json) stays in place on BOTH the producer and the
// consumer. A drift here would silently break the next release or the operator
// installer with no failing lane to catch it.
//
// readContractFile / activeConfigLines are shared with the other package-main
// contract tests (release_management_install_contract_test.go).

import (
	"strings"
	"testing"
)

func TestCosignBundleMigration_CIProducesBundles(t *testing.T) {
	ci := readContractFile(t, ".github/workflows/ci.yml")

	for _, want := range []string{
		"cosign-release: 'v3.0.6'",            // cosign binary pinned to the 3.x line
		"cosign sign-blob --yes",              // binary signing → bundle
		`--bundle "${BINARY}.sigstore.json"`,  // proxy + maint binary bundles
		"cosign attest-blob --yes",            // SBOM bound to the binary digest
		`--predicate "$SBOM"`,                 // predicate = the CycloneDX SBOM
		"--type cyclonedx",                    // typed in-toto predicate
		`--bundle "${SBOM}.sigstore.json"`,    // SBOM attestation bundle
		"culvert.sbom.cdx.json.sigstore.json", // uploaded to the Release
	} {
		if !strings.Contains(ci, want) {
			t.Errorf("ci.yml must produce cosign 3.x bundles: missing %q", want)
		}
	}

	// The removed cosign 2.x detached-output flags must never reappear — they
	// exit non-zero on cosign 3.x and fail the release closed on the next tag.
	active := activeConfigLines(ci)
	for _, forbidden := range []string{"--output-certificate", "--output-signature"} {
		if strings.Contains(active, forbidden) {
			t.Errorf("ci.yml still uses the removed cosign detached flag %q (broken on cosign 3.x)", forbidden)
		}
	}
}

func TestCosignBundleMigration_InstallerVerifiesBundles(t *testing.T) {
	install := readContractFile(t, "packaging/culvert-maint/install.sh")

	for _, want := range []string{
		"verify-blob",
		`--bundle "$_bin.sigstore.json"`, // verify against the bundle
		"$ASSET.sigstore.json",           // download path fetches the bundle
		"CULVERT_MAINT_BUNDLE",           // new local-binary bundle override
		"ghcr.io/sigstore/cosign:v3.0.6", // verifier bumped to cosign 3.x
	} {
		if !strings.Contains(install, want) {
			t.Errorf("install.sh must verify cosign 3.x bundles: missing %q", want)
		}
	}

	// The retired detached-signature scheme must be fully gone from the active
	// surface. NB: cannot assert bare ".sig" absence — it collides with the
	// substring in ".sigstore.json"; the specific tokens below are unambiguous.
	active := activeConfigLines(install)
	for _, forbidden := range []string{
		"--output-certificate",
		"--output-signature",
		"--signature",
		"--certificate ", // trailing space: don't match --certificate-identity/-oidc-issuer
		"CULVERT_MAINT_SIG",
		"CULVERT_MAINT_PEM",
		".pem",
		"cosign:v2",
	} {
		if strings.Contains(active, forbidden) {
			t.Errorf("install.sh still references the retired detached-signature scheme %q", forbidden)
		}
	}
}
