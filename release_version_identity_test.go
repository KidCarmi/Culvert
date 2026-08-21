package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Release runtime-version-stamp invariants. These pin the release-integrity
// contract surfaced by the first LIVE authoritative MCP Observe Acceptance
// (v1.0.202 signed binary reported an empty /healthz version). They test SEMANTIC
// invariants of the release configuration, not a brittle YAML snapshot, so the
// class cannot silently regress: tag ref == build input == main.version ==
// /healthz version.
//
// NOTE: "version stamp" (what version the binary claims to be) is deliberately
// distinct from "release identity" (who signed it — the Sigstore issuer/SAN trust
// policy pinned in release_identity.env and verified by TestReleaseIdentitySSOT).
// This file tests the former only.

func readRepoFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestReleaseVersion_LinkerTargetIsMainVersion pins the linker symbol the release
// build stamps and that the composite targets exactly it via env-indirection.
func TestReleaseVersion_LinkerTargetIsMainVersion(t *testing.T) {
	if !strings.Contains(readRepoFile(t, "version.go"), "var version") {
		t.Fatal("version.go must declare `var version` (the -X main.version linker target)")
	}
	comp := readRepoFile(t, ".github/actions/build-release-binaries/action.yml")
	if !strings.Contains(comp, "-X main.version=${REF_NAME}") {
		t.Error("release composite must stamp the proxy version via `-X main.version=${REF_NAME}`")
	}
	if !strings.Contains(comp, "REF_NAME: ${{ inputs.ref-name }}") {
		t.Error("release composite must set REF_NAME from the `ref-name` input (env-indirection)")
	}
}

// TestReleaseVersion_BothBuildPathsPassTagAndGuard proves the release job AND the
// reproducible-rebuild job both feed the tag into the shared composite and both
// run the fail-closed identity guard, so the publish and verify paths cannot
// drift on the version stamp.
func TestReleaseVersion_BothBuildPathsPassTagAndGuard(t *testing.T) {
	ci := readRepoFile(t, ".github/workflows/ci.yml")

	// Every call to the shared build composite must pass ref-name from the tag.
	uses := strings.Count(ci, "uses: ./.github/actions/build-release-binaries")
	if uses < 2 {
		t.Fatalf("expected >=2 callers of build-release-binaries (release + verify-reproducible), found %d", uses)
	}
	passesTag := strings.Count(ci, "ref-name: ${{ github.ref_name }}")
	if passesTag < uses {
		t.Errorf("every build-release-binaries caller must pass `ref-name: ${{ github.ref_name }}` (callers=%d, passes=%d)", uses, passesTag)
	}

	// Both build paths must invoke the fail-closed release-identity guard.
	if strings.Count(ci, "assert-release-ref.sh") < 2 {
		t.Error("both the release job and the reproducible-rebuild job must run assert-release-ref.sh (fail-closed on empty/non-tag version)")
	}

	// The release job must run the runtime version-identity gate on the native leg.
	if !strings.Contains(ci, "assert-runtime-version.sh") {
		t.Error("release job must run assert-runtime-version.sh (prove the signed binary self-reports its tag on /healthz)")
	}
}

// TestReleaseVersion_GuardFailsClosed pins that the ref guard actually rejects an
// empty and a non-semver ref (fail-closed), rather than accepting anything.
func TestReleaseVersion_GuardFailsClosed(t *testing.T) {
	g := readRepoFile(t, ".github/scripts/assert-release-ref.sh")
	if !strings.Contains(g, `if [ -z "$REF_NAME" ]`) {
		t.Error("assert-release-ref.sh must reject an EMPTY ref name")
	}
	if !regexp.MustCompile(`\^v\[0-9\]\+\\\.\[0-9\]\+\\\.\[0-9\]\+\$`).MatchString(g) {
		t.Error("assert-release-ref.sh must require a vX.Y.Z semver tag")
	}
	for _, forbidden := range []string{"dev", "latest"} {
		// The guard must not fall back to a placeholder identity.
		if regexp.MustCompile(`(?i)fall.?back.*` + forbidden).MatchString(g) {
			t.Errorf("assert-release-ref.sh must never fall back to %q", forbidden)
		}
	}
}

// TestHealthz_VersionWiredInHandlerAndSchema pins that the LIVE /healthz handler
// (apiHealthz) surfaces the version var and the OpenAPI HealthStatus schema
// documents it, so a future refactor cannot silently drop runtime version
// identity again.
func TestHealthz_VersionWiredInHandlerAndSchema(t *testing.T) {
	ha := readRepoFile(t, "ha.go")
	// apiHealthz must include `"version": version` in its responses (SSOT var, not a literal).
	if strings.Count(ha, `"version": version`) < 1 {
		t.Error("apiHealthz (ha.go) must surface `\"version\": version` on /healthz")
	}
	spec := readRepoFile(t, "api/openapi/openapi.yaml")
	// HealthStatus schema documents version. Bound the slice safely (strings.Index
	// can return -1; using it directly as a slice index would panic; gocritic offBy1).
	start := strings.Index(spec, "HealthStatus:")
	if start < 0 {
		t.Fatal("openapi.yaml is missing the HealthStatus schema")
	}
	hs := spec[start:]
	if end := strings.Index(hs, "SetupStatus:"); end >= 0 {
		hs = hs[:end]
	}
	if !strings.Contains(hs, "version:") {
		t.Error("OpenAPI HealthStatus schema must document the `version` property")
	}
}
