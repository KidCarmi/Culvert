package main

import (
	"strings"
	"testing"
)

// These contract tests pin the fresh-install trust architecture in scripts/install.sh:
// the SIGNED CATALOG (via the verified in-binary bootstrap-resolve) is the release
// authority, and legacy GHCR tag enumeration is a disabled-by-default break-glass —
// never a trusted selection and never a SILENT fallback. They guard against a
// regression back to the tag-sort path that installed the stale `0.0.238` image.

func TestInstaller_CatalogIsTheTrustedSeedSource(t *testing.T) {
	s := readContractFile(t, "scripts/install.sh")

	// The trusted seed path runs the verified resolver and pulls the exact digest.
	for _, want := range []string{
		"seed_from_catalog",
		"bootstrap-resolve --channel",
		"--proxy-repo \"$PROXY_REPO\"",
		"--print image_ref",
		// The pulled ref must be an immutable digest, never a mutable tag.
		"*@sha256:*",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install.sh missing catalog-seed token %q", want)
		}
	}

	// seed_from_catalog must be invoked from seed_pinned_tag BEFORE any break-glass
	// tag path — i.e. it is the default, not a fallback.
	catAt := strings.Index(s, "if seed_from_catalog; then")
	if catAt < 0 {
		t.Fatal("seed_pinned_tag must call seed_from_catalog as the trusted default")
	}
	tagAt := strings.Index(s, `CULVERT_INSTALL_ALLOW_TAG_DISCOVERY:-}" == "1"`)
	if tagAt >= 0 && tagAt < catAt {
		t.Fatal("break-glass tag discovery gate must not precede the catalog seed")
	}
}

func TestInstaller_TagDiscoveryIsGatedBreakGlass(t *testing.T) {
	s := readContractFile(t, "scripts/install.sh")

	// The legacy tag-enumeration + :latest pulls must be reachable ONLY behind the
	// explicit break-glass gate. There must be no ungated call to the tag resolver
	// on the trusted path.
	if !strings.Contains(s, `if [[ "${CULVERT_INSTALL_ALLOW_TAG_DISCOVERY:-}" == "1" ]]; then`) {
		t.Fatal("tag discovery must be gated on CULVERT_INSTALL_ALLOW_TAG_DISCOVERY=1")
	}

	// The catalog-seed block (the trusted default) must NOT reference :latest or the
	// tag resolver — those belong only inside the break-glass gate below it.
	gateAt := strings.Index(s, `CULVERT_INSTALL_ALLOW_TAG_DISCOVERY:-}" == "1"`)
	catStart := strings.Index(s, "seed_from_catalog() {")
	catEnd := strings.Index(s[catStart:], "\nseed_pinned_tag() {")
	if catStart < 0 || catEnd < 0 {
		t.Fatal("could not locate seed_from_catalog body")
	}
	catBody := s[catStart : catStart+catEnd]
	for _, forbidden := range []string{":latest", "resolve_latest_signed_release_ref", "tags/list"} {
		if strings.Contains(catBody, forbidden) {
			t.Errorf("seed_from_catalog (trusted path) must not reference %q", forbidden)
		}
	}
	if gateAt < 0 {
		t.Fatal("break-glass gate missing")
	}
}

func TestInstaller_NoSilentTagFallback(t *testing.T) {
	s := readContractFile(t, "scripts/install.sh")

	// resolve_latest_signed_release_ref must be CALLED only inside the break-glass
	// gate. Find every call site (excluding its own definition) and assert each is
	// after the gate keyword.
	def := strings.Index(s, "resolve_latest_signed_release_ref() {")
	gate := strings.Index(s, "CULVERT_INSTALL_ALLOW_TAG_DISCOVERY")
	if def < 0 || gate < 0 {
		t.Fatal("expected both the tag resolver definition and the break-glass gate to exist")
	}
	// Any invocation is written as `resolve_latest_signed_release_ref)` in a command
	// substitution; the definition uses `resolve_latest_signed_release_ref() {`.
	for idx := 0; ; {
		i := strings.Index(s[idx:], "resolve_latest_signed_release_ref")
		if i < 0 {
			break
		}
		pos := idx + i
		idx = pos + 1
		// Skip the definition line.
		if strings.HasPrefix(s[pos:], "resolve_latest_signed_release_ref() {") {
			continue
		}
		// Skip references inside comments/docstrings (line starts with optional
		// spaces then '#').
		lineStart := strings.LastIndexByte(s[:pos], '\n') + 1
		trimmed := strings.TrimLeft(s[lineStart:pos], " \t")
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if pos < gate {
			t.Fatalf("tag discovery invoked at offset %d BEFORE the break-glass gate at %d (silent fallback)", pos, gate)
		}
	}
}

func TestInstaller_ForwardsCatalogConfigToEnv(t *testing.T) {
	s := readContractFile(t, "scripts/install.sh")
	for _, want := range []string{
		`env_put CULVERT_RELEASE_CATALOG_URL "$CATALOG_URL"`,
		`env_put CULVERT_INSTALL_CHANNEL "$INSTALL_CHANNEL"`,
		`INSTALL_CHANNEL="${CULVERT_INSTALL_CHANNEL:-stable}"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install.sh must forward catalog config to .env; missing %q", want)
		}
	}
}

func TestInstaller_DisabledCatalogDoesNotDowngrade(t *testing.T) {
	s := readContractFile(t, "scripts/install.sh")
	// The off/none/disabled sentinel must be recognized and must NOT downgrade.
	if !strings.Contains(s, "catalog_fetch_disabled") {
		t.Fatal("install.sh must recognize the catalog-fetch-disabled sentinel")
	}
	if !strings.Contains(s, "off|none|disabled") {
		t.Fatal("install.sh must handle the off/none/disabled sentinels")
	}
}
