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
		"--print image_ref",
		// The catalog origin must travel via the ENVIRONMENT (not argv) to avoid a
		// world-readable /proc/pid/cmdline leak of a presigned mirror URL.
		`CULVERT_RELEASE_CATALOG_URL="$CATALOG_URL"`,
		// A downloaded verifier must be capability-probed before execution so an old
		// binary lacking the subcommand can never start the proxy and hang the install.
		`grep -qa 'bootstrap-resolve'`,
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

// A wrong host clock (pre-NTP cloud first-boot) can make the local-clock freshness
// check accept a long-expired signed catalog. The installer warns against network
// time before resolving, with actionable NTP guidance.
func TestInstaller_WarnsOnClockSkew(t *testing.T) {
	s := readContractFile(t, "scripts/install.sh")
	for _, want := range []string{
		"warn_if_clock_skewed",
		"set-ntp true", // actionable fix
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install.sh must warn on host clock skew before catalog resolution; missing %q", want)
		}
	}
	// Must be invoked from the catalog seed path.
	def := strings.Index(s, "warn_if_clock_skewed() {")
	call := strings.LastIndex(s, "\n  warn_if_clock_skewed\n")
	if def < 0 || call < 0 || call < def {
		t.Fatal("warn_if_clock_skewed must be defined and invoked in seed_from_catalog")
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

// The verifier download URL is built from GH_REPO + the release tag; both must be
// validated so a CULVERT_GITHUB_REPO / poisoned-tag_name value cannot path-traverse
// to another repo's asset (red-team finding).
func TestInstaller_ValidatesVerifierDownloadInputs(t *testing.T) {
	s := readContractFile(t, "scripts/install.sh")
	for _, want := range []string{
		"safe_release_tag", // release-tag charset guard
		`GH_REPO" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`, // owner/name guard
		`"$GH_REPO" == *".."*`,                          // no traversal in repo
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install.sh must validate verifier download inputs; missing %q", want)
		}
	}
	// The verifier must be staged under an exec-capable dir (not blindly /tmp) so a
	// noexec /tmp does not silently block the trusted install.
	if !strings.Contains(s, `mktemp -d "${INSTALL_DIR}/.verifier`) {
		t.Error("install.sh should stage the verifier under an exec-capable dir (INSTALL_DIR) to survive /tmp noexec")
	}
}

// The verifier binary is the root of trust for the whole fresh install; it MUST be
// cosign verify-blob'd against the pinned release identity BEFORE it is executed,
// and that verification must run before the binary is assigned to BOOTSTRAP_VERIFIER_BIN.
func TestInstaller_VerifierIsCosignVerified(t *testing.T) {
	s := readContractFile(t, "scripts/install.sh")
	for _, want := range []string{
		"verify_bootstrap_verifier",
		"verify-blob",
		".sigstore.json",
		`--certificate-identity-regexp "$MAINT_SIGSTORE_SAN_REGEX"`,
		`--certificate-oidc-issuer "$MAINT_SIGSTORE_ISSUER"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install.sh must cosign-verify the verifier binary; missing %q", want)
		}
	}
	// Ordering: verify_bootstrap_verifier must be called (and gate a failure) BEFORE
	// BOOTSTRAP_VERIFIER_BIN is set, so an unverified binary is never trusted/executed.
	call := strings.Index(s, "if ! verify_bootstrap_verifier ")
	assign := strings.Index(s, `BOOTSTRAP_VERIFIER_BIN="$dir/$asset"`)
	if call < 0 || assign < 0 || call > assign {
		t.Fatal("verify_bootstrap_verifier must run and gate BEFORE BOOTSTRAP_VERIFIER_BIN is assigned")
	}
	// A break-glass skip must exist but be explicit and loud.
	if !strings.Contains(s, "CULVERT_BOOTSTRAP_SKIP_VERIFY") {
		t.Error("a documented break-glass (CULVERT_BOOTSTRAP_SKIP_VERIFY) should exist for air-gapped hosts")
	}
}

// A reinstall over a surviving proxy-data volume must enforce the persisted
// anti-rollback floor so it cannot be silently downgraded below the last-accepted
// version. The installer stages that floor and passes it to bootstrap-resolve.
func TestInstaller_EnforcesRollbackFloorOnReinstall(t *testing.T) {
	s := readContractFile(t, "scripts/install.sh")
	for _, want := range []string{
		"stage_rollback_floor",
		"release_catalog_state.json",
		"cmd+=(--data-dir",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install.sh must enforce a surviving rollback floor on reinstall; missing %q", want)
		}
	}
}

// The appliance must be able to prove which catalog decision provisioned it: the
// installer records the decision into /data (the proxy-data volume) after the stack
// is up, and the Go side surfaces it on /api/releases.
func TestInstaller_PersistsBootstrapProvenance(t *testing.T) {
	s := readContractFile(t, "scripts/install.sh")
	for _, want := range []string{
		"persist_bootstrap_decision",
		"bootstrap_decision.json",
		".catalog-bootstrap.json",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("install.sh must persist the bootstrap decision into /data; missing %q", want)
		}
	}
	// The persist call must come AFTER the compose-up block (the volume must exist).
	up := strings.Index(s, "docker compose up -d --wait")
	call := strings.LastIndex(s, "\npersist_bootstrap_decision\n")
	if up < 0 || call < 0 || call < up {
		t.Fatal("persist_bootstrap_decision must be invoked after the stack is up")
	}
}
