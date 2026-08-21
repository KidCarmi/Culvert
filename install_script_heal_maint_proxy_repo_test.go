package main

// install_script_heal_maint_proxy_repo_test.go — regression coverage for the
// heal_maint_proxy_repo() helper in scripts/install.sh.
//
// Bug: CULVERT_PROXY_REPO / CULVERT_RELEASE_PROXY_REPO is the documented
// override for a custom/private proxy registry (scripts/install.sh §6,
// resolve_latest_signed_release_ref/seed_pinned_tag), and
// wire_release_agent_for_compose resolves the SAME override as release_repo
// to decide whether Release Management can be safely auto-wired to the local
// culvert-maint agent — it refuses to wire when the agent's config.toml
// proxy_repo does not match. But nothing ever propagated a custom
// CULVERT_PROXY_REPO into that config.toml: unlike compose_project_dir and
// socket_path, which install_maint_agent self-heals from the packaging
// example's untouched default, proxy_repo was left at its packaging default
// (ghcr.io/kidcarmi/culvert) forever. Every fresh install with a custom
// registry therefore hit wire_release_agent_for_compose's
// `cfg_repo != release_repo` guard and PERMANENTLY skipped Release-Management
// wiring — silently, and with no path forward short of a manual config.toml
// edit the installer never told the operator to make.
//
// This extracts the REAL heal_maint_proxy_repo() function body out of
// scripts/install.sh (rather than duplicating it here) and exercises it under
// bash, so the test tracks the actual installer script instead of a copy that
// can drift. `sudo` and `install` are shadowed with no-op/plain-copy shell
// functions so the test does not require real root or a pre-existing
// culvert-maint system group.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const maintConfigDefaultRepoBlock = `compose_project_dir = "/srv/culvert"
allow_peers = ["culvert-cp"]
socket_path = "/run/culvert-maint/culvert-maint.sock"
image_allowlist = '^ghcr\.io/kidcarmi/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$'
proxy_repo = "ghcr.io/kidcarmi/culvert"
`

// shadowSudoInstall no-ops `sudo` (the temp config file is already owned by
// the test) and replaces `install` with a plain copy — the test only cares
// about resulting file content, not root:culvert-maint ownership, which the
// real installer applies as a separate, already-covered concern (mirrors
// install_script_patch_allow_peers_test.go's pattern).
const shadowSudoInstall = `
sudo() { "$@"; }
install() {
  local src dst
  src="${@: -2:1}"
  dst="${@: -1}"
  cp "$src" "$dst"
}
`

// runHealMaintProxyRepo extracts the real heal_maint_proxy_repo() function
// and runs it against a temp config.toml seeded with toml, returning the
// resulting file content and the function's own exit status.
func runHealMaintProxyRepo(t *testing.T, toml, wanted string) (content string, exitCode int) {
	t.Helper()
	fn := extractShellFunctionBraceAware(t, "scripts/install.sh", "heal_maint_proxy_repo")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(toml), 0o644); err != nil { //nolint:gosec // test fixture, not sensitive
		t.Fatalf("write config.toml: %v", err)
	}

	script := shadowSudoInstall + fn + "\n" +
		`heal_maint_proxy_repo "` + cfgPath + `" "` + wanted + `"` + "\n" +
		`echo "EXIT:$?"` + "\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()
	exitCode = -1
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "EXIT:") {
			if line == "EXIT:0" {
				exitCode = 0
			} else {
				exitCode = 1
			}
		}
	}
	if err != nil && exitCode == -1 {
		t.Fatalf("shell script failed: %v\n%s", err, out)
	}

	got, rerr := os.ReadFile(cfgPath)
	if rerr != nil {
		t.Fatalf("read config.toml: %v", rerr)
	}
	return string(got), exitCode
}

// TestInstallScript_HealMaintProxyRepo_HealsUntouchedDefault is the core fix
// proof: a config.toml straight from the packaging example (untouched
// proxy_repo + image_allowlist) gets repointed at a custom registry.
func TestInstallScript_HealMaintProxyRepo_HealsUntouchedDefault(t *testing.T) {
	content, exitCode := runHealMaintProxyRepo(t, maintConfigDefaultRepoBlock, "registry.example.com/culvert")

	if exitCode != 0 {
		t.Fatalf("heal_maint_proxy_repo returned failure (exit %d) against an untouched default config; resulting config:\n%s", exitCode, content)
	}
	if !strings.Contains(content, `proxy_repo = "registry.example.com/culvert"`) {
		t.Fatalf("proxy_repo was not repointed at the custom registry; got:\n%s", content)
	}
	wantAllow := `image_allowlist = '^registry\.example\.com/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$'`
	if !strings.Contains(content, wantAllow) {
		t.Fatalf("image_allowlist was not repointed at the custom registry; want substring %q, got:\n%s", wantAllow, content)
	}

	// The escaped dots in the rewritten allowlist must stay LITERAL, not
	// regain their regex-wildcard meaning — otherwise the allowlist would
	// accept image refs it should reject (e.g. any single character standing
	// in for a '.'), silently widening the upgrade-target security boundary.
	line := ""
	for _, l := range strings.Split(content, "\n") {
		if strings.HasPrefix(l, "image_allowlist") {
			line = strings.Trim(strings.TrimPrefix(l, "image_allowlist = "), "'")
			break
		}
	}
	if line == "" {
		t.Fatalf("could not find rewritten image_allowlist line in:\n%s", content)
	}
	if !regexMatches(t, line, "registry.example.com/culvert:v1.2.3") {
		t.Errorf("rewritten image_allowlist %q does not match the intended repo ref", line)
	}
	if regexMatches(t, line, "registryXexampleXcomXculvert:v1.2.3") {
		t.Errorf("rewritten image_allowlist %q treats '.' as a wildcard instead of a literal dot (security widening)", line)
	}
}

// TestInstallScript_HealMaintProxyRepo_FixesTheWiringMismatch is the
// end-to-end proof of the actual bug: it reproduces
// wire_release_agent_for_compose's own cfg_repo/release_repo comparison
// (scripts/install.sh ~line 1577) before and after the heal, showing the
// mismatch that permanently skipped Release-Management wiring is resolved.
func TestInstallScript_HealMaintProxyRepo_FixesTheWiringMismatch(t *testing.T) {
	const wanted = "registry.example.com/culvert"

	fn := extractShellFunctionBraceAware(t, "scripts/install.sh", "heal_maint_proxy_repo")
	maintToml := extractShellFunctionBraceAware(t, "scripts/install.sh", "maint_toml_string")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(maintConfigDefaultRepoBlock), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatalf("write config.toml: %v", err)
	}

	// Mirrors wire_release_agent_for_compose's own resolution exactly:
	//   cfg_repo="$(maint_toml_string proxy_repo "$cfg")"; [[ -n "$cfg_repo" ]] || cfg_repo="$default_repo"
	//   release_repo="${CULVERT_RELEASE_PROXY_REPO:-${CULVERT_PROXY_REPO:-$default_repo}}"
	//   if [[ "$cfg_repo" != "$release_repo" ]]; then <skip wiring>; fi
	checkScript := shadowSudoInstall + maintToml + "\n" + fn + "\n" + `
default_repo="ghcr.io/kidcarmi/culvert"
cfg_repo="$(maint_toml_string proxy_repo "$1")"
[[ -n "$cfg_repo" ]] || cfg_repo="$default_repo"
release_repo="${CULVERT_RELEASE_PROXY_REPO:-${CULVERT_PROXY_REPO:-$default_repo}}"
if [[ "$cfg_repo" != "$release_repo" ]]; then
  echo "MISMATCH cfg_repo=$cfg_repo release_repo=$release_repo"
else
  echo "MATCH cfg_repo=$cfg_repo release_repo=$release_repo"
fi
`
	run := func() string {
		cmd := exec.CommandContext(t.Context(), "bash", "-c", checkScript, "check", cfgPath) // #nosec G204 -- fixed test script content
		cmd.Env = append(os.Environ(), "CULVERT_PROXY_REPO="+wanted)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("check script failed: %v\n%s", err, out)
		}
		return strings.TrimSpace(string(out))
	}

	before := run()
	if !strings.HasPrefix(before, "MISMATCH") {
		t.Fatalf("expected the UNHEALED config to reproduce the wiring-skip mismatch, got %q", before)
	}

	// Now heal it (same helper, invoked directly rather than through run(),
	// since we need it to run once and persist before re-checking).
	healScript := shadowSudoInstall + fn + "\n" + `heal_maint_proxy_repo "$1" "$2"`
	cmd := exec.CommandContext(t.Context(), "bash", "-c", healScript, "heal", cfgPath, wanted) // #nosec G204 -- fixed test script content
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("heal_maint_proxy_repo failed: %v\n%s", err, out)
	}

	after := run()
	if !strings.HasPrefix(after, "MATCH") {
		t.Fatalf("heal_maint_proxy_repo did not resolve the wiring-skip mismatch; wire_release_agent_for_compose would still "+
			"skip Release-Management wiring for this custom-registry install. got %q", after)
	}
}

// TestInstallScript_HealMaintProxyRepo_NoopWhenAlreadyCustomized proves the
// fix does not over-correct: an operator-edited proxy_repo (no longer the
// packaging default) must be left untouched, mirroring the "never touch an
// operator edit" rule the compose_project_dir/socket_path self-heals follow.
func TestInstallScript_HealMaintProxyRepo_NoopWhenAlreadyCustomized(t *testing.T) {
	toml := strings.Replace(maintConfigDefaultRepoBlock,
		`proxy_repo = "ghcr.io/kidcarmi/culvert"`,
		`proxy_repo = "myregistry.local/culvert"`, 1)

	content, exitCode := runHealMaintProxyRepo(t, toml, "otherregistry.local/culvert")

	if exitCode == 0 {
		t.Fatalf("heal_maint_proxy_repo reported success against an already-customized proxy_repo — it must no-op instead; resulting config:\n%s", content)
	}
	if !strings.Contains(content, `proxy_repo = "myregistry.local/culvert"`) {
		t.Fatalf("heal_maint_proxy_repo modified an operator-edited proxy_repo; got:\n%s", content)
	}
}

// TestInstallScript_HealMaintProxyRepo_NoopWhenWantedIsDefault proves the
// helper does nothing when the resolved repo already IS the packaging
// default (the common case — no CULVERT_PROXY_REPO override at all).
func TestInstallScript_HealMaintProxyRepo_NoopWhenWantedIsDefault(t *testing.T) {
	content, exitCode := runHealMaintProxyRepo(t, maintConfigDefaultRepoBlock, "ghcr.io/kidcarmi/culvert")

	if exitCode == 0 {
		t.Fatalf("heal_maint_proxy_repo reported success when the wanted repo already matches the default; resulting config:\n%s", content)
	}
	if content != maintConfigDefaultRepoBlock {
		t.Fatalf("heal_maint_proxy_repo modified the config when no change was needed; got:\n%s", content)
	}
}

// regexMatches reports whether an EXTENDED regex (as image_allowlist stores
// it) matches s, using grep -E so the test exercises the exact regex flavor
// the real image_allowlist consumer (cmd/culvert-maint) is documented against.
func regexMatches(t *testing.T, pattern, s string) bool {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "grep", "-Eq", pattern) // #nosec G204 -- fixed pattern built from test-local strings
	cmd.Stdin = strings.NewReader(s + "\n")
	return cmd.Run() == nil
}
