package main

// install_script_maint_proxy_repo_allowlist_test.go — regression coverage for
// check_proxy_repo_matches_allowlist() in packaging/culvert-maint/install.sh.
//
// proxy_repo and image_allowlist MUST describe the same repository (P1.4
// §3.1): the agent's own image_allowlist gate (cmd/culvert-maint/internal/
// config) rejects every upgrade/rollback dispatch whose requested
// <proxy_repo>@sha256:... ref does not match image_allowlist. Before this
// fix, the installer's cross-check was skipped entirely whenever
// image_allowlist was left unset in config.toml — which is exactly the
// common case of an operator customizing proxy_repo (e.g. a private mirror)
// without also remembering to override image_allowlist away from its
// ghcr.io/kidcarmi/culvert-anchored default. That let install.sh complete
// successfully with a self-contradictory config: sudoers correctly bound to
// the custom repo, but every future Release Management upgrade/rollback
// silently and permanently rejected by the agent's own default allowlist.
//
// This extracts the REAL check_proxy_repo_matches_allowlist() function body
// (and die(), which it calls) out of packaging/culvert-maint/install.sh and
// exercises it under bash, so the test tracks the actual installer script
// instead of a copy that can drift.

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// extractShellOneLiner pulls a single-line "name() { ...; }" shell function
// definition out of scriptPath. die()/log()/warn() in
// packaging/culvert-maint/install.sh are written this way (unlike the
// multi-line functions extractShellFunction handles).
func extractShellOneLiner(t *testing.T, scriptPath, name string) string {
	t.Helper()
	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read %s: %v", scriptPath, err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, name+"()") && strings.HasSuffix(trimmed, "}") {
			return trimmed
		}
	}
	t.Fatalf("could not find one-line function %q in %s", name, scriptPath)
	return ""
}

// runCheckProxyRepoMatchesAllowlist runs the real check against (repo,
// allowlist) and reports whether it died (exit non-zero) and its combined
// output.
func runCheckProxyRepoMatchesAllowlist(t *testing.T, repo, allowlist string) (died bool, out string) {
	t.Helper()
	const script = "packaging/culvert-maint/install.sh"
	dieFn := extractShellOneLiner(t, script, "die")
	checkFn := extractShellFunction(t, script, "check_proxy_repo_matches_allowlist")

	body := dieFn + "\n" + checkFn + "\n" +
		`check_proxy_repo_matches_allowlist "$1" "$2"` + "\n" +
		`echo OK` + "\n"
	cmd := exec.CommandContext(t.Context(), "bash", "-c", body, "install_script_maint_proxy_repo_allowlist_test", repo, allowlist) // #nosec G204 -- fixed test script content, not external/user input
	b, err := cmd.CombinedOutput()
	return err != nil, string(b)
}

// TestCheckProxyRepoMatchesAllowlist_CustomRepoWithUnsetAllowlist_Dies is the
// core regression: a customized proxy_repo with image_allowlist left UNSET
// must fail the install loudly, not silently succeed with a config that can
// never dispatch an upgrade/rollback again.
func TestCheckProxyRepoMatchesAllowlist_CustomRepoWithUnsetAllowlist_Dies(t *testing.T) {
	died, out := runCheckProxyRepoMatchesAllowlist(t, "registry.example.com/culvert", "")
	if !died {
		t.Fatalf("expected check_proxy_repo_matches_allowlist to die for a custom proxy_repo with an unset "+
			"image_allowlist (the unset allowlist defaults to a pattern anchored to ghcr.io/kidcarmi/culvert, "+
			"which can never match the custom repo) — got success:\n%s", out)
	}
	if !strings.Contains(out, "is not referenced by image_allowlist") {
		t.Errorf("expected the P1.4 mismatch error message, got:\n%s", out)
	}
}

// TestCheckProxyRepoMatchesAllowlist_DefaultRepoWithUnsetAllowlist_Passes is
// the baseline: the default proxy_repo with an unset image_allowlist (the
// overwhelmingly common install) must still pass — the Go-side default
// pattern is anchored to exactly that repo.
func TestCheckProxyRepoMatchesAllowlist_DefaultRepoWithUnsetAllowlist_Passes(t *testing.T) {
	died, out := runCheckProxyRepoMatchesAllowlist(t, "ghcr.io/kidcarmi/culvert", "")
	if died {
		t.Fatalf("expected the default proxy_repo with an unset image_allowlist to pass, got failure:\n%s", out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("expected the script to reach 'echo OK', got:\n%s", out)
	}
}

// TestCheckProxyRepoMatchesAllowlist_CustomRepoWithMatchingAllowlist_Passes
// proves the fix doesn't over-correct: a custom proxy_repo with an EXPLICIT,
// matching image_allowlist must still pass (this was already the case before
// the fix; guards against a regression in the matching branch).
func TestCheckProxyRepoMatchesAllowlist_CustomRepoWithMatchingAllowlist_Passes(t *testing.T) {
	died, out := runCheckProxyRepoMatchesAllowlist(t,
		"registry.example.com/culvert",
		`^registry\.example\.com/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$`)
	if died {
		t.Fatalf("expected a custom proxy_repo with a matching explicit image_allowlist to pass, got failure:\n%s", out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("expected the script to reach 'echo OK', got:\n%s", out)
	}
}

// TestCheckProxyRepoMatchesAllowlist_CustomRepoWithUnrelatedAllowlist_Dies
// proves the explicitly-set mismatch case (already handled before this fix)
// still dies — no regression in the pre-existing branch.
func TestCheckProxyRepoMatchesAllowlist_CustomRepoWithUnrelatedAllowlist_Dies(t *testing.T) {
	died, out := runCheckProxyRepoMatchesAllowlist(t,
		"registry.example.com/culvert",
		`^ghcr\.io/kidcarmi/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$`)
	if !died {
		t.Fatalf("expected a custom proxy_repo with an unrelated explicit image_allowlist to die, got success:\n%s", out)
	}
	if !strings.Contains(out, "is not referenced by image_allowlist") {
		t.Errorf("expected the P1.4 mismatch error message, got:\n%s", out)
	}
}
