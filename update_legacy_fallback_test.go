package main

import (
	"os"
	"strings"
	"testing"
)

// M0-PR4: the legacy unauthenticated GitHub-tags update fallback is OFF by default.
// These tests prove the default build makes NO GitHub dial on the update path, that
// the ON path still works, and that checkUpdateNow has no direct GitHub reference
// (only the seam). Every test that mutates a package var save/restores it (no leak
// under -count=2 -shuffle=on) and does NOT call t.Parallel.

func TestResolveLegacyGhTagCheck(t *testing.T) {
	on := []string{"1", "true", "TRUE", " yes ", "on", "On"}
	off := []string{"", "0", "false", "no", "off", "garbage", "2", "y"}
	for _, v := range on {
		enabled, note := resolveLegacyGhTagCheck(v)
		if !enabled {
			t.Errorf("resolveLegacyGhTagCheck(%q) = false; want enabled", v)
		}
		if !strings.Contains(note, envLegacyGhTagCheck) {
			t.Errorf("enabled note for %q must name %s; got %q", v, envLegacyGhTagCheck, note)
		}
	}
	for _, v := range off {
		enabled, note := resolveLegacyGhTagCheck(v)
		if enabled {
			t.Errorf("resolveLegacyGhTagCheck(%q) = true; want DISABLED (fail-safe)", v)
		}
		if !strings.Contains(note, envLegacyGhTagCheck) {
			t.Errorf("disabled note for %q must name %s; got %q", v, envLegacyGhTagCheck, note)
		}
	}
}

func TestApplyLegacyGhTagCheckEnv(t *testing.T) {
	origGate, origNote := legacyGhTagCheck.Load(), legacyGhTagCheckNote
	t.Cleanup(func() { legacyGhTagCheck.Store(origGate); legacyGhTagCheckNote = origNote })

	applyLegacyGhTagCheckEnv(func(k string) string {
		if k == envLegacyGhTagCheck {
			return "true"
		}
		return ""
	})
	if !legacyGhTagCheck.Load() {
		t.Fatal("env=true should enable the gate")
	}
	applyLegacyGhTagCheckEnv(func(string) string { return "" })
	if legacyGhTagCheck.Load() {
		t.Fatal("unset env should disable the gate (default OFF)")
	}
}

// withFallbackSpy installs a counting dial spy + sets the gate, restoring both after.
func withFallbackSpy(t *testing.T, enabled bool, ret string) *int {
	t.Helper()
	origGate, origFn := legacyGhTagCheck.Load(), checkGitHubLatestTagFn
	t.Cleanup(func() { legacyGhTagCheck.Store(origGate); checkGitHubLatestTagFn = origFn })
	calls := 0
	legacyGhTagCheck.Store(enabled)
	checkGitHubLatestTagFn = func() string { calls++; return ret }
	return &calls
}

func TestMaybeGitHubTagFallback_DefaultNoDial(t *testing.T) {
	calls := withFallbackSpy(t, false, "v9.9.9") // gate OFF (default)
	latest, available, used := maybeGitHubTagFallback("v0.0.1", false, "v0.0.1")
	if used || available || latest != "v0.0.1" {
		t.Fatalf("gate off must not change result; got latest=%q available=%v used=%v", latest, available, used)
	}
	if *calls != 0 {
		t.Fatalf("gate off must NOT dial GitHub; dialed %d times", *calls)
	}
}

func TestMaybeGitHubTagFallback_EnabledUsesGitHub(t *testing.T) {
	calls := withFallbackSpy(t, true, "v9.9.9")
	latest, available, used := maybeGitHubTagFallback("v0.0.1", false, "v0.0.1")
	if !used || !available || latest != "v9.9.9" {
		t.Fatalf("gate on + newer tag must apply fallback; got latest=%q available=%v used=%v", latest, available, used)
	}
	if *calls != 1 {
		t.Fatalf("gate on must dial exactly once; dialed %d times", *calls)
	}
}

func TestMaybeGitHubTagFallback_ShortCircuits(t *testing.T) {
	// Registry already reports an update ⇒ no dial even with the gate ON.
	calls := withFallbackSpy(t, true, "v9.9.9")
	if _, _, used := maybeGitHubTagFallback("v2.0.0", true, "v0.0.1"); used {
		t.Fatal("must not run fallback when the registry already has an update")
	}
	if *calls != 0 {
		t.Fatalf("registry-has-update must not dial; dialed %d", *calls)
	}
	// Unversioned 'dev' build ⇒ no dial.
	calls2 := withFallbackSpy(t, true, "v9.9.9")
	if _, _, used := maybeGitHubTagFallback("", false, "dev"); used {
		t.Fatal("must not run fallback for a dev build")
	}
	if *calls2 != 0 {
		t.Fatalf("dev build must not dial; dialed %d", *calls2)
	}
	// Gate on but GitHub not strictly newer ⇒ not used.
	calls3 := withFallbackSpy(t, true, "v0.0.1")
	if _, _, used := maybeGitHubTagFallback("v0.0.1", false, "v0.0.1"); used {
		t.Fatal("equal GitHub tag must not count as an update")
	}
	if *calls3 != 1 {
		t.Fatalf("gate on still dials to compare; dialed %d", *calls3)
	}
}

// TestCheckUpdateNow_NoDirectGitHubCall pins the objective at the source level: the
// update-check caller must reach GitHub ONLY through the seam (maybeGitHubTagFallback),
// never via a direct checkGitHubLatestTag() call or a raw api.github.com reference —
// so a future edit cannot silently re-add the unauthenticated dial to the hot path.
func TestCheckUpdateNow_NoDirectGitHubCall(t *testing.T) {
	src, err := os.ReadFile("update.go")
	if err != nil {
		t.Fatalf("read update.go: %v", err)
	}
	body := funcBody(t, string(src), "func checkUpdateNow()")
	if strings.Contains(body, "checkGitHubLatestTag(") {
		t.Error("checkUpdateNow must not call checkGitHubLatestTag() directly — route via maybeGitHubTagFallback")
	}
	if strings.Contains(body, "api.github.com") {
		t.Error("checkUpdateNow must not reference api.github.com directly")
	}
	if !strings.Contains(body, "maybeGitHubTagFallback(") {
		t.Error("checkUpdateNow must reach the GitHub fallback via maybeGitHubTagFallback")
	}
}

// funcBody returns the source text of the function starting at `sig` up to the next
// top-level `\nfunc ` (sufficient for a single-function scan in this flat package).
func funcBody(t *testing.T, src, sig string) string {
	t.Helper()
	i := strings.Index(src, sig)
	if i < 0 {
		t.Fatalf("signature %q not found", sig)
	}
	rest := src[i+len(sig):]
	if j := strings.Index(rest, "\nfunc "); j >= 0 {
		return rest[:j]
	}
	return rest
}
