package main

import "testing"

// TestFileProfileEnforced_MatchesDispatchActionCanonicalization pins the
// predicate to the request path's own reading of PolicyRule.Action.
//
// SEC-POLICYACTION-1 made applyPolicyDecision (proxy.go) dispatch on
// canonicalPolicyAction, which folds ASCII case and resolves an EMPTY action to
// Allow. A rule stored as "allow", "ALLOW" or "" therefore reaches the
// ActionAllow branch and has FileProfileBlocked evaluated against it. The
// file_profile_resolution diagnostics row must agree, or a dangling profile on
// such a rule blocks file-bearing transactions while the row reports ok and the
// administrator is given no reason for it.
//
// Negative control included: an action this build cannot dispatch at all is
// blocked outright by applyPolicyDecision's fail-closed branch, so its file
// profile is never evaluated and the predicate must say so.
func TestFileProfileEnforced_MatchesDispatchActionCanonicalization(t *testing.T) {
	enabled := true
	rule := func(a PolicyAction) *PolicyRule {
		return &PolicyRule{
			Name:          "fp",
			Action:        a,
			Enabled:       &enabled,
			FileFiltering: true,
			FileProfile:   "Executables",
			FileProfileID: "fp-1",
		}
	}

	for _, tc := range []struct {
		action PolicyAction
		want   bool
		why    string
	}{
		{ActionAllow, true, "the canonical spelling"},
		{"allow", true, "lowercase: dispatch folds case, so the profile IS evaluated"},
		{"ALLOW", true, "uppercase: same"},
		{"", true, "unset resolves to Allow in dispatch (canonicalPolicyAction)"},
		{ActionDrop, false, "Drop never reaches the file-profile check"},
		{"drop", false, "folded Drop: blocked before the profile check"},
		{ActionBlockPage, false, "Block_Page never reaches it"},
		{"not_an_action", false, "unknown action is blocked outright (fail-closed)"},
	} {
		if got := fileProfileEnforced(rule(tc.action)); got != tc.want {
			t.Errorf("fileProfileEnforced(action=%q) = %v, want %v — %s", tc.action, got, tc.want, tc.why)
		}
	}
}

// TestFileProfileDangling_ReportsCaseVariantAllowRule is the end-to-end half:
// the dangling-reference scan itself must name a rule whose action is a case
// variant of Allow, because that rule's downloads are being blocked.
// danglingFileProfileRules is pure over the slice it is handed (the only store
// it reads is globalProfileStore, and the ID below resolves in no store), so
// this needs no shared-state restoration.
func TestFileProfileDangling_ReportsCaseVariantAllowRule(t *testing.T) {
	enabled := true
	rules := []PolicyRule{{
		Name:          "lowercase-allow-with-dangling-profile",
		Action:        "allow",
		Enabled:       &enabled,
		FileFiltering: true,
		FileProfile:   "Executables",
		FileProfileID: "does-not-exist-" + t.Name(),
	}}

	dangling := danglingFileProfileRules(rules)
	if len(dangling) != 1 || dangling[0] != "lowercase-allow-with-dangling-profile" {
		t.Fatalf("dangling = %v, want the lowercase-allow rule named — its file-bearing transactions are blocked fail-closed and the operator gets no row otherwise", dangling)
	}
}
