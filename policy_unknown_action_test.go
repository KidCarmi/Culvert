package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// SEC-POLICYACTION-1 — an action this build does not dispatch must fail CLOSED.
//
// applyPolicyDecision's `switch match.Action` had no `default:`, so an
// unrecognized action fell out of the switch to the function's trailing
// `return "OK", false`: the request was ALLOWED, no decision was recorded, and
// because the rule scan is first-match-wins (evalAccessRules) every
// LOWER-PRIORITY DENY RULE WAS SKIPPED TOO. One unrecognized action on a
// priority-1 `destFqdn: "*"` rule therefore disabled the whole rulebase under
// it, silently.
//
// It was reachable without hand-editing, because Action was validated only on
// the API ingress path (validateAccessRule): PolicyStore.Load (the
// operator-managed policy_file), and PolicyStore.ReplaceAll (the CP->DP
// snapshot apply and replace-mode config import) installed it verbatim. So a
// mixed-version cluster, a restored backup, or a renamed action in a newer
// build all produced one.
//
// The sibling gate in the same engine already fails closed for exactly this
// class: IPFilter.Allowed denies all traffic on an unrecognized mode.

// unknownActions are values canonicalPolicyAction cannot resolve at all — the
// version-skew shapes a rename or a newer build actually produces, plus the
// whitespace-padded near-misses. These are the ones that must fail closed.
//
// NOTE what is deliberately NOT here: the empty action and case variants of the
// four real actions. Both RESOLVE (see canonicalPolicyAction), and each has its
// own test below — because resolving them is what keeps this fix from changing
// the direction of traffic in a deployment whose policy file already carries
// them.
var unknownActions = []PolicyAction{
	"Block", "Deny", "Quarantine", "Isolate", "Warn", "Monitor",
	"Drop ", " Allow", "Block-Page", "allow!", "Allow\n",
}

// ─── 1. Runtime dispatch ────────────────────────────────────────────────────

// TestSECPOLICYACTION1_UnknownActionBlocksAndIsTerminal is the DEFECT GATE.
// Pre-fix every row returned ("OK", false) with a 200.
func TestSECPOLICYACTION1_UnknownActionBlocksAndIsTerminal(t *testing.T) {
	setupProxyTest(t)
	for _, action := range unknownActions {
		t.Run(string("action="+action), func(t *testing.T) {
			rule := &PolicyRule{Priority: 1, Name: "probe-unknown-action", DestFQDN: "*", Action: action}
			match := &PolicyMatch{Rule: rule, Action: action, MatchedConditions: "destFQDN=*"}

			r := httptest.NewRequest(http.MethodGet, "http://blocked.example.com/", http.NoBody)
			r.Host = "blocked.example.com"
			w := httptest.NewRecorder()

			status, terminal := applyPolicyDecision(w, r, "203.0.113.9", "blocked.example.com",
				"req-probe", "", AuthLogFields{}, match)

			if !terminal {
				t.Errorf("DEFECT: action %q is not terminal — the request proceeds upstream and every lower-priority deny rule is skipped (status=%q)",
					action, status)
			}
			if status == "OK" {
				t.Errorf("DEFECT: action %q produced status %q (allowed)", action, status)
			}
			if w.Code == http.StatusOK && terminal {
				t.Errorf("action %q: terminal but answered 200 — nothing was served to the client", action)
			}
		})
	}
}

// TestSECPOLICYACTION1_KnownActionsStillDispatchUnchanged is the not-vacuous
// control. Without it the gate above would be satisfied by blocking everything.
func TestSECPOLICYACTION1_KnownActionsStillDispatchUnchanged(t *testing.T) {
	setupProxyTest(t)
	for _, tc := range []struct {
		action       PolicyAction
		wantStatus   string
		wantTerminal bool
	}{
		{ActionAllow, "OK", false},
		{ActionBlockPage, "POLICY_BLOCK", true},
		{ActionRedirect, "POLICY_REDIRECT", true},
	} {
		t.Run(string(tc.action), func(t *testing.T) {
			rule := &PolicyRule{
				Priority: 1, Name: "probe-" + string(tc.action), DestFQDN: "*",
				Action:      tc.action,
				RedirectURL: "https://portal.example.com/notice",
			}
			match := &PolicyMatch{Rule: rule, Action: tc.action, MatchedConditions: "destFQDN=*"}

			r := httptest.NewRequest(http.MethodGet, "http://dest.example.com/", http.NoBody)
			r.Host = "dest.example.com"
			w := httptest.NewRecorder()

			status, terminal := applyPolicyDecision(w, r, "203.0.113.9", "dest.example.com",
				"req-probe", "", AuthLogFields{}, match)

			if status != tc.wantStatus || terminal != tc.wantTerminal {
				t.Errorf("action %q = (%q, %v), want (%q, %v) — the fix changed a known action",
					tc.action, status, terminal, tc.wantStatus, tc.wantTerminal)
			}
		})
	}
}

// ─── 2. The durable / bulk install gate ────────────────────────────────────

// TestSECPOLICYACTION1_PersistableRefusesUnknownAction pins the gate itself.
func TestSECPOLICYACTION1_PersistableRefusesUnknownAction(t *testing.T) {
	for _, action := range unknownActions {
		rule := &PolicyRule{Priority: 1, Name: "probe", DestFQDN: "*", Action: action}
		ok, reason := policyRulePersistable(rule)
		if ok {
			t.Errorf("DEFECT: policyRulePersistable accepted action %q", action)
		} else if reason == "" {
			t.Errorf("action %q refused with no reason — the load warning would be empty", action)
		}
	}
	// CONTROL: every dispatchable action is still persistable.
	for _, action := range []PolicyAction{ActionAllow, ActionDrop, ActionBlockPage, ActionRedirect} {
		rule := &PolicyRule{Priority: 1, Name: "probe", DestFQDN: "*", Action: action}
		if ok, reason := policyRulePersistable(rule); !ok {
			t.Errorf("policyRulePersistable rejected the valid action %q: %s", action, reason)
		}
	}
}

// TestSECPOLICYACTION1_ReplaceAllDropsUnknownActionKeepsValid covers the
// CP->DP snapshot apply and replace-mode config import, which share
// ReplaceAll. The valid rule must survive, so the drop is per-rule and does not
// discard a whole pushed rulebase.
func TestSECPOLICYACTION1_ReplaceAllDropsUnknownActionKeepsValid(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyStoreForTest(t)

	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "probe-bad-action", DestFQDN: "*", Action: "Block"},
		{Priority: 2, Name: "probe-good-action", DestFQDN: "*.example.com", Action: ActionBlockPage},
	})

	var sawBad, sawGood bool
	for _, r := range policyStore.List() {
		switch r.Name {
		case "probe-bad-action":
			sawBad = true
		case "probe-good-action":
			sawGood = true
		}
	}
	if sawBad {
		t.Error("DEFECT: ReplaceAll installed a rule whose action this build does not dispatch")
	}
	if !sawGood {
		t.Error("ReplaceAll dropped the VALID rule too — the gate is not per-rule")
	}
}

// TestSECPOLICYACTION1_ResolutionIsNeverMorePermissiveThanPreFix is the
// property that keeps this fix from changing the direction of traffic anywhere.
//
// Pre-fix, EVERY value outside the four exact constants fell out of the switch
// and was ALLOWED. So for each tolerated spelling, resolution must land on an
// action at least as strict as "allow": "allow" in any case may resolve to
// Allow (unchanged), and every other tolerated spelling must resolve to
// something that BLOCKS. Nothing may become more permissive than it already
// was.
func TestSECPOLICYACTION1_ResolutionIsNeverMorePermissiveThanPreFix(t *testing.T) {
	for _, tc := range []struct {
		stored PolicyAction
		want   PolicyAction
	}{
		// Unset: the historical fall-through was Allow, and it stays Allow, so
		// no deployment carrying action-less rules changes behaviour.
		{"", ActionAllow},
		// Case folding. The allow rows are unchanged from pre-fix; the rest
		// previously allowed and now block — strictly fail-closed.
		{"allow", ActionAllow},
		{"ALLOW", ActionAllow},
		{"Allow", ActionAllow},
		{"drop", ActionDrop},
		{"DROP", ActionDrop},
		{"block_page", ActionBlockPage},
		{"BLOCK_PAGE", ActionBlockPage},
		{"Block_page", ActionBlockPage},
		{"redirect", ActionRedirect},
		{"REDIRECT", ActionRedirect},
	} {
		got, known := canonicalPolicyAction(tc.stored)
		if !known {
			t.Errorf("canonicalPolicyAction(%q) reported UNKNOWN; a rule carrying it would be dropped at load, which changes which rules remain", tc.stored)
			continue
		}
		if got != tc.want {
			t.Errorf("canonicalPolicyAction(%q) = %q, want %q", tc.stored, got, tc.want)
		}
	}

	// And the unresolvable set stays unresolvable.
	for _, action := range unknownActions {
		if got, known := canonicalPolicyAction(action); known {
			t.Errorf("canonicalPolicyAction(%q) resolved to %q — a version-skew action must fail closed, not be guessed at", action, got)
		}
	}
}

// TestSECPOLICYACTION1_ResolvedActionsDispatchToTheirBranch closes the loop: a
// tolerated spelling must reach the SAME branch its canonical form does, or
// resolution would be a lie told only to the load gate.
func TestSECPOLICYACTION1_ResolvedActionsDispatchToTheirBranch(t *testing.T) {
	setupProxyTest(t)
	for _, tc := range []struct {
		stored       PolicyAction
		wantStatus   string
		wantTerminal bool
	}{
		{"", "OK", false},
		{"allow", "OK", false},
		{"ALLOW", "OK", false},
		{"block_page", "POLICY_BLOCK", true},
		{"BLOCK_PAGE", "POLICY_BLOCK", true},
		{"redirect", "POLICY_REDIRECT", true},
	} {
		t.Run(string("stored="+tc.stored), func(t *testing.T) {
			rule := &PolicyRule{
				Priority: 1, Name: "probe-resolved", DestFQDN: "*", Action: tc.stored,
				RedirectURL: "https://portal.example.com/notice",
			}
			match := &PolicyMatch{Rule: rule, Action: tc.stored, MatchedConditions: "destFQDN=*"}
			r := httptest.NewRequest(http.MethodGet, "http://dest.example.com/", http.NoBody)
			r.Host = "dest.example.com"
			w := httptest.NewRecorder()

			status, terminal := applyPolicyDecision(w, r, "203.0.113.9", "dest.example.com",
				"req-probe", "", AuthLogFields{}, match)

			if status != tc.wantStatus || terminal != tc.wantTerminal {
				t.Errorf("stored action %q = (%q, %v), want (%q, %v)",
					tc.stored, status, terminal, tc.wantStatus, tc.wantTerminal)
			}
		})
	}
}

// TestSECPOLICYACTION1_ToleratedSpellingsStillInstall is the availability
// control for the load gate: a policy file or snapshot that already carries an
// empty or lowercase action must keep ALL of its rules. Dropping them would
// change which rules remain and so could deny traffic that previously flowed.
func TestSECPOLICYACTION1_ToleratedSpellingsStillInstall(t *testing.T) {
	setupProxyTest(t)
	snapshotPolicyStoreForTest(t)

	policyStore.ReplaceAll([]PolicyRule{
		{Priority: 1, Name: "unset-action", DestFQDN: "a.example.com"},
		{Priority: 2, Name: "lowercase-allow", DestFQDN: "b.example.com", Action: "allow"},
		{Priority: 3, Name: "lowercase-block", DestFQDN: "c.example.com", Action: "block_page"},
		{Priority: 4, Name: "exact-allow", DestFQDN: "d.example.com", Action: ActionAllow},
	})

	got := map[string]bool{}
	for _, r := range policyStore.List() {
		got[r.Name] = true
	}
	for _, name := range []string{"unset-action", "lowercase-allow", "lowercase-block", "exact-allow"} {
		if !got[name] {
			t.Errorf("rule %q was dropped at install — the load gate is too strict and would change which rules remain in an existing deployment", name)
		}
	}
}
