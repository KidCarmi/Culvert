package main

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// file_profile_health.go — operator-contract row for dangling file profiles.
//
// A policy rule that references a file profile by ID fails CLOSED when the
// profile no longer resolves (policy.go fileProfileBlockedByID): file-bearing
// transactions on that rule are blocked. The only signals today are a WARN log
// line (rate-limited to once per 5 minutes) and a /metrics counter. An
// administrator whose users report "downloads are blocked" has to SSH in and
// grep logs, or scrape /metrics, to learn why. This surfaces the condition as
// one row on /api/diagnostics. It reads the policy and profile stores plus an
// atomic and changes no enforcement, policy decision, or logging.
//
// The status is keyed on the CURRENT dangling references (like checkClusterCA's
// rotation state), not on the monotonic counter: re-pointing the rule or
// restoring the profile clears the warning without a restart. The counter is
// reported only as context, and as evaluations rather than transactions — the
// inspected-HTTPS path evaluates the rule's profile twice per blocked request
// (inspectFileBlocked, then recordInspectBlock for attribution).
func checkFileProfileResolution() OperatorContractCheck {
	return fileProfileResolutionRow(danglingFileProfileRules(policyStore.List()),
		atomic.LoadInt64(&statFileProfileUnresolvedBlocked))
}

// danglingFileProfileRules names the rules whose authoritative FileProfileID
// does not resolve — exactly the rules fileProfileBlockedByID fails closed on.
// Only rules that can reach that path count: an enabled access rule whose
// action is Allow (Drop/Block_Page/Redirect terminate in applyPolicyDecision
// before any file-profile evaluation, and auth rules never reach Stage 2).
// Legacy rules without an ID resolve by name and never fail closed.
func danglingFileProfileRules(rules []PolicyRule) []string {
	var names []string
	for i := range rules {
		r := &rules[i]
		if !fileProfileEnforced(r) || r.FileProfileID == "" {
			continue
		}
		if globalProfileStore.GetByID(r.FileProfileID) != nil {
			continue
		}
		name := r.Name
		if name == "" {
			name = r.ID
		}
		names = append(names, name)
	}
	return names
}

// fileProfileEnforced reports whether a rule's file profile is ever evaluated
// by FileProfileBlocked on the request path.
//
// The action test goes through canonicalPolicyAction because that is what the
// request path dispatches on (applyPolicyDecision, proxy.go). SEC-POLICYACTION-1
// made the dispatch fold case and resolve an EMPTY action to Allow, so a rule
// persisted as "allow" — or with no action at all, the shape an operator-managed
// policy_file or a replayed snapshot produces — reaches the ActionAllow branch
// and really does have its file profile evaluated. Comparing the RAW action here
// answered "no" for exactly those rules, so a dangling profile on one of them
// blocked every file-bearing transaction it matched (fail-closed, correctly)
// while file_profile_resolution still reported diagOK — the one row that exists
// to tell an administrator why downloads stopped. The predicate's own contract
// above is "ever evaluated by FileProfileBlocked on the request path", so it has
// to read the action the way the request path does. Enforcement is untouched:
// this function feeds only the diagnostics row.
func fileProfileEnforced(r *PolicyRule) bool {
	action, known := canonicalPolicyAction(r.Action)
	return ruleIsEnabled(r) && ruleTypeOf(r) == ruleTypeAccess && known && action == ActionAllow &&
		r.FileFiltering && r.FileProfile != FileProfileNone
}

func fileProfileResolutionRow(dangling []string, evaluations int64) OperatorContractCheck {
	if len(dangling) == 0 {
		msg := "no enabled Allow rule references a missing file profile"
		if evaluations > 0 {
			msg += fmt.Sprintf(" (%d fail-closed file-profile evaluation(s) since boot)", evaluations)
		}
		return OperatorContractCheck{
			Code:    "file_profile_resolution",
			Status:  diagOK,
			Message: msg,
		}
	}
	return OperatorContractCheck{
		Code:   "file_profile_resolution",
		Status: diagWarn,
		Message: fmt.Sprintf("%d enabled Allow rule(s) reference a file profile that no longer exists, so file downloads/uploads they match are blocked (fail-closed; %d fail-closed evaluation(s) since boot): %s",
			len(dangling), evaluations, strings.Join(dangling, ", ")),
		OperatorAction: "Open Policies > Access Rules, edit each rule named here and select an existing file profile (Objects > File Profiles). Rules reference a profile by ID, so creating a new profile with the old name does not repair them.",
	}
}
