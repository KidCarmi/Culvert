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
// Legacy rules without an ID resolve by name and never fail closed; a disabled
// rule never matches, so it blocks nothing.
func danglingFileProfileRules(rules []PolicyRule) []string {
	var names []string
	for i := range rules {
		r := &rules[i]
		if !ruleIsEnabled(r) || !r.FileFiltering || r.FileProfile == FileProfileNone || r.FileProfileID == "" {
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

func fileProfileResolutionRow(dangling []string, evaluations int64) OperatorContractCheck {
	if len(dangling) == 0 {
		msg := "every policy rule's file profile resolves"
		if evaluations > 0 {
			msg += fmt.Sprintf(" (%d fail-closed file-profile evaluation(s) since boot, before the reference was repaired)", evaluations)
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
		Message: fmt.Sprintf("%d policy rule(s) reference a file profile that no longer exists, so file downloads/uploads they match are blocked (fail-closed; %d fail-closed evaluation(s) since boot): %s",
			len(dangling), evaluations, strings.Join(dangling, ", ")),
		OperatorAction: "Open Policies > Access Rules, edit each rule named here and select an existing file profile (Objects > File Profiles). Rules reference a profile by ID, so creating a new profile with the old name does not repair them.",
	}
}
