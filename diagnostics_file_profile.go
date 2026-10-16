package main

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// fileProfileDiagMaxNames bounds how many rule names the row lists so a large
// ruleset cannot bloat the Diagnostics payload.
const fileProfileDiagMaxNames = 5

// fileProfileUnresolvedDiagnostics surfaces rules whose authoritative file
// profile no longer resolves. Enforcement already fails CLOSED for those rules
// (PolicyRule.fileProfileBlockedByID); until now the only signals were a
// rate-limited log line and a /metrics counter, so an operator saw blocked
// downloads with no explanation in the GUI. Report-only: it reads the same
// rule/profile state the enforcement path reads and changes no decision.
// Contributes nothing when every file-profile reference resolves.
func fileProfileUnresolvedDiagnostics(rules []PolicyRule) []OperatorContractCheck {
	var names []string
	for i := range rules {
		r := &rules[i]
		if !ruleIsEnabled(r) || !r.FileFiltering || r.FileProfile == FileProfileNone || r.FileProfileID == "" {
			continue
		}
		if globalProfileStore.GetByID(r.FileProfileID) == nil {
			names = append(names, r.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	listed := names
	if len(listed) > fileProfileDiagMaxNames {
		listed = listed[:fileProfileDiagMaxNames]
	}
	msg := fmt.Sprintf("%d enabled rule(s) reference a file profile that no longer exists — file downloads matching them are BLOCKED (fail-closed): %s",
		len(names), strings.Join(listed, ", "))
	if len(names) > len(listed) {
		msg += fmt.Sprintf(" and %d more", len(names)-len(listed))
	}
	if n := atomic.LoadInt64(&statFileProfileUnresolvedBlocked); n > 0 {
		msg += fmt.Sprintf(" (%d transactions blocked since boot)", n)
	}
	return []OperatorContractCheck{{
		Code:           "policy_file_profile_unresolved",
		Status:         diagWarn,
		Message:        msg,
		OperatorAction: "Recreate or restore the missing file profile under File Control, or edit each listed rule to select an existing profile.",
	}}
}
