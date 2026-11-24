package main

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// Category groups are policy-load-bearing: a rule scoped to a group matches a
// destination only when the group resolves. When the groups file failed to load
// at startup (corrupt JSON, an envelope written by a newer release, an
// unreadable file) the store stayed EMPTY, the failure was one log line, and
// startup went on. Every group-scoped rule then matched nothing: a Block or
// Drop rule stopped blocking and a credential-required rule stopped
// challenging, so the traffic fell through to the default action or to an Allow
// behind it. Nothing told the operator.
//
// The rule applied here is the one the policy file and the URL categories
// already follow: do not start serving with a policy that is known to be weaker
// than the one configured.
//
//   - If the running policy holds an ENABLED rule scoped to a category group,
//     a failed groups load is fatal, naming the rules and the file.
//   - If no rule depends on a group, nothing is weakened: startup continues,
//     the failure is logged as a warning and shown in Diagnostics until groups
//     are present again (a control-plane sync repopulates the store).

// categoryGroupsLoadFailure is the startup load error text, nil when the groups
// file loaded (or was absent, which is a first run).
var categoryGroupsLoadFailure atomic.Pointer[string]

// loadCategoryGroupsAtStartup loads the groups file and applies the rule above.
// It must run after the policy file is loaded (initPolicy precedes
// initURLCategories), because the verdict depends on what the policy holds.
func loadCategoryGroupsAtStartup(path string) {
	err := globalCategoryGroups.Load(path)
	if err == nil {
		categoryGroupsLoadFailure.Store(nil)
		return
	}
	msg := err.Error()
	categoryGroupsLoadFailure.Store(&msg)
	if fatal := categoryGroupsStartupVerdict(err, policyRulesUsingCategoryGroups(policyStore.List()), path); fatal != "" {
		logFatalf("%s", fatal)
	}
	logWarnf("CategoryGroups: %s could not be loaded (%s); no enabled policy rule is scoped to a category group, so nothing is weakened. The store is empty until the file is restored or groups are synced.",
		sanitizeLog(path), sanitizeLog(msg))
}

// categoryGroupsStartupVerdict returns the fatal message for a failed groups
// load that leaves enabled group-scoped rules unable to match, or "" when
// startup may continue. Pure, so the decision is testable without exiting.
func categoryGroupsStartupVerdict(loadErr error, dependents []string, path string) string {
	if loadErr == nil || len(dependents) == 0 {
		return ""
	}
	const maxListed = 5
	listed := dependents
	more := ""
	if len(listed) > maxListed {
		more = fmt.Sprintf(" and %d more", len(listed)-maxListed)
		listed = listed[:maxListed]
	}
	quoted := make([]string, len(listed))
	for i, n := range listed {
		quoted[i] = fmt.Sprintf("%q", sanitizeLog(n))
	}
	return fmt.Sprintf("Cannot load category groups from %s: %s. %d enabled policy rule(s) are scoped to a category group and would match nothing without it (%s%s), so the proxy will not start with that policy weakened. Restore the file from a backup or a stored config version; on a data-plane node, removing the file lets the next control-plane sync rebuild it.",
		sanitizeLog(path), sanitizeLog(loadErr.Error()), len(dependents), strings.Join(quoted, ", "), more)
}

// policyRulesUsingCategoryGroups returns the names of the ENABLED rules, access
// and auth alike, that are scoped to a category group. A disabled rule enforces
// nothing, so its group does not have to resolve.
func policyRulesUsingCategoryGroups(rules []PolicyRule) []string {
	var out []string
	for i := range rules {
		r := &rules[i]
		if !ruleIsEnabled(r) {
			continue
		}
		if r.DestCategoryGroup != "" || r.DestCategoryGroupID != "" {
			out = append(out, r.Name)
		}
	}
	return out
}

// checkCategoryGroupsLoadFailed keeps a non-fatal startup load failure visible
// after its log line has scrolled away. It contributes nothing once the store
// holds groups again.
func checkCategoryGroupsLoadFailed() []OperatorContractCheck {
	msg := categoryGroupsLoadFailure.Load()
	if msg == nil || len(globalCategoryGroups.List()) > 0 {
		return nil
	}
	return []OperatorContractCheck{{
		Code:           "category_groups_load_failed",
		Status:         diagWarn,
		Message:        fmt.Sprintf("The category groups file could not be loaded at startup (%s); the group store is empty. No enabled policy rule depended on a group at that time.", sanitizeLog(*msg)),
		OperatorAction: "Restore the category groups file from a backup or a stored config version, then restart; on a data-plane node the next control-plane sync rebuilds it. A rule scoped to a category group matches nothing until its group exists.",
	}}
}
