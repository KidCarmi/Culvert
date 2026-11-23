package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

// policy_category_health.go — stored policy rules whose destination category
// or category-group reference no current category authority resolves
// (POL-005's reporting half; the drift question itself is POL-902).
//
// New and modified rules are refused at every interactive door when a
// reference does not resolve (validateRuleObjectRefs) or spells the reserved
// wildcard in another case (validateDestCategoryNotReservedVariant). A rule
// that is ALREADY stored can still carry such a reference:
//
//   - it was written before those doors existed (a hand-edited policy file, a
//     destCategory spelled "any" — which is a category name, not the
//     wildcard);
//   - its category disappeared after it was written: a signed feed generation
//     dropped the class, a SaaS override tombstoned it, the effective view
//     armed (so a BuiltIn-only catStore name stopped counting), or the
//     community DB is absent on this node.
//
// Such a rule matches no traffic — for a Drop or Block_Page rule that is
// fail-open, silently. The owner decision (B) is to keep it loading and
// enforcing exactly as today, and to make it visible instead: refusing it on
// load would be wrong because the authorities load AFTER policy and the feed
// arrives asynchronously, and canonicalizing "any" to "Any" would turn a Drop
// that matches nothing into drop-all.
//
// Three read-only signals, none of which changes enforcement:
//
//   - a WARN-level logger line per unresolved reference, emitted once per
//     (rule, reference) when it is first seen unresolved: after the category
//     authorities load at startup (armUnresolvedCategoryRefReporting, called
//     from main AFTER initURLCategories — never from PolicyStore.Load, which
//     runs before any category authority exists), after every effective-view
//     transition (feed activation, override or taxonomy recompose, recovery —
//     all publish through feedLiveStore.Swap), and after a SIGHUP policy
//     reload;
//   - the gauge culvert_policy_rules_unresolved_refs{type=category|category_group},
//     computed on scrape;
//   - the policy_category_resolution row on /api/diagnostics, computed on
//     read, like file_profile_resolution (file_profile_health.go).
//
// The gauge and the row are keyed on the CURRENT state, so restoring the
// category, re-pointing the rule or deleting it clears them without a restart.
// No field is added to PolicyRule's JSON: clients echo rules back through the
// strict decodeJSON (DisallowUnknownFields), so a new response field would
// break their round-trips.

const (
	unresolvedRefCategory      = "category"
	unresolvedRefCategoryGroup = "category_group"
)

// unresolvedRuleRef is one stored reference that no current authority resolves.
type unresolvedRuleRef struct {
	RuleID string
	Rule   string // display name; the ID when the rule has none
	Type   string // unresolvedRefCategory | unresolvedRefCategoryGroup
	Name   string // the referenced name, verbatim
}

// unresolvedCategoryRefs lists the category and category-group references in
// rules that the hot path cannot resolve. It mirrors the evaluator, not the
// stores:
//
//   - category: exact "Any" and "" are wildcards (matchDestNorm); every other
//     value is judged by the same predicate the write doors use
//     (categoryRefResolver), with the authority state captured once for the
//     whole list. A destCategory spelled "any" is therefore reported unless
//     some authority really carries a category of that name.
//   - category group: only a rule with a group NAME scopes on a group
//     (catGroupSet in matchDestNorm); it resolves ID-first with a name
//     fallback (categoryGroupMatchesHostScratch), so it is unresolved only
//     when neither the stamped ID nor the name finds a live group.
//
// Every rule counts, enabled or not and access or auth: a disabled rule with a
// dangling reference still makes every bulk door (import, rollback, cluster
// publish) refuse the whole candidate that carries it.
func unresolvedCategoryRefs(rules []PolicyRule) []unresolvedRuleRef {
	var out []unresolvedRuleRef
	var cr *categoryRefResolver
	for i := range rules {
		r := &rules[i]
		display := r.Name
		if display == "" {
			display = r.ID
		}
		if r.DestCategory != "" && r.DestCategory != CategoryAny {
			if cr == nil {
				c := newCategoryRefResolver()
				cr = &c
			}
			if !cr.resolvable(string(r.DestCategory)) {
				out = append(out, unresolvedRuleRef{RuleID: r.ID, Rule: display, Type: unresolvedRefCategory, Name: string(r.DestCategory)})
			}
		}
		if r.DestCategoryGroup != "" && !categoryGroupRefResolves(r) {
			out = append(out, unresolvedRuleRef{RuleID: r.ID, Rule: display, Type: unresolvedRefCategoryGroup, Name: r.DestCategoryGroup})
		}
	}
	return out
}

// categoryGroupRefResolves mirrors categoryGroupMatchesHostScratch's
// resolution: the stamped ID wins when it resolves, else the name.
func categoryGroupRefResolves(r *PolicyRule) bool {
	if r.DestCategoryGroupID != "" && globalCategoryGroups.GetByID(r.DestCategoryGroupID) != nil {
		return true
	}
	return globalCategoryGroups.GetByName(r.DestCategoryGroup) != nil
}

// unresolvedRefCounts returns how many rules carry an unresolved reference of
// each type (a rule with both counts once in each).
func unresolvedRefCounts(refs []unresolvedRuleRef) (categories, groups int) {
	for i := range refs {
		if refs[i].Type == unresolvedRefCategoryGroup {
			groups++
		} else {
			categories++
		}
	}
	return categories, groups
}

func unresolvedRefTypeLabel(t string) string {
	if t == unresolvedRefCategoryGroup {
		return "category group"
	}
	return "category"
}

// unresolvedRefReporter owns the once-per-reference WARN lines. armed stays
// false until the category authorities have loaded, so a startup-time view
// install that runs before them can never report a reference as unresolved
// merely because its authority has not loaded yet.
var unresolvedRefReporter struct {
	mu     sync.Mutex
	armed  bool
	logged map[string]struct{}
}

// armUnresolvedCategoryRefReporting runs the first check. main calls it once,
// after initURLCategories (catStore, category groups, the effective view and
// the community DB are all loaded by then) and the rename reconciliation.
func armUnresolvedCategoryRefReporting() {
	unresolvedRefReporter.mu.Lock()
	unresolvedRefReporter.armed = true
	unresolvedRefReporter.mu.Unlock()
	reportUnresolvedCategoryRefs()
}

// reportUnresolvedCategoryRefs logs each running-rule reference that is
// unresolved now and was not unresolved at the previous check. A reference
// that resolves again is forgotten, so drifting away a second time warns
// again. No-op until armed. Read-only with respect to policy.
func reportUnresolvedCategoryRefs() {
	unresolvedRefReporter.mu.Lock()
	defer unresolvedRefReporter.mu.Unlock()
	if !unresolvedRefReporter.armed {
		return
	}
	refs := unresolvedCategoryRefs(policyStore.List())
	next := make(map[string]struct{}, len(refs))
	for i := range refs {
		ref := &refs[i]
		key := ref.RuleID + "\x00" + ref.Type + "\x00" + ref.Name
		next[key] = struct{}{}
		if _, seen := unresolvedRefReporter.logged[key]; seen {
			continue
		}
		logger.Printf("Policy: rule %q references %s %q which no current category authority resolves; it matches no traffic",
			sanitizeLog(ref.Rule), unresolvedRefTypeLabel(ref.Type), sanitizeLog(ref.Name))
	}
	unresolvedRefReporter.logged = next
}

// noteCategoryAuthorityChanged is the effective-view transition hook
// (feedLiveStore.Swap on the process-wide holder).
func noteCategoryAuthorityChanged() { reportUnresolvedCategoryRefs() }

// writePolicyUnresolvedRefMetrics emits the gauge. Always emitted, both
// series: 0 is the healthy value on every node that has policy, and the
// alert is simply > 0. The only label is the bounded reference type — rule
// and category names never reach /metrics, which is unauthenticated on the
// proxy port.
func writePolicyUnresolvedRefMetrics(w io.Writer) {
	cats, groups := unresolvedRefCounts(unresolvedCategoryRefs(policyStore.List()))
	_, _ = fmt.Fprintf(w, `
# HELP culvert_policy_rules_unresolved_refs Policy rules whose destination category or category-group reference no current category authority resolves; such a rule matches no traffic
# TYPE culvert_policy_rules_unresolved_refs gauge
culvert_policy_rules_unresolved_refs{type="category"} %d
culvert_policy_rules_unresolved_refs{type="category_group"} %d
`, cats, groups)
}

// maxUnresolvedRefsListed bounds the diagnostics message; the count is always
// exact.
const maxUnresolvedRefsListed = 20

// checkPolicyCategoryResolution is the /api/diagnostics row.
func checkPolicyCategoryResolution() OperatorContractCheck {
	return policyCategoryResolutionRow(unresolvedCategoryRefs(policyStore.List()))
}

func policyCategoryResolutionRow(refs []unresolvedRuleRef) OperatorContractCheck {
	if len(refs) == 0 {
		return OperatorContractCheck{
			Code:    "policy_category_resolution",
			Status:  diagOK,
			Message: "every policy rule's destination category and category-group reference resolves",
		}
	}
	listed := make([]string, 0, min(len(refs), maxUnresolvedRefsListed))
	for i := range refs {
		if i == maxUnresolvedRefsListed {
			listed = append(listed, fmt.Sprintf("and %d more", len(refs)-maxUnresolvedRefsListed))
			break
		}
		listed = append(listed, fmt.Sprintf("%q (%s %q)", refs[i].Rule, unresolvedRefTypeLabel(refs[i].Type), refs[i].Name))
	}
	return OperatorContractCheck{
		Code:   "policy_category_resolution",
		Status: diagWarn,
		Message: fmt.Sprintf("%d policy rule reference(s) name a category or category group that no current category authority resolves, so those rules match no traffic: %s",
			len(refs), strings.Join(listed, ", ")),
		OperatorAction: `Open Policies, then edit or remove each rule named here, or restore the category (Objects > URL Categories, or the SaaS feed and its overrides) or category group it references. A destCategory spelled "any" or "ANY" is a category name, not the wildcard; only exact "Any" matches every destination, so changing such a rule to "Any" makes it match all traffic: decide that deliberately. Until these rules are fixed, a config import, rollback or cluster publish that carries them is refused as a dangling reference.`,
	}
}
