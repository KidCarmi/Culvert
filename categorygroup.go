package main

// categorygroup.go — package-main glue for named category groups, moved to
// internal/catgroup (post-ADR-0002 recorded extraction). The alias shim
// keeps the API handlers, cluster sync (ConfigSnapshot.CategoryGroups), and
// config-version rollback on the original unqualified names.
//
// main deliberately owns the HOST-level match: resolving a host to its
// category is the two-tier catStore+communityDB fusion (lookupHostCategory,
// policy.go), the same boundary the urlcat extraction drew. The engine
// exposes the pure MatchesCategory half.

import "github.com/KidCarmi/Culvert/internal/catgroup"

// CategoryGroup is a named bundle of URL category names (engine type is
// catgroup.Group).
type CategoryGroup = catgroup.Group

// CategoryGroupStore manages persistent category groups (engine type is
// catgroup.Store).
type CategoryGroupStore = catgroup.Store

var globalCategoryGroups = catgroup.New()

// categoryGroupMatchesHostRule reports whether host belongs to the category
// group the rule references — the hot-path function called during policy
// evaluation (matchDestNorm). Host → category goes through the two-tier fusion
// (lookupHostCategory); the group membership check is the engine's O(1) catSet
// lookup. Unknown group or uncategorized host = no match (fail-closed).
//
// References-by-id (S2): it resolves the group by the rule's AUTHORITATIVE ID
// first (rename-safe), falling back to the denormalized name only when the id
// resolves to no group (un-migrated / dangling). A resolved group's membership
// result is final — the stale name is never consulted, so a rename can't make a
// rule match a different group. Byte-identical to the name path for rules with
// no DestCategoryGroupID.
func categoryGroupMatchesHostRule(rule *PolicyRule, host string) bool {
	hostCat, _, _ := lookupHostCategory(host)
	if id := rule.DestCategoryGroupID; id != "" {
		if matched, resolved := globalCategoryGroups.MatchesCategoryByID(id, hostCat); resolved {
			return matched
		}
	}
	return globalCategoryGroups.MatchesCategory(rule.DestCategoryGroup, hostCat)
}
