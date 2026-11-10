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

// CategoryGroupSnapshot is one coherent groups+names+version capture (engine
// type is catgroup.Snapshot) — the GET /api/category-groups list contract.
type CategoryGroupSnapshot = catgroup.Snapshot

var globalCategoryGroups = catgroup.New()

// categoryGroupMatchesHostScratch reports whether the scratch's host belongs to
// the category group the rule references — the hot-path function called during
// policy evaluation (matchDestNorm), and therefore by every scan that reaches
// it: the access scan and Policy Tester (PolicyStore.Evaluate), CDR
// (CDRPolicyStore.Evaluate) and Stage-1 auth (authRuleMatchesScratch).
// Unknown group or uncategorized host = no match (fail-closed).
//
// MEMBERSHIP, not classification: the group matches when the host belongs to
// ANY category in it — exactly the semantics single-category rules have
// (hostCatScratch.matchesCategory, finding F-1), and that is the primitive used
// here. It used to compare only the host's single classification winner
// (sc.fusion) against the group, which dropped every other category the host
// belongs to. Since F3b-4 put admin-created categories first on the armed
// effective-view path, an admin category covering a host by PARENT suffix
// (admin "webmail" = example.test) wins the classification over a built-in
// EXACT entry ("News" = news.example.test), so a Block rule on the group
// {Social Media, News} stopped matching news.example.test while a
// destCategory=News rule still blocked it (fail-open). The classification
// itself — order and winner — is unchanged; logging and the URL-lookup API
// (lookupHostCategory) still consume it.
//
// Cost: the winner key is probed first (one O(1) catSet probe; the winner is
// always a member, so every host that matched before still matches on that
// probe alone). Only a categorized host whose winner is NOT in the group pays
// one membership probe per remaining group category — the same O(labels) index
// probe a single-category rule pays, against the scan-shared normalized host
// and memoized community lookup, with no allocation.
//
// References-by-id (S2): it resolves the group by the rule's AUTHORITATIVE ID
// first (rename-safe), falling back to the denormalized name only when the id
// resolves to no group (un-migrated / dangling). A resolved group's membership
// result is final — the stale name is never consulted, so a rename can't make a
// rule match a different group. Byte-identical to the name path for rules with
// no DestCategoryGroupID.
// It takes the SCAN-SCOPED host scratch, so every category-group rule in one
// policy evaluation shares ONE host→category resolution instead of repeating
// the two-tier fusion per rule (policy_hostcat.go). Callers outside a scan
// build a throwaway scratch with newHostCatScratch(host).
func categoryGroupMatchesHostScratch(rule *PolicyRule, sc *hostCatScratch) bool {
	hostCat, _, _ := sc.fusion()
	if hostCat == "" {
		// An UNCATEGORIZED host is in no category group: no tier classifies it,
		// and each tier's classification succeeds whenever any of its
		// membership probes would (the same exact-then-suffix keys), so no group
		// category can claim it either. Answering here skips a group resolve
		// once per category-group rule, and the uncategorized host is the
		// COMMON case on a gateway (clean traffic to a destination no tier
		// classifies), so on that shape the whole per-rule membership probe
		// disappears rather than merely getting cheaper. Behaviour-preserving:
		// an empty category is never a catSet member (buildCatSet refuses it by
		// construction), and the engine's membership matchers return false on
		// an empty key without consulting the member probe.
		return false
	}
	// The catSet KEY, not the display-cased category name: it is derived from
	// the fusion result, so it is request-invariant and the scratch hoists it
	// out of the rule scan. Passing the name instead made catgroup lower it
	// once per category-group rule per request, which ALLOCATES for every
	// category the product ships — see hostCatScratch.fusionCatKey.
	catKey := sc.fusionCatKey()
	// The membership probe: a func literal over the scratch pointer. The engine
	// calls it synchronously and does not let it escape, so it lives on this
	// frame and the scan stays allocation-free
	// (TestBenchGate_PolicyEvalCategoryGroupAllocs).
	member := func(category string) bool { return sc.matchesCategory(URLCategory(category)) }
	if id := rule.DestCategoryGroupID; id != "" {
		if matched, resolved := globalCategoryGroups.MatchesMemberKeyByID(id, catKey, member); resolved {
			return matched
		}
	}
	return globalCategoryGroups.MatchesMemberKey(rule.DestCategoryGroup, catKey, member)
}
