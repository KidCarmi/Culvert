package main

// policy_hostcat.go — the per-scan destination-category scratch.
//
// Evaluate already hoists the request-invariant work out of its rule scan: the
// normalized host, the parsed client IP, and one clock read are each derived
// ONCE per request and reused by every rule. Each hoist exists for the same
// reason — the value depends on the REQUEST, not on the rule, so deriving it
// inside the loop multiplies a fixed cost by the rule count.
//
// The destination CATEGORY of the request host is the largest remaining member
// of that class, and the most expensive one:
//
//   - lookupHostCategory, which every category-GROUP rule calls, resolves the
//     host through catStore.LookupHost. At the time of this hoist that was an
//     O(total host patterns) scan; it has since gained a reverse index
//     (urlcat hostIndex, O(labels) probes) — the two changes compose, and the
//     measurements below predate that index (they bound the worst case).
//   - communityDB.Lookup opens a BadgerDB read transaction per domain label. On
//     a feed-backed deployment that is a transaction, and a trip through
//     Badger's read-timestamp oracle, per rule per request.
//
// Measured before this hoist (12 categories / 480 host patterns, no feed DB,
// uncategorized destination — the case that forces every tier to run to
// completion): a scan of category-group rules cost 207 µs at 10 rules and
// 4.08 ms at 200 rules, per request, with 91% of the profile in LookupHost.
//
// Freezing the effective-view pointer for the duration of the scan is
// deliberate and mirrors the scanNow hoist: every rule in one evaluation now
// decides against a single taxonomy generation instead of racing a mid-scan
// signed-feed activation. That is a consistency improvement, not a relaxation —
// the pointer is loaded at most one instant earlier than it would have been.

import "strings"

// hostCatScratch memoizes the host-only halves of destination-category
// resolution for the lifetime of ONE rule scan. It is keyed by the host it was
// built for, so it can never serve an answer for a different destination.
//
// Every field is derived lazily: a scan whose rules carry no category or
// category-group scope — the common deployment — computes nothing and the
// scratch stays a zeroed stack value.
//
// The per-CATEGORY halves are deliberately NOT memoized. catStore.MatchesHost /
// MatchesHostAdmin depend on the rule's category as well as the host, and they
// are index lookups (O(labels)), not scans — memoizing them would trade a cheap
// map probe for a map allocation.
type hostCatScratch struct {
	host string

	viewSet bool
	view    *effectiveCategoryView

	fusionSet     bool
	fusionCat     string
	fusionTier    string
	fusionPattern string

	viewLookupSet bool
	viewLookupCat string
	viewLookupOK  bool

	communitySet bool
	communityCat string
	communityOK  bool
}

// newHostCatScratch returns a scratch bound to host. Scans build one per
// request; the non-scan callers (matchDest, the admin URL-lookup API) build a
// throwaway one and are byte-identical to the pre-hoist behaviour.
func newHostCatScratch(host string) hostCatScratch { return hostCatScratch{host: host} }

// effectiveView returns the signed-feed effective category view, loading the
// atomic pointer at most once per scan. nil means the lifecycle is unarmed (the
// full catStore taxonomy serves, exactly as before).
func (sc *hostCatScratch) effectiveView() *effectiveCategoryView {
	if !sc.viewSet {
		sc.view = saasEffectiveView.Current()
		sc.viewSet = true
	}
	return sc.view
}

// viewLookup resolves the host against the effective view. Both callers reach
// it only behind a non-nil effectiveView(), and effectiveView() is itself
// memoized so its nil-ness is fixed for the scratch's lifetime — the nil branch
// is defensive, and memoizing its miss is exactly right.
func (sc *hostCatScratch) viewLookup() (string, bool) {
	if !sc.viewLookupSet {
		if view := sc.effectiveView(); view != nil {
			sc.viewLookupCat, sc.viewLookupOK = view.LookupHost(sc.host)
		}
		sc.viewLookupSet = true
	}
	return sc.viewLookupCat, sc.viewLookupOK
}

// communityLookup resolves the host against the Layer-2 community feed.
//
// One memo serves both callers even though matchCategory passed the raw host
// and lookupHostCategory passed the normalized one: catdb.Lookup normalizes its
// argument itself and normalization is idempotent, so both calls always
// produced the same answer.
//
// A nil store is NOT memoized — the feed is opened during startup, so caching
// "no Layer 2" from a scan that ran before it opened would be a stale answer
// with no upside. The local binding also keeps the nil check and the call on
// the SAME store, so a mid-scan swap cannot land between them.
func (sc *hostCatScratch) communityLookup() (string, bool) {
	if sc.communitySet {
		return sc.communityCat, sc.communityOK
	}
	db := communityDB
	if db == nil {
		return "", false
	}
	sc.communityCat, sc.communityOK = db.Lookup(sc.host)
	sc.communitySet = true
	return sc.communityCat, sc.communityOK
}

// fusion is lookupHostCategory's core: the full two-tier host→category
// resolution, computed at most once per scan.
func (sc *hostCatScratch) fusion() (category, tier, matchedBy string) {
	if !sc.fusionSet {
		sc.fusionCat, sc.fusionTier, sc.fusionPattern = sc.resolveFusion()
		sc.fusionSet = true
	}
	return sc.fusionCat, sc.fusionTier, sc.fusionPattern
}

// resolveFusion carries the resolution order verbatim from the pre-hoist
// lookupHostCategory: with the signed-feed view installed, admin-created
// categories first, then the SaaS taxonomy from the view, then UT1; without it,
// the full catStore taxonomy, then UT1.
func (sc *hostCatScratch) resolveFusion() (category, tier, matchedBy string) {
	if view := sc.effectiveView(); view != nil {
		if name, pattern, ok := catStore.LookupHostAdmin(sc.host); ok {
			return name, "admin", pattern
		}
		if c, ok := sc.viewLookup(); ok {
			return c, "saas", normalizeHost(sc.host)
		}
	} else if name, pattern, ok := catStore.LookupHost(sc.host); ok {
		return name, "admin", pattern
	}

	// Layer 2: community BadgerDB feed.
	h := normalizeHost(sc.host)
	if communityDB != nil {
		if foundCat, ok := sc.communityLookup(); ok {
			return foundCat, "community", h
		}
	}
	return "", "none", ""
}

// matchesCategory is matchCategory's core against a scan-scoped scratch. The
// cross-layer OR semantics are unchanged: a view classification under a
// DIFFERENT category is a membership check, not a short-circuit, and still
// falls through to the UT1 layer.
func (sc *hostCatScratch) matchesCategory(cat URLCategory) bool {
	if view := sc.effectiveView(); view != nil {
		if catStore.MatchesHostAdmin(cat, sc.host) {
			return true
		}
		// MEMBERSHIP, not classification. sc.viewLookup answers "what is this
		// host?" — ONE category, taken from the most specific key. This asks
		// "is this host in category C?", which the classification answer
		// cannot decide: the baseline taxonomy is many-to-many (linkedin.com
		// is both "Social Media" and "HR & Recruiting"), so comparing against
		// the single classified category dropped every other category the
		// host belongs to — and with it any Deny rule keyed on one of them
		// (fail-open). MatchesCategory reproduces catStore.MatchesHost
		// exactly: exact key then every suffix key, no shadowing by a more
		// specific key in a different category. Deliberately NOT memoized on
		// the scratch — it depends on the rule's category and is an O(labels)
		// index probe, same policy as MatchesHost/MatchesHostAdmin.
		//
		// Still not a short-circuit: a non-match must fall through to the UT1
		// layer, matching the original cross-layer OR semantics.
		if view.MatchesCategory(string(cat), sc.host) {
			return true
		}
	} else if catStore.MatchesHost(cat, sc.host) {
		return true
	}
	// Layer 2: community BadgerDB feed — domain-walking point lookups.
	if communityDB != nil {
		if foundCat, ok := sc.communityLookup(); ok {
			return strings.EqualFold(foundCat, string(cat))
		}
	}
	return false
}
