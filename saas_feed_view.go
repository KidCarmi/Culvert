package main

// saas_feed_view.go — F3b-3: the immutable effective category view + the atomic live
// holder (the design's `atomic.Pointer[EffectiveView]`, §B.1 concern 4 / §B.5 S5) and
// the legacy-syncer single-writer guard.
//
// The effective view is the composed, served category set: the feed-owned normalized
// snapshot (from a fully re-verified immutable generation) with the admin category
// overrides (internal/catoverride) layered on. It is IMMUTABLE after construction, so a
// cutover is a single atomic pointer swap — a reader always observes an entirely-old or
// entirely-new view, never a partial blend (no policy-update race can produce a
// half-old/half-new effective store).
//
// SCOPE / DORMANCY. This holder is the coordinator's OWN live store. It is NOT yet
// consulted by the policy hot path (policy.go still reads catStore), so wiring it in is
// a later step and category-matching semantics are unchanged by this slice. Because the
// coordinator is dormant (no startup wiring, no scheduler), it cannot race with or
// overwrite the existing catStore path. The ownership flag below is the mechanism that,
// once the feed DOES own the live store, makes the legacy raw syncer a no-op — proving
// the single-writer contract without changing today's behavior (the flag stays false
// while dormant).

import (
	"strings"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// saasEffectiveView is the PROCESS-WIDE atomic holder of the effective signed-SaaS
// category view that the policy hot path consults (F3b-4 hot-path routing). It is the
// single source-aware SaaS layer: installed offline at startup (embedded baseline →
// recovered LKG), atomically replaced on a committed signed activation or an override
// recompose, and read lock-free by matchCategory / lookupHostCategory. The signed-feed
// runtime uses THIS holder as its live store, so a cutover is observed by policy as a
// single all-or-nothing pointer swap. When it is nil (lifecycle unarmed / disabled
// build / most unit tests) the policy path falls back to the full catStore taxonomy —
// byte-identical to the pre-F3b-4 behavior.
var saasEffectiveView = newFeedLiveStore()

// effectiveSource classifies where a live view's content came from (surfaced read-only
// for F3b-4; the recovery classifier sets it).
type effectiveSource int

const (
	sourceEmbedded   effectiveSource = iota // compiled baseline (fail-closed fallback / fresh install)
	sourceDownloaded                        // fresh network activation
	sourceCached                            // restart re-activation of the committed active generation (LKG)
	sourceResumed                           // floor-ahead crash-recovery completion
)

func (s effectiveSource) String() string {
	switch s {
	case sourceEmbedded:
		return "embedded"
	case sourceDownloaded:
		return "downloaded"
	case sourceCached:
		return "cached"
	case sourceResumed:
		return "resumed"
	default:
		return "unknown"
	}
}

// effectiveCategoryView is an IMMUTABLE composed host→category snapshot plus its
// provenance/identity. Never mutated after newEffectiveView returns; a new activation or
// override rebuild produces a NEW view that atomically replaces it.
type effectiveCategoryView struct {
	// entries maps a NORMALIZED feed/override host to its canonical category. Keys carry
	// host+subdomain suffix scope (a key covers itself and every subdomain), matching the
	// feed/override grammar. This is the CLASSIFICATION index ("what is this host?") —
	// one category per key.
	entries map[string]string

	// members maps the same normalized keys to EVERY category the key belongs to, in
	// precedence order (index 0 == entries[key]). It is the MEMBERSHIP index ("is this
	// host in category C?"), and it is what matchCategory must consult.
	//
	// The two indices differ only where the source taxonomy is many-to-many. The signed
	// feed and the override grammar are one-category-per-host, so for those sources
	// members is exactly entries. The EMBEDDED baseline is not: it is catStore's
	// BuiltIn taxonomy, where a host may legitimately sit in several categories at once
	// (linkedin.com is both "Social Media" and "HR & Recruiting"). Answering a
	// membership question from the classification index silently drops every category
	// but one, which drops any policy rule keyed on a losing category — a fail-open.
	// Keeping both indices is what makes the view a byte-faithful replacement for
	// catStore.MatchesHost.
	members map[string][]string

	// sealed is the set of override boundary keys (recategorization / addition /
	// tombstone hosts). A membership walk that reaches a sealed key STOPS there
	// instead of climbing to an ancestor baseline category: the override is the
	// sole authority for its subtree, so an ancestor category it did not assert
	// must not leak back in. Empty/nil for override-free views (embedded baseline,
	// signed feed with no overrides), where the walk behaves exactly as before.
	sealed map[string]bool

	// Identity / provenance (all read-only).
	Source         effectiveSource
	FeedVersion    int64  // 0 for the embedded baseline
	GenerationID   string // "" for embedded
	ManifestSHA256 string
	SnapshotSHA256 string
	GeneratedAt    string
	ExpiresAt      string
	ConfigRevision string // the override/config revision folded in ("compiled" for embedded/no-overrides)
	Stale          bool   // a committed generation served past expires_at (§B.11) — never fail-closed on age
}

// newEffectiveView builds an immutable view from a composed host→category map (defensive
// copy so the caller cannot mutate it post-publication). The membership index is derived
// 1:1 from the classification map — correct for every ONE-CATEGORY-PER-HOST source (the
// signed feed snapshot and the override grammar). A many-to-many source must use
// newEffectiveViewWithMembership instead, or membership queries lose categories.
func newEffectiveView(entries map[string]string, meta effectiveCategoryView) *effectiveCategoryView {
	members := make(map[string][]string, len(entries))
	for h, c := range entries {
		members[h] = []string{c}
	}
	return newEffectiveViewWithMembership(entries, members, meta)
}

// newEffectiveViewWithMembership builds an immutable view from a composed
// classification map plus its MEMBERSHIP map (host → every category, index 0 being the
// classification winner). Both are defensively copied. Used by the embedded-baseline
// paths, whose source (catStore's BuiltIn taxonomy) is many-to-many.
//
// A key present in members but absent from entries would be invisible to
// LookupHost/HostCount while still matching, and a key present in entries but absent
// from members would classify but never match — both are drift, so the constructor
// reconciles: entries seeds any missing members list, and members[key][0] seeds any
// missing entries value. Callers pass compositions produced by ComposeView and
// ComposeMembership over the same overrides, which agree on keys by construction.
func newEffectiveViewWithMembership(entries map[string]string, members map[string][]string, meta effectiveCategoryView) *effectiveCategoryView {
	ecp := make(map[string]string, len(entries))
	for h, c := range entries {
		ecp[h] = c
	}
	mcp := make(map[string][]string, len(members))
	for h, cats := range members {
		if len(cats) == 0 {
			continue
		}
		cp := make([]string, len(cats))
		copy(cp, cats)
		mcp[h] = cp
		if _, ok := ecp[h]; !ok {
			ecp[h] = cats[0]
		}
	}
	for h, c := range ecp {
		if _, ok := mcp[h]; !ok {
			mcp[h] = []string{c}
		}
	}
	// Defensively copy the override seal set so the view stays immutable after
	// construction (nil when there are no overrides — the walk then never seals).
	if len(meta.sealed) > 0 {
		scp := make(map[string]bool, len(meta.sealed))
		for h := range meta.sealed {
			scp[h] = true
		}
		meta.sealed = scp
	} else {
		meta.sealed = nil
	}
	meta.entries = ecp
	meta.members = mcp
	return &meta
}

// HasCategoryName reports whether the view carries any host classified (or
// membership-listed) under the named category, case-insensitively. Used by the
// reference-validity predicate (referencedCategoryResolvable): a rule or group
// member may legitimately reference a signed-feed class that is not a writable
// catStore object. Admin-rate write-door read — O(view) is acceptable there
// and this deliberately adds NO index the hot path would have to maintain.
func (v *effectiveCategoryView) HasCategoryName(name string) bool {
	for _, c := range v.entries {
		if strings.EqualFold(c, name) {
			return true
		}
	}
	for _, cats := range v.members {
		for _, c := range cats {
			if strings.EqualFold(c, name) {
				return true
			}
		}
	}
	return false
}

// HostCount / CategoryCount report the composed view's size.
func (v *effectiveCategoryView) HostCount() int { return len(v.entries) }

func (v *effectiveCategoryView) CategoryCount() int {
	seen := make(map[string]struct{}, len(v.entries))
	for _, c := range v.entries {
		seen[c] = struct{}{}
	}
	return len(seen)
}

// LookupHost resolves a host to its category using host+subdomain SUFFIX semantics
// (exact key, then progressively strip the leftmost label): a query `a.b.example.com`
// matches a key `example.com`. This mirrors the feed/override suffix grammar. The query
// is IDNA-normalized via hostutil.NormalizeHost — the SAME canonicalization the policy
// hot path applies to catStore/UT1 lookups — so a Unicode/punycode query resolves against
// the view's canonical A-label keys identically to the other category layers (F3b-4
// closes the prior plain-ToLower divergence). Returns ("", false) when no key covers the
// host.
func (v *effectiveCategoryView) LookupHost(host string) (string, bool) {
	h := hostutil.NormalizeHost(host)
	if h == "" {
		return "", false
	}
	for {
		if cat, ok := v.entries[h]; ok {
			return cat, true
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return "", false
		}
		h = h[i+1:]
	}
}

// MatchesCategory reports whether host belongs to cat, with EXACTLY the semantics of
// urlcat.Store.MatchesHost — the function it replaces on the policy hot path:
//
//   - the host is IDNA-normalized the same way (hostutil.NormalizeHost);
//   - the exact host key is checked, then EVERY suffix key ("a.b.example.com" checks
//     "a.b.example.com", "b.example.com", "example.com", "com"); and
//   - the walk does NOT stop at the first key that carries any category. A more
//     specific key belonging to a DIFFERENT category must not shadow an ancestor key
//     that does belong to cat — MatchesHost never shadowed, so neither does this.
//
// Category comparison is case-insensitive, matching MatchesHost's lowercased index.
// This is the MEMBERSHIP query; LookupHost answers the separate CLASSIFICATION query
// and is not a substitute for it.
func (v *effectiveCategoryView) MatchesCategory(cat, host string) bool {
	if cat == "" {
		return false
	}
	h := hostutil.NormalizeHost(host)
	if h == "" {
		return false
	}
	for {
		for _, c := range v.members[h] {
			if strings.EqualFold(c, cat) {
				return true
			}
		}
		if v.sealed[h] {
			// h is an explicit override boundary (recategorization / addition /
			// tombstone): it is the sole authority for itself and its subtree, so
			// an ancestor baseline category it did not assert is shadowed — stop
			// climbing rather than leaking the ancestor's category back in.
			return false
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			return false
		}
		h = h[i+1:]
	}
}

// ─── embedded baseline ─────────────────────────────────────────────────────────────

// embeddedBaselineEntries is the RAW (pre-override) embedded SaaS taxonomy: the live
// catStore's BuiltIn=true host→category set. Sourcing it from catStore — not the compiled
// urlcat.DefaultEntries — preserves any admin host-additions to built-in categories and
// any already-persisted legacy-merged SaaS hosts, so wiring the effective view onto the
// policy path leaves the pre-signed-activation match result byte-identical to the prior
// full-store behavior. On a fresh install catStore == DefaultEntries, so this is exactly
// the compiled baseline.
func embeddedBaselineEntries() map[string]string {
	classes, _ := embeddedBaselinePair()
	return classes
}

// embeddedBaselinePair returns the classification and membership maps derived
// from ONE snapshot of catStore's BuiltIn taxonomy. Capturing them with two
// separate store reads let a concurrent built-in edit land between them and
// produce a torn classification/membership pair inside one composed view
// (review P2 on the membership fix). The classification map is a pure
// projection of the membership map (first category wins — the same rule
// BuiltInHostCategories applies), so deriving both from the same snapshot
// removes the window entirely.
func embeddedBaselinePair() (map[string]string, map[string][]string) {
	members := catStore.BuiltInHostMemberships()
	classes := make(map[string]string, len(members))
	for h, cats := range members {
		classes[h] = cats[0]
	}
	return classes, members
}

// embeddedBaselineMemberships is the MEMBERSHIP companion of embeddedBaselineEntries:
// the same BuiltIn=true taxonomy with every category a host belongs to retained rather
// than collapsed to one. The embedded baseline is the only many-to-many source the view
// composes, so this is what keeps a multi-category host (e.g. linkedin.com under both
// "Social Media" and "HR & Recruiting") matching BOTH categories on the policy path,
// exactly as catStore.MatchesHost did before the view was wired in.
func embeddedBaselineMemberships() map[string][]string {
	return catStore.BuiltInHostMemberships()
}

// embeddedBaselineView builds the terminal fail-closed view from the embedded SaaS
// taxonomy WITHOUT overrides. It carries no feed version and source=embedded — used where
// a raw baseline is wanted; the coordinator's installEmbedded composes admin overrides on
// top (F3b-4 override-only recompose applies to the embedded baseline too).
func embeddedBaselineView() *effectiveCategoryView {
	classes, members := embeddedBaselinePair()
	return newEffectiveViewWithMembership(classes, members,
		effectiveCategoryView{
			Source:         sourceEmbedded,
			ConfigRevision: "compiled",
		})
}

// ─── the atomic live holder (§B.5 S5) ──────────────────────────────────────────────

// liveCategorySwapper is the cutover seam. Production is *feedLiveStore (an
// atomic.Pointer swap); tests may inject a fake that panics to exercise the cutover
// failure boundary (crash matrix #15).
type liveCategorySwapper interface {
	// Swap installs v as the live view (the atomic cutover) and returns the previous
	// view (nil if none).
	Swap(v *effectiveCategoryView) *effectiveCategoryView
	// Current returns the live view without blocking readers (nil if never set).
	Current() *effectiveCategoryView
}

// feedLiveStore is the production live holder: a single atomic.Pointer so the cutover is
// a lock-free, all-or-nothing swap and concurrent readers never observe a torn view.
type feedLiveStore struct {
	ptr atomic.Pointer[effectiveCategoryView]
}

func newFeedLiveStore() *feedLiveStore { return &feedLiveStore{} }

func (s *feedLiveStore) Swap(v *effectiveCategoryView) *effectiveCategoryView {
	return s.ptr.Swap(v)
}

func (s *feedLiveStore) Current() *effectiveCategoryView { return s.ptr.Load() }

// ─── legacy-syncer single-writer guard ─────────────────────────────────────────────

// signedFeedOwnsLiveStore reports whether the signed activation coordinator owns the
// live SaaS category store. While the coordinator is dormant (this slice) it stays
// FALSE, so the legacy raw syncer behaves exactly as before. Once the feed owns the live
// store, the legacy syncer's merge is gated to a no-op (mergeSaaSCategories) so there is
// exactly ONE writer and no signed→raw fallback / dual writer.
var signedFeedOwnsLiveStore atomic.Bool

// setSignedFeedOwnsLiveStore publishes ownership. Called by the coordinator after the
// first signed activation commits (kept as an explicit toggle so the legacy path can be
// proven a no-op under ownership without arming any runtime scheduling in this slice).
func setSignedFeedOwnsLiveStore(owned bool) { signedFeedOwnsLiveStore.Store(owned) }

// signedFeedOwnsLive reports the current ownership (read by the legacy syncer guard).
func signedFeedOwnsLive() bool { return signedFeedOwnsLiveStore.Load() }

// signedFeedOwnsBuiltInCategories is the AUTHORITATIVE mutability predicate for
// BUILT-IN categories (2D-B final correction, Blocker D): true iff the live
// effective view is serving a COMMITTED SIGNED GENERATION's classes. It is
// derived from the actual authority semantics — the live view's Source — not
// from provenance strings or status.state:
//
//   - view == nil (lifecycle unarmed): the full catStore taxonomy serves the
//     policy path directly — built-in edits are live. NOT owned.
//   - Source == embedded: the view is COMPOSED FROM catStore's BuiltIn
//     taxonomy (embeddedBaselineEntries), so a built-in edit + recompose is
//     effective. NOT owned.
//   - Source == downloaded / cached / resumed: the classes come from the
//     signed snapshot; a recompose rebuilds overrides over the SIGNED
//     classes, so a catStore built-in edit is durable yet NEVER reaches
//     enforcement. OWNED — the admin manages that content with SaaS
//     Overrides. (This covers disabled-recovery/stale too by construction:
//     whatever state the scheduler is in, the view Source says whose classes
//     are actually serving — stale keeps serving the LKG signed generation,
//     so it stays owned.)
//
// Admin-created (BuiltIn=false) categories are never feed-owned: the policy
// path resolves them from catStore's adminIndex regardless of the view.
func signedFeedOwnsBuiltInCategories() bool {
	v := saasEffectiveView.Current()
	return v != nil && v.Source != sourceEmbedded
}
