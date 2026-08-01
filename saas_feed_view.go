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

	"github.com/KidCarmi/Culvert/internal/urlcat"
)

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
	// feed/override grammar.
	entries map[string]string

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
// copy so the caller cannot mutate it post-publication).
func newEffectiveView(entries map[string]string, meta effectiveCategoryView) *effectiveCategoryView {
	cp := make(map[string]string, len(entries))
	for h, c := range entries {
		cp[h] = c
	}
	meta.entries = cp
	return &meta
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
// matches a key `example.com`. This mirrors the feed/override suffix grammar WITHOUT
// touching the policy engine's existing urlcat matching (this holder is not yet on the
// hot path). Returns ("", false) when no key covers the host.
func (v *effectiveCategoryView) LookupHost(host string) (string, bool) {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
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

// ─── embedded baseline ─────────────────────────────────────────────────────────────

// embeddedBaselineView builds the terminal fail-closed view from the compiled category
// baseline (urlcat.DefaultEntries). It carries no feed version and source=embedded — the
// recovery step-4 fallback (§B.7) and the fresh-install state. ConfigRevision is
// "compiled" (overrides never apply to the embedded baseline in this slice; the
// composed-with-overrides view is only built for a re-verified generation).
func embeddedBaselineView() *effectiveCategoryView {
	entries := map[string]string{}
	for _, e := range urlcat.DefaultEntries() {
		if e == nil {
			continue
		}
		for _, h := range e.Hosts {
			nh := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
			if nh != "" {
				entries[nh] = e.Name
			}
		}
	}
	return newEffectiveView(entries, effectiveCategoryView{
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
