package main

// urlcat_state_api.go — 2D-B.0a: the v2 URL-category management seam.
//
// GET /api/urlcat/state is the explicit v2 read contract:
//
//	{ "categories": [...], "revision": "<server semantic fingerprint>" }
//
// It exists so the legacy GET /api/urlcat (a raw array, consumed by the v1
// GUI and scripts) never changes shape (2D-B §8). The revision is the
// server-owned restart-stable ContentFingerprint — the browser never
// reproduces it, only echoes it back on mutations via ?ifRevision= (§9).
//
// Mutations carrying ?ifRevision= run through the store's fenced durable
// primitives (fence + mutation + durable publish in ONE serialization
// domain — no detached handler check, no TOCTOU); a stale assertion is the
// structured 409 {error, currentRevision, yourRevision}. Mutations without
// it keep the legacy best-effort contract byte-for-byte.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/KidCarmi/Culvert/internal/feedsync"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// enrichedURLCategory is one category row with the UT1 community-feed
// enrichment (the `feedBacked` flag means "this category NAME is mapped by
// the UT1 community feed", never "backed by the signed SaaS corpus") and the
// SERVER-OWNED mutability truth (`writable`, Blocker D): false exactly when
// the row is a BuiltIn category whose classes are currently served from a
// committed signed feed generation (signedFeedOwnsBuiltInCategories) — a
// local edit would be durable yet superseded, so the v2 mutation surface
// refuses it and the GUI must not offer it. The browser NEVER derives this
// from builtIn/provenance/status.state.
type enrichedURLCategory struct {
	CategoryEntry
	FeedBacked bool `json:"feedBacked"`
	Writable   bool `json:"writable"`
}

// enrichedURLCategories returns every category with the UT1 enrichment —
// the legacy GET /api/urlcat array read (no revision, so no pairing to keep
// coherent). The v2 /state contract goes through enrichURLCategories over a
// coherent SnapshotWithRevision capture instead.
func enrichedURLCategories() []enrichedURLCategory {
	return enrichURLCategories(catStore.All(), signedFeedOwnsBuiltInCategories())
}

// enrichURLCategories layers the UT1 community-feed badge over an
// already-captured row set. The enrichment is DERIVED display state from a
// separate subsystem (the UT1 corpus), deliberately outside the taxonomy
// revision — it decorates the captured rows and never mutates them, so the
// revision paired with the rows by SnapshotWithRevision keeps describing
// exactly what is returned (Blocker A).
func enrichURLCategories(all []CategoryEntry, feedOwned bool) []enrichedURLCategory {
	ut1Set := make(map[string]bool)
	if communityDB != nil { // badge only when the community feed is actually configured
		for _, cat := range feedsync.MappedCategories() {
			ut1Set[strings.ToLower(cat)] = true
		}
	}
	enriched := make([]enrichedURLCategory, len(all))
	for i, e := range all {
		enriched[i] = enrichedURLCategory{
			CategoryEntry: e,
			FeedBacked:    ut1Set[strings.ToLower(e.Name)],
			Writable:      !(e.BuiltIn && feedOwned),
		}
	}
	return enriched
}

// GET /api/urlcat/state — v2 read: categories + the server-owned semantic
// revision, captured as ONE coherent snapshot (the revision describes exactly
// the rows returned — never All() then ContentFingerprint() as two reads a
// writer can land between; Blocker A).
func apiURLCatState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	entries, revision := catStore.SnapshotWithRevision()
	// builtInAuthority is the page-level ownership truth (Blocker D):
	// "signed-feed" while a committed signed generation's classes are serving
	// (built-in rows are read-only, managed via SaaS Overrides), "local"
	// while the embedded baseline / raw catStore serves (built-in rows are
	// editable and a recompose makes edits effective). Runtime authority
	// state, deliberately OUTSIDE the taxonomy revision — but captured ONCE
	// for the whole response (§15): the page-level authority and every
	// row.writable derive from this exact same fact, so a source transition
	// between two reads can never tear authority against writability.
	feedOwned := signedFeedOwnsBuiltInCategories()
	authority := "local"
	if feedOwned {
		authority = "signed-feed"
	}
	jsonOK(w, map[string]any{
		"categories":       enrichURLCategories(entries, feedOwned),
		"revision":         revision,
		"builtInAuthority": authority,
	})
}

// writeFeedOwnedConflict renders the structured Blocker-D 409: a BuiltIn row
// whose classes are currently owned by a committed signed feed generation is
// read-only on the v2 (fenced) mutation surface — a durable 2xx the enforced
// view ignores is a lie the fenced contract must not tell. Legacy unfenced
// callers keep their pre-existing compatibility behavior (durable write,
// superseded until the feed releases ownership), and admin-created
// (BuiltIn=false) categories are never refused.
func writeFeedOwnedConflict(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // response write
		"error":      "category is owned by the active signed SaaS feed: local edits are superseded until the feed releases ownership",
		"owner":      "signed-feed",
		"manageWith": "saas-overrides",
	})
}

// beginV2CategoryMutation linearizes a v2 category mutation against signed
// authority transitions (Blocker C §§12–14). For a BuiltIn row it enters the
// SHARED side of taxonomyAuthorityGate, re-reads the ownership fact under it
// and either refuses (409, refused=true — the transition already won) or
// returns with the gate HELD: the caller performs the durable catStore
// mutation, then calls release() BEFORE recomposing (the recompose publishes
// through feedLiveStore.Swap, the gate's exclusive side — holding the shared
// side across it would self-deadlock). A transition landing after release is
// a legitimate LATER ordered supersession (§14 outcome B). Admin-created /
// unknown rows return a no-op release and never serialize against signed
// activation (§13).
func beginV2CategoryMutation(w http.ResponseWriter, name string) (release func(), refused bool) {
	builtIn, found := catStore.BuiltInFlag(name)
	if !found || !builtIn {
		return func() {}, false
	}
	taxonomyAuthorityGate.RLock()
	if signedFeedOwnsBuiltInCategories() {
		taxonomyAuthorityGate.RUnlock()
		writeFeedOwnedConflict(w)
		return nil, true
	}
	return taxonomyAuthorityGate.RUnlock, false
}

// parseIfRevision reads the optional ?ifRevision= optimistic-fence assertion.
// nil = legacy caller (no fence); the v2 frontend always sends it.
func parseIfRevision(r *http.Request) *string {
	if !r.URL.Query().Has("ifRevision") {
		return nil
	}
	v := r.URL.Query().Get("ifRevision")
	return &v
}

// writeTaxonomyMutationError maps a fenced-mutation failure to its response.
//   - *urlcat.RevisionConflictError → structured 409 (stale fence; no merge)
//   - ErrNameExists → 409 (strict create — never a silent upsert, §10)
//   - ErrTooManyHosts → 400 (MaxHostsPerCategory boundary, §11)
//   - ErrPersist → 500 (mutation rolled back; nothing durable changed)
//   - not-found from the store → 404 (legacy status parity)
//   - anything else → 400
func writeTaxonomyMutationError(w http.ResponseWriter, err error) {
	var conflict *urlcat.RevisionConflictError
	switch {
	case errors.As(err, &conflict):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // response write
			"error":           "taxonomy revision conflict",
			"currentRevision": conflict.Current,
			"yourRevision":    conflict.Asserted,
		})
	case errors.Is(err, urlcat.ErrNameExists):
		http.Error(w, "category name already exists", http.StatusConflict)
	case errors.Is(err, urlcat.ErrTooManyHosts):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, urlcat.ErrPersist):
		http.Error(w, "failed to persist url categories: the mutation was rolled back", http.StatusInternalServerError)
	case strings.Contains(err.Error(), "not found"), strings.Contains(err.Error(), "not in category"):
		http.Error(w, err.Error(), http.StatusNotFound)
	default:
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}
