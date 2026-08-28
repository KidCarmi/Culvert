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
// the UT1 community feed", never "backed by the signed SaaS corpus").
type enrichedURLCategory struct {
	CategoryEntry
	FeedBacked bool `json:"feedBacked"`
}

// enrichedURLCategories returns every category with the UT1 enrichment —
// shared by the legacy GET /api/urlcat array and the v2 /state contract so
// the two reads can never disagree.
func enrichedURLCategories() []enrichedURLCategory {
	all := catStore.All()
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
		}
	}
	return enriched
}

// GET /api/urlcat/state — v2 read: categories + the server-owned semantic
// revision. Viewer read; no side effects.
func apiURLCatState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonOK(w, map[string]any{
		"categories": enrichedURLCategories(),
		"revision":   catStore.ContentFingerprint(),
	})
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
