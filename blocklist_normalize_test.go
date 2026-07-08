package main

// blocklist_normalize_test.go — the engine-level normalize / attribution /
// cascade tests moved in-package to internal/blocklist with the extraction
// (ADR-0002, store.go decomposition Phase A). What remains is the API-handler
// integration test for the cleanup-unattributed server-side gate.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/blocklist"
)

// newAttributedBlocklist builds a blocklist with two attributed feeds, one
// legacy unattributed entry, and one manual entry — via the public API.
func newAttributedBlocklist(t *testing.T) *Blocklist {
	t.Helper()
	ensureBlocklistStartupTestLogger(t)
	b := blocklist.New()
	b.MergeFromLines([]string{"a.feed-one.invalid", "*.w.feed-one.invalid"}, "https://feeds.example/one.txt")
	b.MergeFromLines([]string{"b.feed-two.invalid"}, "https://feeds.example/two.txt")
	b.MergeFromLines([]string{"legacy.orphan.invalid"}, "") // pre-attribution import
	b.AddManual("keep.manual.invalid")
	return b
}

// TestCleanupUnattributed_RefusedWithoutFeeds pins the server-side gate:
// with zero configured feeds, unattributed entries are likely static-file
// or config-restored operator data, so the purge must be refused.
func TestCleanupUnattributed_RefusedWithoutFeeds(t *testing.T) {
	swapFeedSyncer(t, newTestBlocklistSyncer(t)) // zero feeds
	origBL := bl
	bl = newAttributedBlocklist(t)
	t.Cleanup(func() { bl = origBL })

	r := adminCtx(httptest.NewRequestWithContext(context.Background(),
		http.MethodDelete, "/api/blocklist?scope=unattributed", http.NoBody))
	w := httptest.NewRecorder()
	apiBlocklist(w, r)
	if w.Code != http.StatusConflict {
		t.Fatalf("cleanup without feeds: status = %d; want 409 (%s)", w.Code, w.Body.String())
	}
	if !bl.IsBlocked("legacy.orphan.invalid") {
		t.Error("orphan must NOT be removed when the gate refuses")
	}

	// With a feed configured the same call succeeds.
	blFeedSyncer.SetFeed("https://feeds.example/gate.txt", 0)
	w = httptest.NewRecorder()
	r = adminCtx(httptest.NewRequestWithContext(context.Background(),
		http.MethodDelete, "/api/blocklist?scope=unattributed", http.NoBody))
	apiBlocklist(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("cleanup with feeds: status = %d; want 200 (%s)", w.Code, w.Body.String())
	}
	if bl.IsBlocked("legacy.orphan.invalid") {
		t.Error("orphan should be removed once the gate passes")
	}
}
