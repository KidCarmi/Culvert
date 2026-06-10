package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// GET /api/blocklist with an offset must never read past the offset reslice.
// Before the fix, `limit` defaulted to the pre-offset total, so
// filtered[:limit] indexed beyond the reslice — returning garbage zero-value
// entries, or panicking with a slice-bounds error (viewer-role DoS) when the
// backing array cap was tight.
func TestAPIBlocklist_OffsetDoesNotPanicOrLeak(t *testing.T) {
	hosts := []string{
		"pg-a.example.com", "pg-b.example.com", "pg-c.example.com",
		"pg-d.example.com", "pg-e.example.com", "pg-f.example.com",
	}
	for _, h := range hosts {
		bl.Add(h)
	}
	t.Cleanup(func() {
		for _, h := range hosts {
			bl.Remove(h)
		}
	})

	total := len(bl.ListWithSource())
	offset := total - 2 // leaves only 2 entries after the reslice

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet,
		"/api/blocklist?offset="+strconv.Itoa(offset), http.NoBody)
	r.RemoteAddr = "198.51.100.9:5555"
	apiBlocklist(w, adminCtx(r)) // must not panic

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}

	var resp struct {
		Entries []BlocklistEntry `json:"entries"`
		Count   int              `json:"count"`
		Offset  int              `json:"offset"`
		Limit   int              `json:"limit"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Exactly the post-offset remainder, and every entry must be a real
	// blocklist host (no zero-value Host leaking from beyond the reslice).
	if got := len(resp.Entries); got != total-offset {
		t.Fatalf("returned %d entries, want %d", got, total-offset)
	}
	for i, e := range resp.Entries {
		if e.Host == "" {
			t.Fatalf("entry %d has empty Host — leaked past the offset reslice: %+v", i, resp.Entries)
		}
	}
}
