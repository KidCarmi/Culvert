package logstore

// ADR-FE-002 Monitor keyset-pagination proofs. The load-bearing gate is
// DETERMINISTIC SCAN COUNTS (PageResult.Scanned), not wall-clock: page cost
// must be bounded by the entries visited to fill one page — never by how
// many pages precede it (the old offset/exact-total contract's O(depth)
// behavior).

import (
	"testing"
	"time"
)

// seedStore writes n entries with strictly increasing timestamps starting at
// base (1ms apart) and waits until they are all durably queryable. Adds in
// bounded chunks with a drain between them — Add is a drop-on-full async
// queue (cap 4096), so an unthrottled multi-thousand seed would overflow it.
func seedStore(t *testing.T, s *Store, base int64, n int) {
	t.Helper()
	const chunk = 2000
	for i := 0; i < n; i++ {
		status := "OK"
		if i%10 == 0 {
			status = "BLOCKED"
		}
		s.Add(Entry{TS: base + int64(i), Host: "h.example.com", Status: status, Level: "INFO"})
		if (i+1)%chunk == 0 {
			drainLogStore(t, s, i+1)
		}
	}
	drainLogStore(t, s, n)
}

func pageStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenTTL(t.TempDir(), 0, 0, nil, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestQueryPage_FirstPageNewestFirstBounded(t *testing.T) {
	s := pageStore(t)
	base := time.Now().Add(-time.Hour).UnixMilli()
	seedStore(t, s, base, 500)

	page, err := s.QueryPage(0, 0, 0, 0, 100, nil)
	if err != nil {
		t.Fatalf("QueryPage: %v", err)
	}
	if len(page.Entries) != 100 {
		t.Fatalf("page size = %d, want 100 (server-bounded)", len(page.Entries))
	}
	if !page.HasMore {
		t.Fatal("HasMore = false with 400 more entries behind the page")
	}
	// Newest-first, deterministic ordering.
	for i := 1; i < len(page.Entries); i++ {
		if page.Entries[i].TS > page.Entries[i-1].TS {
			t.Fatalf("ordering violated at %d: %d > %d", i, page.Entries[i].TS, page.Entries[i-1].TS)
		}
	}
	if page.Entries[0].TS != base+499 {
		t.Fatalf("first entry TS = %d, want newest %d", page.Entries[0].TS, base+499)
	}
	// Cost proof: an unfiltered first page visits page+1 entries, not the store.
	if page.Scanned > 101 {
		t.Fatalf("first page scanned %d entries, want <= 101", page.Scanned)
	}
}

func TestQueryPage_DeepPageCostDoesNotGrowWithDepth(t *testing.T) {
	s := pageStore(t)
	base := time.Now().Add(-time.Hour).UnixMilli()
	const n = 5000
	seedStore(t, s, base, n)

	// Walk 40 pages deep via cursors, recording each page's scan cost.
	var afterTS int64
	var afterSeq uint32
	seen := map[int64]bool{}
	maxScan := 0
	for pageNo := 0; pageNo < 40; pageNo++ {
		page, err := s.QueryPage(0, 0, afterTS, afterSeq, 100, nil)
		if err != nil {
			t.Fatalf("page %d: %v", pageNo, err)
		}
		if len(page.Entries) != 100 {
			t.Fatalf("page %d size = %d, want 100", pageNo, len(page.Entries))
		}
		for i := range page.Entries {
			if seen[page.Entries[i].TS] {
				t.Fatalf("page %d: duplicate entry TS %d across pages", pageNo, page.Entries[i].TS)
			}
			seen[page.Entries[i].TS] = true
		}
		if page.Scanned > maxScan {
			maxScan = page.Scanned
		}
		afterTS, afterSeq = page.NextTS, page.NextSeq
	}
	// THE contract: page-40's cost equals page-1's cost class. The old offset
	// path would have scanned offset+limit (≈4000+) entries by this depth.
	if maxScan > 101 {
		t.Fatalf("deep-page scan cost %d, want <= 101 (must not grow with page depth)", maxScan)
	}
	if len(seen) != 4000 {
		t.Fatalf("walked %d distinct entries, want 4000", len(seen))
	}
}

func TestQueryPage_FilterAndWindowEnforcedServerSide(t *testing.T) {
	s := pageStore(t)
	base := time.Now().Add(-time.Hour).UnixMilli()
	seedStore(t, s, base, 1000) // every 10th BLOCKED (100 total)

	blocked := func(e *Entry) bool { return e.Status == "BLOCKED" }
	page, err := s.QueryPage(0, 0, 0, 0, 30, blocked)
	if err != nil {
		t.Fatalf("QueryPage: %v", err)
	}
	if len(page.Entries) != 30 {
		t.Fatalf("filtered page = %d, want 30", len(page.Entries))
	}
	for i := range page.Entries {
		if page.Entries[i].Status != "BLOCKED" {
			t.Fatalf("server-side filter leaked entry %q", page.Entries[i].Status)
		}
	}
	if !page.HasMore {
		t.Fatal("HasMore = false with 70 more BLOCKED entries")
	}
	// Cursor continues within the SAME filter without duplication.
	page2, err := s.QueryPage(0, 0, page.NextTS, page.NextSeq, 100, blocked)
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Entries) != 70 {
		t.Fatalf("second filtered page = %d, want the remaining 70", len(page2.Entries))
	}
	if page2.HasMore {
		t.Fatal("HasMore = true after the last matching entry")
	}

	// Time window: only entries inside [from, to] are visited.
	from := base + 100
	to := base + 199
	win, err := s.QueryPage(from, to, 0, 0, 500, nil)
	if err != nil {
		t.Fatalf("window: %v", err)
	}
	if len(win.Entries) != 100 {
		t.Fatalf("window result = %d, want 100", len(win.Entries))
	}
	for i := range win.Entries {
		if win.Entries[i].TS < from || win.Entries[i].TS > to {
			t.Fatalf("entry TS %d escaped window [%d,%d]", win.Entries[i].TS, from, to)
		}
	}
	if win.HasMore {
		t.Fatal("window exhausted but HasMore = true")
	}
}

func TestQueryPage_StableUnderConcurrentAppends(t *testing.T) {
	s := pageStore(t)
	base := time.Now().Add(-time.Hour).UnixMilli()
	seedStore(t, s, base, 300)

	page1, err := s.QueryPage(0, 0, 0, 0, 100, nil)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	// New traffic arrives AFTER the cursor was issued (newer keys).
	for i := 0; i < 200; i++ {
		s.Add(Entry{TS: base + 10_000 + int64(i), Host: "h.example.com", Status: "OK", Level: "INFO"})
	}
	drainLogStore(t, s, 500) // 300 seeded + 200 appended
	page2, err := s.QueryPage(0, 0, page1.NextTS, page1.NextSeq, 100, nil)
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	// The cursor keeps paging the OLDER window: no duplicates, no skips —
	// page2 continues exactly below page1.
	if page2.Entries[0].TS != page1.Entries[len(page1.Entries)-1].TS-1 {
		t.Fatalf("page2 starts at %d, want %d (continuation, unaffected by appends)",
			page2.Entries[0].TS, page1.Entries[len(page1.Entries)-1].TS-1)
	}
	seenPage1 := map[int64]bool{}
	for i := range page1.Entries {
		seenPage1[page1.Entries[i].TS] = true
	}
	for i := range page2.Entries {
		if seenPage1[page2.Entries[i].TS] {
			t.Fatalf("append race duplicated TS %d across pages", page2.Entries[i].TS)
		}
	}
}

func TestQueryPage_LimitClampedAndNilStoreSafe(t *testing.T) {
	var nilStore *Store
	page, err := nilStore.QueryPage(0, 0, 0, 0, 100, nil)
	if err != nil || len(page.Entries) != 0 || page.HasMore {
		t.Fatalf("nil store: %+v err=%v", page, err)
	}
	s := pageStore(t)
	seedStore(t, s, time.Now().Add(-time.Hour).UnixMilli(), 5)
	big, err := s.QueryPage(0, 0, 0, 0, 1<<30, nil)
	if err != nil {
		t.Fatalf("big limit: %v", err)
	}
	if len(big.Entries) != 5 {
		t.Fatalf("clamped query returned %d, want 5", len(big.Entries))
	}
}
