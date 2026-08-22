package main

// API-level scan-limited continuation tests for GET /api/logs?source=store
// (FE-4 hardening §1/§2). The raw-scan budget is injected through
// apiLogsCursorScanBudget so the sparse-filter contract is provable through
// the REAL handler with a small fixture; production keeps the engine default.

import (
	"net/url"
	"testing"
)

func withSmallScanBudget(t *testing.T, budget int) {
	t.Helper()
	old := apiLogsCursorScanBudget
	apiLogsCursorScanBudget = budget
	t.Cleanup(func() { apiLogsCursorScanBudget = old })
}

// Zero matching rows in a scan segment must NOT be a terminal empty page:
// the response distinguishes "more history to search" (scan_limited) from
// "window exhausted", carries a non-empty continuation cursor, and repeated
// bounded continuation makes forward progress to the true terminal.
func TestApiLogsCursor_ScanLimitedZeroMatchContinuation(t *testing.T) {
	cursorStoreFixture(t, 250)
	withSmallScanBudget(t, 100)

	q := "source=store&filter=absent-host.test&cursor="
	page1, code := getCursorPage(t, q)
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	if len(page1.Logs) != 0 {
		t.Fatalf("segment 1 rows = %d, want 0", len(page1.Logs))
	}
	if !page1.HasMore || !page1.ScanLimited || page1.NextCursor == "" {
		t.Fatalf("segment 1 must be a continuation: has_more=%v scan_limited=%v cursor=%q",
			page1.HasMore, page1.ScanLimited, page1.NextCursor)
	}

	page2, code := getCursorPage(t, "source=store&filter=absent-host.test&cursor="+url.QueryEscape(page1.NextCursor))
	if code != 200 {
		t.Fatalf("segment 2 status %d", code)
	}
	if !page2.ScanLimited || page2.NextCursor == "" || page2.NextCursor == page1.NextCursor {
		t.Fatalf("segment 2 made no forward progress: scan_limited=%v cursor=%q (prev %q)",
			page2.ScanLimited, page2.NextCursor, page1.NextCursor)
	}

	page3, code := getCursorPage(t, "source=store&filter=absent-host.test&cursor="+url.QueryEscape(page2.NextCursor))
	if code != 200 {
		t.Fatalf("segment 3 status %d", code)
	}
	// 250 entries under budget 100: segment 3 scans the final 50 and the
	// window is exhausted — the TRUE terminal empty result.
	if page3.HasMore || page3.ScanLimited || page3.NextCursor != "" || len(page3.Logs) != 0 {
		t.Fatalf("segment 3 must be terminal empty: %+v", page3)
	}
}

// Sparse matches ahead of a budget-sized gap: the continuation cursor must
// advance past the scanned gap (never loop on the last returned match) and
// eventually reach the true terminal without rescanning.
func TestApiLogsCursor_ScanLimitedPartialResultsAdvance(t *testing.T) {
	// 250 "cursor.example.com" entries; every 5th is BLOCKED (50 matches
	// spread through the store), so a status filter is sparse but present.
	cursorStoreFixture(t, 250)
	withSmallScanBudget(t, 100)

	var (
		cursor   string
		rows     int
		segments int
	)
	for {
		page, code := getCursorPage(t, "source=store&status=BLOCKED&cursor="+url.QueryEscape(cursor))
		if code != 200 {
			t.Fatalf("segment %d status %d", segments, code)
		}
		segments++
		rows += len(page.Logs)
		if !page.HasMore {
			if page.ScanLimited || page.NextCursor != "" {
				t.Fatalf("terminal segment inconsistent: %+v", page)
			}
			break
		}
		if page.NextCursor == "" {
			t.Fatalf("segment %d: has_more with no continuation cursor", segments)
		}
		if page.NextCursor == cursor {
			t.Fatalf("segment %d: cursor did not advance (loop)", segments)
		}
		cursor = page.NextCursor
		if segments > 10 {
			t.Fatal("continuation did not terminate")
		}
	}
	if rows != 50 {
		t.Fatalf("total matching rows = %d, want all 50 (nothing skipped, nothing duplicated)", rows)
	}
}

// Dense pages keep the original contract byte-for-byte: normal look-ahead
// has_more with scan_limited=false.
func TestApiLogsCursor_DensePageNotScanLimited(t *testing.T) {
	cursorStoreFixture(t, 250)

	page, code := getCursorPage(t, "source=store&cursor=")
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	if page.ScanLimited {
		t.Fatal("dense first page must not be scan_limited")
	}
	if len(page.Logs) != apiLogsCursorDefaultLimit || !page.HasMore || page.NextCursor == "" {
		t.Fatalf("dense page shape changed: %+v", page)
	}
}
