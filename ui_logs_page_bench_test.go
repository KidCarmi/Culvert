package main

// ui_logs_page_bench_test.go — before/after evidence for the GET /api/logs page
// assembly over the in-memory request-log ring (ui_config.go filterLogPage).
//
// Run:
//
//	go test -run '^$' -bench 'BenchmarkAPILogsPage|BenchmarkLogPage' -benchmem -count=6 .
//
// filterLogPageLegacy is the FROZEN pre-change shape: materialize every match
// into a slice grown from zero capacity, then slice that down to the page. It
// is kept in-tree so the comparison stays reproducible rather than living only
// in a commit message. It is not called by production and must NOT be "kept in
// sync" with filterLogPage — its whole value is that it does not move.
//
// Measured on this machine (Go 1.27.3, linux/amd64, 4 vCPU, a full 5 000-entry
// ring, 352 B per LogEntry), page assembly in isolation — legacy vs current,
// median of 5:
//
//	                      B/op legacy    B/op now   allocs      ns/op
//	default (limit 1000)   7 487 074     352 256    17 -> 1   6.38M -> 0.26M
//	50-row page            7 487 075      18 432    17 -> 1   6.77M -> 0.07M
//	50-row @ offset 4000   7 487 074      18 432    17 -> 1   6.57M -> 0.06M
//	narrow filter             11 872      18 432     5 -> 1   0.31M -> 0.33M
//
// and whole-handler (ring copy + page + JSON encode), same input:
//
//	                      before        after        delta
//	default poll       9 904 kB/op   2 442 kB/op    -75.3%
//	50-row page        9 288 kB/op   1 802 kB/op    -80.6%
//	50-row @off=4000   9 288 kB/op   1 802 kB/op    -80.6%
//	narrow filter      1 784 kB/op   1 791 kB/op     +0.4%  (the page prealloc)
//
// The narrow-filter row is the deliberate trade documented on filterLogPage:
// the page is sized by the requested limit, not by the match count, so a
// selective filter over-allocates by one slice. The ~1.8 MB floor that remains
// in every whole-handler row is reqlog.Get()'s full-ring copy — a separate
// concern, deliberately not touched here.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/reqlog"
)

// filterLogPageLegacy is the pre-change page assembly, frozen verbatim.
func filterLogPageLegacy(all []LogEntry, fromMs, toMs int64, offset, limit int, pred func(*LogEntry) bool) (page []LogEntry, total int) {
	filtered := all[:0:0]
	for i := range all {
		e := &all[i]
		if fromMs != 0 && e.TS < fromMs {
			continue
		}
		if toMs != 0 && e.TS > toMs {
			continue
		}
		if !pred(e) {
			continue
		}
		filtered = append(filtered, *e)
	}
	total = len(filtered)
	if offset >= total {
		filtered = nil
	} else {
		end := offset + limit
		if end > total {
			end = total
		}
		filtered = filtered[offset:end]
	}
	return filtered, total
}

// benchLogEntries builds a full ring's worth of browser-shaped entries. A full
// ring is the only honest input: at any real request rate the ring is always at
// capacity, so that is the steady state every dashboard poll scans.
func benchLogEntries(n int) []LogEntry {
	now := time.Now().UnixMilli()
	out := make([]LogEntry, n)
	for i := range out {
		out[i] = LogEntry{
			TS:       now + int64(i),
			IP:       "10.0.0.7",
			Method:   "GET",
			Host:     fmt.Sprintf("host%04d.example.com", i%512),
			Status:   "OK",
			Level:    "INFO",
			Identity: "alice@example.com",
		}
	}
	return out
}

func benchLogPage(b *testing.B, offset, limit int, query string, fn func([]LogEntry, int64, int64, int, int, func(*LogEntry) bool) ([]LogEntry, int)) {
	b.Helper()
	all := benchLogEntries(reqlog.MaxRing)
	q, err := url.ParseQuery(query)
	if err != nil {
		b.Fatalf("ParseQuery(%q): %v", query, err)
	}
	pred := buildLogFilterPredicate(q)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		page, total := fn(all, 0, 0, offset, limit, pred)
		if total == 0 && len(page) != 0 {
			b.Fatal("page without matches")
		}
	}
}

// ── Page assembly in isolation (apples-to-apples, no ring copy, no JSON) ──

func BenchmarkLogPage_Default(b *testing.B)       { benchLogPage(b, 0, 1000, "", filterLogPage) }
func BenchmarkLogPage_DefaultLegacy(b *testing.B) { benchLogPage(b, 0, 1000, "", filterLogPageLegacy) }
func BenchmarkLogPage_SmallPage(b *testing.B)     { benchLogPage(b, 0, 50, "", filterLogPage) }
func BenchmarkLogPage_SmallPageLegacy(b *testing.B) {
	benchLogPage(b, 0, 50, "", filterLogPageLegacy)
}

// Deep offset: the scan still visits every entry, so this isolates the page
// copy from the scan.
func BenchmarkLogPage_DeepOffset(b *testing.B) { benchLogPage(b, 4000, 50, "", filterLogPage) }
func BenchmarkLogPage_DeepOffsetLegacy(b *testing.B) {
	benchLogPage(b, 4000, 50, "", filterLogPageLegacy)
}

// A narrow filter matches almost nothing, so both shapes are dominated by the
// scan. This is the row that must NOT regress materially.
func BenchmarkLogPage_Filtered(b *testing.B) {
	benchLogPage(b, 0, 50, "filter=host0001.example.com", filterLogPage)
}
func BenchmarkLogPage_FilteredLegacy(b *testing.B) {
	benchLogPage(b, 0, 50, "filter=host0001.example.com", filterLogPageLegacy)
}

// ── Whole-handler evidence (ring copy + page + JSON encode) ───────────────

func benchServeLogs(b *testing.B, target string) {
	b.Helper()
	b.Cleanup(reqlog.SwapRingForTest())
	seed := benchLogEntries(reqlog.MaxRing)
	for i := range seed {
		logAdd(seed[i])
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequestWithContext(b.Context(), http.MethodGet, target, http.NoBody)
		w := httptest.NewRecorder()
		apiLogs(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("status = %d, want 200", w.Code)
		}
	}
}

// BenchmarkAPILogsPage_Default is the dashboard's own poll: no filter, default
// page size, first page.
func BenchmarkAPILogsPage_Default(b *testing.B) { benchServeLogs(b, "/api/logs") }

// BenchmarkAPILogsPage_SmallPage is the React log table's incremental page.
func BenchmarkAPILogsPage_SmallPage(b *testing.B) { benchServeLogs(b, "/api/logs?limit=50") }

// BenchmarkAPILogsPage_DeepOffset pages near the end of the ring.
func BenchmarkAPILogsPage_DeepOffset(b *testing.B) {
	benchServeLogs(b, "/api/logs?limit=50&offset=4000")
}

// BenchmarkAPILogsPage_Filtered narrows to a single host.
func BenchmarkAPILogsPage_Filtered(b *testing.B) {
	benchServeLogs(b, "/api/logs?filter=host0001.example.com&limit=50")
}
