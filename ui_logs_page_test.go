package main

// ui_logs_page_test.go — behavior contract for the GET /api/logs page assembly
// (ui_config.go filterLogPage) and the allocation gate that keeps it there.
//
// The page is now assembled DURING the scan instead of after it, so the thing
// most worth pinning is that nothing observable changed: the differential
// oracle below runs the frozen pre-change shape (filterLogPageLegacy, in
// ui_logs_page_bench_test.go) over the same grid of windows and filters and
// requires byte-identical pages, identical totals, AND the same nil-vs-empty
// slice shape — `"logs": null` for an out-of-range offset is pre-existing wire
// behavior that clients may depend on.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"
)

// logPageOracleEntries builds a deterministic set with a mix of hosts, statuses
// and timestamps so the window, the predicate and the pagination all bite.
func logPageOracleEntries(n int) []LogEntry {
	const base int64 = 1_700_000_000_000
	out := make([]LogEntry, n)
	for i := range out {
		status, level := "OK", "INFO"
		if i%7 == 0 {
			status, level = "POLICY_BLOCK", "WARN"
		}
		out[i] = LogEntry{
			TS:       base + int64(i)*1000,
			IP:       fmt.Sprintf("10.0.%d.%d", i/256%256, i%256),
			Method:   []string{"GET", "POST", "CONNECT"}[i%3],
			Host:     fmt.Sprintf("host%03d.example.com", i%40),
			Status:   status,
			Level:    level,
			Identity: fmt.Sprintf("user%d@example.com", i%5),
		}
	}
	return out
}

func TestFilterLogPage_MatchesLegacyShape(t *testing.T) {
	const base int64 = 1_700_000_000_000
	all := logPageOracleEntries(500)

	queries := []string{
		"",
		"filter=host007.example.com",
		"filter=10.0.0.3",
		"status=POLICY_BLOCK",
		"level=WARN",
		"method=CONNECT",
		"identity=user3@example.com",
		"status=NO_SUCH_STATUS", // negative control: matches nothing
	}
	windows := []struct{ from, to int64 }{
		{0, 0},
		{base + 100_000, 0},
		{0, base + 100_000},
		{base + 100_000, base + 200_000},
		{base + 10_000_000, 0}, // negative control: window past the data
	}
	pages := []struct{ offset, limit int }{
		{0, 1}, {0, 50}, {0, 1000}, {7, 13}, {499, 10}, {500, 10}, {5000, 10},
	}

	for _, q := range queries {
		vals, err := url.ParseQuery(q)
		if err != nil {
			t.Fatalf("ParseQuery(%q): %v", q, err)
		}
		pred := buildLogFilterPredicate(vals)
		for _, w := range windows {
			for _, p := range pages {
				gotPage, gotTotal := filterLogPage(all, w.from, w.to, p.offset, p.limit, pred)
				wantPage, wantTotal := filterLogPageLegacy(all, w.from, w.to, p.offset, p.limit, pred)
				label := fmt.Sprintf("q=%q from=%d to=%d offset=%d limit=%d", q, w.from, w.to, p.offset, p.limit)
				if gotTotal != wantTotal {
					t.Errorf("%s: total = %d, want %d", label, gotTotal, wantTotal)
				}
				if (gotPage == nil) != (wantPage == nil) {
					t.Errorf("%s: page nil = %v, want %v (the wire shape of an empty page must not change)",
						label, gotPage == nil, wantPage == nil)
				}
				if !reflect.DeepEqual(gotPage, wantPage) {
					t.Errorf("%s: page = %d entries, want %d (contents differ)", label, len(gotPage), len(wantPage))
				}
			}
		}
	}
}

func TestFilterLogPage_EmptyInput(t *testing.T) {
	pred := buildLogFilterPredicate(url.Values{})
	page, total := filterLogPage(nil, 0, 0, 0, 1000, pred)
	if total != 0 {
		t.Errorf("total = %d, want 0", total)
	}
	if page != nil {
		t.Errorf("page = %#v, want nil", page)
	}
}

func TestFilterLogPage_PageIsIndependentOfInput(t *testing.T) {
	all := logPageOracleEntries(10)
	pred := buildLogFilterPredicate(url.Values{})
	page, _ := filterLogPage(all, 0, 0, 0, 3, pred)
	if len(page) != 3 {
		t.Fatalf("page = %d entries, want 3", len(page))
	}
	page[0].Host = "mutated.example.com"
	if all[0].Host == "mutated.example.com" {
		t.Error("mutating the returned page wrote through to the caller's slice")
	}
}

// TestBenchGate_APILogsPageAllocs keeps the page assembly from drifting back to
// "materialize every match, then paginate". The bound is on the page assembly
// alone (no ring copy, no JSON encode): a 50-row page over a full ring must
// cost one allocation's worth of entries, not 5 000.
func TestBenchGate_APILogsPageAllocs(t *testing.T) {
	if testing.Short() {
		t.Skip("benchmark gate: skipped under -short")
	}
	// 50 entries x 352 B = 17.6 kB, plus slack for the predicate closure. The
	// frozen pre-change shape costs ~7.5 MB here, so the bound is nowhere near
	// tight enough to be flaky and still catches a reintroduction by ~400x.
	const maxBytes int64 = 128 << 10

	all := logPageOracleEntries(5000)
	pred := buildLogFilterPredicate(url.Values{})
	run := func(fn func([]LogEntry, int64, int64, int, int, func(*LogEntry) bool) ([]LogEntry, int)) testing.BenchmarkResult {
		return testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				fn(all, 0, 0, 0, 50, pred)
			}
		})
	}
	cur, legacy := run(filterLogPage), run(filterLogPageLegacy)
	curB, legacyB := cur.AllocedBytesPerOp(), legacy.AllocedBytesPerOp()
	t.Logf("filterLogPage:       %8d B/op, %d allocs/op (bound %d)", curB, cur.AllocsPerOp(), maxBytes)
	t.Logf("filterLogPageLegacy: %8d B/op, %d allocs/op", legacyB, legacy.AllocsPerOp())

	if curB > maxBytes {
		t.Errorf("page assembly allocates %d B/op, bound %d — the scan is materializing matches outside the requested page again",
			curB, maxBytes)
	}
	if curB >= legacyB {
		t.Errorf("page assembly (%d B/op) is no cheaper than the frozen pre-change shape (%d B/op); the optimization has been undone",
			curB, legacyB)
	}
}

// TestAPILogs_OutOfRangeOffsetStillNull pins the handler-level wire shape that
// the helper's nil return exists to preserve.
func TestAPILogs_OutOfRangeOffsetStillNull(t *testing.T) {
	isolateLogRing(t)
	now := time.Now().UnixMilli()
	for i := 0; i < 5; i++ {
		logAdd(LogEntry{TS: now + int64(i), Method: "GET", Host: "t.example.com", Status: "OK", Level: "INFO"})
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/logs?offset=99&limit=10", http.NoBody)
	w := httptest.NewRecorder()
	apiLogs(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var body struct {
		Logs  []LogEntry `json:"logs"`
		Total int        `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Total != 5 {
		t.Errorf("total = %d, want 5", body.Total)
	}
	if body.Logs != nil {
		t.Errorf("logs = %#v, want null for an out-of-range offset", body.Logs)
	}
}
