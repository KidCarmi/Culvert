package logstore

// Sparse-filter scan-continuation proofs (FE-4 hardening). A filter that
// matches almost nothing must still page with GUARANTEED forward progress:
// when the raw-scan budget stops a walk before the window is exhausted, the
// continuation point is the last raw entry already evaluated (LastScan*), so
// a follow-up request never rescans a range this walk proved non-matching —
// even when ZERO matching rows were returned. The budget is injected via
// QueryPageWithBudget so the algorithm is provable with small fixtures; the
// production default (scanCap) is untouched.

import (
	"testing"
	"time"
)

// seedHosts writes one entry per host label at base+i (strictly increasing
// keys, insertion order = ascending time) and drains the async queue.
func seedHosts(t *testing.T, s *Store, base int64, hosts []string) {
	t.Helper()
	for i, h := range hosts {
		s.Add(Entry{TS: base + int64(i), Host: h, Status: "OK", Level: "INFO"})
	}
	drainLogStore(t, s, len(hosts))
}

func repeatHosts(h string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = h
	}
	return out
}

func matchHost(want string) func(*Entry) bool {
	return func(e *Entry) bool { return e.Host == want }
}

// Case A: zero matches in the scan segment ⇒ scan_limited with a usable
// continuation point, and each bounded continuation makes strict forward
// progress until the window is genuinely exhausted.
func TestQueryPageBudget_ZeroMatchSegmentForwardProgress(t *testing.T) {
	s := pageStore(t)
	base := time.Now().Add(-time.Hour).UnixMilli()
	seedHosts(t, s, base, repeatHosts("noise.test", 300))
	filter := matchHost("never-matches.test")

	p1, err := s.QueryPageWithBudget(0, 0, 0, 0, 100, 100, filter)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(p1.Entries) != 0 || !p1.HasMore || !p1.ScanLimited {
		t.Fatalf("page 1 = %d entries, HasMore=%v, ScanLimited=%v; want 0/true/true",
			len(p1.Entries), p1.HasMore, p1.ScanLimited)
	}
	if p1.Scanned != 100 {
		t.Fatalf("page 1 scanned %d, want exactly the budget 100", p1.Scanned)
	}
	if p1.LastScanTS != base+200 {
		t.Fatalf("page 1 LastScanTS = %d, want %d (the 100th-newest raw entry)", p1.LastScanTS, base+200)
	}

	p2, err := s.QueryPageWithBudget(0, 0, p1.LastScanTS, p1.LastScanSeq, 100, 100, filter)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if p2.LastScanTS >= p1.LastScanTS {
		t.Fatalf("no forward progress: page 2 LastScanTS %d >= page 1 %d", p2.LastScanTS, p1.LastScanTS)
	}
	if p2.Scanned != 100 || !p2.ScanLimited || p2.LastScanTS != base+100 {
		t.Fatalf("page 2 scanned=%d ScanLimited=%v LastScanTS=%d; want 100/true/%d",
			p2.Scanned, p2.ScanLimited, p2.LastScanTS, base+100)
	}

	p3, err := s.QueryPageWithBudget(0, 0, p2.LastScanTS, p2.LastScanSeq, 100, 100, filter)
	if err != nil {
		t.Fatalf("page 3: %v", err)
	}
	// The final 100 raw entries fit the budget exactly and the iterator then
	// runs out: this is a TRUE terminal — never reported as scan-limited.
	if p3.Scanned != 100 || p3.HasMore || p3.ScanLimited {
		t.Fatalf("page 3 scanned=%d HasMore=%v ScanLimited=%v; want 100/false/false",
			p3.Scanned, p3.HasMore, p3.ScanLimited)
	}
	if got := p1.Scanned + p2.Scanned + p3.Scanned; got != 300 {
		t.Fatalf("total raw scans = %d, want exactly 300 (each entry visited once)", got)
	}
}

// Case B: a few matches followed by a budget-sized non-matching gap — the
// continuation advances past the gap already scanned; no segment is ever
// rescanned (the infinite-loop shape the last-RETURNED-key cursor had).
func TestQueryPageBudget_MatchesThenGapNeverRescans(t *testing.T) {
	s := pageStore(t)
	base := time.Now().Add(-time.Hour).UnixMilli()
	// Insertion order oldest→newest: 200 noise entries, then 5 matches, so
	// newest-first iteration sees 5 matches first, then the 200-entry gap.
	hosts := append(repeatHosts("noise.test", 200), repeatHosts("needle.test", 5)...)
	seedHosts(t, s, base, hosts)
	filter := matchHost("needle.test")

	p1, err := s.QueryPageWithBudget(0, 0, 0, 0, 10, 100, filter)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(p1.Entries) != 5 || !p1.HasMore || !p1.ScanLimited {
		t.Fatalf("page 1 = %d entries, HasMore=%v, ScanLimited=%v; want 5/true/true",
			len(p1.Entries), p1.HasMore, p1.ScanLimited)
	}
	if p1.NextTS != base+200 {
		t.Fatalf("page 1 NextTS (last RETURNED) = %d, want %d", p1.NextTS, base+200)
	}
	// Continuation is deeper than the last returned match: the evaluated
	// slice of the gap is not rescanned.
	if p1.LastScanTS >= p1.NextTS {
		t.Fatalf("LastScanTS %d not past the returned matches (NextTS %d)", p1.LastScanTS, p1.NextTS)
	}
	if p1.LastScanTS != base+105 {
		t.Fatalf("page 1 LastScanTS = %d, want %d (5 matches + 95 gap entries)", p1.LastScanTS, base+105)
	}

	p2, err := s.QueryPageWithBudget(0, 0, p1.LastScanTS, p1.LastScanSeq, 10, 100, filter)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if len(p2.Entries) != 0 || !p2.ScanLimited || p2.Scanned != 100 || p2.LastScanTS != base+5 {
		t.Fatalf("page 2 = %d entries, ScanLimited=%v, Scanned=%d, LastScanTS=%d; want 0/true/100/%d",
			len(p2.Entries), p2.ScanLimited, p2.Scanned, p2.LastScanTS, base+5)
	}

	p3, err := s.QueryPageWithBudget(0, 0, p2.LastScanTS, p2.LastScanSeq, 10, 100, filter)
	if err != nil {
		t.Fatalf("page 3: %v", err)
	}
	if p3.Scanned != 5 || p3.HasMore || p3.ScanLimited || len(p3.Entries) != 0 {
		t.Fatalf("page 3 scanned=%d HasMore=%v ScanLimited=%v entries=%d; want 5/false/false/0",
			p3.Scanned, p3.HasMore, p3.ScanLimited, len(p3.Entries))
	}
	if got := p1.Scanned + p2.Scanned + p3.Scanned; got != 205 {
		t.Fatalf("total raw scans = %d, want exactly 205 (no segment rescanned)", got)
	}
}

// Case C: repeated bounded continuation eventually reaches a single sparse
// match deep behind a multi-budget gap.
func TestQueryPageBudget_ContinuationReachesOldSparseMatch(t *testing.T) {
	s := pageStore(t)
	base := time.Now().Add(-time.Hour).UnixMilli()
	// Oldest entry is the one match; 250 noise entries above it.
	hosts := append([]string{"needle.test"}, repeatHosts("noise.test", 250)...)
	seedHosts(t, s, base, hosts)
	filter := matchHost("needle.test")

	var (
		afterTS  int64
		afterSeq uint32
		segments int
		found    []Entry
	)
	for {
		p, err := s.QueryPageWithBudget(0, 0, afterTS, afterSeq, 10, 100, filter)
		if err != nil {
			t.Fatalf("segment %d: %v", segments, err)
		}
		segments++
		found = append(found, p.Entries...)
		if !p.ScanLimited {
			if p.HasMore {
				t.Fatalf("segment %d: HasMore without ScanLimited on a 1-match store", segments)
			}
			break
		}
		afterTS, afterSeq = p.LastScanTS, p.LastScanSeq
		if segments > 10 {
			t.Fatal("continuation did not terminate (no forward progress)")
		}
	}
	if len(found) != 1 || found[0].Host != "needle.test" || found[0].TS != base {
		t.Fatalf("found = %+v, want exactly the one oldest needle entry", found)
	}
	if segments != 3 {
		t.Fatalf("segments = %d, want 3 (250 noise + 1 match under budget 100)", segments)
	}
}

// Case D: window truly exhausted with no match and no budget pressure — a
// terminal empty page, never a continuation.
func TestQueryPageBudget_ExhaustedWindowIsTerminalEmpty(t *testing.T) {
	s := pageStore(t)
	base := time.Now().Add(-time.Hour).UnixMilli()
	seedHosts(t, s, base, repeatHosts("noise.test", 50))

	p, err := s.QueryPageWithBudget(0, 0, 0, 0, 10, 100, matchHost("never-matches.test"))
	if err != nil {
		t.Fatalf("QueryPageWithBudget: %v", err)
	}
	if len(p.Entries) != 0 || p.HasMore || p.ScanLimited {
		t.Fatalf("got %d entries, HasMore=%v, ScanLimited=%v; want a terminal empty page",
			len(p.Entries), p.HasMore, p.ScanLimited)
	}
	if p.Scanned != 50 {
		t.Fatalf("scanned %d, want 50", p.Scanned)
	}
}

// Case E: dense pages keep the original semantics — normal look-ahead stop,
// not scan-limited, and the continuation from the last RETURNED key returns
// the look-ahead match first on the next page (never skipped, never
// duplicated).
func TestQueryPageBudget_DensePagesUnchangedAndLookAheadNotSkipped(t *testing.T) {
	s := pageStore(t)
	base := time.Now().Add(-time.Hour).UnixMilli()
	seedHosts(t, s, base, repeatHosts("dense.test", 300))

	p1, err := s.QueryPageWithBudget(0, 0, 0, 0, 100, 0, nil)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if len(p1.Entries) != 100 || !p1.HasMore || p1.ScanLimited {
		t.Fatalf("page 1 = %d entries, HasMore=%v, ScanLimited=%v; want 100/true/false",
			len(p1.Entries), p1.HasMore, p1.ScanLimited)
	}
	last := p1.Entries[len(p1.Entries)-1].TS
	p2, err := s.QueryPageWithBudget(0, 0, p1.NextTS, p1.NextSeq, 100, 0, nil)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if p2.Entries[0].TS != last-1 {
		t.Fatalf("page 2 starts at %d, want %d (the look-ahead match, contiguous, no skip/dup)",
			p2.Entries[0].TS, last-1)
	}
}
