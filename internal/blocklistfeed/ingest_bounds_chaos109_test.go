// ingest_bounds_chaos109_test.go — CHAOS-109 gates for this loop's feed-body
// byte and line budgets.
//
// CHAOS-108 §8.3 recorded, as the open half of that round, that no feed loop
// capped its response body. Of the loops it named this was the one with no
// retention bound of ANY kind: every non-empty line is kept in the returned
// slice, so the live cost of a round was "httpTimeout (30s) x link speed".
// internal/threatfeed already capped accepted lines and internal/saasfeed
// already read under a 10 MB io.LimitReader; this loop had neither.
package blocklistfeed

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

func lowerFeedBudgets(t *testing.T, bytesBudget int64, lineCap int) {
	t.Helper()
	oB, oL := maxFeedBodyBytes, maxFeedLines
	t.Cleanup(func() { maxFeedBodyBytes, maxFeedLines = oB, oL })
	maxFeedBodyBytes, maxFeedLines = bytesBudget, lineCap
}

// hostListServer serves `lines` host entries, one per line.
func hostListServer(t *testing.T, lines int) *httptest.Server {
	t.Helper()
	var b strings.Builder
	for i := range lines {
		fmt.Fprintf(&b, "h%d.example.com\n", i)
	}
	body := b.String()
	// The SSRF guard runs inline at the fetch call site, so an httptest origin
	// on loopback needs the same allowance the CHAOS-108 gates use.
	t.Cleanup(ssrf.AllowLoopbackForTest())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// OverrunIsRefusedAndNotMergedAsAShortFeed is the gate that matters most here,
// and it is why io.LimitReader is not used for this: a LimitReader reports a
// spent budget as a clean io.EOF, bufio.Scanner reports that as a complete
// body, and the caller would then MERGE the prefix and record the round as a
// success. That is the identical mistake CHAOS-108 fixed one layer up — a
// round whose notion of success was "the transport returned bytes" rather than
// "the origin served the feed" — so the fix must fail, not truncate.
func TestOverrunIsRefusedAndNotMergedAsAShortFeed(t *testing.T) {
	lowerFeedBudgets(t, 1<<10, maxFeedLines)
	srv := hostListServer(t, 5_000) // comfortably over 1 KiB

	bs := New(&fakeMerger{})
	lines, err := bs.fetchFeedLines(context.Background(), srv.URL)
	if err == nil {
		t.Fatalf("an origin that overran its byte budget was accepted as a %d-line feed; "+
			"the prefix would be merged into a deny control and the round recorded healthy",
			len(lines))
	}
	if !errors.Is(err, errBudgetExceeded) {
		t.Errorf("the refusal must carry errBudgetExceeded, got %q", err)
	}
	if !strings.Contains(err.Error(), "feed body") {
		t.Errorf("the error must name which budget was spent, got %q", err)
	}
	if lines != nil {
		t.Errorf("a refused round must return no lines to merge, got %d", len(lines))
	}
	t.Logf("refused as expected: %v", err)
}

// LineCapTruncatesRatherThanFails records the deliberate asymmetry against the
// gate above: the BYTE budget fails the round, the LINE cap truncates it. The
// merge is merge-only and persisted, so a truncated round adds fewer new hosts
// and un-blocks none — whereas failing on the line cap would freeze the list
// the first time a legitimate aggregated feed outgrew it.
func TestLineCapTruncatesRatherThanFails(t *testing.T) {
	lowerFeedBudgets(t, maxFeedBodyBytes, 100)
	srv := hostListServer(t, 1_000)

	bs := New(&fakeMerger{})
	lines, err := bs.fetchFeedLines(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("reaching the line cap must not fail the round, got: %v", err)
	}
	if len(lines) != maxFeedLines {
		t.Errorf("expected exactly the cap (%d) lines, got %d", maxFeedLines, len(lines))
	}
}

// LegitimateFeedWithinBothBudgetsIsUnaffected is the negative control: the
// bounds must not change the behavior of a normal feed.
func TestLegitimateFeedWithinBothBudgetsIsUnaffected(t *testing.T) {
	srv := hostListServer(t, 2_000)
	bs := New(&fakeMerger{})
	lines, err := bs.fetchFeedLines(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("a 2000-line feed is well inside both budgets, got: %v", err)
	}
	if len(lines) != 2_000 {
		t.Errorf("expected all 2000 lines through, got %d", len(lines))
	}
}

// BoundedReaderReportsOverrunAsAnErrorNotEOF pins the semantic the refusal
// above depends on.
func TestBoundedReaderReportsOverrunAsAnErrorNotEOF(t *testing.T) {
	br := &boundedReader{r: strings.NewReader(strings.Repeat("x", 100)), what: "test budget", limit: 10}
	buf := make([]byte, 7)
	total := 0
	var err error
	for {
		n, rerr := br.Read(buf)
		total += n
		if rerr != nil {
			err = rerr
			break
		}
	}
	if err == nil || strings.Contains(err.Error(), "EOF") {
		t.Fatalf("overrun must be a named error, not EOF; got %v", err)
	}
	if !errors.Is(err, errBudgetExceeded) {
		t.Errorf("overrun must carry errBudgetExceeded, got %q", err)
	}
	if total != 10 {
		t.Errorf("reader delivered %d bytes against a 10-byte budget", total)
	}
}
