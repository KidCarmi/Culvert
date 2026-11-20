// truncated_test.go — the line-cap truncation is recorded on the feed's status
// (2026-11-19 security regression review, "Reported, not fixed").
//
// TestLineCapTruncatesRatherThanFails pins the deliberate choice that reaching
// maxFeedLines TRUNCATES rather than failing the round. The consequence it did
// not pin is that such a round was then indistinguishable from a clean one:
// LastSync advanced and LastError cleared, so the CHAOS-123 freshness plane
// asserted "fresh" over a deny list that had silently been cut short. These
// gates pin the bit that tells the two apart, and that it does not leak the
// feed URL into the log while doing so.
package blocklistfeed

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/obs"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// countingMerger reports every line it is handed as newly added, so a feed's
// ImportedCount equals the number of lines the round actually imported.
type countingMerger struct {
	mu    sync.Mutex
	lines int
}

func (m *countingMerger) MergeFromLines(lines []string, _ string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lines += len(lines)
	return len(lines)
}

// resizableHostListServer serves n.Load() host entries per request, so one
// feed URL can be served over the cap and then under it.
func resizableHostListServer(t *testing.T, n *atomic.Int64) *httptest.Server {
	t.Helper()
	t.Cleanup(ssrf.AllowLoopbackForTest())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var b strings.Builder
		for i := range n.Load() {
			fmt.Fprintf(&b, "t%d.example.com\n", i)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(b.String()))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// captureObsLog routes the package log sink into a buffer for the test.
//
// obs.SetSink is a process global with no getter, so this restores the package
// default (stderr) rather than a captured previous value — the same restoration
// internal/feedsync's CHAOS-109 gate uses.
func captureObsLog(t *testing.T) func() string {
	t.Helper()
	var mu sync.Mutex
	var logged strings.Builder
	obs.SetSink(func(line string) {
		mu.Lock()
		defer mu.Unlock()
		logged.WriteString(line + "\n")
	})
	t.Cleanup(func() { obs.SetSink(func(line string) { fmt.Fprintln(os.Stderr, line) }) })
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return logged.String()
	}
}

// truncationLines returns the log lines that report a line-cap truncation.
func truncationLines(log string) []string {
	var out []string
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "TRUNCATED") {
			out = append(out, line)
		}
	}
	return out
}

func feedByURL(t *testing.T, bs *Syncer, feedURL string) Feed {
	t.Helper()
	for _, f := range bs.Feeds() {
		if f.URL == feedURL {
			return f
		}
	}
	t.Fatalf("feed %q is not configured", feedURL)
	return Feed{}
}

// TestTruncatedSyncIsRecordedOnTheFeedAndClearedByAFullOne is the finding's
// gate: a body over the line cap is still a SUCCESSFUL round (the deliberate
// choice is kept), imports exactly the cap, and is marked Truncated; the next
// round whose body fits under the cap clears the mark.
func TestTruncatedSyncIsRecordedOnTheFeedAndClearedByAFullOne(t *testing.T) {
	const lineCap = 100
	lowerFeedBudgets(t, maxFeedBodyBytes, lineCap)
	var served atomic.Int64
	served.Store(1_000)
	srv := resizableHostListServer(t, &served)
	const leakProbe = "token-trunc-9f3e"
	feedURL := srv.URL + "/deny.txt?key=" + leakProbe
	logOf := captureObsLog(t)

	m := &countingMerger{}
	bs := New(m)
	bs.SetFeed(feedURL, 0) // manual only: the cap is about the body, not the cadence

	added, err := bs.SyncFeed(feedURL)
	if err != nil {
		t.Fatalf("a body over the line cap must still sync successfully (truncate, not fail), got: %v", err)
	}
	if added != lineCap {
		t.Errorf("want exactly the cap (%d) imported, got %d", lineCap, added)
	}
	f := feedByURL(t, bs, feedURL)
	if !f.Truncated {
		t.Fatalf("a round cut short at the %d-line cap must be recorded as Truncated: %+v", lineCap, f)
	}
	if f.ImportedCount != lineCap {
		t.Errorf("want ImportedCount == cap (%d), got %d", lineCap, f.ImportedCount)
	}
	if f.LastError != "" || f.LastSync.IsZero() {
		t.Errorf("truncation is not a failure: want LastError empty and LastSync set, got %+v", f)
	}

	trunc := truncationLines(logOf())
	if len(trunc) != 1 {
		t.Fatalf("want exactly one truncation log line per truncating round, got %d: %q", len(trunc), trunc)
	}
	if !strings.Contains(trunc[0], fmt.Sprintf("%d-line cap", lineCap)) {
		t.Errorf("the truncation line must name the cap, got %q", trunc[0])
	}
	if strings.Contains(trunc[0], leakProbe) || strings.Contains(trunc[0], "deny.txt") || strings.Contains(trunc[0], "127.0.0.1") {
		t.Errorf("the truncation line leaked the feed URL: %q", trunc[0])
	}

	// The origin trims the list below the cap: the next clean round is the
	// evidence that the feed is no longer cut short.
	served.Store(40)
	if _, err := bs.SyncFeed(feedURL); err != nil {
		t.Fatalf("a body under the cap must sync, got: %v", err)
	}
	f = feedByURL(t, bs, feedURL)
	if f.Truncated {
		t.Errorf("a successful round under the cap must clear Truncated: %+v", f)
	}
	if f.ImportedCount != lineCap+40 {
		t.Errorf("want ImportedCount %d after the second round, got %d", lineCap+40, f.ImportedCount)
	}
	if n := len(truncationLines(logOf())); n != 1 {
		t.Errorf("a round under the cap must not log a truncation; want 1 line in total, got %d", n)
	}
}

// TestFailedRoundLeavesTheLastSuccessTruncationInPlace pins the documented
// rule: Truncated describes the latest SUCCESSFUL sync, so a failed round in
// between neither sets nor clears it.
func TestFailedRoundLeavesTheLastSuccessTruncationInPlace(t *testing.T) {
	const lineCap = 50
	lowerFeedBudgets(t, maxFeedBodyBytes, lineCap)
	var served atomic.Int64
	served.Store(500)
	var fail atomic.Bool
	t.Cleanup(ssrf.AllowLoopbackForTest())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		for i := range served.Load() {
			fmt.Fprintf(w, "f%d.example.com\n", i)
		}
	}))
	t.Cleanup(srv.Close)
	feedURL := srv.URL + "/deny.txt"
	captureObsLog(t)

	bs := New(&countingMerger{})
	bs.SetFeed(feedURL, 0)
	if _, err := bs.SyncFeed(feedURL); err != nil {
		t.Fatalf("first round: %v", err)
	}
	fail.Store(true)
	if _, err := bs.SyncFeed(feedURL); err == nil {
		t.Fatal("second round: expected the 503 to fail the round")
	}
	f := feedByURL(t, bs, feedURL)
	if !f.Truncated || f.LastError == "" {
		t.Errorf("a failed round must leave the last success's Truncated in place and record its own error: %+v", f)
	}
}
