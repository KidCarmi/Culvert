// ingest_bounds_chaos109_test.go — CHAOS-109 gate for this loop's feed-body
// byte budget.
//
// This loop is the one CHAOS-108 §8.3 got wrong, and the correction is worth
// stating plainly: §8.3 recorded all three feed loops as having unbounded
// bodies because none used an io.LimitReader. That is true of the reader and
// false of the retention — maxFeedLines caps accepted entries at 500_000 "to
// limit memory usage", so this loop never had its siblings' heap exposure.
//
// What it did have is narrower: the accept loop `continue`s on blank and '#'
// lines WITHOUT charging the counter, so a body of nothing but comments is
// scanned for the full feedHTTPTimeout while the cap never advances. That
// spends CPU and bandwidth, not heap, which is why the budget added here is
// described as a work bound and rated LOW rather than carried at the siblings'
// severity.
package threatfeed

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func lowerBodyBudget(t *testing.T, budget int64) {
	t.Helper()
	old := maxFeedBodyBytes
	t.Cleanup(func() { maxFeedBodyBytes = old })
	maxFeedBodyBytes = budget
}

// CommentOnlyBodyIsChargedToTheByteBudget is the gate for the defect: before
// it, maxFeedLines could not stop this body because no line ever reached the
// counter.
func TestCommentOnlyBodyIsChargedToTheByteBudget(t *testing.T) {
	lowerBodyBudget(t, 4<<10)

	body := strings.Repeat("# this line is never charged to maxFeedLines\n", 500) // ~22 KiB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	tf := New()
	urls, domains := map[string]entry{}, map[string]entry{}
	n, err := tf.fetchTextFeed(context.Background(), srv.URL, sourceURLhaus, urls, domains)
	if err == nil {
		t.Fatal("a comment-only body past the byte budget was scanned to completion; " +
			"maxFeedLines cannot bound it because no line is ever charged")
	}
	if !errors.Is(err, errBudgetExceeded) {
		t.Errorf("the error must carry errBudgetExceeded, got %q", err)
	}
	if n != 0 {
		t.Errorf("no entry should have been accepted, got %d", n)
	}
	if len(urls) != 0 || len(domains) != 0 {
		t.Errorf("nothing should have been written into the maps, got %d urls / %d domains",
			len(urls), len(domains))
	}
	t.Logf("refused as expected: %v", err)
}

// LegitimateFeedWithinTheBudgetIsUnaffected is the negative control.
func TestLegitimateFeedWithinTheBudgetIsUnaffected(t *testing.T) {
	var b strings.Builder
	for i := range 100 {
		b.WriteString("http://bad")
		b.WriteString(strings.Repeat("x", i%5))
		b.WriteString(".example.com/p\n")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(b.String()))
	}))
	defer srv.Close()

	tf := New()
	urls, domains := map[string]entry{}, map[string]entry{}
	n, err := tf.fetchTextFeed(context.Background(), srv.URL, sourceURLhaus, urls, domains)
	if err != nil {
		t.Fatalf("a small normal feed is well inside the budget, got: %v", err)
	}
	if n == 0 {
		t.Error("expected entries to be accepted")
	}
}
