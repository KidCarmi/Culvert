// ingest_bounds_chaos109_test.go — CHAOS-109 gates for the category-feed
// ingest path's byte and entry budgets.
//
// What these gates defend, and why each one exists, is recorded in
// roadmap/CHAOS-REVIEW-2026-11-02.md. In short: this loop fetches a 50+ MB
// gzip tarball from a third-party GitHub mirror and expands it in-process on
// every node, and before CHAOS-109 the only bound on that was
// feedSyncHTTPTimeout. The round guard the loop advertises
// (obs.SafeCall, CHAOS-24 — "so a malformed/hostile archive costs one sync
// window rather than terminating an in-line gateway") cannot see a heap
// exhaustion: recover() does not run for a Go out-of-memory, and the
// GOMEMLIMIT backstop's own doc concedes it "CANNOT reclaim memory that is
// still REACHABLE", which is exactly what the domain map is for the whole parse.
package feedsync

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/obs"
)

// writeTarball builds a gzip tarball with `members` copies of the SAME member
// path, each carrying `perMember` distinct synthetic domains. Duplicate member
// paths are legal tar and are the whole point: the pre-CHAOS-109 cap was a
// local counter inside parseDomainFile, reset on every call.
func writeTarball(t *testing.T, path string, members, perMember int) []byte {
	t.Helper()
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	for m := range members {
		var body bytes.Buffer
		for i := range perMember {
			fmt.Fprintf(&body, "d%d-%d.example.com\n", m, i)
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: path, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(body.Len()),
		}); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write(body.Bytes()); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return raw.Bytes()
}

// lowerBudgets lowers the ingest budgets for one test and restores them. The
// budgets are package vars precisely so a gate need not move 512 MiB to prove
// one engages; see their declaration comment.
func lowerBudgets(t *testing.T, total int, compressed, decompressed int64) {
	t.Helper()
	oT, oC, oD := maxDomainsTotal, maxFeedCompressedBytes, maxFeedDecompressedBytes
	t.Cleanup(func() {
		maxDomainsTotal, maxFeedCompressedBytes, maxFeedDecompressedBytes = oT, oC, oD
	})
	maxDomainsTotal, maxFeedCompressedBytes, maxFeedDecompressedBytes = total, compressed, decompressed
}

// DuplicateMembersCannotExceedTheAggregateCap is the gate for the defect that
// made the nominal bound a fiction: maxDomainsPerCategory was charged to a
// counter local to one member, and tar permits the same member path any number
// of times, so N duplicate members each started a fresh budget.
func TestDuplicateMembersCannotExceedTheAggregateCap(t *testing.T) {
	const members, perMember = 40, 1_000
	lowerBudgets(t, 5_000, maxFeedCompressedBytes, maxFeedDecompressedBytes)

	tb := writeTarball(t, "blacklists/malware/domains", members, perMember)
	entries, err := parseTarball(bytes.NewReader(tb))
	if err != nil {
		t.Fatalf("parseTarball: %v", err)
	}
	// The archive offers 40_000 domains against a 5_000 aggregate ceiling.
	if len(entries) > maxDomainsTotal {
		t.Errorf("aggregate cap breached: %d entries ingested against a cap of %d "+
			"(%d duplicate members x %d domains offered) — the cap is still being "+
			"charged per member, so an origin steps around it by repeating a path",
			len(entries), maxDomainsTotal, members, perMember)
	}
	if len(entries) == 0 {
		t.Error("nothing ingested at all; the cap must truncate, not refuse")
	}
	t.Logf("offered %d domains across %d duplicate members, ingested %d (cap %d)",
		members*perMember, members, len(entries), maxDomainsTotal)
}

// TruncationKeepsTheRoundSuccessful records the deliberate asymmetry: the
// entry cap truncates, it does not fail. BulkWrite overwrites keys and never
// deletes, so a short round adds fewer NEW domains and un-categorises nothing
// — whereas refusing would freeze coverage the first time a legitimate feed
// outgrew the ceiling.
func TestTruncationKeepsTheRoundSuccessful(t *testing.T) {
	lowerBudgets(t, 100, maxFeedCompressedBytes, maxFeedDecompressedBytes)
	tb := writeTarball(t, "blacklists/malware/domains", 10, 500)
	entries, err := parseTarball(bytes.NewReader(tb))
	if err != nil {
		t.Fatalf("a truncated import must not be an error, got: %v", err)
	}
	if len(entries) == 0 || len(entries) > maxDomainsTotal {
		t.Errorf("expected a non-empty truncated map within the cap, got %d (cap %d)",
			len(entries), maxDomainsTotal)
	}
}

// CompressedBodyBudgetFailsTheRound is the gate for the origin's byte budget.
// Pre-CHAOS-109 the only limit on what a third-party mirror could spend was
// feedSyncHTTPTimeout, so the effective bound was "whatever the link delivers
// in five minutes, times the ~50x live-heap amplification".
func TestCompressedBodyBudgetFailsTheRound(t *testing.T) {
	lowerBudgets(t, maxDomainsTotal, 4<<10, maxFeedDecompressedBytes)

	tb := writeTarball(t, "blacklists/malware/domains", 4, 5_000) // comfortably over 4 KiB
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(tb)
	}))
	defer srv.Close()

	_, err := downloadAndParse(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("an origin that overran the compressed budget was accepted; " +
			"the round must fail so the last-good store stays authoritative")
	}
	if !strings.Contains(err.Error(), "compressed feed body") {
		t.Errorf("the error must name which budget was spent, got %q", err)
	}
	if !errors.Is(err, errBudgetExceeded) {
		t.Errorf("a spent byte budget must carry errBudgetExceeded so it cannot be "+
			"swallowed by the skip-a-corrupt-member path, got %q", err)
	}
	t.Logf("refused as expected: %v", err)
}

// BudgetOverrunIsNotLoggedAsASkippedMember guards the coupling the first run of
// these gates exposed: parseTarball logs-and-continues on a member it cannot
// parse, so before errBudgetExceeded existed a spent budget reached the
// operator as "FeedSync: skipping blacklists/malware/domains: ..." — a benign
// line for the one condition that has to fail the round. The round did still
// fail on the next tar read, so this is a diagnosability gate, not a
// correctness one, and it is labelled as such.
func TestBudgetOverrunIsNotLoggedAsASkippedMember(t *testing.T) {
	lowerBudgets(t, maxDomainsTotal, maxFeedCompressedBytes, 8<<10)

	// obs.SetSink is a process global with no getter, so this test restores the
	// package default (stderr) rather than a captured previous value — the same
	// restoration conventions.md requires of any global a test changes.
	var mu sync.Mutex
	var logged strings.Builder
	obs.SetSink(func(line string) {
		mu.Lock()
		defer mu.Unlock()
		logged.WriteString(line + "\n")
	})
	t.Cleanup(func() { obs.SetSink(func(line string) { fmt.Fprintln(os.Stderr, line) }) })

	tb := writeTarball(t, "blacklists/malware/domains", 4, 5_000)
	if _, err := parseTarball(bytes.NewReader(tb)); err == nil {
		t.Fatal("expected the expansion budget to fail the round")
	}
	mu.Lock()
	out := logged.String()
	mu.Unlock()
	if strings.Contains(out, "skipping") {
		t.Errorf("a spent budget was reported as a skipped member: %q", out)
	}
}

// DecompressedBudgetFailsTheRound is the second half of the dual bound: a small
// compressed body can expand without limit, so bounding the input alone is not
// a bound. This is the ingest-plane counterpart of secscan.MaxDecompressBytes
// (CHAOS-106) on the inspection plane.
func TestDecompressedBudgetFailsTheRound(t *testing.T) {
	lowerBudgets(t, maxDomainsTotal, maxFeedCompressedBytes, 8<<10)

	tb := writeTarball(t, "blacklists/malware/domains", 4, 5_000)
	if int64(len(tb)) >= maxFeedCompressedBytes {
		t.Fatalf("test setup: the archive must be WITHIN the compressed budget so "+
			"only the expansion bound can refuse it (got %d)", len(tb))
	}
	_, err := parseTarball(bytes.NewReader(tb))
	if err == nil {
		t.Fatal("an archive that expanded past the decompression budget was accepted")
	}
	if !strings.Contains(err.Error(), "decompressed feed archive") {
		t.Errorf("the error must name which budget was spent, got %q", err)
	}
	t.Logf("refused as expected: %v", err)
}

// SkippedMembersAreChargedToTheExpansionBudget closes the shape that spends the
// node's work without ever producing an entry: members whose path is not in
// ut1CategoryMap are skipped, but tar.Reader still reads through their payload.
func TestSkippedMembersAreChargedToTheExpansionBudget(t *testing.T) {
	lowerBudgets(t, maxDomainsTotal, maxFeedCompressedBytes, 8<<10)

	tb := writeTarball(t, "blacklists/not-a-real-category/domains", 4, 5_000)
	_, err := parseTarball(bytes.NewReader(tb))
	if err == nil {
		t.Fatal("an archive of unclassified members was streamed without charge; " +
			"an origin can then spend the whole fetch window producing no entries")
	}
	if !strings.Contains(err.Error(), "decompressed feed archive") {
		t.Errorf("expected the expansion budget to refuse it, got %q", err)
	}
}

// BoundedReaderReportsOverrunAsAnErrorNotEOF is the semantic the whole fix
// rests on. io.LimitReader would report a spent budget as a clean io.EOF, which
// gzip and tar both report as a truncated archive — indistinguishable from a
// real transfer cut, and for the line-oriented sibling loops indistinguishable
// from a complete short feed, which is how an overrun would be MERGED and
// recorded as a success.
func TestBoundedReaderReportsOverrunAsAnErrorNotEOF(t *testing.T) {
	br := &boundedReader{r: strings.NewReader(strings.Repeat("x", 100)), what: "test budget", limit: 10}
	got, err := bytes.NewBuffer(nil), error(nil)
	buf := make([]byte, 7)
	total := 0
	for {
		n, rerr := br.Read(buf)
		total += n
		got.Write(buf[:n])
		if rerr != nil {
			err = rerr
			break
		}
	}
	if err == nil {
		t.Fatal("overrun returned no error")
	}
	if strings.Contains(err.Error(), "EOF") {
		t.Errorf("overrun must not look like EOF, got %q", err)
	}
	if !strings.Contains(err.Error(), "test budget") {
		t.Errorf("error must name the budget, got %q", err)
	}
	if total != 10 {
		t.Errorf("reader delivered %d bytes against a 10-byte budget", total)
	}
}
