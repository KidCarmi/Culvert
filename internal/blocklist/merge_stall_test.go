package blocklist

import (
	"maps"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Contract tests for the three-phase feed merge (PERF-BLOCKLIST-MERGE-1). The
// wall-clock evidence lives in merge_stall_bench_test.go; nothing here asserts
// on elapsed time.

// referenceMerge is the pre-change MergeFromLines body, verbatim, minus the
// Save: one pass over the raw lines under a single write-lock hold. It is the
// oracle the phased merge must agree with entry for entry.
func referenceMerge(b *Store, lines []string, source string) int {
	added := 0
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, raw := range lines {
		line, ok := NormalizeLine(raw)
		if !ok {
			continue
		}
		if strings.HasPrefix(line, "*.") {
			key := line[1:]
			if !b.wildcards[key] {
				b.wildcards[key] = true
				added++
			}
		} else if !b.exact[line] {
			b.exact[line] = true
			added++
		}
		if source != "" && !b.manual[line] {
			if b.feedSrc == nil {
				b.feedSrc = map[string]string{}
			}
			if b.feedSrc[line] != source {
				b.feedSrc[line] = source
			}
		}
	}
	return added
}

// mergeFixtureLines spans several chunks and every line shape the parser
// distinguishes, with duplicates on both sides of a chunk boundary.
func mergeFixtureLines() []string {
	lines := []string{
		"# header comment", "", "   ",
		"0.0.0.0 localhost", "127.0.0.1 0.0.0.0",
		"*.Wild.Example.com", "*.wild.example.com",
		"https://Scheme.Example.com/path?q=1", "trailing.example.com.",
		"0.0.0.0 hosts-format.example.com alias.example.com # inline",
		"manual-exact.example.com", "*.manual-wild.example.com",
		"preexisting.example.com", "other-feed.example.com",
	}
	for i := range 3*mergeChunk + 17 {
		lines = append(lines, "0.0.0.0 bulk-"+strconv.Itoa(i)+".example.net")
		if i%500 == 0 {
			lines = append(lines, "*.bulk-wild-"+strconv.Itoa(i)+".example.net", "BULK-"+strconv.Itoa(i)+".example.net")
		}
	}
	return append(lines, "bulk-0.example.net", "*.wild.example.com")
}

// mergeFixtureStore returns a store with manual, unattributed and
// other-feed-attributed entries already present.
func mergeFixtureStore() *Store {
	s := New()
	s.AddManual("manual-exact.example.com")
	s.AddManual("*.manual-wild.example.com")
	s.Add("preexisting.example.com")
	s.MergeFromLines([]string{"other-feed.example.com", "bulk-7.example.net"}, "https://other.example/feed")
	return s
}

func assertSameMergeState(t *testing.T, got, want *Store) {
	t.Helper()
	got.mu.RLock()
	defer got.mu.RUnlock()
	want.mu.RLock()
	defer want.mu.RUnlock()
	if !maps.Equal(got.exact, want.exact) {
		t.Errorf("exact entries differ: got %d, want %d", len(got.exact), len(want.exact))
	}
	if !maps.Equal(got.wildcards, want.wildcards) {
		t.Errorf("wildcard entries differ: got %d, want %d", len(got.wildcards), len(want.wildcards))
	}
	if !maps.Equal(got.manual, want.manual) {
		t.Errorf("manual set differs: got %d, want %d", len(got.manual), len(want.manual))
	}
	if !maps.Equal(got.feedSrc, want.feedSrc) {
		t.Errorf("feed attribution differs: got %d, want %d", len(got.feedSrc), len(want.feedSrc))
	}
}

// The phased merge must leave exactly the state, and return exactly the count,
// that the single-hold merge did — across chunk boundaries, for every line
// shape, with and without a source, and again on a re-sync.
func TestMergeFromLines_MatchesSingleHoldReference(t *testing.T) {
	for _, source := range []string{"https://feeds.example.net/hosts.txt", ""} {
		t.Run("source="+source, func(t *testing.T) {
			lines := mergeFixtureLines()
			input := append([]string(nil), lines...)
			got, want := mergeFixtureStore(), mergeFixtureStore()

			for pass := range 2 {
				gotAdded := got.MergeFromLines(lines, source)
				wantAdded := referenceMerge(want, lines, source)
				if gotAdded != wantAdded {
					t.Fatalf("pass %d: added = %d, reference added %d", pass, gotAdded, wantAdded)
				}
				if pass == 0 && gotAdded <= 3*mergeChunk {
					t.Fatalf("fixture too small to cross chunk boundaries: added %d", gotAdded)
				}
				if pass == 1 && gotAdded != 0 {
					t.Fatalf("re-sync of an unchanged feed added %d entries", gotAdded)
				}
				assertSameMergeState(t, got, want)
			}
			for i := range lines {
				if lines[i] != input[i] {
					t.Fatalf("MergeFromLines modified its input at %d: %q -> %q", i, input[i], lines[i])
				}
			}
			if !got.IsBlocked("bulk-3000.example.net") || !got.IsBlocked("a.wild.example.com") {
				t.Fatal("merged entries are not enforced")
			}
		})
	}
}

// A re-sync of an unchanged feed is the steady state: it repeats every sync
// interval for every feed, and the store does not change. It must therefore
// never need the write lock, which is what stalls IsBlocked. Proven without a
// clock: the test holds EVERY reader shard, so a merge that asked for the
// write lock could not return.
func TestMergeFromLines_SteadyStateResyncTakesNoWriteLock(t *testing.T) {
	const feed = "https://feeds.example.net/hosts.txt"
	lines := mergeFixtureLines()
	s := mergeFixtureStore()
	s.MergeFromLines(lines, feed)

	for i := range s.mu.shards {
		s.mu.shards[i].RLock()
	}
	done := make(chan int, 1)
	go func() { done <- s.MergeFromLines(lines, feed) }()
	var added int
	select {
	case added = <-done:
	case <-time.After(30 * time.Second):
		for i := range s.mu.shards {
			s.mu.shards[i].RUnlock()
		}
		<-done
		t.Fatal("an unchanged re-sync blocked behind readers: it took the write lock")
	}
	for i := range s.mu.shards {
		s.mu.shards[i].RUnlock()
	}
	if added != 0 {
		t.Fatalf("unchanged re-sync added %d entries", added)
	}
}

// The filter pass decides under a read lock that is released before the apply
// pass, so a writer can get in between. The apply pass must decide again: a
// host an admin claimed in that window keeps its manual badge and is neither
// counted as added nor attributed to the feed.
func TestMergeApply_RechecksAfterInterleavedWriter(t *testing.T) {
	const feed = "https://feeds.example.net/hosts.txt"
	s := New()
	pending := s.mergePending([]string{"claimed.example.com", "*.claimed-wild.example.com", "feed-only.example.com"}, feed)
	if len(pending) != 3 {
		t.Fatalf("pending = %d entries, want 3", len(pending))
	}

	s.AddManual("claimed.example.com")
	s.AddManual("*.claimed-wild.example.com")

	added, attributed := s.mergeApply(pending, feed)
	if added != 1 || !attributed {
		t.Fatalf("added = %d, attributed = %v; want 1, true", added, attributed)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.feedSrc) != 1 || s.feedSrc["feed-only.example.com"] != feed {
		t.Fatalf("feed attribution = %v, want only feed-only.example.com", s.feedSrc)
	}
}

// mergeWouldChangeLocked is the read-only mirror of mergeApply: an entry it
// calls unchanged must be one mergeApply leaves alone, or the filter would
// drop work the merge owes.
func TestMergeWouldChange_AgreesWithApply(t *testing.T) {
	for _, source := range []string{"https://feeds.example.net/hosts.txt", "https://other.example/feed", ""} {
		for _, line := range []string{
			"manual-exact.example.com", "*.manual-wild.example.com", "preexisting.example.com",
			"other-feed.example.com", "brand-new.example.com", "*.brand-new.example.com",
		} {
			s := mergeFixtureStore()
			s.mu.RLock()
			predicted := s.mergeWouldChangeLocked(line, source)
			s.mu.RUnlock()
			added, attributed := s.mergeApply([]string{line}, source)
			if changed := added > 0 || attributed; changed != predicted {
				t.Errorf("line %q source %q: filter said change=%v, apply changed=%v", line, source, predicted, changed)
			}
		}
	}
}

// Race-detector half: merges, request-path readers and admin writers together.
func TestMergeFromLines_ConcurrentReadersAndWriters(t *testing.T) {
	s := New()
	lines := mergeFixtureLines()
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					s.IsBlocked("bulk-12.example.net")
					s.IsBlocked("x.wild.example.com")
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 200 {
			h := "admin-" + strconv.Itoa(i%5) + ".example.org"
			s.AddManual(h)
			s.Remove("bulk-" + strconv.Itoa(i) + ".example.net")
			s.Count()
		}
	}()
	var merges sync.WaitGroup
	for i := range 3 {
		merges.Add(1)
		go func() {
			defer merges.Done()
			for range 3 {
				s.MergeFromLines(lines, "https://feed-"+strconv.Itoa(i)+".example/list")
			}
		}()
	}
	merges.Wait()
	close(stop)
	wg.Wait()

	// Nothing above removes this host, so every interleaving must leave it listed.
	if !s.IsBlocked("bulk-3000.example.net") {
		t.Fatal("a merged entry no writer removed is not enforced")
	}
}
