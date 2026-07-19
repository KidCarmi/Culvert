package blocklist

// feedid_test.go — T3 P2 slice 1: feed-URL interning (map[string]uint32 + feeds
// table). These pin the memory win (one shared URL string per feed, not per
// host) AND byte-identical attribution semantics through the public accessors.

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFeedInterning_SharesOneIDPerFeed: N hosts from ONE feed URL must intern to
// ONE feeds-table entry (the ~1.3 GB → ~40 MB memory win at scale), while every
// host still resolves to that URL via the public accessors.
func TestFeedInterning_SharesOneIDPerFeed(t *testing.T) {
	b := New()
	const url = "https://feed.example/list.txt"
	hosts := []string{"a.example", "b.example", "c.example", "*.d.example"}
	b.MergeFromLines(hosts, url)

	// feeds table: [""(0), url] — exactly one interned URL despite 4 hosts.
	if len(b.feeds) != 2 || b.feeds[1] != url {
		t.Fatalf("feeds table = %v, want [\"\", %q] (one entry per distinct feed)", b.feeds, url)
	}
	// All hosts share the SAME feed-source ID.
	if b.feedSrc["a.example"] == 0 || b.feedSrc["a.example"] != b.feedSrc["b.example"] {
		t.Fatal("hosts of the same feed must share one non-zero feed-source ID")
	}
	// Public accessor resolves the ID back to the URL.
	for _, e := range b.ListWithSource() {
		if e.Source != "feed" || e.Feed != url {
			t.Fatalf("ListWithSource entry %q: source=%q feed=%q, want feed/%q", e.Host, e.Source, e.Feed, url)
		}
	}
	// A SECOND distinct feed gets a NEW ID; a re-merge of the FIRST does not grow the table.
	b.MergeFromLines([]string{"e.example"}, "https://other.example/l.txt")
	b.MergeFromLines([]string{"f.example"}, url) // same first feed
	if len(b.feeds) != 3 {
		t.Fatalf("feeds table = %v, want 3 (two distinct feeds + unattributed slot)", b.feeds)
	}
}

// TestFeedInterning_RemoveAndCountByURL: the public URL-keyed operations resolve
// through the intern table and match pre-interning semantics (only the named
// feed's non-manual hosts are affected).
func TestFeedInterning_RemoveAndCountByURL(t *testing.T) {
	b := New()
	feedA := "https://a.example/list"
	feedB := "https://b.example/list"
	b.MergeFromLines([]string{"a1.example", "a2.example"}, feedA)
	b.MergeFromLines([]string{"b1.example"}, feedB)
	b.AddManual("a1.example") // now manual — must survive a cascade delete of feedA

	if n := b.CountByFeedSource(feedA); n != 1 { // a2 only (a1 is manual)
		t.Fatalf("CountByFeedSource(A) = %d, want 1 (manual a1 excluded)", n)
	}
	if n := b.RemoveByFeedSource(feedA); n != 1 {
		t.Fatalf("RemoveByFeedSource(A) removed %d, want 1", n)
	}
	if !b.IsBlocked("a1.example") {
		t.Fatal("manual host must survive a feed cascade delete")
	}
	if b.IsBlocked("a2.example") {
		t.Fatal("a2 (feed A, non-manual) should have been removed")
	}
	if !b.IsBlocked("b1.example") {
		t.Fatal("feed B host must be untouched by removing feed A")
	}
	// An unknown URL removes nothing.
	if n := b.RemoveByFeedSource("https://never.example/x"); n != 0 {
		t.Fatalf("RemoveByFeedSource(unknown) = %d, want 0", n)
	}
}

// TestFeedInterning_ReattributionOverwrites: a host re-imported by a different
// feed takes the new feed's attribution (matching the old map[string]string
// overwrite semantics).
func TestFeedInterning_ReattributionOverwrites(t *testing.T) {
	b := New()
	b.MergeFromLines([]string{"h.example"}, "https://old.example/l")
	b.MergeFromLines([]string{"h.example"}, "https://new.example/l")
	snap := b.SnapshotFeedSources()
	if snap["h.example"] != "https://new.example/l" {
		t.Fatalf("re-attribution: got %q, want the newer feed URL", snap["h.example"])
	}
}

// TestFeedInterning_SaveLoadRoundTrip: attribution survives a Save→Load cycle
// through the on-disk host→URL .sources format (unchanged wire format), and the
// reloaded store re-interns correctly.
func TestFeedInterning_SaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.txt")

	src := New()
	if err := src.Load(path); err != nil && !os.IsNotExist(err) {
		// Load on a missing main file returns an error; seed via a written file instead.
	}
	src.path = path
	src.MergeFromLines([]string{"x.example", "y.example"}, "https://feed.example/l")
	src.AddManual("m.example")
	src.Save()

	// Reload into a fresh store.
	dst := New()
	if err := dst.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !dst.IsBlocked("x.example") || !dst.IsBlocked("m.example") {
		t.Fatal("reloaded store missing hosts")
	}
	snap := dst.SnapshotFeedSources()
	if snap["x.example"] != "https://feed.example/l" || snap["y.example"] != "https://feed.example/l" {
		t.Fatalf("attribution not preserved across Save/Load: %v", snap)
	}
	if _, ok := snap["m.example"]; ok {
		t.Fatal("manual host must not appear in the feed-source snapshot")
	}
	// Interning still collapsed the two hosts to one feeds entry after reload.
	if len(dst.feeds) != 2 {
		t.Fatalf("reloaded feeds table = %v, want 2 (unattributed + one feed)", dst.feeds)
	}
}
