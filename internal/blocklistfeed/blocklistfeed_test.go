package blocklistfeed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// fakeMerger records the lines it was handed and returns a fixed new-count.
type fakeMerger struct {
	calls     int
	lastLines []string
	added     int
}

func (m *fakeMerger) MergeFromLines(lines []string, _ string) int {
	m.calls++
	m.lastLines = lines
	return m.added
}

func TestSyncer_CRUD(t *testing.T) {
	bs := New(&fakeMerger{})
	bs.SetFeed("https://feeds.example/a.txt", 12*time.Hour)
	bs.SetFeed("https://feeds.example/b.txt", 0) // manual-only
	bs.SetFeed("", time.Hour)                    // ignored

	feeds := bs.Feeds()
	if len(feeds) != 2 {
		t.Fatalf("Feeds len = %d, want 2", len(feeds))
	}
	// Sorted by URL.
	if feeds[0].URL != "https://feeds.example/a.txt" || feeds[1].Interval != 0 {
		t.Errorf("unexpected feeds snapshot: %+v", feeds)
	}

	// Update preserves identity, replaces interval.
	bs.SetFeed("https://feeds.example/a.txt", 48*time.Hour)
	if got := bs.Feeds()[0].Interval; got != 48*time.Hour {
		t.Errorf("interval after update = %v, want 48h", got)
	}
	if len(bs.Feeds()) != 2 {
		t.Error("update must not add a feed")
	}

	if !bs.RemoveFeed("https://feeds.example/b.txt") {
		t.Error("RemoveFeed of known URL = false")
	}
	if bs.RemoveFeed("https://feeds.example/b.txt") {
		t.Error("RemoveFeed of already-removed URL = true")
	}
	bs.ClearFeeds()
	if len(bs.Feeds()) != 0 {
		t.Error("ClearFeeds left entries")
	}
}

func TestSyncer_ZeroValueSafe(t *testing.T) {
	var bs Syncer // zero value — feeds map nil
	if len(bs.Feeds()) != 0 {
		t.Error("zero-value Feeds should be empty")
	}
	bs.SetFeed("https://feeds.example/z.txt", time.Hour) // must lazily init
	if len(bs.Feeds()) != 1 {
		t.Error("SetFeed on zero value did not init")
	}
}

func TestSyncer_SyncFeed_MergesAndCounts(t *testing.T) {
	t.Cleanup(ssrf.AllowLoopbackForTest())
	fm := &fakeMerger{added: 2}
	bs := New(fm)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# comment\n a.invalid \n\nb.invalid\n"))
	}))
	defer srv.Close()

	bs.SetFeed(srv.URL, 0)
	added, err := bs.SyncFeed(srv.URL)
	if err != nil {
		t.Fatalf("SyncFeed: %v", err)
	}
	if added != 2 {
		t.Errorf("added = %d, want 2 (fake merger)", added)
	}
	// Blank/comment lines are passed through to the merger (it does the
	// normalization); the fetcher only strips empty lines.
	if len(fm.lastLines) != 3 {
		t.Errorf("merger got %d lines, want 3 (empty stripped): %v", len(fm.lastLines), fm.lastLines)
	}
	f := bs.Feeds()[0]
	if f.ImportedCount != 2 || f.LastSync.IsZero() || f.LastError != "" {
		t.Errorf("feed status after sync = %+v", f)
	}
}

func TestSyncer_SyncFeed_UnknownURL(t *testing.T) {
	bs := New(&fakeMerger{})
	if _, err := bs.SyncFeed("https://feeds.example/nope.txt"); err == nil {
		t.Error("SyncFeed of unconfigured URL must error")
	}
}

func TestSyncer_SyncFeed_BlocksPrivateHost(t *testing.T) {
	// No loopback relaxation: the inline guard must reject the private host.
	bs := New(&fakeMerger{})
	bs.SetFeed("http://127.0.0.1:9/feed.txt", 0)
	_, err := bs.SyncFeed("http://127.0.0.1:9/feed.txt")
	if err == nil {
		t.Fatal("SyncFeed to a private host must be blocked by the SSRF guard")
	}
	if f := bs.Feeds()[0]; f.LastError == "" {
		t.Error("guard rejection must be recorded in LastError")
	}
}

func TestSyncer_SyncFeed_RejectsNonHTTPScheme(t *testing.T) {
	bs := New(&fakeMerger{})
	bs.SetFeed("ftp://feeds.example/a.txt", 0)
	if _, err := bs.SyncFeed("ftp://feeds.example/a.txt"); err == nil {
		t.Error("non-http(s) scheme must be rejected")
	}
}

func TestFeedCheckRedirect(t *testing.T) {
	mkReq := func(u string) *http.Request {
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u, http.NoBody)
		return r
	}
	// Too many redirects.
	via := make([]*http.Request, maxRedirects)
	if err := feedCheckRedirect(mkReq("http://example.com/"), via); err == nil {
		t.Error("must reject after maxRedirects hops")
	}
	// Private redirect target.
	if err := feedCheckRedirect(mkReq("http://10.0.0.1/feed"), nil); err == nil {
		t.Error("must reject a redirect to a private address")
	}
	// Non-http scheme.
	if err := feedCheckRedirect(mkReq("ftp://example.com/"), nil); err == nil {
		t.Error("must reject a non-http redirect scheme")
	}
}
