// Package blocklistfeed is the remote blocklist syncer: it periodically
// downloads one or more remote blocklists (one domain per line, '#' comments
// allowed) and merges new entries into the live blocklist without removing
// manually-added entries. Extracted from package main per ADR-0002; it
// depends on the Blocklist hub only through the narrow Merger interface (main
// passes its *Blocklist) and on the internal/ssrf seam for the outbound
// fetch guard. package main keeps the blFeedSyncer singleton and the admin
// API handler (blocklist_feed.go shim).
//
// Multi-feed: each feed has its own URL, sync interval, and status. A single
// scheduler goroutine (Start) wakes every tickInterval and syncs every feed
// whose interval has elapsed since its last attempt. The scheduler is ALWAYS
// started at startup — feeds added later via the admin API are picked up on
// the next tick without a restart.
package blocklistfeed

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/obs"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

const (
	httpTimeout  = 30 * time.Second
	tickInterval = 60 * time.Second
	maxRedirects = 5

	// DefaultInterval is the fallback auto-sync interval when none is
	// configured. Exported for the main-side callers (admin settings restore,
	// startup config, API handler) that pick the interval.
	DefaultInterval = 24 * time.Hour
)

var urlPattern = regexp.MustCompile(`^https?://[^/?#\s]+(?:[/?#]\S*)?$`)

// Merger is the blocklist surface the syncer needs: fold downloaded feed
// lines into the live blocklist and report how many were newly added. main's
// *Blocklist satisfies this (MergeFromLines).
type Merger interface {
	MergeFromLines(lines []string, source string) int
}

// Feed is a point-in-time status snapshot of one configured feed, returned by
// Feeds() for the admin API and settings persistence.
type Feed struct {
	URL           string
	Interval      time.Duration // 0 = auto-sync disabled (manual Sync Now only)
	LastSync      time.Time     // last successful sync (zero = never)
	LastError     string        // error from the most recent attempt ("" = ok)
	ImportedCount int64         // cumulative new domains merged from this feed
}

// feedState is the internal mutable state of one feed.
type feedState struct {
	interval      time.Duration
	lastSync      time.Time
	lastAttempt   time.Time
	lastError     string
	importedCount int64
}

// Syncer downloads and merges remote domain feeds into a Merger.
// The zero value is safe for all methods (feeds map is lazily initialized).
type Syncer struct {
	bl    Merger
	mu    sync.RWMutex
	feeds map[string]*feedState // keyed by feed URL
}

// New creates an empty syncer for bl. Feeds are added via SetFeed (startup
// config seed or admin API).
func New(bl Merger) *Syncer {
	return &Syncer{bl: bl, feeds: map[string]*feedState{}}
}

// SetFeed adds or updates a feed. interval 0 disables auto-sync for that
// feed (it can still be synced manually). Existing sync statistics are
// preserved on update.
func (bs *Syncer) SetFeed(feedURL string, interval time.Duration) {
	if feedURL == "" {
		return
	}
	if interval < 0 {
		interval = 0
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if bs.feeds == nil {
		bs.feeds = map[string]*feedState{}
	}
	if st, ok := bs.feeds[feedURL]; ok {
		st.interval = interval
		return
	}
	bs.feeds[feedURL] = &feedState{interval: interval}
}

// ClearFeeds removes every configured feed. Used when restoring persisted
// settings, which are authoritative over the YAML/CLI startup seed.
// Domains already merged into the blocklist are NOT removed.
func (bs *Syncer) ClearFeeds() {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.feeds = map[string]*feedState{}
}

// RemoveFeed deletes a feed by URL. Returns false when no such feed exists.
// Domains already merged into the blocklist are NOT removed (feed imports
// are merge-only by design).
func (bs *Syncer) RemoveFeed(feedURL string) bool {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if _, ok := bs.feeds[feedURL]; !ok {
		return false
	}
	delete(bs.feeds, feedURL)
	return true
}

// Feeds returns a snapshot of all configured feeds, sorted by URL for
// deterministic API output and persistence. A nil syncer (feeds never
// configured/initialized) has no feeds — return empty rather than panic, so the
// read-only /api/blocklist/feed endpoint stays a 200 in that state.
// (Upstream fix ae1b1c1, ported into the extracted engine at merge time.)
func (bs *Syncer) Feeds() []Feed {
	if bs == nil {
		return nil
	}
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	out := make([]Feed, 0, len(bs.feeds))
	for feedURL, st := range bs.feeds {
		out = append(out, Feed{
			URL:           feedURL,
			Interval:      st.interval,
			LastSync:      st.lastSync,
			LastError:     st.lastError,
			ImportedCount: st.importedCount,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

// Start launches the background scheduler. It runs an immediate pass, then
// wakes every tickInterval and syncs each feed whose interval has elapsed
// since its last attempt. Feeds with interval 0 are skipped.
func (bs *Syncer) Start(ctx context.Context) {
	go func() {
		bs.syncDue()
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(tickInterval):
				bs.syncDue()
			}
		}
	}()
}

// syncDue syncs every feed that is due: auto-sync enabled (interval > 0)
// and never attempted, or last attempted at least one interval ago.
func (bs *Syncer) syncDue() {
	now := time.Now()
	bs.mu.RLock()
	var due []string
	for feedURL, st := range bs.feeds {
		if st.interval <= 0 {
			continue
		}
		if st.lastAttempt.IsZero() || now.Sub(st.lastAttempt) >= st.interval {
			due = append(due, feedURL)
		}
	}
	bs.mu.RUnlock()
	for _, feedURL := range due {
		_, _ = bs.SyncFeed(feedURL)
	}
}

// SyncFeed fetches one feed by URL and merges new domains into the blocklist.
// Returns the number of new domains added and any error encountered. The
// feed's status fields are updated either way.
func (bs *Syncer) SyncFeed(feedURL string) (int, error) {
	bs.mu.RLock()
	_, known := bs.feeds[feedURL]
	bs.mu.RUnlock()
	if !known {
		return 0, fmt.Errorf("feed not configured: %s", feedURL)
	}

	lines, err := bs.fetchFeedLines(feedURL)

	bs.mu.Lock()
	st, still := bs.feeds[feedURL]
	if !still { // removed while the fetch was in flight
		bs.mu.Unlock()
		return 0, nil
	}
	st.lastAttempt = time.Now()
	if err != nil {
		st.lastError = err.Error()
		bs.mu.Unlock()
		return 0, err
	}
	bs.mu.Unlock()

	added := bs.bl.MergeFromLines(lines, feedURL)

	bs.mu.Lock()
	if st, ok := bs.feeds[feedURL]; ok {
		st.lastSync = time.Now()
		st.lastError = ""
		st.importedCount += int64(added)
	}
	bs.mu.Unlock()

	obs.Printf("BlocklistFeed: synced %q — added %d new entries", obs.Sanitize(feedURL), added)
	return added, nil
}

// SyncAll syncs every configured feed (manual "Sync All Now"), regardless of
// interval. Returns the total domains added and the first error encountered.
func (bs *Syncer) SyncAll() (int, error) {
	var total int
	var firstErr error
	for _, f := range bs.Feeds() {
		n, err := bs.SyncFeed(f.URL)
		total += n
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return total, firstErr
}

// fetchFeedLines downloads the feed body and returns its non-empty lines.
// The SSRF guard runs inline at this call site (not only at admin-API save
// time) so every sync — scheduler, manual, or settings-restored feed — is
// re-checked, closing the gap where a feed host starts resolving to a
// private address after it was saved.
func (bs *Syncer) fetchFeedLines(feedURL string) ([]string, error) {
	if !urlPattern.MatchString(feedURL) {
		return nil, fmt.Errorf("feed URL must be an absolute http(s) URL")
	}
	u, err := url.Parse(feedURL)
	if err != nil {
		return nil, fmt.Errorf("invalid feed URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("feed URL scheme %q must be http or https", u.Scheme)
	}
	if err := ssrf.PrivateHost(u.Hostname()); err != nil {
		return nil, fmt.Errorf("feed URL blocked by SSRF guard: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", feedURL, err)
	}
	client := feedHTTPClient()
	resp, err := client.Do(req) // #nosec G107 -- operator-configured URL; scheme + ssrf.PrivateHost guard above
	if err != nil {
		obs.Printf("BlocklistFeed: fetch %q failed: %v", obs.Sanitize(feedURL), err)
		return nil, fmt.Errorf("fetch %s: %w", feedURL, err)
	}
	defer resp.Body.Close()

	var lines []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		obs.Printf("BlocklistFeed: read error from %q: %v", obs.Sanitize(feedURL), err)
		return nil, fmt.Errorf("read %s: %w", feedURL, err)
	}
	return lines, nil
}

func feedHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       httpTimeout,
		CheckRedirect: feedCheckRedirect,
		Transport: &http.Transport{
			DialContext:           ssrf.SafeDialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}
}

func feedCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("too many redirects")
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return fmt.Errorf("redirect URL scheme %q must be http or https", req.URL.Scheme)
	}
	if err := ssrf.PrivateHost(req.URL.Host); err != nil {
		return fmt.Errorf("redirect blocked by SSRF guard: %w", err)
	}
	return nil
}
