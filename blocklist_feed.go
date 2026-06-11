package main

// BlocklistSyncer — periodically downloads one or more remote blocklists
// (one domain per line, '#' comments allowed) and merges new entries into
// the live Blocklist without removing manually-added entries.
//
// Multi-feed: each feed has its own URL, sync interval, and status. A single
// scheduler goroutine (Start) wakes every blFeedTickInterval and syncs every
// feed whose interval has elapsed since its last attempt. The scheduler is
// ALWAYS started at startup — feeds added later via the admin API are picked
// up on the next tick without a restart.

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
)

const (
	blFeedHTTPTimeout     = 30 * time.Second
	blFeedDefaultInterval = 24 * time.Hour
	blFeedTickInterval    = 60 * time.Second
	blFeedMaxRedirects    = 5
)

var blFeedURLPattern = regexp.MustCompile(`^https?://[^/?#\s]+(?:[/?#]\S*)?$`)

// BlocklistFeed is a point-in-time status snapshot of one configured feed,
// returned by Feeds() for the admin API and settings persistence.
type BlocklistFeed struct {
	URL           string
	Interval      time.Duration // 0 = auto-sync disabled (manual Sync Now only)
	LastSync      time.Time     // last successful sync (zero = never)
	LastError     string        // error from the most recent attempt ("" = ok)
	ImportedCount int64         // cumulative new domains merged from this feed
}

// blFeedState is the internal mutable state of one feed.
type blFeedState struct {
	interval      time.Duration
	lastSync      time.Time
	lastAttempt   time.Time
	lastError     string
	importedCount int64
}

// BlocklistSyncer downloads and merges remote domain feeds into a Blocklist.
// The zero value is safe for all methods (feeds map is lazily initialized).
type BlocklistSyncer struct {
	bl    *Blocklist
	mu    sync.RWMutex
	feeds map[string]*blFeedState // keyed by feed URL
}

// newBlocklistSyncer creates an empty syncer for bl. Feeds are added via
// SetFeed (startup config seed or admin API).
func newBlocklistSyncer(bl *Blocklist) *BlocklistSyncer {
	return &BlocklistSyncer{bl: bl, feeds: map[string]*blFeedState{}}
}

// SetFeed adds or updates a feed. interval 0 disables auto-sync for that
// feed (it can still be synced manually). Existing sync statistics are
// preserved on update.
func (bs *BlocklistSyncer) SetFeed(feedURL string, interval time.Duration) {
	if feedURL == "" {
		return
	}
	if interval < 0 {
		interval = 0
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if bs.feeds == nil {
		bs.feeds = map[string]*blFeedState{}
	}
	if st, ok := bs.feeds[feedURL]; ok {
		st.interval = interval
		return
	}
	bs.feeds[feedURL] = &blFeedState{interval: interval}
}

// ClearFeeds removes every configured feed. Used when restoring persisted
// settings, which are authoritative over the YAML/CLI startup seed.
// Domains already merged into the blocklist are NOT removed.
func (bs *BlocklistSyncer) ClearFeeds() {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.feeds = map[string]*blFeedState{}
}

// RemoveFeed deletes a feed by URL. Returns false when no such feed exists.
// Domains already merged into the blocklist are NOT removed (feed imports
// are merge-only by design).
func (bs *BlocklistSyncer) RemoveFeed(feedURL string) bool {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if _, ok := bs.feeds[feedURL]; !ok {
		return false
	}
	delete(bs.feeds, feedURL)
	return true
}

// Feeds returns a snapshot of all configured feeds, sorted by URL for
// deterministic API output and persistence.
func (bs *BlocklistSyncer) Feeds() []BlocklistFeed {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	out := make([]BlocklistFeed, 0, len(bs.feeds))
	for feedURL, st := range bs.feeds {
		out = append(out, BlocklistFeed{
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
// wakes every blFeedTickInterval and syncs each feed whose interval has
// elapsed since its last attempt. Feeds with interval 0 are skipped.
func (bs *BlocklistSyncer) Start(ctx context.Context) {
	go func() {
		bs.syncDue()
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(blFeedTickInterval):
				bs.syncDue()
			}
		}
	}()
}

// syncDue syncs every feed that is due: auto-sync enabled (interval > 0)
// and never attempted, or last attempted at least one interval ago.
func (bs *BlocklistSyncer) syncDue() {
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
func (bs *BlocklistSyncer) SyncFeed(feedURL string) (int, error) {
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

	added := bs.bl.MergeFromLines(lines)

	bs.mu.Lock()
	if st, ok := bs.feeds[feedURL]; ok {
		st.lastSync = time.Now()
		st.lastError = ""
		st.importedCount += int64(added)
	}
	bs.mu.Unlock()

	logger.Printf("BlocklistFeed: synced %q — added %d new entries", sanitizeLog(feedURL), added)
	return added, nil
}

// SyncAll syncs every configured feed (manual "Sync All Now"), regardless of
// interval. Returns the total domains added and the first error encountered.
func (bs *BlocklistSyncer) SyncAll() (int, error) {
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
func (bs *BlocklistSyncer) fetchFeedLines(feedURL string) ([]string, error) {
	if !blFeedURLPattern.MatchString(feedURL) {
		return nil, fmt.Errorf("feed URL must be an absolute http(s) URL")
	}
	u, err := url.Parse(feedURL)
	if err != nil {
		return nil, fmt.Errorf("invalid feed URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("feed URL scheme %q must be http or https", u.Scheme)
	}
	if err := isPrivateHost(u.Hostname()); err != nil {
		return nil, fmt.Errorf("feed URL blocked by SSRF guard: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), blFeedHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", feedURL, err)
	}
	client := blocklistFeedHTTPClient()
	resp, err := client.Do(req) // #nosec G107 -- operator-configured URL; scheme + isPrivateHost guard above
	if err != nil {
		logger.Printf("BlocklistFeed: fetch %q failed: %v", sanitizeLog(feedURL), err)
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
		logger.Printf("BlocklistFeed: read error from %q: %v", sanitizeLog(feedURL), err)
		return nil, fmt.Errorf("read %s: %w", feedURL, err)
	}
	return lines, nil
}

func blocklistFeedHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       blFeedHTTPTimeout,
		CheckRedirect: blocklistFeedCheckRedirect,
		Transport: &http.Transport{
			DialContext:           ssrfSafeDialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}
}

func blocklistFeedCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= blFeedMaxRedirects {
		return fmt.Errorf("too many redirects")
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return fmt.Errorf("redirect URL scheme %q must be http or https", req.URL.Scheme)
	}
	if err := isPrivateHost(req.URL.Host); err != nil {
		return fmt.Errorf("redirect blocked by SSRF guard: %w", err)
	}
	return nil
}
