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
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	blFeedHTTPTimeout     = 30 * time.Second
	blFeedDefaultInterval = 24 * time.Hour
	blFeedTickInterval    = 60 * time.Second
)

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
func (bs *BlocklistSyncer) SetFeed(url string, interval time.Duration) {
	if url == "" {
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
	if st, ok := bs.feeds[url]; ok {
		st.interval = interval
		return
	}
	bs.feeds[url] = &blFeedState{interval: interval}
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
func (bs *BlocklistSyncer) RemoveFeed(url string) bool {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if _, ok := bs.feeds[url]; !ok {
		return false
	}
	delete(bs.feeds, url)
	return true
}

// Feeds returns a snapshot of all configured feeds, sorted by URL for
// deterministic API output and persistence.
func (bs *BlocklistSyncer) Feeds() []BlocklistFeed {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	out := make([]BlocklistFeed, 0, len(bs.feeds))
	for url, st := range bs.feeds {
		out = append(out, BlocklistFeed{
			URL:           url,
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
	for url, st := range bs.feeds {
		if st.interval <= 0 {
			continue
		}
		if st.lastAttempt.IsZero() || now.Sub(st.lastAttempt) >= st.interval {
			due = append(due, url)
		}
	}
	bs.mu.RUnlock()
	for _, url := range due {
		_, _ = bs.SyncFeed(url)
	}
}

// SyncFeed fetches one feed by URL and merges new domains into the blocklist.
// Returns the number of new domains added and any error encountered. The
// feed's status fields are updated either way.
func (bs *BlocklistSyncer) SyncFeed(url string) (int, error) {
	bs.mu.RLock()
	_, known := bs.feeds[url]
	bs.mu.RUnlock()
	if !known {
		return 0, fmt.Errorf("feed not configured: %s", url)
	}

	lines, err := bs.fetchFeedLines(url)

	bs.mu.Lock()
	st, still := bs.feeds[url]
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
	if st, ok := bs.feeds[url]; ok {
		st.lastSync = time.Now()
		st.lastError = ""
		st.importedCount += int64(added)
	}
	bs.mu.Unlock()

	logger.Printf("BlocklistFeed: synced %q — added %d new entries", sanitizeLog(url), added)
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
func (bs *BlocklistSyncer) fetchFeedLines(url string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), blFeedHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", url, err)
	}
	client := &http.Client{Timeout: blFeedHTTPTimeout}
	resp, err := client.Do(req) // #nosec G107 -- URL is operator-configured
	if err != nil {
		logger.Printf("BlocklistFeed: fetch %q failed: %v", sanitizeLog(url), err)
		return nil, fmt.Errorf("fetch %s: %w", url, err)
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
		logger.Printf("BlocklistFeed: read error from %q: %v", sanitizeLog(url), err)
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	return lines, nil
}
