package main

// BlocklistSyncer — periodically downloads a remote blocklist (one domain per
// line, '#' comments allowed) and merges new entries into the live Blocklist
// without removing manually-added entries.

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

const (
	blFeedHTTPTimeout    = 30 * time.Second
	blFeedDefaultInterval = 24 * time.Hour
)

// BlocklistSyncer downloads and merges a remote domain feed into a Blocklist.
type BlocklistSyncer struct {
	bl           *Blocklist
	feedURL      atomic.Value // string
	interval     atomic.Value // time.Duration
	lastSync     atomic.Value // time.Time
	importedCount atomic.Int64
}

// newBlocklistSyncer creates a syncer for bl with the given feed URL and interval.
// interval 0 uses the default of 24h.
func newBlocklistSyncer(bl *Blocklist, feedURL string, interval time.Duration) *BlocklistSyncer {
	bs := &BlocklistSyncer{bl: bl}
	bs.feedURL.Store(feedURL)
	if interval <= 0 {
		interval = blFeedDefaultInterval
	}
	bs.interval.Store(interval)
	bs.lastSync.Store(time.Time{})
	return bs
}

// Start launches the background sync loop. It runs an immediate sync on
// startup, then repeats every configured interval.
func (bs *BlocklistSyncer) Start(ctx context.Context) {
	go func() {
		bs.Sync()
		for {
			d := bs.interval.Load().(time.Duration)
			select {
			case <-ctx.Done():
				return
			case <-time.After(d):
				bs.Sync()
			}
		}
	}()
}

// Sync fetches the feed URL and merges new domains into the blocklist.
func (bs *BlocklistSyncer) Sync() {
	url := bs.feedURL.Load().(string)
	if url == "" {
		return
	}
	client := &http.Client{Timeout: blFeedHTTPTimeout}
	resp, err := client.Get(url) // #nosec G107 -- URL is operator-configured
	if err != nil {
		logger.Printf("BlocklistFeed: fetch %s failed: %v", url, err)
		return
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
		logger.Printf("BlocklistFeed: read error from %s: %v", url, err)
		return
	}

	added := bs.bl.MergeFromLines(lines)
	bs.importedCount.Add(int64(added))
	bs.lastSync.Store(time.Now())
	logger.Printf("BlocklistFeed: synced %s — added %d new entries", url, added)
}

// SetFeed updates the feed URL and sync interval at runtime.
func (bs *BlocklistSyncer) SetFeed(url string, interval time.Duration) {
	bs.feedURL.Store(url)
	if interval <= 0 {
		interval = blFeedDefaultInterval
	}
	bs.interval.Store(interval)
}

// Stats returns current feed configuration and sync status.
func (bs *BlocklistSyncer) Stats() (url string, lastSync time.Time, count int64, interval time.Duration) {
	url      = bs.feedURL.Load().(string)
	lastSync = bs.lastSync.Load().(time.Time)
	count    = bs.importedCount.Load()
	interval = bs.interval.Load().(time.Duration)
	return
}
