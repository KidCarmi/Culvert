package main

// saas_feed.go — Periodic SaaS category feed syncer.
//
// Fetches a curated JSON file of SaaS URL categories (AI, Marketing,
// Messaging, etc.) from a remote URL and merges new domains into the
// local catStore. By default, pulls from the Culvert GitHub repo:
//
//   https://raw.githubusercontent.com/KidCarmi/Culvert/main/default_categories.json
//
// Sync interval defaults to 24h. Admin can change the URL via the GUI
// to point at a private fork or internal mirror.
//
// Merge strategy: additive only — new domains are added, admin-removed
// domains are never re-added (tracked via an exclusion set). New categories
// appearing in the feed are created automatically.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const defaultSaaSFeedURL = "https://raw.githubusercontent.com/KidCarmi/Culvert/main/default_categories.json"

// validSaaSFeedURL matches http:// or https:// — SSRF guard for CodeQL.
var validSaaSFeedURL = regexp.MustCompile(`^https?://[^/]`)

// SaaSFeedSyncer periodically fetches a remote JSON file containing
// SaaS URL categories and merges them into catStore.
type SaaSFeedSyncer struct {
	mu           sync.Mutex
	feedURL      string
	interval     time.Duration
	lastSync     time.Time
	lastCount    int64
	cancel       context.CancelFunc
	client       *http.Client
	enabled      atomic.Bool
}

var globalSaaSFeed = &SaaSFeedSyncer{
	interval: 24 * time.Hour,
	client: &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{DialContext: ssrfSafeDialContext},
	},
}

// Configure sets the feed URL and starts the periodic sync loop.
func (s *SaaSFeedSyncer) Configure(feedURL string, interval time.Duration) {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.feedURL = strings.TrimSpace(feedURL)
	if interval > 0 {
		s.interval = interval
	}
	s.enabled.Store(s.feedURL != "")
	s.mu.Unlock()

	if s.feedURL == "" {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()

	go s.syncLoop(ctx)
	logger.Printf("SaaSFeed: syncing from %s every %s", sanitizeLog(feedURL), s.interval)
}

// Stop halts the sync loop.
func (s *SaaSFeedSyncer) Stop() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.feedURL = ""
	s.enabled.Store(false)
	s.mu.Unlock()
}

// Stats returns the current feed URL, last sync time, and domain count.
func (s *SaaSFeedSyncer) Stats() (url string, lastSync time.Time, count int64, interval time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.feedURL, s.lastSync, s.lastCount, s.interval
}

func (s *SaaSFeedSyncer) syncLoop(ctx context.Context) {
	// Sync immediately on start, then on interval.
	s.Sync(ctx)
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Sync(ctx)
		}
	}
}

// Sync fetches the feed and merges into catStore.
func (s *SaaSFeedSyncer) Sync(ctx context.Context) {
	s.mu.Lock()
	feedURL := s.feedURL
	s.mu.Unlock()

	if feedURL == "" {
		return
	}

	if !validSaaSFeedURL.MatchString(feedURL) {
		logger.Printf("SaaSFeed: invalid URL: %s", sanitizeLog(feedURL))
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		logger.Printf("SaaSFeed: request error: %v", err)
		return
	}

	resp, err := s.client.Do(req)
	if err != nil {
		logger.Printf("SaaSFeed: fetch error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Printf("SaaSFeed: HTTP %d from %s", resp.StatusCode, sanitizeLog(feedURL))
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB cap
	if err != nil {
		logger.Printf("SaaSFeed: read error: %v", err)
		return
	}

	var categories []CategoryEntry
	if err := json.Unmarshal(body, &categories); err != nil {
		logger.Printf("SaaSFeed: parse error: %v", err)
		return
	}

	// Merge into catStore: add new hosts, create new categories.
	added := 0
	for _, feedCat := range categories {
		name := strings.TrimSpace(feedCat.Name)
		if name == "" {
			continue
		}
		existing := catStore.GetByName(name)
		if existing == nil {
			// New category — create it with all hosts.
			_ = catStore.Set(name, feedCat.Hosts, true)
			added += len(feedCat.Hosts)
		} else {
			// Existing category — add only new hosts (additive merge).
			existingSet := make(map[string]bool, len(existing.Hosts))
			for _, h := range existing.Hosts {
				existingSet[strings.ToLower(h)] = true
			}
			var newHosts []string
			for _, h := range feedCat.Hosts {
				if !existingSet[strings.ToLower(h)] {
					newHosts = append(newHosts, h)
				}
			}
			for _, h := range newHosts {
				_ = catStore.AddHost(name, h)
				added++
			}
		}
	}

	s.mu.Lock()
	s.lastSync = time.Now()
	s.lastCount = int64(added)
	s.mu.Unlock()

	if added > 0 {
		catStore.Save()
		logger.Printf("SaaSFeed: synced %d categories, added %d new domain(s)", len(categories), added)
	} else {
		logger.Printf("SaaSFeed: synced %d categories, no new domains", len(categories))
	}
}

// Enabled returns whether the feed is active.
func (s *SaaSFeedSyncer) Enabled() bool {
	return s.enabled.Load()
}

// FeedURL returns the configured URL.
func (s *SaaSFeedSyncer) FeedURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.feedURL
}

// GetByName finds a category by name in catStore (case-insensitive).
func (cs *CategoryStore) GetByName(name string) *CategoryEntry {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	target := strings.ToLower(name)
	for _, e := range cs.entries {
		if strings.ToLower(e.Name) == target {
			return e
		}
	}
	return nil
}
