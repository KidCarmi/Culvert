// Package saasfeed is the SaaS category feed syncer: it periodically fetches
// a curated JSON file of SaaS URL categories (AI, Marketing, Messaging, …)
// from a remote URL and hands the parsed categories to an injected merge
// callback. Extracted from package main per ADR-0002 (five-seam design
// recorded there): the category store lives in main's policy engine, so the
// MERGE is main's closure over catStore; the LIFECYCLE context provider is
// injected (the sync loop must die with the process, P6.1 UC-3); the CLIENT
// is injected (main builds it on ssrf.SafeDialContext); the sync-failure
// COUNTER is package-owned (SyncFailures, read by urlcat_metrics.go); and
// test construction goes through New/SeedStats/SetFeedURLForTest instead of
// struct-literal field pokes.
//
// Sync interval defaults to 24h. Admin can change the URL via the GUI to
// point at a private fork or internal mirror. Merge strategy is additive
// only (implemented by the injected callback).
package saasfeed

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

	"github.com/KidCarmi/Culvert/internal/obs"
)

// DefaultFeedURL is the built-in feed location (the Culvert GitHub repo);
// package main's urlcategories startup slice uses it as the config default.
const DefaultFeedURL = "https://raw.githubusercontent.com/KidCarmi/Culvert/main/default_categories.json"

// validFeedURL matches http:// or https:// — SSRF guard for CodeQL.
var validFeedURL = regexp.MustCompile(`^https?://[^/]`)

// syncFailures counts invalid-URL/fetch/parse failures; package main's
// urlcat metrics surface reads it via SyncFailures().
var syncFailures atomic.Int64

// SyncFailures returns the cumulative SaaS feed sync failure count.
func SyncFailures() int64 { return syncFailures.Load() }

// Category is the feed's wire type: one named URL category with its host
// list. JSON-compatible with main's CategoryEntry (whose builtIn field the
// feed does not carry).
type Category struct {
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
}

// Deps carries the injectable collaborators for New.
type Deps struct {
	// Client performs the feed fetches. nil → a 30s-timeout default client
	// WITHOUT the SSRF-safe dialer; production (package main) always passes
	// a client built on ssrf.SafeDialContext.
	Client *http.Client
	// Merge folds parsed categories into the category store and returns the
	// number of hosts added (it owns persistence of the store). nil → the
	// fetch/parse result is dropped with added=0 (test convenience).
	Merge func(categories []Category) (added int)
	// Lifecycle returns the context the sync loop is parented to, resolved
	// at Configure time (P6.1 UC-3: process shutdown must cancel the loop).
	// nil → context.Background().
	Lifecycle func() context.Context
}

// Syncer periodically fetches the feed and merges it via the injected
// callback.
type Syncer struct {
	mu        sync.Mutex
	feedURL   string
	interval  time.Duration
	lastSync  time.Time
	lastCount int64
	cancel    context.CancelFunc
	// done closes when the current syncLoop goroutine exits. nil when the
	// syncer is not running. Each Configure call installs a fresh channel
	// alongside the matching cancel func; Done() exposes the current one
	// so callers (process shutdown, tests) can wait deterministically for
	// the goroutine to actually exit after cancellation. Per P6.1 UC-3.
	done    chan struct{}
	client  *http.Client
	enabled atomic.Bool

	merge     func([]Category) int
	lifecycle func() context.Context
}

// New builds a Syncer from injected collaborators. The syncer starts idle
// (Configure enables it); interval defaults to 24h.
func New(deps Deps) *Syncer {
	s := &Syncer{
		interval:  24 * time.Hour,
		client:    deps.Client,
		merge:     deps.Merge,
		lifecycle: deps.Lifecycle,
	}
	if s.client == nil {
		s.client = &http.Client{Timeout: 30 * time.Second}
	}
	if s.lifecycle == nil {
		s.lifecycle = context.Background
	}
	return s
}

// Configure sets the feed URL and starts the periodic sync loop.
func (s *Syncer) Configure(feedURL string, interval time.Duration) {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
		// Clear cancel/done now so the empty-URL path below leaves the
		// "not running" state consistent (Done() returns nil). The
		// non-empty-URL path re-installs fresh values further down. The
		// old goroutine exits via its already-cancelled ctx and closes
		// its captured done channel from inside the wrapper — callers
		// that captured Done() before this reset still observe close.
		s.cancel = nil
		s.done = nil
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

	// P6.1 UC-3: parent the sync-loop context to the injected lifecycle
	// (package main passes resolveLifecycleCtx, which falls back to
	// context.Background() when appLifecycleCtx is nil — test binaries /
	// alternate startup flows).
	ctx, cancel := context.WithCancel(s.lifecycle())
	done := make(chan struct{})
	s.mu.Lock()
	s.cancel = cancel
	s.done = done
	s.mu.Unlock()

	go func() {
		defer close(done)
		s.syncLoop(ctx)
	}()
	obs.Printf("SaaSFeed: syncing from %s every %s", obs.Sanitize(feedURL), s.interval)
}

// Done returns the channel that closes when the current syncLoop
// goroutine exits, or nil when the syncer is not running. Provided as a
// test seam so the P6.1 UC-3 regression can wait deterministically for
// the goroutine to actually finish after the lifecycle context is
// cancelled; production code does not call this today.
func (s *Syncer) Done() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.done
}

// Stop halts the sync loop.
func (s *Syncer) Stop() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	// Pair with cancel so Done() returns nil for the now-stopped syncer;
	// the cancelled goroutine still closes its captured done channel,
	// which is what any caller that captured Done() before Stop sees.
	s.done = nil
	s.feedURL = ""
	s.enabled.Store(false)
	s.mu.Unlock()
}

// Stats returns the current feed URL, last sync time, and domain count.
func (s *Syncer) Stats() (url string, lastSync time.Time, count int64, interval time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.feedURL, s.lastSync, s.lastCount, s.interval
}

// SeedStats sets the last-sync timestamp and added-count directly. Test
// support for the metrics surface (production values are set by Sync).
func (s *Syncer) SeedStats(lastSync time.Time, count int64) {
	s.mu.Lock()
	s.lastSync = lastSync
	s.lastCount = count
	s.mu.Unlock()
}

// SetFeedURLForTest sets the feed URL without starting the sync loop, so a
// test can drive Sync synchronously (e.g. the invalid-URL failure-counter
// regression). Production code configures via Configure.
func (s *Syncer) SetFeedURLForTest(feedURL string) {
	s.mu.Lock()
	s.feedURL = feedURL
	s.mu.Unlock()
}

func (s *Syncer) syncLoop(ctx context.Context) {
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

// Sync fetches the feed and merges it via the injected callback.
func (s *Syncer) Sync(ctx context.Context) {
	s.mu.Lock()
	feedURL := s.feedURL
	s.mu.Unlock()

	if feedURL == "" {
		return
	}

	if !validFeedURL.MatchString(feedURL) {
		syncFailures.Add(1)
		obs.Printf("SaaSFeed: invalid URL: %s", obs.Sanitize(feedURL))
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, http.NoBody)
	if err != nil {
		syncFailures.Add(1)
		obs.Printf("SaaSFeed: request error: %v", err)
		return
	}

	resp, err := s.client.Do(req)
	if err != nil {
		syncFailures.Add(1)
		obs.Printf("SaaSFeed: fetch error: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		syncFailures.Add(1)
		obs.Printf("SaaSFeed: HTTP %d from %s", resp.StatusCode, obs.Sanitize(feedURL))
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB cap
	if err != nil {
		syncFailures.Add(1)
		obs.Printf("SaaSFeed: read error: %v", err)
		return
	}

	var categories []Category
	if err := json.Unmarshal(body, &categories); err != nil {
		syncFailures.Add(1)
		obs.Printf("SaaSFeed: parse error: %v", err)
		return
	}

	// Merge via the injected callback (main's closure over catStore; it
	// owns persistence of the store when added > 0).
	added := 0
	if s.merge != nil {
		added = s.merge(categories)
	}

	s.mu.Lock()
	s.lastSync = time.Now()
	s.lastCount = int64(added)
	s.mu.Unlock()

	if added > 0 {
		obs.Printf("SaaSFeed: synced %d categories, added %d new domain(s)", len(categories), added)
	} else {
		obs.Printf("SaaSFeed: synced %d categories, no new domains", len(categories))
	}
}

// Enabled returns whether the feed is active.
func (s *Syncer) Enabled() bool {
	return s.enabled.Load()
}

// FeedURL returns the configured URL.
func (s *Syncer) FeedURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.feedURL
}
