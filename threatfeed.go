package main

// Local Threat Feed Manager
//
// Downloads, persists, and provides instant offline lookups for known-malicious
// URL/domain lists. Zero external API dependency — all feeds are freely
// available without registration or rate limits.
//
// Feeds:
//   - URLhaus (abuse.ch): malware distribution URLs
//     https://urlhaus.abuse.ch/downloads/text/
//   - OpenPhish: phishing URLs
//     https://openphish.com/feed.txt
//
// The feed data is stored in a JSON file so the proxy survives restarts
// without waiting for a fresh download. A background goroutine re-syncs on
// the configured interval (default: 6 hours).

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// feedEntry records the threat intel source for a URL or domain.
type feedEntry struct {
	Source  string    `json:"source"`   // "urlhaus" | "openphish"
	AddedAt time.Time `json:"added_at"` // time the entry was ingested
}

// feedDB is the on-disk persistence format.
type feedDB struct {
	LastSync time.Time            `json:"last_sync"`
	URLs     map[string]feedEntry `json:"urls"`
	Domains  map[string]feedEntry `json:"domains"`
}

// ThreatFeed manages local copies of public threat intelligence lists.
// All methods are safe for concurrent use.
type ThreatFeed struct {
	mu           sync.RWMutex
	urls         map[string]feedEntry // normalised URL  → entry
	domains      map[string]feedEntry // lowercase hostname → entry
	dbPath       string
	syncInterval time.Duration
	lastSync     time.Time
	totalEntries atomic.Int64
	enabled      bool
}

// globalThreatFeed is the process-wide threat feed instance.
var globalThreatFeed = &ThreatFeed{
	urls:         make(map[string]feedEntry),
	domains:      make(map[string]feedEntry),
	syncInterval: 6 * time.Hour,
}

const (
	urlHausTextFeed = "https://urlhaus.abuse.ch/downloads/text/"
	openPhishFeed   = "https://openphish.com/feed.txt"
	feedUserAgent   = "ProxyShield/1.0 (+https://github.com/KidCarmi/Claude-Test)"
	feedHTTPTimeout = 60 * time.Second
	maxFeedLines    = 500_000 // safety cap per feed to limit memory usage
)

// Init configures the feed manager and loads any persisted DB from disk.
// dbPath may be "" to disable persistence (feed data lives in-memory only).
func (tf *ThreatFeed) Init(dbPath string, syncInterval time.Duration) {
	tf.mu.Lock()
	tf.dbPath = dbPath
	if syncInterval > 0 {
		tf.syncInterval = syncInterval
	}
	tf.enabled = true
	tf.mu.Unlock()

	if dbPath != "" {
		if err := tf.loadFromDisk(dbPath); err != nil {
			logger.Printf("ThreatFeed: could not load persisted DB (%v) — will sync fresh", err)
		}
	}
}

// Start launches the background sync goroutine.
// An immediate sync is performed when the cache is empty or has never synced.
func (tf *ThreatFeed) Start(ctx context.Context) {
	tf.mu.RLock()
	needSync := tf.lastSync.IsZero() || tf.totalEntries.Load() == 0
	tf.mu.RUnlock()

	go func() {
		if needSync {
			tf.Sync()
		}
		ticker := time.NewTicker(tf.syncInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				tf.Sync()
			}
		}
	}()
}

// Sync downloads all configured feeds and atomically replaces the in-memory
// lookup tables. Safe to call concurrently; calls run sequentially.
func (tf *ThreatFeed) Sync() {
	logger.Printf("ThreatFeed: starting sync")
	newURLs := make(map[string]feedEntry, 50_000)
	newDomains := make(map[string]feedEntry, 20_000)

	n, err := fetchTextFeed(urlHausTextFeed, "urlhaus", newURLs, newDomains)
	if err != nil {
		logger.Printf("ThreatFeed: URLhaus sync failed: %v", err)
	} else {
		logger.Printf("ThreatFeed: URLhaus → %d entries", n)
	}

	n, err = fetchTextFeed(openPhishFeed, "openphish", newURLs, newDomains)
	if err != nil {
		logger.Printf("ThreatFeed: OpenPhish sync failed: %v", err)
	} else {
		logger.Printf("ThreatFeed: OpenPhish → %d entries", n)
	}

	tf.mu.Lock()
	tf.urls = newURLs
	tf.domains = newDomains
	tf.lastSync = time.Now()
	tf.mu.Unlock()
	tf.totalEntries.Store(int64(len(newURLs)))

	logger.Printf("ThreatFeed: sync complete — %d unique URLs, %d unique domains", len(newURLs), len(newDomains))

	if tf.dbPath != "" {
		if err := tf.saveToDisk(); err != nil {
			logger.Printf("ThreatFeed: save to disk failed: %v", err)
		}
	}
}

// CheckURL looks up a full URL against the threat feed.
// Returns (isMalicious, sourceName).
func (tf *ThreatFeed) CheckURL(rawURL string) (bool, string) {
	if !tf.Enabled() {
		return false, ""
	}
	normURL, host := normaliseFeedURL(rawURL)

	tf.mu.RLock()
	defer tf.mu.RUnlock()

	if normURL != "" {
		if e, ok := tf.urls[normURL]; ok {
			return true, e.Source
		}
	}
	if host != "" {
		if e, ok := tf.domains[host]; ok {
			return true, e.Source
		}
	}
	return false, ""
}

// CheckDomain looks up a bare hostname against the threat feed.
func (tf *ThreatFeed) CheckDomain(domain string) (bool, string) {
	if !tf.Enabled() {
		return false, ""
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	tf.mu.RLock()
	defer tf.mu.RUnlock()

	if e, ok := tf.domains[domain]; ok {
		return true, e.Source
	}
	return false, ""
}

// Enabled reports whether the feed is active.
func (tf *ThreatFeed) Enabled() bool {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	return tf.enabled
}

// Stats returns (totalEntries, lastSync, syncInterval) for monitoring.
func (tf *ThreatFeed) Stats() (int64, time.Time, time.Duration) {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	return tf.totalEntries.Load(), tf.lastSync, tf.syncInterval
}

// ── Feed fetching ─────────────────────────────────────────────────────────────

// fetchTextFeed downloads a plain-text URL list (one URL per line; lines
// beginning with '#' are comments) and populates the urls and domains maps.
func fetchTextFeed(feedURL, source string, urls, domains map[string]feedEntry) (int, error) {
	client := &http.Client{Timeout: feedHTTPTimeout}
	req, err := http.NewRequest(http.MethodGet, feedURL, nil)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", feedUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d from %s", resp.StatusCode, feedURL)
	}

	now := time.Now()
	count := 0
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() && count < maxFeedLines {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// URLhaus may wrap entries in quotes in some CSV exports.
		line = strings.Trim(line, `"`)

		normURL, host := normaliseFeedURL(line)
		if normURL == "" || host == "" {
			continue
		}
		entry := feedEntry{Source: source, AddedAt: now}
		urls[normURL] = entry
		domains[host] = entry
		count++
	}
	return count, sc.Err()
}

// normaliseFeedURL parses a raw URL string into a canonical lookup key
// (scheme + host + path, no query or fragment) and the bare hostname.
// Returns ("", "") for invalid, private-IP, or non-HTTP(S) entries.
func normaliseFeedURL(raw string) (string, string) {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		// Some feeds omit the scheme; default to http.
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", ""
	}
	// Exclude private / loopback IPs (likely scanner artefacts in the feed).
	if ip := net.ParseIP(host); ip != nil && isPrivateIP(ip) {
		return "", ""
	}
	// Canonical form: scheme://host/path  (query and fragment stripped)
	norm := strings.ToLower(u.Scheme) + "://" + host + strings.ToLower(u.Path)
	norm = strings.TrimRight(norm, "/")
	return norm, host
}

// ── Persistence ───────────────────────────────────────────────────────────────

func (tf *ThreatFeed) loadFromDisk(path string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- admin-configured path
	if os.IsNotExist(err) {
		return nil // no DB yet; normal on first run
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var db feedDB
	if err := json.Unmarshal(data, &db); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	if db.URLs == nil {
		db.URLs = make(map[string]feedEntry)
	}
	if db.Domains == nil {
		db.Domains = make(map[string]feedEntry)
	}

	tf.mu.Lock()
	tf.urls = db.URLs
	tf.domains = db.Domains
	tf.lastSync = db.LastSync
	tf.mu.Unlock()
	tf.totalEntries.Store(int64(len(db.URLs)))

	logger.Printf("ThreatFeed: loaded %d URLs from %s (last sync: %s)",
		len(db.URLs), path, db.LastSync.Format(time.RFC3339))
	return nil
}

func (tf *ThreatFeed) saveToDisk() error {
	tf.mu.RLock()
	db := feedDB{
		LastSync: tf.lastSync,
		URLs:     tf.urls,
		Domains:  tf.domains,
	}
	tf.mu.RUnlock()

	data, err := json.Marshal(db)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	tmp := tf.dbPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil { // #nosec G306
		return fmt.Errorf("write tmp: %w", err)
	}
	return os.Rename(tmp, tf.dbPath)
}
