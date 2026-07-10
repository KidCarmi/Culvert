// Package threatfeed is the local threat-feed manager: it downloads,
// persists, and provides instant offline lookups for known-malicious
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
//
// Extracted from package main per ADR-0002. The package is a pure leaf: the
// SSRF private-IP table comes from internal/ssrf, durable writes from
// internal/fileutil, and logging from the obs facade (including the new
// obs.Debugf for the sync-start debug line). package main keeps the
// globalThreatFeed singleton and the admin/cluster surfaces behind a type
// alias.
package threatfeed

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/hostutil"
	"github.com/KidCarmi/Culvert/internal/obs"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// entry records the threat intel source for a URL or domain.
type entry struct {
	Source  string    `json:"source"`   // "urlhaus" | "openphish"
	AddedAt time.Time `json:"added_at"` // time the entry was ingested
}

// feedDB is the on-disk persistence format.
type feedDB struct {
	LastSync time.Time `json:"last_sync"`
	// LastSuccess and LastSyncErr persist the SyncStatus fields across
	// restarts. Both are omitempty so a DB written before these fields
	// existed loads as zero/"" — loadFromDisk treats that legacy shape as
	// "LastSync was itself a success" (matching the pre-SyncStatus
	// behavior, where a successful sync was the only thing ever recorded).
	LastSuccess time.Time        `json:"last_success,omitempty"`
	LastSyncErr string           `json:"last_sync_err,omitempty"`
	URLs        map[string]entry `json:"urls"`
	Domains     map[string]entry `json:"domains"`
	// DomainAllowlist persists the admin-managed allowlist. Tag has NO
	// `omitempty` so an admin-cleared (zero-entry) allowlist serializes
	// as `"domain_allowlist": []` and round-trips through loadFromDisk
	// as an explicit wipe — not as "field absent" which loadFromDisk
	// treats as "keep the seeded defaults". Pre-fix this combination
	// silently reverted explicit clears on every restart; see
	// roadmap/DOMAIN-ALLOWLIST-ROLLBACK-CLASSIFICATION.md §3.3.
	DomainAllowlist []string `json:"domain_allowlist"`
}

// Feed manages local copies of public threat intelligence lists.
// All methods are safe for concurrent use.
type Feed struct {
	mu              sync.RWMutex
	urls            map[string]entry // normalised URL  → entry
	domains         map[string]entry // lowercase hostname → entry
	domainAllowlist map[string]bool  // domains exempt from domain-level blocking
	dbPath          string
	syncInterval    time.Duration
	lastSync        time.Time // time of the most recent sync attempt, success or failure
	lastSuccess     time.Time // time of the most recent sync where every feed fetched cleanly
	lastSyncErr     string    // summary of the most recent failure(s); empty when the last sync fully succeeded
	totalEntries    atomic.Int64
	enabled         bool
}

// New returns an idle Feed with the same shape as the pre-extraction
// package-main literal: initialised maps and the 6-hour default sync
// interval. Init configures and enables it.
func New() *Feed {
	return &Feed{
		urls:            make(map[string]entry),
		domains:         make(map[string]entry),
		domainAllowlist: make(map[string]bool),
		syncInterval:    6 * time.Hour,
	}
}

const (
	urlHausTextFeed = "https://urlhaus.abuse.ch/downloads/text/"
	openPhishFeed   = "https://openphish.com/feed.txt"
	feedUserAgent   = "Culvert/1.0 (+https://github.com/KidCarmi/Claude-Test)"
	feedHTTPTimeout = 60 * time.Second
	maxFeedLines    = 500_000 // safety cap per feed to limit memory usage

	// Source names stamped on entries. Each feed's name appears in exactly
	// two places (the fetch call and the replacedSources bookkeeping in
	// Sync), both via these constants — carryForward's keep-by-exclusion
	// depends on the strings matching exactly, so they must never be
	// spelled inline. "cluster-sync" (ImportFeedData) is deliberately NOT
	// here: it is never a local fetch source, which is what makes those
	// entries survive local syncs.
	sourceURLhaus   = "urlhaus"
	sourceOpenPhish = "openphish"
)

// Init configures the feed manager and loads any persisted DB from disk.
// dbPath may be "" to disable persistence (feed data lives in-memory only).
func (tf *Feed) Init(dbPath string, syncInterval time.Duration) {
	tf.mu.Lock()
	tf.dbPath = dbPath
	if syncInterval > 0 {
		tf.syncInterval = syncInterval
	}
	tf.enabled = true
	// Seed domain allowlist with defaults if empty (first run).
	if len(tf.domainAllowlist) == 0 {
		tf.domainAllowlist = make(map[string]bool, len(defaultDomainAllowlist))
		for _, d := range defaultDomainAllowlist {
			tf.domainAllowlist[d] = true
		}
	}
	tf.mu.Unlock()

	if dbPath != "" {
		if err := tf.loadFromDisk(dbPath); err != nil {
			obs.Printf("ThreatFeed: could not load persisted DB (%v) — will sync fresh", err)
		}
	}
}

// Start launches the background sync goroutine.
// An immediate sync is performed when the cache is empty or has never synced.
func (tf *Feed) Start(ctx context.Context) {
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
func (tf *Feed) Sync() {
	obs.Debugf("ThreatFeed: starting sync")
	newURLs := make(map[string]entry, 50_000)
	newDomains := make(map[string]entry, 20_000)
	var failures []string
	replacedSources := make(map[string]bool, 2)

	if ok, fail := tf.fetchFeedInto(urlHausTextFeed, sourceURLhaus, "URLhaus", newURLs, newDomains); ok {
		replacedSources[sourceURLhaus] = true
	} else {
		failures = append(failures, fail)
	}
	if ok, fail := tf.fetchFeedInto(openPhishFeed, sourceOpenPhish, "OpenPhish", newURLs, newDomains); ok {
		replacedSources[sourceOpenPhish] = true
	} else {
		failures = append(failures, fail)
	}

	tf.applySync(newURLs, newDomains, failures, replacedSources, time.Now())

	obs.Printf("ThreatFeed: sync complete — %d unique URLs, %d unique domains", len(newURLs), len(newDomains))

	if tf.dbPath != "" {
		if err := tf.saveToDisk(); err != nil {
			obs.Printf("ThreatFeed: save to disk failed: %v", err)
		}
	}
}

// applySync installs freshly-fetched feed tables. Only entries owned by a
// feed that fetched CLEANLY this sync (replacedSources) are replaced; every
// other previous entry is carried forward. That covers two failure classes:
//   - a feed whose fetch failed keeps its last-known-good entries — otherwise
//     one sync with both feeds unreachable would wipe the entire threat DB in
//     memory AND on disk (Sync persists right after), silently disabling
//     threat-feed blocking until the next successful sync;
//   - entries a local fetch never owns — the DP's "cluster-sync" import
//     (ImportFeedData) — survive local syncs instead of being wiped until the
//     next CP snapshot re-imports them.
//
// A feed that fetched cleanly is always fully replaced, so its stale entries
// still age out; cluster-sync entries are refreshed wholesale by
// ImportFeedData on every snapshot apply.
func (tf *Feed) applySync(newURLs, newDomains map[string]entry, failures []string, replacedSources map[string]bool, now time.Time) {
	tf.mu.Lock()
	carryForward(newURLs, tf.urls, replacedSources)
	carryForward(newDomains, tf.domains, replacedSources)
	tf.urls = newURLs
	tf.domains = newDomains
	tf.lastSync = now
	if len(failures) == 0 {
		tf.lastSuccess = now
		tf.lastSyncErr = ""
	} else {
		tf.lastSyncErr = strings.Join(failures, "; ")
	}
	tf.mu.Unlock()
	tf.totalEntries.Store(int64(len(newURLs)))
}

// fetchFeedInto fetches one feed into the fresh maps and reports whether the
// result should REPLACE that source's previous entries. A fetch error keeps
// last-known-good via carryForward — and so does a ZERO-entry "success": an
// HTTP 200 maintenance page or empty/truncated-at-a-line-boundary body
// returns (0, nil) from fetchTextFeed, and these public feeds are never
// legitimately empty, so treating it as clean would wipe the feed the same
// way a hard error used to (caught by review on PR #587).
func (tf *Feed) fetchFeedInto(feedURL, source, label string, urls, domains map[string]entry) (replaced bool, failure string) {
	n, err := tf.fetchTextFeed(feedURL, source, urls, domains)
	if err != nil {
		obs.Printf("ThreatFeed: %s sync failed: %v", label, err)
		return false, fmt.Sprintf("%s: %v", label, err)
	}
	if n == 0 {
		obs.Printf("ThreatFeed: %s returned 0 entries — keeping previous data", label)
		return false, label + ": returned 0 entries"
	}
	obs.Printf("ThreatFeed: %s %d entries", label, n)
	return true, ""
}

// carryForward copies into dst the entries of old whose Source is NOT in
// replaced (feeds that fetched cleanly this sync). Fresh entries win on key
// collision.
func carryForward(dst, old map[string]entry, replaced map[string]bool) {
	for k, e := range old {
		if replaced[e.Source] {
			continue
		}
		if _, ok := dst[k]; !ok {
			dst[k] = e
		}
	}
}

// CheckURL looks up a full URL against the threat feed.
// Returns (isMalicious, sourceName).
func (tf *Feed) CheckURL(rawURL string) (malicious bool, source string) {
	if !tf.Enabled() {
		return false, ""
	}
	normURL, host := NormaliseURL(rawURL)

	tf.mu.RLock()
	defer tf.mu.RUnlock()

	if normURL != "" {
		if e, ok := tf.urls[normURL]; ok {
			return true, e.Source
		}
	}
	if host != "" {
		if e, ok := tf.domains[host]; ok && !tf.domainAllowlist[host] {
			return true, e.Source
		}
	}
	return false, ""
}

// CheckDomain looks up a bare hostname against the threat feed.
// Returns (isMalicious, sourceName).
func (tf *Feed) CheckDomain(domain string) (malicious bool, source string) {
	if !tf.Enabled() {
		return false, ""
	}
	domain = normaliseDomain(domain)

	tf.mu.RLock()
	defer tf.mu.RUnlock()

	if domain == "" || tf.domainAllowlist[domain] {
		return false, ""
	}
	if e, ok := tf.domains[domain]; ok {
		return true, e.Source
	}
	return false, ""
}

// Enabled reports whether the feed is active.
func (tf *Feed) Enabled() bool {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	return tf.enabled
}

// Stats returns (totalEntries, lastSync, syncInterval) for monitoring.
func (tf *Feed) Stats() (int64, time.Time, time.Duration) {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	return tf.totalEntries.Load(), tf.lastSync, tf.syncInterval
}

// SyncStatus reports whether the most recent sync fetched every feed
// cleanly, the time of the last fully-successful sync (which may lag
// lastSync from Stats if recent attempts have been failing), and a
// summary of the most recent failure (empty when the last sync succeeded).
// lastSync updates on every attempt regardless of outcome, so relying on
// Stats alone lets a persistently-failing feed hide behind a
// perpetually-fresh timestamp.
func (tf *Feed) SyncStatus() (ok bool, lastSuccess time.Time, errSummary string) {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	return tf.lastSyncErr == "", tf.lastSuccess, tf.lastSyncErr
}

// defaultDomainAllowlist seeds the threat-feed domain allowlist with popular
// hosting platforms where user-uploaded content is common. A single malicious
// file on these domains must NOT block the entire domain; only the specific
// URL is recorded. Admins can add/remove entries at runtime via the API.
var defaultDomainAllowlist = []string{
	"github.com", "raw.githubusercontent.com", "gist.githubusercontent.com",
	"objects.githubusercontent.com", "gitlab.com", "bitbucket.org",
	"drive.google.com", "docs.google.com", "storage.googleapis.com",
	"s3.amazonaws.com", "dropbox.com", "dl.dropboxusercontent.com",
	"onedrive.live.com", "1drv.ms", "cdn.discordapp.com", "discord.com",
	"mediafire.com", "mega.nz", "transfer.sh", "pastebin.com",
	"catbox.moe", "files.catbox.moe", "archive.org", "web.archive.org",
	"cdn.jsdelivr.net", "unpkg.com",
}

// DomainAllowlisted reports whether a domain is on the threat-feed allowlist
// (domain-level blocking skipped; URL-level blocking still applies).
func (tf *Feed) DomainAllowlisted(domain string) bool {
	domain = normaliseDomain(domain)
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	return tf.domainAllowlist[domain]
}

// DomainAllowlist returns the current allowlist entries sorted.
func (tf *Feed) DomainAllowlist() []string {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	out := make([]string, 0, len(tf.domainAllowlist))
	for d := range tf.domainAllowlist {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// SetDomainAllowlist replaces the entire allowlist and persists to disk.
func (tf *Feed) SetDomainAllowlist(domains []string) error {
	tf.mu.Lock()
	tf.domainAllowlist = make(map[string]bool, len(domains))
	for _, d := range domains {
		d = normaliseDomain(d)
		if d != "" {
			tf.domainAllowlist[d] = true
		}
	}
	tf.mu.Unlock()
	if tf.dbPath != "" {
		if err := tf.saveToDisk(); err != nil {
			obs.Printf("ThreatFeed: save allowlist failed: %v", err)
			return err
		}
	}
	return nil
}

// AddDomainAllowlist adds a domain to the allowlist and persists.
func (tf *Feed) AddDomainAllowlist(domain string) error {
	domain = normaliseDomain(domain)
	if domain == "" {
		return nil
	}
	tf.mu.Lock()
	if tf.domainAllowlist == nil {
		tf.domainAllowlist = make(map[string]bool)
	}
	tf.domainAllowlist[domain] = true
	tf.mu.Unlock()
	if tf.dbPath != "" {
		if err := tf.saveToDisk(); err != nil {
			obs.Printf("ThreatFeed: save allowlist failed: %v", err)
			return err
		}
	}
	return nil
}

// RemoveDomainAllowlist removes a domain from the allowlist and persists.
func (tf *Feed) RemoveDomainAllowlist(domain string) error {
	domain = normaliseDomain(domain)
	tf.mu.Lock()
	delete(tf.domainAllowlist, domain)
	tf.mu.Unlock()
	if tf.dbPath != "" {
		if err := tf.saveToDisk(); err != nil {
			obs.Printf("ThreatFeed: save allowlist failed: %v", err)
			return err
		}
	}
	return nil
}

// ── Feed fetching ─────────────────────────────────────────────────────────────

// fetchTextFeed downloads a plain-text URL list (one URL per line; lines
// beginning with '#' are comments) and populates the urls and domains maps.
// Allowlisted domains are still recorded as threat intel; the allowlist only
// masks domain-level blocking at lookup time so removal re-enables the block
// immediately without waiting for another sync.
//
// A method (pre-extraction it was a package function reading the
// globalThreatFeed singleton for the allowlist check): the only caller is
// Sync on the same instance, so behavior is unchanged.
func (tf *Feed) fetchTextFeed(feedURL, source string, urls, domains map[string]entry) (int, error) {
	client := &http.Client{Timeout: feedHTTPTimeout}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, feedURL, http.NoBody)
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

		normURL, host := NormaliseURL(line)
		if normURL == "" || host == "" {
			continue
		}
		e := entry{Source: source, AddedAt: now}
		urls[normURL] = e
		domains[host] = e
		count++
	}
	return count, sc.Err()
}

// NormaliseURL parses a raw URL string into a canonical lookup key
// (scheme + host + path, no query or fragment) and the bare hostname.
// Returns ("", "") for invalid, private-IP, or non-HTTP(S) entries.
func NormaliseURL(raw string) (norm, host string) {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		// Some feeds omit the scheme; default to http.
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", ""
	}
	host = canonicalHost(u.Hostname())
	if host == "" {
		return "", ""
	}
	// Exclude private / loopback IPs (likely scanner artefacts in the feed).
	if ip := net.ParseIP(host); ip != nil && ssrf.PrivateIP(ip) {
		return "", ""
	}
	// Canonical form: scheme://host/path  (query and fragment stripped)
	norm = strings.ToLower(u.Scheme) + "://" + host + strings.ToLower(u.Path)
	norm = strings.TrimRight(norm, "/")
	return norm, host
}

func normaliseDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	if strings.Contains(domain, "://") {
		u, err := url.Parse(domain)
		if err != nil || u.Host == "" {
			return ""
		}
		domain = u.Host
	} else if strings.Contains(domain, "/") {
		// URL- or path-shaped input MUST yield a host. Falling through
		// to canonicalHost with the raw string would mint an unmatchable
		// key like "10.0.0.1/24" — a silent no-op security exception
		// that persists, syncs to DPs, and is counted in the audit.
		_, host := NormaliseURL(domain)
		if host == "" {
			return ""
		}
		domain = host
	}
	return canonicalHost(domain)
}

func canonicalHost(host string) string {
	host = hostutil.StripHostPort(strings.ToLower(strings.TrimSpace(host)))
	return hostutil.NormalizeHost(host)
}

// ── Persistence ───────────────────────────────────────────────────────────────

func (tf *Feed) loadFromDisk(path string) error {
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
		db.URLs = make(map[string]entry)
	}
	if db.Domains == nil {
		db.Domains = make(map[string]entry)
	}
	// Re-canonicalize legacy keys (one-time upgrade cost, load only). DBs
	// written before host canonicalization (IDNA/punycode, trailing dots)
	// carry keys the canonicalized lookups in CheckURL/CheckDomain would
	// no longer match — without this rekey those entries silently stop
	// blocking until the next feed sync rewrites the maps. A key that
	// fails canonicalization keeps its original form (fail-safe: the
	// entry is retained and matches exactly as it did before).
	urls := make(map[string]entry, len(db.URLs))
	for k, v := range db.URLs {
		if nk, _ := NormaliseURL(k); nk != "" {
			urls[nk] = v
		} else {
			urls[k] = v
		}
	}
	domains := make(map[string]entry, len(db.Domains))
	for k, v := range db.Domains {
		if nk := normaliseDomain(k); nk != "" {
			domains[nk] = v
		} else {
			domains[k] = v
		}
	}

	tf.mu.Lock()
	tf.urls = urls
	tf.domains = domains
	tf.lastSync = db.LastSync
	tf.lastSyncErr = db.LastSyncErr
	switch {
	case !db.LastSuccess.IsZero():
		tf.lastSuccess = db.LastSuccess
	case db.LastSyncErr == "":
		// Legacy DB (saved before LastSuccess existed) or a DB saved by a
		// clean sync before this field was ever set: LastSync IS the last
		// success, so back-fill it rather than reporting "never synced".
		tf.lastSuccess = db.LastSync
	}
	// Restore the persisted allowlist. The guard keys on nil, not
	// len()==0, so an admin-cleared explicit-empty `[]` (saved as
	// `"domain_allowlist": []` per the no-omitempty tag) replaces the
	// seeded defaults — i.e. the admin's clear survives restart. A nil
	// value (field absent: legacy save from before the omitempty fix, or
	// any pre-allowlist DB shape) is treated as "keep the seeded
	// defaults", preserving backward compatibility. Mirrors the
	// nil-vs-empty contract used by the rollback-surface stores
	// (CategoryGroups / URLCategories / RateLimitExempt).
	if db.DomainAllowlist != nil {
		tf.domainAllowlist = make(map[string]bool, len(db.DomainAllowlist))
		for _, d := range db.DomainAllowlist {
			if d = normaliseDomain(d); d != "" {
				tf.domainAllowlist[d] = true
			}
		}
	}
	tf.mu.Unlock()
	// Count the post-rekey map, not db.URLs — rekey collisions (a legacy
	// Unicode key alongside its punycode twin) shrink the map.
	tf.totalEntries.Store(int64(len(urls)))

	obs.Printf("ThreatFeed: loaded %d URLs from %s (last sync: %s)",
		len(urls), path, db.LastSync.Format(time.RFC3339))
	return nil
}

func (tf *Feed) saveToDisk() error {
	tf.mu.RLock()
	allowlist := make([]string, 0, len(tf.domainAllowlist))
	for d := range tf.domainAllowlist {
		allowlist = append(allowlist, d)
	}
	sort.Strings(allowlist)
	// The persisted `domains` key keeps its pre-masking meaning — "hosts
	// a lookup may block" — so currently-allowlisted hosts are filtered
	// OUT on disk. Older binaries have no lookup-time allowlist mask;
	// persisting masked hosts would make a binary rollback hard-block
	// allowlisted platforms (github.com etc. routinely appear in
	// URLhaus). The in-memory map retains them, so while this process
	// lives, removing an allowlist entry re-blocks immediately; across a
	// restart the masked intel is rebuilt by the next sync/import.
	domains := make(map[string]entry, len(tf.domains))
	for d, e := range tf.domains {
		if !tf.domainAllowlist[d] {
			domains[d] = e
		}
	}
	db := feedDB{
		LastSync:        tf.lastSync,
		LastSuccess:     tf.lastSuccess,
		LastSyncErr:     tf.lastSyncErr,
		URLs:            tf.urls,
		Domains:         domains,
		DomainAllowlist: allowlist,
	}
	tf.mu.RUnlock()

	data, err := json.Marshal(db)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	// Bucket-4 durability hardening: fileutil.AtomicWrite gives unique
	// tmp + chmod + fsync(file) + rename + best-effort fsync(parent
	// dir) — replaces the previous os.WriteFile+os.Rename which was
	// atomic-via-rename but NOT fsynced (P6.2 SC-4).
	return fileutil.AtomicWrite(tf.dbPath, data, 0o600)
}

// Save is the caller-facing wrapper around saveToDisk. Used by paths
// like applyConfigSnapshot that mutate via ImportFeedData — which
// does NOT auto-persist (unlike SetDomainAllowlist /
// AddDomainAllowlist / RemoveDomainAllowlist which call saveToDisk
// internally). Errors are logged, not returned, to match the
// void-Save convention of the other Bucket-1 snapshot stores
// (policyStore, globalProfileStore, etc.).
func (tf *Feed) Save() {
	if tf.dbPath == "" {
		return
	}
	if err := tf.saveToDisk(); err != nil {
		obs.Printf("ThreatFeed: Save failed: %v", err)
	}
}

// ExportURLs returns a copy of the URL threat map as url→unix-timestamp.
// Used by the Control Plane to include feed data in config sync.
func (tf *Feed) ExportURLs() map[string]int64 {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	out := make(map[string]int64, len(tf.urls))
	for u, e := range tf.urls {
		out[u] = e.AddedAt.Unix()
	}
	return out
}

// ExportDomains returns a copy of the domain threat map as domain→unix-timestamp.
// Used by the Control Plane to include feed data in config sync.
//
// Currently-allowlisted hosts are excluded: the ThreatFeedDomains wire field
// keeps its pre-masking meaning ("hosts a lookup may block") because DP nodes
// running an older binary have no lookup-time allowlist mask — exporting
// masked hosts would make a mixed-version rolling upgrade (new CP, old DPs)
// hard-block allowlisted platforms fleet-wide. New DPs lose nothing: their
// own allowlist (synced separately) masks these hosts at lookup anyway.
func (tf *Feed) ExportDomains() map[string]int64 {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	out := make(map[string]int64, len(tf.domains))
	for d, e := range tf.domains {
		if tf.domainAllowlist[d] {
			continue
		}
		out[d] = e.AddedAt.Unix()
	}
	return out
}

// ImportFeedData replaces the in-memory URL and domain maps with data received
// from the Control Plane config sync. Each value is a unix timestamp (added_at).
// The source is set to "cluster-sync" to distinguish from direct feed downloads.
func (tf *Feed) ImportFeedData(urls map[string]int64, domains map[string]int64) {
	newURLs := make(map[string]entry, len(urls))
	for u, ts := range urls {
		// Re-canonicalize keys from an older CP (Unicode hosts, trailing
		// dots) so exact-URL entries stay reachable by the canonicalized
		// CheckURL lookup; keep the original key when canonicalization
		// fails (fail-safe, mirrors loadFromDisk).
		if nu, _ := NormaliseURL(u); nu != "" {
			u = nu
		}
		newURLs[u] = entry{Source: "cluster-sync", AddedAt: time.Unix(ts, 0)}
	}
	newDomains := make(map[string]entry, len(domains))
	for d, ts := range domains {
		d = normaliseDomain(d)
		if d == "" {
			continue
		}
		newDomains[d] = entry{Source: "cluster-sync", AddedAt: time.Unix(ts, 0)}
	}
	tf.mu.Lock()
	tf.urls = newURLs
	tf.domains = newDomains
	tf.lastSync = time.Now()
	tf.mu.Unlock()
	tf.totalEntries.Store(int64(len(newURLs)))
}

// ── Test support ──────────────────────────────────────────────────────────────

// SeedForTest inserts URL and domain entries directly (value = source name),
// replacing the whitebox map pokes package main's integration tests used
// pre-extraction. AddedAt is stamped now; totalEntries tracks the URL count.
func (tf *Feed) SeedForTest(urls, domains map[string]string) {
	now := time.Now()
	tf.mu.Lock()
	for u, src := range urls {
		tf.urls[u] = entry{Source: src, AddedAt: now}
	}
	for d, src := range domains {
		tf.domains[d] = entry{Source: src, AddedAt: now}
	}
	total := int64(len(tf.urls))
	tf.mu.Unlock()
	tf.totalEntries.Store(total)
}

// SetDBPathForTest swaps the persistence path and returns the previous one.
// Test support for main-side durability tests that point the process-wide
// feed at a temp dir; pair the restore with ImportFeedData(nil, nil) to
// clear seeded data.
func (tf *Feed) SetDBPathForTest(path string) (old string) {
	tf.mu.Lock()
	old = tf.dbPath
	tf.dbPath = path
	tf.mu.Unlock()
	return old
}

// SetEnabledForTest toggles the feed's enabled flag and returns the previous
// value. Test support for main-side tests that assert CheckURL/CheckDomain
// verdicts on the process-wide feed: outside tests the flag is only set by
// Init, so a test that needs positive verdicts must enable the feed itself
// (and restore the old value in cleanup) instead of depending on whether an
// earlier test happened to run Init — that ordering dependence is exactly
// what the shuffle/determinism gate flags.
func (tf *Feed) SetEnabledForTest(enabled bool) (old bool) {
	tf.mu.Lock()
	old = tf.enabled
	tf.enabled = enabled
	tf.mu.Unlock()
	return old
}
