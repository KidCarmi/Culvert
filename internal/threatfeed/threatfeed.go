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

	"github.com/KidCarmi/Culvert/internal/feedsched"
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
	maskedHits      atomic.Int64 // domain hits suppressed by the allowlist (security-bypass observability)
	enabled         bool

	// failedSources is the BOUNDED classification of the most recent failure:
	// the names of the feeds that did not fetch cleanly, sorted and joined
	// ("urlhaus", "openphish", "urlhaus+openphish", "" when all fetched).
	//
	// It exists because lastSyncErr must NOT reach an alert. Alert dispatch
	// dedups on event+Detail, and lastSyncErr embeds an error string carrying
	// the feed URL and, for a transport failure, the ephemeral local port — so
	// a per-attempt-unique Detail defeats the dedup window by construction and
	// the fan-out evicts real threat alerts from the retry queue. The verbose
	// text stays on the role-gated admin API and in the log; the alert and the
	// metrics carry this three-valued class.
	failedSources string

	// consecutiveFailures counts sync rounds since the last fully-clean one.
	// Reset to zero by the first success. Drives the health plane's degraded
	// determination and is reported to the sync observer.
	consecutiveFailures int

	// totalFailures is the cumulative count of failed sync rounds since
	// process start — the MAGNITUDE that the rate-limited log line omits.
	totalFailures atomic.Int64

	// view is the lock-free read side of the three per-request lookups
	// (Enabled / CheckDomain / CheckURL). See readView.
	view atomic.Pointer[readView]
}

// readView is the immutable read-side projection of the feed, published under
// tf.mu and consumed WITHOUT any lock by Enabled, CheckDomain and CheckURL.
//
// Why it exists: CheckDomain runs on EVERY proxied request and CheckURL
// additionally on every plain-HTTP one, and both used to take tf.mu.RLock twice
// — once inside Enabled(), once for the map probe. sync.RWMutex.RLock is an
// atomic read-modify-write on a single shared word, so on a multi-core gateway
// every request was writing the same cache line three times (Enabled, plus the
// probe, plus secscan's own gate) purely to read tables that in steady state
// never change. That is not a constant cost, it is a THROUGHPUT CEILING:
// measured on a 4-core Xeon with 100k entries, CheckDomain cost 100 ns/op
// serial but 218 ns/op at 4x parallel — it got 2.2x SLOWER as cores were added,
// exactly when a gateway is busiest. Off the view it is 87 ns/op serial and
// 21 ns/op at 4x parallel: ~4x linear scaling, and 10x the old parallel figure.
//
// The contract that makes the lock-free read safe is simple and load-bearing:
//
//	A map reachable from a PUBLISHED readView is never mutated in place.
//
// Every writer that changes enabled / urls / domains / domainAllowlist installs
// a REPLACEMENT map (or a copy — see AddDomainAllowlist / RemoveDomainAllowlist
// / SeedForTest, which used to edit the live allowlist and now copy-then-swap)
// and calls publishLocked before releasing tf.mu. Readers therefore observe one
// self-consistent generation; the previous shape could straddle two, because it
// dropped the lock between the Enabled() check and the probe.
//
// The view ALIASES the maps rather than cloning them, so publishing is O(1) —
// a sync that replaces 500k entries pays one pointer store, not a second copy.
type readView struct {
	enabled   bool
	urls      map[string]entry
	domains   map[string]entry
	allowlist map[string]bool
}

// publishLocked republishes the read view from the current fields. Callers MUST
// hold tf.mu for WRITING; every mutator of enabled/urls/domains/domainAllowlist
// ends with this call, and TestReadView_EveryMutatorRepublishes pins that.
func (tf *Feed) publishLocked() {
	tf.view.Store(&readView{
		enabled:   tf.enabled,
		urls:      tf.urls,
		domains:   tf.domains,
		allowlist: tf.domainAllowlist,
	})
}

// readState returns the current read view. The nil branch materialises it on
// first use so a Feed assembled as a struct literal — the shape the package's
// whitebox tests build — still resolves; New() and every mutator publish
// eagerly, so production never reaches it after startup.
//
// That branch takes tf.mu, so readState (and therefore Enabled / CheckDomain /
// CheckURL) must not be called by in-package code that already holds the lock.
// Nothing does today; the lookups are called only from outside the package,
// where tf.mu is unreachable.
func (tf *Feed) readState() *readView {
	if v := tf.view.Load(); v != nil {
		return v
	}
	tf.mu.Lock()
	defer tf.mu.Unlock()
	if v := tf.view.Load(); v == nil {
		tf.publishLocked()
	}
	return tf.view.Load()
}

// New returns an idle Feed with the same shape as the pre-extraction
// package-main literal: initialised maps and the 6-hour default sync
// interval. Init configures and enables it.
func New() *Feed {
	tf := &Feed{
		urls:            make(map[string]entry),
		domains:         make(map[string]entry),
		domainAllowlist: make(map[string]bool),
		syncInterval:    6 * time.Hour,
	}
	tf.publishLocked() // no other reference exists yet; no lock needed
	return tf
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
	tf.publishLocked()
	tf.mu.Unlock()

	if dbPath != "" {
		if err := tf.loadFromDisk(dbPath); err != nil {
			obs.Printf("ThreatFeed: could not load persisted DB (%v) — will sync fresh", err)
		}
	}
}

// Backoff bounds for a failed sync round. See feedRetryRationale.
const (
	// syncRetryMin is the first retry delay after a failed round.
	syncRetryMin = 5 * time.Minute
	// syncRetryMax caps it. feedsched additionally clamps this to the
	// configured interval, so retrying can only tighten the cadence.
	syncRetryMax = 1 * time.Hour
)

// Start launches the background sync goroutine.
// An immediate sync is performed when the cache is empty or has never synced.
//
// The loop is a feedsched.Scheduler rather than a bare time.Ticker, and both
// halves of that change are load-bearing:
//
//   - BACKOFF. A ticker retried a failed round only after the FULL interval
//     (six hours by default). One transient fault on the customer's egress
//     path — a DNS blip, a 503 from the provider, a restarted upstream proxy —
//     therefore froze threat intelligence for six hours. The severe shape is
//     the cold start: needSync is true when the on-disk DB is empty, so a
//     fresh or re-imaged node whose FIRST sync fails serves with NO threat
//     intelligence at all (not stale — none) until that tick, while /health,
//     /ready and every metric report a completely healthy node. Retries are
//     now 5 min doubling to 1 h, reset on the first success.
//   - JITTER. A ticker fires at a fixed offset from process start, so nodes
//     that boot together stay in phase forever. The two feed origins are
//     public third-party endpoints shared by every Culvert deployment, and a
//     fleet syncing in lockstep is answered with rate-limiting of the
//     customer's egress IP — which then causes the very failure the absent
//     backoff would hold the fleet at for six hours.
func (tf *Feed) Start(ctx context.Context) {
	go feedsched.New(tf.schedulerConfig()).Run(ctx)
}

// schedulerConfig builds the feed's cadence configuration. Split out of Start
// so the cadence contract (backoff bounds below the interval, cold-start
// arming) is asserted directly instead of by driving a live loop against two
// third-party origins.
func (tf *Feed) schedulerConfig() feedsched.Config {
	return feedsched.Config{
		Name:       "threatfeed",
		Interval:   tf.SyncInterval,
		BackoffMin: syncRetryMin,
		BackoffMax: syncRetryMax,
		RunNow: func() bool {
			tf.mu.RLock()
			defer tf.mu.RUnlock()
			return tf.lastSync.IsZero() || tf.totalEntries.Load() == 0
		},
		// CHAOS-24: Sync parses third-party feed bodies (URLhaus/OpenPhish), so
		// its panic surface is attacker-adjacent input this operator does not
		// control. Guard the ROUND, not the goroutine: a bad feed pass costs
		// one sync, not the whole gateway, and the loop keeps running so the
		// next window can recover on its own. A panicked round is charged as a
		// FAILURE by the scheduler, so a systematically panicking body backs
		// off rather than retrying at speed.
		Run: func(context.Context) bool {
			var ok bool
			if obs.SafeCall("threatfeed", func() { ok = tf.syncRound() }) {
				return false
			}
			return ok
		},
	}
}

// SyncInterval reports the configured cadence between successful syncs.
func (tf *Feed) SyncInterval() time.Duration {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	return tf.syncInterval
}

// Sync downloads all configured feeds and atomically replaces the in-memory
// lookup tables. Safe to call concurrently; calls run sequentially.
//
// Retained as the void-returning entry point for the admin API's manual sync
// and for callers that do not schedule; syncRound carries the outcome the
// scheduler and the health plane need.
func (tf *Feed) Sync() { tf.syncRound() }

// syncRound performs one sync and reports whether EVERY configured feed
// fetched cleanly. A partial success is a failure for scheduling purposes: the
// sources that did fetch are installed (see applySync), but the round is
// retried on the backoff schedule because one source's coverage is now frozen.
func (tf *Feed) syncRound() bool {
	obs.Debugf("ThreatFeed: starting sync")
	newURLs := make(map[string]entry, 50_000)
	newDomains := make(map[string]entry, 20_000)
	var failures []string
	var failedSources []string
	replacedSources := make(map[string]bool, 2)

	if ok, fail := tf.fetchFeedInto(urlHausTextFeed, sourceURLhaus, "URLhaus", newURLs, newDomains); ok {
		replacedSources[sourceURLhaus] = true
	} else {
		failures = append(failures, fail)
		failedSources = append(failedSources, sourceURLhaus)
	}
	if ok, fail := tf.fetchFeedInto(openPhishFeed, sourceOpenPhish, "OpenPhish", newURLs, newDomains); ok {
		replacedSources[sourceOpenPhish] = true
	} else {
		failures = append(failures, fail)
		failedSources = append(failedSources, sourceOpenPhish)
	}

	outcome := tf.applySync(newURLs, newDomains, failures, replacedSources, time.Now(), failedSources...)

	obs.Printf("ThreatFeed: sync complete — %d unique URLs, %d unique domains", len(newURLs), len(newDomains))

	tf.mu.RLock()
	dbPath := tf.dbPath
	tf.mu.RUnlock()
	if dbPath != "" {
		if err := tf.saveToDisk(); err != nil {
			obs.Printf("ThreatFeed: save to disk failed: %v", err)
		}
	}

	notifySyncObserver(outcome)
	return outcome.OK
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
// The variadic failedSources carries the BOUNDED per-source classification
// (see Feed.failedSources). It is variadic purely so the package's existing
// whitebox tests, which call applySync with the original five arguments, keep
// compiling and keep asserting the carry-forward contract unchanged.
func (tf *Feed) applySync(newURLs, newDomains map[string]entry, failures []string, replacedSources map[string]bool, now time.Time, failedSources ...string) SyncOutcome {
	tf.mu.Lock()
	carryForward(newURLs, tf.urls, replacedSources)
	carryForward(newDomains, tf.domains, replacedSources)
	// AFTER carryForward: the carried-forward entries of a source that failed
	// this round are part of what the feed now serves, so counting before the
	// merge would under-report a partially-failed sync as an emptied feed.
	entries := int64(len(newURLs))
	tf.urls = newURLs
	tf.domains = newDomains
	tf.lastSync = now
	if len(failures) == 0 {
		tf.lastSuccess = now
		tf.lastSyncErr = ""
		tf.failedSources = ""
		tf.consecutiveFailures = 0
	} else {
		tf.lastSyncErr = strings.Join(failures, "; ")
		tf.failedSources = classifyFailedSources(failedSources)
		tf.consecutiveFailures++
		tf.totalFailures.Add(1)
	}
	outcome := SyncOutcome{
		OK:                  len(failures) == 0,
		FailedSources:       tf.failedSources,
		ConsecutiveFailures: tf.consecutiveFailures,
		LastSuccess:         tf.lastSuccess,
		SyncInterval:        tf.syncInterval,
		Entries:             entries,
	}
	tf.publishLocked()
	tf.mu.Unlock()
	tf.totalEntries.Store(entries)
	return outcome
}

// classifyFailedSources renders the bounded reason class. Sorted so the value
// is stable regardless of fetch order — an alert Detail that flipped between
// "urlhaus+openphish" and "openphish+urlhaus" would defeat its own dedup.
func classifyFailedSources(sources []string) string {
	if len(sources) == 0 {
		return ""
	}
	out := append([]string(nil), sources...)
	sort.Strings(out)
	return strings.Join(out, "+")
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
	// One lock-free read view for the whole lookup — see readView. Taking it
	// once also makes the verdict self-consistent: the previous shape released
	// the lock between the Enabled() probe and the table probe, so a concurrent
	// Sync could be observed half-applied.
	v := tf.readState()
	if !v.enabled {
		return false, ""
	}
	normURL, host := NormaliseURL(rawURL)

	if normURL != "" {
		if e, ok := v.urls[normURL]; ok {
			return true, e.Source
		}
	}
	if host != "" {
		if e, ok := v.domains[host]; ok {
			if v.allowlist[host] {
				// A real domain-level threat entry suppressed by the
				// allowlist — a security-control bypass, counted so an
				// operator can see the allowlist overriding live intel.
				tf.maskedHits.Add(1)
			} else {
				return true, e.Source
			}
		}
	}
	return false, ""
}

// CheckDomain looks up a bare hostname against the threat feed.
// Returns (isMalicious, sourceName).
func (tf *Feed) CheckDomain(domain string) (malicious bool, source string) {
	// Lock-free read view — see readView and the note in CheckURL.
	v := tf.readState()
	if !v.enabled {
		return false, ""
	}
	domain = normaliseDomain(domain)
	if domain == "" {
		return false, ""
	}

	e, ok := v.domains[domain]
	if !ok {
		return false, ""
	}
	if v.allowlist[domain] {
		// Suppressed by the allowlist — count the bypass (see CheckURL).
		tf.maskedHits.Add(1)
		return false, ""
	}
	return true, e.Source
}

// AllowlistMaskedTotal returns the cumulative count of domain-level threat
// hits suppressed by the domain allowlist since process start. A rising
// value means the allowlist is actively overriding live threat intel —
// worth an operator's attention (the exemption may be too broad, or an
// allowlisted platform is now hosting malware at the domain level).
func (tf *Feed) AllowlistMaskedTotal() int64 {
	return tf.maskedHits.Load()
}

// Enabled reports whether the feed is active. Lock-free: secscan calls it as a
// gate before CheckDomain/CheckURL, so it is on the same per-request path.
func (tf *Feed) Enabled() bool {
	return tf.readState().enabled
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

// ── Sync health ───────────────────────────────────────────────────────────────

// SyncOutcome is the result of one sync round, delivered to the observer
// registered by SetSyncObserver.
//
// FailedSources is the BOUNDED reason class — never a raw error string. See
// Feed.failedSources for why that distinction is load-bearing for the alert
// plane.
type SyncOutcome struct {
	OK                  bool
	FailedSources       string
	ConsecutiveFailures int
	LastSuccess         time.Time
	SyncInterval        time.Duration
	Entries             int64
}

// Health is a consistent snapshot of the feed's sync state, read by package
// main's health plane at scrape/diagnostics time.
type Health struct {
	// Configured is false until Init runs. Every surface reports "not
	// configured" rather than a zero in that case: a last-success of zero on a
	// node that never had the feed is indistinguishable from a node whose feed
	// has never once succeeded, and the two demand opposite operator actions.
	Configured          bool
	LastAttempt         time.Time
	LastSuccess         time.Time
	ConsecutiveFailures int
	TotalFailures       int64
	FailedSources       string
	ErrSummary          string
	SyncInterval        time.Duration
	Entries             int64
}

// Health returns the current sync-health snapshot.
func (tf *Feed) Health() Health {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	return Health{
		Configured:          tf.enabled,
		LastAttempt:         tf.lastSync,
		LastSuccess:         tf.lastSuccess,
		ConsecutiveFailures: tf.consecutiveFailures,
		TotalFailures:       tf.totalFailures.Load(),
		FailedSources:       tf.failedSources,
		ErrSummary:          tf.lastSyncErr,
		SyncInterval:        tf.syncInterval,
		Entries:             tf.totalEntries.Load(),
	}
}

// syncObserver receives every completed sync round. Published once at startup
// by package main (threatfeed_health.go), which owns the alert/metric plane —
// internal/* cannot import package main (ADR-0003), so this is the seam.
//
// A round is reported whether it succeeded or failed, because the RECOVERY
// edge matters as much as the failure edge: the health plane clears its
// degraded state on OBSERVED evidence (a clean round), never on elapsed time.
var syncObserver atomic.Pointer[func(SyncOutcome)]

// SetSyncObserver publishes the sync observer. A nil fn clears it.
func SetSyncObserver(fn func(SyncOutcome)) {
	if fn == nil {
		syncObserver.Store(nil)
		return
	}
	syncObserver.Store(&fn)
}

// notifySyncObserver delivers an outcome, panic-contained.
//
// Containment here is not decoration: the observer is package main's alert and
// metric plane, and a panic in it would otherwise be charged to the feed round
// by the scheduler's own recover — turning an observability bug into a feed
// that backs off and reports itself unhealthy. The observability plane must
// never be able to break the thing it observes.
//
// The observer MUST NOT call back into Sync (directly or transitively); the
// production observer only records state and fires an alert.
func notifySyncObserver(outcome SyncOutcome) {
	fn := syncObserver.Load()
	if fn == nil {
		return
	}
	defer func() {
		if v := recover(); v != nil {
			obs.Warnf("ThreatFeed: sync observer panicked (recovered): %s", obs.Sanitize(fmt.Sprint(v)))
		}
	}()
	(*fn)(outcome)
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

// cloneAllowlist returns a mutable copy of src (never nil), so an allowlist
// edit can be applied to a fresh map and swapped in rather than written into
// the map a published readView is already serving. See readView.
func cloneAllowlist(src map[string]bool) map[string]bool {
	out := make(map[string]bool, len(src)+1)
	for d, on := range src {
		out[d] = on
	}
	return out
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
	tf.publishLocked()
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
	// Copy-then-swap, NOT an in-place insert: the live map is aliased by the
	// published readView that CheckDomain/CheckURL read without a lock, so
	// writing into it would be a data race against every in-flight request.
	// Allowlist edits are admin-rate, the map is tens of entries.
	next := cloneAllowlist(tf.domainAllowlist)
	next[domain] = true
	tf.domainAllowlist = next
	tf.publishLocked()
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
	// Copy-then-swap for the same reason as AddDomainAllowlist.
	next := cloneAllowlist(tf.domainAllowlist)
	delete(next, domain)
	tf.domainAllowlist = next
	tf.publishLocked()
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
	tf.publishLocked()
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
	tf.publishLocked()
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
	// Copy-then-swap, matching the readView contract the production writers
	// obey — an in-place insert into the map a published view already serves
	// would race any concurrent lookup (and the race detector would say so).
	newURLs := make(map[string]entry, len(tf.urls)+len(urls))
	for u, e := range tf.urls {
		newURLs[u] = e
	}
	for u, src := range urls {
		newURLs[u] = entry{Source: src, AddedAt: now}
	}
	newDomains := make(map[string]entry, len(tf.domains)+len(domains))
	for d, e := range tf.domains {
		newDomains[d] = e
	}
	for d, src := range domains {
		newDomains[d] = entry{Source: src, AddedAt: now}
	}
	tf.urls = newURLs
	tf.domains = newDomains
	total := int64(len(tf.urls))
	tf.publishLocked()
	tf.mu.Unlock()
	tf.totalEntries.Store(total)
}

// SeedSyncSuccessForTest records a clean sync round at t, without performing
// any fetch. Test support for package main's staleness plane, which reads this
// feed's Health() snapshot: driving it through a real Sync would require two
// reachable third-party origins and a 60-second-per-feed timeout budget.
func (tf *Feed) SeedSyncSuccessForTest(t time.Time) {
	tf.mu.Lock()
	tf.lastSync = t
	tf.lastSuccess = t
	tf.lastSyncErr = ""
	tf.failedSources = ""
	tf.consecutiveFailures = 0
	tf.mu.Unlock()
}

// SeedSyncFailureForTest records a failed sync round with the given bounded
// source class. Counterpart to SeedSyncSuccessForTest.
func (tf *Feed) SeedSyncFailureForTest(failedSources string) {
	tf.mu.Lock()
	tf.lastSyncErr = "seeded test failure"
	tf.failedSources = failedSources
	tf.consecutiveFailures++
	tf.totalFailures.Add(1)
	tf.mu.Unlock()
}

// republishForTest re-publishes the read view after a whitebox field poke —
// an in-package test assigning tf.urls / tf.domains / tf.enabled directly
// instead of going through a mutator. Production code never needs it: every
// mutator publishes for itself before releasing tf.mu.
func (tf *Feed) republishForTest() {
	tf.mu.Lock()
	tf.publishLocked()
	tf.mu.Unlock()
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
	tf.publishLocked()
	tf.mu.Unlock()
	return old
}
