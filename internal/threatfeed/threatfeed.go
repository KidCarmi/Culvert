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
	"math/rand"
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
	LastSuccess time.Time `json:"last_success,omitempty"`
	// LastRefresh is the last round in which AT LEAST ONE source replaced its
	// entries — i.e. the age of the intelligence actually being served. It is
	// deliberately distinct from LastSuccess, which requires EVERY source to
	// have fetched cleanly. One of two free public feeds 403ing indefinitely
	// is an ordinary steady state, not an incident, and keying freshness on
	// LastSuccess would report a feed whose other source refreshes on every
	// window as permanently stale (Codex review, PR #1264). LastSuccess keeps
	// its original meaning because SyncStatus() and the admin surfaces
	// document and consume it.
	//
	// omitempty + the loadFromDisk back-fill keep legacy DBs (written before
	// this field existed) loading as "LastSuccess was the last refresh",
	// which is exactly true for them.
	LastRefresh time.Time        `json:"last_refresh,omitempty"`
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
	lastRefresh     time.Time // time of the most recent sync where AT LEAST ONE feed replaced its entries — the age of the served intelligence
	lastSyncErr     string    // summary of the most recent failure(s); empty when the last sync fully succeeded
	totalEntries    atomic.Int64
	maskedHits      atomic.Int64 // domain hits suppressed by the allowlist (security-bypass observability)
	enabled         bool

	// consecutiveFailures counts sync rounds that brought in NOTHING — no
	// feed replaced its entries. It is deliberately not "any failure": with
	// two feeds, one of them 403ing indefinitely (which is the ordinary
	// steady state of a free public feed) would otherwise hold the retry
	// cadence at its floor forever, aiming a fleet at a service that is
	// already refusing it. A round that refreshed at least one source did
	// its job; only a round that refreshed none is a failure to retry.
	// Process-lifetime, not persisted: the retry cadence is a runtime
	// decision, and the durable record of "how long since fresh data" is
	// lastSuccess, which IS persisted.
	consecutiveFailures int

	// syncObserver is called after every completed sync round (and once at
	// startup when the boot round is skipped). It is the seam the freshness
	// alert plane hangs off in package main — this package deliberately
	// knows nothing about alerts, metrics or diagnostics.
	syncObserver func()

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

// Feed origins. These are vars rather than consts for ONE reason: without a
// seam, the only way to exercise Sync is to let the test suite fetch the real
// URLhaus and OpenPhish endpoints — two 60-second timeouts per run on a CI
// runner with no egress, and a request to a free public service on every
// invocation. A change whose whole subject is not hammering those feeds must
// not hammer them from CI. They are never reassigned in production; the
// in-package test seam is swapFeedURLsForTest.
var (
	urlHausTextFeed = "https://urlhaus.abuse.ch/downloads/text/"
	openPhishFeed   = "https://openphish.com/feed.txt"
)

const (
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

// Scheduling constants for the background sync loop (CHAOS-57).
const (
	// syncJitterFrac spreads every scheduled sync by ±10% so a fleet that
	// booted together does not stay phase-locked against a free public
	// service for the life of the deployment. Same fraction, and the same
	// reasoning, as the release-catalog refresh loop.
	syncJitterFrac = 0.10

	// syncRetryInitial / syncRetryMax bound the cadence of the retry that
	// follows a round which fetched NOTHING. Before CHAOS-57 there was no
	// retry at all: the next attempt was one full syncInterval away, so a
	// 30-second resolver blip landing on the tick cost six hours of frozen
	// threat intelligence. The retry is bounded in RATE and never in
	// ATTEMPTS — a feed that is down for a day must still be picked up the
	// minute it returns — which is the same posture the HA lease recovery
	// loop settled on, and it is not a hidden retry: every attempt logs its
	// outcome and the failure count is on /metrics.
	syncRetryInitial = 5 * time.Minute
	syncRetryMax     = 30 * time.Minute

	// bootResyncFloor is the anti-hammer floor on the freshness-triggered
	// boot sync. Stale data justifies fetching at startup; a process that
	// is crash-looping must not turn that into a request per restart, so a
	// boot sync is skipped when the previous ATTEMPT (success or failure,
	// which is what lastSync records and persists) is more recent than
	// this.
	bootResyncFloor = 15 * time.Minute
)

// Start launches the background sync goroutine.
//
// An immediate sync is performed when the cache is empty, has never synced, or
// is STALE — the last of which is the CHAOS-57 fix. The previous condition was
// `lastSync.IsZero() || totalEntries == 0`, and because lastSync is restored
// from the persisted DB, an appliance that had been powered off for three
// weeks came up holding three-week-old malware intelligence and skipped its
// boot sync precisely BECAUSE it had data — then served that data for another
// full interval. Restart is the operator's remedy for a stale feed, and it
// made a fresh install strictly better off than a recovered one. This is the
// same shape as the CHAOS-28 finding in StartCAAutoRotation, whose first check
// at +24h skipped exactly the restart an operator makes to recover.
//
// The new condition is a strict superset of the old one (lastSync.IsZero()
// implies lastSuccess.IsZero() — loadFromDisk only back-fills lastSuccess FROM
// lastSync), so the loop can only ever sync at least as often as before.
func (tf *Feed) Start(ctx context.Context) {
	go tf.runSyncLoop(ctx, time.Now())
}

// bootDecision is why runSyncLoop did or did not fetch at startup. The reason
// matters, not just the verdict: a fetch skipped because the data is FRESH
// should wait a full interval, but a fetch skipped because of the crash-loop
// floor should be retried the moment that floor expires — otherwise the floor,
// which is meant to defer a fetch by at most bootResyncFloor, silently defers
// it by a whole syncInterval instead (Codex review, PR #1264).
type bootDecision int

const (
	bootFetchNow  bootDecision = iota // stale or empty: fetch immediately
	bootDataFresh                     // within one interval of a refresh: normal cadence
	bootFloored                       // stale, but we attempted too recently
)

// runSyncLoop is Start's body, split out so tests can drive it directly with a
// controlled "now" and a cancellable context.
func (tf *Feed) runSyncLoop(ctx context.Context, now time.Time) {
	// CHAOS-24: Sync parses third-party feed bodies (URLhaus/OpenPhish), so
	// its panic surface is attacker-adjacent input this operator does not
	// control. Guard the ROUND, not the goroutine: a bad feed pass costs
	// one sync, not the whole gateway, and the loop keeps running so the
	// next window can recover on its own.
	decision, floorLeft := tf.bootSyncDecision(now)
	if decision == bootFetchNow {
		obs.SafeCall("threatfeed", tf.Sync)
	} else {
		// No boot fetch, but the freshness plane must still be evaluated
		// once at startup — otherwise an appliance that comes up holding
		// data too old to be useful stays silent until the first tick.
		// Mirrors evaluateSaaSFeedStartupAlerts / the release-catalog
		// startup stale evaluation.
		tf.notifySyncObserver()
	}

	timer := time.NewTimer(tf.firstDelay(decision, floorLeft))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			obs.SafeCall("threatfeed", tf.Sync)
			timer.Reset(tf.nextSyncDelay())
		}
	}
}

// firstDelay is the wait before the FIRST scheduled attempt. It is the normal
// jittered cadence except after a floored boot, where waiting a full interval
// would leave stale intelligence frozen for a whole window because
// consecutiveFailures is process-local and resets to zero on restart — so the
// retry path that would otherwise shorten this wait is not yet armed.
func (tf *Feed) firstDelay(decision bootDecision, floorLeft time.Duration) time.Duration {
	d := tf.nextSyncDelay()
	if decision == bootFloored && floorLeft > 0 && floorLeft < d {
		return jitterDuration(floorLeft, syncJitterFrac)
	}
	return d
}

// needBootSync reports whether to fetch immediately at startup. Retained as the
// boolean form for readability at the call sites that do not care WHY.
func (tf *Feed) needBootSync(now time.Time) bool {
	d, _ := tf.bootSyncDecision(now)
	return d == bootFetchNow
}

// bootSyncDecision decides whether to fetch immediately at startup, and when
// the decision is bootFloored also returns how long is left on the floor.
//
// Freshness is measured against lastRefresh — the last round that brought in
// entries from ANY source — not lastSuccess, which requires EVERY source to
// have fetched cleanly. With one of two free public feeds 403ing indefinitely
// (an ordinary steady state, and the exact case consecutiveFailures is
// deliberately narrow about) lastSuccess never advances at all, so keying on
// it would force a fetch on every single restart while the node in fact holds
// intelligence refreshed on the last window — the crash-loop hammering this
// floor exists to prevent (Codex review, PR #1264).
func (tf *Feed) bootSyncDecision(now time.Time) (bootDecision, time.Duration) {
	tf.mu.RLock()
	lastRefresh, lastAttempt, interval := tf.lastRefresh, tf.lastSync, tf.syncInterval
	tf.mu.RUnlock()

	// Nothing usable on disk: fetch, exactly as before this change.
	if tf.totalEntries.Load() == 0 || lastRefresh.IsZero() {
		return bootFetchNow, 0
	}
	// Fresh enough to serve: the scheduled cadence is sufficient. A node
	// restarted ten minutes after a refresh must NOT refetch — that is the
	// direction that builds a thundering herd out of a rolling upgrade.
	if now.Sub(lastRefresh) < interval {
		return bootDataFresh, 0
	}
	// Stale. Fetch, unless we already attempted recently (crash-loop floor).
	if since := now.Sub(lastAttempt); since < bootResyncFloor {
		return bootFloored, bootResyncFloor - since
	}
	return bootFetchNow, 0
}

// nextSyncDelay returns the jittered wait before the next scheduled sync: the
// configured interval after a round that fetched something, an exponentially
// backed-off retry after a round that fetched nothing. The retry is clamped to
// the interval so a deployment configured with a short interval never has its
// cadence SLOWED by the retry path.
func (tf *Feed) nextSyncDelay() time.Duration {
	tf.mu.RLock()
	interval, fails := tf.syncInterval, tf.consecutiveFailures
	tf.mu.RUnlock()
	return jitterDuration(retryDelay(interval, fails), syncJitterFrac)
}

// retryDelay is nextSyncDelay's pure core (jitter-free, so it is exactly
// testable).
func retryDelay(interval time.Duration, consecutiveFailures int) time.Duration {
	if consecutiveFailures <= 0 {
		return interval
	}
	d := syncRetryInitial
	for i := 1; i < consecutiveFailures && d < syncRetryMax; i++ {
		d *= 2
	}
	if d > syncRetryMax {
		d = syncRetryMax
	}
	if d > interval {
		d = interval
	}
	return d
}

// jitterDuration spreads d by ±frac so a fleet sharing a boot time does not
// converge on one cadence against a shared third-party feed.
func jitterDuration(d time.Duration, frac float64) time.Duration {
	if d <= 0 || frac <= 0 {
		return d
	}
	span := float64(d) * frac
	off := (rand.Float64()*2 - 1) * span // #nosec G404 -- fleet spread, not crypto
	out := d + time.Duration(off)
	if out < time.Millisecond {
		out = time.Millisecond
	}
	return out
}

// SetSyncObserver installs the callback invoked after every completed sync
// round, and once at startup when the boot round is skipped. Package main
// wires the freshness alert/metric evaluation through it; this package stays
// free of any dependency on that plane. Not safe to call concurrently with a
// running loop — it is a startup wiring call.
func (tf *Feed) SetSyncObserver(fn func()) {
	tf.mu.Lock()
	tf.syncObserver = fn
	tf.mu.Unlock()
}

// notifySyncObserver invokes the observer with the lock RELEASED. The observer
// reads the feed's own status accessors (Stats / SyncStatus / SyncFailures),
// every one of which takes tf.mu — calling it under the lock would deadlock on
// a non-reentrant RWMutex, which is the CHAOS-50 cluster-CA defect exactly.
func (tf *Feed) notifySyncObserver() {
	tf.mu.RLock()
	fn := tf.syncObserver
	tf.mu.RUnlock()
	if fn != nil {
		fn()
	}
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

	// Last, and outside every lock: let the freshness plane re-evaluate. This
	// runs for the admin's manual "sync now" too, so a successful manual sync
	// clears a stale alert immediately instead of at the next tick.
	tf.notifySyncObserver()
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
	// A round that replaced NO source brought in nothing at all — that is the
	// condition the retry cadence and the sync-failing alert key on. A round
	// where one of two feeds succeeded refreshed real intelligence and is not
	// charged as a failure (see the consecutiveFailures field comment).
	//
	// lastRefresh moves on exactly that same condition, and that pairing is
	// load-bearing: keying freshness on lastSuccess instead would contradict
	// this very rule, reporting a feed whose surviving source refreshes every
	// window as permanently stale for as long as the other one 403s.
	if len(replacedSources) == 0 {
		tf.consecutiveFailures++
	} else {
		tf.consecutiveFailures = 0
		tf.lastRefresh = now
	}
	tf.publishLocked()
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

// ConsecutiveFailures returns the number of sync rounds in a row that replaced
// NO source — i.e. that brought in no fresh intelligence at all. It is the
// signal the freshness alert plane trips on, and it is deliberately narrower
// than "the last sync reported an error": see the field comment.
func (tf *Feed) ConsecutiveFailures() int {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	return tf.consecutiveFailures
}

// Freshness is the single self-consistent read of everything the freshness
// plane needs. Composing it from Stats + SyncStatus + ConsecutiveFailures
// would take tf.mu three times and could straddle a concurrent applySync,
// reporting (for example) a fresh lastSuccess alongside the failure count that
// preceded it — the half-applied read the readView contract exists to
// prevent on the request path.
//
// A zero lastSuccess means "never fetched successfully", which the caller must
// distinguish from "fetched successfully at the Unix epoch": staleness is not
// computable from it, and an unconfigured feed must not be reported as
// infinitely stale (the CHAOS-54 rule — a zero on a node that never had the
// feature is indistinguishable from a broken one).
func (tf *Feed) Freshness() FreshnessSnapshot {
	tf.mu.RLock()
	defer tf.mu.RUnlock()
	return FreshnessSnapshot{
		Enabled:             tf.enabled,
		Entries:             tf.totalEntries.Load(),
		LastAttempt:         tf.lastSync,
		LastSuccess:         tf.lastSuccess,
		LastRefresh:         tf.lastRefresh,
		LastErr:             tf.lastSyncErr,
		ConsecutiveFailures: tf.consecutiveFailures,
		SyncInterval:        tf.syncInterval,
	}
}

// FreshnessSnapshot is one consistent view of the feed's sync health.
type FreshnessSnapshot struct {
	Enabled     bool
	Entries     int64
	LastAttempt time.Time // most recent attempt, success or failure
	LastSuccess time.Time // most recent round where EVERY feed fetched cleanly; zero = never
	// LastRefresh is the most recent round where AT LEAST ONE feed replaced
	// its entries — the age of the intelligence actually being served, and
	// therefore the field staleness must be computed from. See the feedDB
	// field comment for why this is not LastSuccess.
	LastRefresh         time.Time
	LastErr             string // summary of the most recent failure(s)
	ConsecutiveFailures int
	SyncInterval        time.Duration
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
	// LastRefresh back-fill: a DB written before the field existed recorded
	// only fully-clean rounds, so its LastSuccess IS its last refresh. Never
	// weaker than the value it replaces — a legacy DB can only be reported as
	// exactly as fresh as it already claimed to be.
	if !db.LastRefresh.IsZero() {
		tf.lastRefresh = db.LastRefresh
	} else {
		tf.lastRefresh = tf.lastSuccess
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
		LastRefresh:     tf.lastRefresh,
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
