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
// that is due. The scheduler is ALWAYS started at startup — feeds added later
// via the admin API are picked up on the next tick without a restart.
//
// # CHAOS-108: the fourth feed loop
//
// internal/feedsched exists to fix two named failure modes in Culvert's
// periodic feeds — "a failed round is not retried until the next full
// interval" and "a fleet stays in phase forever" — and its package doc
// enumerates THREE feed loops. This was the fourth, and it had both defects
// plus the sharper version of the first:
//
//   - A failed sync stamped the attempt time and the due-check gated on it, so
//     ANY transient failure (DNS blip, a 503 from the origin, a connection
//     reset, a TLS error) pushed the next attempt a FULL interval away —
//     DefaultInterval, 24 hours, on a stock install. Nothing retried in
//     between. The worst shape is the boot pass: the immediate round runs
//     because no attempt has been recorded, so a node that boots into a feed
//     outage merges NO domains from that feed — not stale entries, none — and
//     does not try again for a day. The blocklist is a deny control, so that
//     window is fail-open on exactly the destinations the operator configured
//     the feed to block.
//   - The cadence carried no jitter and its phase was pinned at boot, so nodes
//     that boot together (rolling upgrade, compose restart, a hypervisor
//     recovering a rack) sync together against a third-party origin forever.
//     That closes the same loop feedsched's doc describes: the herd provokes
//     the rate-limit, and the absent retry then holds the whole fleet at that
//     failure for the full interval.
//   - The fetch was parented to context.Background(), so shutdown could not
//     interrupt an in-flight sync.
//
// The fix reuses the OWNER's ladder rather than growing a second one: each
// feed holds a feedsched.Scheduler used purely as a delay calculator
// (NextDelay), which brings bounded exponential backoff, the interval-aware
// floor/ceiling clamp that keeps retrying a strict TIGHTENING of the cadence,
// and a stable per-feed jitter offset. The single shared tick is kept, so a
// feed added through the admin API is still picked up within one tick and no
// goroutine is created per feed.
//
// NOT fixed here, and recorded as the open half: this feed still has no
// staleness alert or health row. internal/threatfeed has both (a
// threat_feed_stale alert, plus a deferred startup variant); a blocklist feed
// that has never synced, or is arbitrarily stale, raises neither and is
// visible only as LastError in the admin API and one log line per attempt.
// Adding an alert type is an owner decision with GUI/API parity consequences,
// not a drive-by rider on a scheduling fix.
package blocklistfeed

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/feedsched"
	"github.com/KidCarmi/Culvert/internal/obs"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

const (
	httpTimeout = 30 * time.Second

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

// feedState is the internal mutable state of one feed. Every field is
// read and written under Syncer.mu.
type feedState struct {
	interval    time.Duration
	lastSync    time.Time
	lastAttempt time.Time // last round, success or failure (zero = never)
	// nextAttempt is the earliest next AUTO sync: lastAttempt plus the delay
	// the ladder returned for that round's outcome. Zero means "never
	// attempted", which is due immediately — that is what makes the boot pass
	// run. It replaced the old lastAttempt+interval gate, whose effect was
	// that a FAILED round waited a full interval (CHAOS-108).
	nextAttempt   time.Time
	lastError     string
	importedCount int64

	// sched owns this feed's retry ladder and its stable jitter offset. It is
	// used purely as a DELAY CALCULATOR (feedsched.Scheduler.NextDelay), never
	// as a running loop: the Syncer keeps its single shared tick, so a feed
	// added through the admin API is still picked up within one tick and no
	// goroutine is created per feed. Lazily built by scheduleNextLocked.
	sched *feedsched.Scheduler
}

// Syncer downloads and merges remote domain feeds into a Merger.
// The zero value is safe for all methods (feeds map is lazily initialized).
type Syncer struct {
	bl    Merger
	mu    sync.RWMutex
	feeds map[string]*feedState // keyed by feed URL

	// now and jitter are test seams, nil in production (see timeNow and
	// newFeedScheduler). They exist so the cadence contract — backoff growth,
	// the interval clamp, fleet spread — is asserted against a fake clock
	// without sleeping, the way internal/feedsched's own tests do.
	now    func() time.Time
	jitter func(time.Duration) time.Duration
}

// timeNow reads the clock through the test seam.
func (bs *Syncer) timeNow() time.Time {
	if bs.now != nil {
		return bs.now()
	}
	return time.Now()
}

// newFeedScheduler builds the delay calculator for one feed.
//
// Interval is a function so an admin edit to the cadence is re-read on every
// round instead of being frozen here — and feedsched re-reads it to clamp the
// backoff floor AND ceiling to the live interval, which is what keeps a retry
// strictly faster than a healthy node's sync (see feedsched.backoffBounds).
func (bs *Syncer) newFeedScheduler(st *feedState) *feedsched.Scheduler {
	return feedsched.New(feedsched.Config{
		Name: "blocklistfeed",
		// Reads st.interval WITHOUT taking bs.mu: NextDelay is only ever
		// called from scheduleNextLocked, whose caller holds the lock, and
		// st.interval is only mutated under that same lock. Taking it here
		// would deadlock — sync.RWMutex is not reentrant.
		Interval: func() time.Duration { return st.interval },
		// nil in production, so feedsched draws one StableJitter offset per
		// feed: spread across the fleet and across this node's own feeds,
		// chosen once rather than re-rolled per tick.
		Jitter: bs.jitter,
	})
}

// scheduleNextLocked charges the round to the feed's ladder and sets the
// earliest next auto-sync. Returns the delay it applied, for the caller's log
// line. Caller MUST hold bs.mu: NextDelay mutates the per-feed consecutive-
// failure count and reads st.interval, and neither is otherwise synchronized
// against a concurrent admin-API sync of the same feed.
//
// A feed with auto-sync disabled (interval <= 0) is still stamped; dueURLs
// skips it on the interval check, so the value is inert until auto-sync is
// re-enabled, at which point SetFeed re-derives it.
func (bs *Syncer) scheduleNextLocked(st *feedState, ok bool) time.Duration {
	if st.sched == nil {
		st.sched = bs.newFeedScheduler(st)
	}
	d := st.sched.NextDelay(ok)
	st.nextAttempt = st.lastAttempt.Add(d)
	return d
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
		setFeedIntervalLocked(st, interval)
		return
	}
	bs.feeds[feedURL] = &feedState{interval: interval}
}

// setFeedIntervalLocked re-intervals an existing feed, keeping the pending
// next-attempt honest about the new cadence. Caller holds Syncer.mu.
//
// The gate this replaced was lastAttempt+interval, recomputed on every tick,
// so SHORTENING the cadence took effect immediately. nextAttempt is absolute,
// so without this the feed would sit on a wait derived from the interval the
// operator just replaced. The pending wait is only ever pulled IN, never
// pushed out: when a backoff delay is already sooner than the new interval —
// the failing case — it stays, so re-intervalling can never slow a retry down.
func setFeedIntervalLocked(st *feedState, interval time.Duration) {
	if st.interval == interval {
		return
	}
	st.interval = interval
	if st.lastAttempt.IsZero() || interval <= 0 {
		return
	}
	if due := st.lastAttempt.Add(interval); due.Before(st.nextAttempt) {
		st.nextAttempt = due
	}
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
	round := func() { bs.syncDue(ctx) }
	go func() {
		// CHAOS-24: syncDue fetches and merges operator-configured remote
		// blocklists. Guard the ROUND so one bad feed body costs a tick, not
		// the process; the scheduler keeps waking and retries the next window.
		//
		// CHAOS-108: ctx now reaches the fetch, so shutdown interrupts an
		// in-flight sync instead of waiting out httpTimeout. A panicking
		// round is still charged as a failed round by scheduleNextLocked's
		// caller only when it gets that far; a panic BEFORE the stamp leaves
		// nextAttempt unchanged, so the next tick retries — the pre-existing
		// "costs a tick, not the process" posture, unchanged.
		obs.SafeCall("blocklistfeed", round)
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(tickInterval):
				obs.SafeCall("blocklistfeed", round)
			}
		}
	}()
}

// syncDue syncs every feed that is due, stopping promptly on cancellation so
// a shutdown does not start further fetches.
func (bs *Syncer) syncDue(ctx context.Context) {
	for _, feedURL := range bs.dueURLs(bs.timeNow()) {
		if ctx.Err() != nil {
			return
		}
		_, _ = bs.SyncFeedContext(ctx, feedURL)
	}
}

// dueURLs lists the feeds whose next-attempt time has arrived: auto-sync
// enabled (interval > 0) and either never attempted or past nextAttempt.
// Sorted, so a round's order is deterministic for tests and log reading.
func (bs *Syncer) dueURLs(now time.Time) []string {
	bs.mu.RLock()
	defer bs.mu.RUnlock()
	var due []string
	for feedURL, st := range bs.feeds {
		if st.interval <= 0 {
			continue
		}
		if st.nextAttempt.IsZero() || !now.Before(st.nextAttempt) {
			due = append(due, feedURL)
		}
	}
	sort.Strings(due)
	return due
}

// SyncFeed fetches one feed by URL and merges new domains into the blocklist.
// Returns the number of new domains added and any error encountered. The
// feed's status fields are updated either way.
//
// Deliberately NOT parented to the caller's request context: this is the
// manual "Sync Now" path, and an operator who clicks it and then navigates
// away must not abort the fetch. The SCHEDULER path uses SyncFeedContext so
// shutdown can interrupt it.
func (bs *Syncer) SyncFeed(feedURL string) (int, error) {
	return bs.SyncFeedContext(context.Background(), feedURL)
}

// SyncFeedContext is SyncFeed with a caller-supplied context, used by the
// scheduler so a shutdown interrupts an in-flight fetch rather than waiting
// out httpTimeout (CHAOS-108).
func (bs *Syncer) SyncFeedContext(ctx context.Context, feedURL string) (int, error) {
	bs.mu.RLock()
	_, known := bs.feeds[feedURL]
	bs.mu.RUnlock()
	if !known {
		return 0, fmt.Errorf("feed not configured: %s", feedURL)
	}

	lines, err := bs.fetchFeedLines(ctx, feedURL)

	bs.mu.Lock()
	st, still := bs.feeds[feedURL]
	if !still { // removed while the fetch was in flight
		bs.mu.Unlock()
		return 0, nil
	}
	st.lastAttempt = bs.timeNow()
	// CHAOS-108: charge the round to the ladder BEFORE branching, so the
	// failure path gets bounded backoff instead of a full interval. The old
	// code stamped only the attempt time, and the due-check read it against
	// the interval — which meant one 503 bought the origin a day of silence.
	delay := bs.scheduleNextLocked(st, err == nil)
	if err != nil {
		st.lastError = err.Error()
		failures := st.sched.Failures()
		bs.mu.Unlock()
		// Neither the error nor any request-derived value reaches this sink:
		// the URL is operator-configured and sanitized with %q, and the
		// remaining values are a count and a duration computed here. The
		// error detail is already logged, at its own sink, by fetchFeedLines.
		obs.Printf("BlocklistFeed: sync %q failed (%d consecutive) — retrying in %s, not at the configured interval",
			obs.Sanitize(feedURL), failures, delay.Round(time.Second))
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

// SyncAll syncs every configured feed (manual "Refresh All Now"), regardless
// of interval. Returns the total domains added and the first error encountered.
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
func (bs *Syncer) fetchFeedLines(ctx context.Context, feedURL string) ([]string, error) {
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

	// Derived from the caller's context (the scheduler's lifecycle ctx, or
	// Background for a manual sync), so httpTimeout still bounds the fetch
	// while cancellation can also end it early.
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
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

	// CHAOS-108: the status gate both sibling feeds already have
	// (internal/threatfeed, internal/feedsync). Without it this loop's notion
	// of success was "the transport returned bytes", not "the origin served
	// the feed", with two consequences:
	//
	//   - The error page was MERGED. blocklist.NormalizeLine takes fields[0]
	//     of any line, so "upstream down" lists the host "upstream" and an
	//     HTML body lists "<html>" — merge-only entries, attributed to this
	//     feed, saved to disk and never removed. A deny control's durable
	//     state took dictation from whatever answered the URL.
	//   - The round was recorded as a SUCCESS: lastSync advanced and
	//     lastError cleared, so an origin that has served 503 for a week
	//     reported "synced just now, no error" — and would reset the retry
	//     ladder added above, so backoff would never engage for the single
	//     most common feed outage mode.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, feedURL)
	}

	var lines []string
	// CHAOS-109: read under a byte budget. A spent budget must NOT look like a
	// clean end of body, or an origin that overran it would be recorded as a
	// successful short feed — the same "success meant the transport returned
	// bytes" mistake CHAOS-108 fixed one layer up.
	scanner := bufio.NewScanner(&boundedReader{r: resp.Body, what: "feed body", limit: maxFeedBodyBytes})
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
		if len(lines) >= maxFeedLines {
			obs.Printf("BlocklistFeed: line cap of %d reached for %q; this round is TRUNCATED. Already merged hosts are unaffected (the merge never deletes).", maxFeedLines, obs.Sanitize(feedURL))
			return lines, nil
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

// boundedReader fails the read once more than limit bytes have been consumed,
// naming which budget was spent. io.LimitReader is deliberately not used: it
// reports a spent budget as a clean io.EOF, which bufio.Scanner would report as
// a complete body — so an origin that overran the budget would be recorded as a
// successful short feed and merged. The error path is the whole point.
// errBudgetExceeded marks a spent byte budget, so a caller can tell an origin
// that overran its budget from a transport that simply ended.
var errBudgetExceeded = errors.New("feed byte budget exceeded")

type boundedReader struct {
	r     io.Reader
	what  string
	limit int64
	read  int64
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.read > b.limit {
		return 0, b.exceeded()
	}
	if b.read == b.limit {
		return b.probeBoundary()
	}
	if over := b.read + int64(len(p)) - b.limit; over > 0 {
		p = p[:int64(len(p))-over]
	}
	n, err := b.r.Read(p)
	b.read += int64(n)
	return n, err
}

// probeBoundary decides a spent budget by evidence rather than by position. A
// body of EXACTLY limit bytes is within budget, but its final read need not
// carry io.EOF: a chunked response that flushes its last payload before the
// terminating chunk returns the data with a nil error and io.EOF only on the
// next call. Treating that next call as an overrun rejected a valid feed at
// the boundary on every round (Codex review, PR #1796). So read ONE more byte:
// a clean io.EOF is a complete body, a real byte is the overrun, and any other
// outcome (a transport error, or a no-progress (0, nil)) is passed through.
func (b *boundedReader) probeBoundary() (int, error) {
	var one [1]byte
	n, err := b.r.Read(one[:])
	if n > 0 {
		b.read += int64(n)
		return 0, b.exceeded()
	}
	return 0, err
}

func (b *boundedReader) exceeded() error {
	return fmt.Errorf("%s exceeded its %d-byte budget: %w", b.what, b.limit, errBudgetExceeded)
}

// The CHAOS-109 ingest budgets are var, not const, so the bound gates can
// lower them: a gate that had to move 64 MiB to prove the budget engages is a
// gate that gets skipped. Production never assigns these; gates restore them
// through t.Cleanup.
var (
	// maxFeedBodyBytes bounds what the ORIGIN may send for one feed, and it is
	// a heap bound, not a courtesy: every non-empty line is RETAINED in the
	// returned slice, so before this the live cost of a round was
	// "httpTimeout (30s) x link speed", with no ceiling of any kind. The
	// sibling loops already bound their retention — internal/threatfeed caps
	// accepted lines at maxFeedLines "to limit memory usage",
	// internal/saasfeed reads under a 10 MB io.LimitReader — and this loop was
	// the one with neither (CHAOS-109; recorded as open in CHAOS-108 §8.3).
	// 64 MiB is ~10x a large combined host list. Exceeding it FAILS the round,
	// so the last-good merged blocklist stays authoritative.
	maxFeedBodyBytes int64 = 64 << 20

	// maxFeedLines bounds accepted lines independently of the byte budget, and
	// matches internal/threatfeed's cap of the same name so the two loops agree
	// on the posture. Reaching it TRUNCATES rather than failing: the merge is
	// merge-only and persisted, so a short round adds fewer new hosts and
	// removes none.
	maxFeedLines = 1_000_000
)
