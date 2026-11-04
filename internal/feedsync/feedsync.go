// Package feedsync is the UT1 URL-category feed syncer: it periodically
// downloads the UT1 Capitole blacklist tarball (via the NethServer mirror),
// extracts the categories in the ingest map, and bulk-writes them into the
// community URL-category database (internal/catdb). Extracted from package
// main per ADR-0002; the feedSyncer singleton and the urlcategories startup
// slice stay in main (feedsync.go shim).
package feedsync

// FeedSyncer — downloads the UT1 Capestat blacklist tarball, parses the
// per-category "domains" files, and bulk-writes the result to CommunityDB.
//
// UT1 tarball structure:
//
//   blacklists/
//     adult/domains
//     gambling/domains
//     social_networks/domains
//     malware/domains
//     ...
//
// Each "domains" file contains one bare domain per line (no scheme, no path).
// Lines starting with '#' are comments.
//
// Only categories listed in ut1CategoryMap are ingested; all others are
// silently skipped. Domains that appear in multiple categories get the last
// ingested mapping — callers should list more-specific categories later in the
// map if ordering matters.
//
// Feed URL (default): https://ftp.ut-capitole.fr/pub/reseau/cache/squidguard_contrib/blacklists.tar.gz

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/catdb"
	"github.com/KidCarmi/Culvert/internal/feedsched"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// syncFailures counts download/parse/bulk-write failures; package main's
// urlcat metrics surface reads it via SyncFailures().
var syncFailures atomic.Int64

// SyncFailures returns the cumulative UT1 sync failure count.
func SyncFailures() int64 { return syncFailures.Load() }

// MappedCategories returns the URLCategory values the UT1 ingest map produces
// (with duplicates — multiple UT1 directories can map to one category).
// Consumers: the category-store seeding at startup and the admin UI's
// feed-backed badge enrichment.
func MappedCategories() []string {
	out := make([]string, 0, len(ut1CategoryMap))
	for _, cat := range ut1CategoryMap {
		out = append(out, cat)
	}
	return out
}

// userAgent matches internal/threatfeed's feedUserAgent — the project-wide
// feed-fetch identification string.
const userAgent = "Culvert/1.0 (+https://github.com/KidCarmi/Claude-Test)"

const (
	// defaultUT1FeedURL is the NethServer daily mirror of the UT1 Capitole
	// blacklists. The official UT1 FTP/HTTP endpoints are unreliable (403/404),
	// so we use this actively maintained GitHub mirror instead.
	defaultUT1FeedURL = "https://raw.githubusercontent.com/NethServer/toulouse-bl-mirror/master/blacklists.tar.gz"

	// feedSyncHTTPTimeout caps the download of the full tarball (can be 50+ MB).
	feedSyncHTTPTimeout = 5 * time.Minute

	// maxDomainsPerCategory caps ingestion to limit memory during bulk build.
	// CHAOS-109: this is a PER-MEMBER cap, not an aggregate one. `count` is a
	// local in parseDomainFile, reset on every call, and tar permits the same
	// member path any number of times — so it bounded nothing an origin could
	// not step around by repeating "blacklists/malware/domains". It is kept
	// because it still bounds one honest category; maxDomainsTotal is the bound
	// that actually holds. Measured: 40 duplicate members of 50_000 domains each
	// produced exactly 2_000_000 live map entries without any single member ever
	// reaching this cap.
	maxDomainsPerCategory = 2_000_000
)

// The three CHAOS-109 ingest budgets are var, not const, for one reason: the
// bound gates must be able to lower them. A gate that had to move 512 MiB of
// gzip to prove the budget engages would never run in CI, and an unrun gate is
// not a gate. Production code never assigns these; the gates restore them
// through t.Cleanup.
var (
	// maxDomainsTotal is the AGGREGATE ingest ceiling across every member of the
	// archive, and it is the real heap bound on this path: the domain→category
	// map is REACHABLE for the whole parse, so it is exactly the memory the
	// GOMEMLIMIT backstop documents it cannot reclaim (memory_backstop.go,
	// "It CANNOT reclaim memory that is still REACHABLE"). Measured cost is
	// ~128 B of live heap per entry, so this ceiling is ~512 MiB — the same
	// order as the ~410–470 MiB reachable peak that backstop is sized around.
	// The real UT1 feed carries ~3–4 M domains across all categories, so this
	// leaves headroom for genuine growth.
	//
	// Reaching it TRUNCATES the round rather than refusing it, and that is safe
	// in a way a truncated fetch would not be: BulkWrite overwrites keys as they
	// arrive and never deletes, so a short round only adds fewer NEW domains and
	// every previously known domain stays categorised. Refusing here would
	// instead freeze coverage the first time a legitimate feed outgrew the
	// ceiling, which is the worse failure.
	maxDomainsTotal = 4_000_000

	// maxFeedCompressedBytes bounds what the ORIGIN may send. The feed is a
	// "50+ MB" tarball from a third-party GitHub mirror Culvert does not
	// control, so this is ~10x its documented size: a feed that grew is still
	// served, an origin sending ten times the feed is a fault or an attack.
	// Exceeding it FAILS the round (charged failDownload — "the tarball did not
	// arrive intact") and leaves the last-good BadgerDB authoritative.
	maxFeedCompressedBytes int64 = 512 << 20

	// maxFeedDecompressedBytes bounds the EXPANSION, independently of the
	// compressed size, because a small body can expand without limit. This is
	// the ingest-plane counterpart of secscan.MaxDecompressBytes on the
	// inspection plane (CHAOS-106): bound the input AND bound what it expands
	// to, and never let one stand in for the other. Exceeding it fails the round.
	maxFeedDecompressedBytes int64 = 4 << 30
)

// errBudgetExceeded marks a spent byte budget. It is a distinct sentinel from
// errIngestCapReached because the two outcomes are opposite: a spent BYTE
// budget fails the round, while a reached ENTRY cap truncates it. It also has
// to be distinguishable from a corrupt member: parseTarball logs-and-continues
// on a member it cannot parse, and a budget error swallowed into that path
// would be reported to the operator as "skipping <member>" — a benign line for
// the one condition that must fail the round.
var errBudgetExceeded = errors.New("ingest byte budget exceeded")

// errMemberCapReached signals that maxDomainsPerCategory was reached for the
// member being read. Unlike errIngestCapReached it stops only that member: the
// import continues with the next one.
var errMemberCapReached = errors.New("per-member domain cap reached")

// errIngestCapReached signals that maxDomainsTotal was reached mid-member. It
// is not a failure: parseTarball stops reading further members, records the
// truncation and returns what it has.
var errIngestCapReached = errors.New("aggregate domain ingest cap reached")

// boundedReader fails the read once more than limit bytes have been consumed,
// with an error naming WHICH budget was spent. io.LimitReader is not usable
// here: it reports a spent budget as a clean io.EOF, which gzip and tar would
// both report as a truncated archive — indistinguishable from a real transfer
// cut, and the operator needs to be able to tell those apart.
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
// next call. Treating that next call as an overrun fails the round for an
// archive that is exactly the budget. So read ONE more byte: a clean io.EOF is
// a complete body, a real byte is the overrun, and any other outcome (a
// transport error, or a no-progress (0, nil)) is passed through.
//
// This is the same correction PR #1796 made to the blocklistfeed and
// threatfeed copies of this reader (Codex P2 4448735208); this third copy was
// missed there. Keeping the three in agreement matters because the gates lower
// these limits, and a limit the gates can lower is a limit a boundary bug can
// reach.
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

// ut1CategoryMap maps UT1 directory names to our URLCategory values.
// Only directories listed here are ingested; all others are ignored.
var ut1CategoryMap = map[string]string{
	// Security threats
	"adult":         "Adult",
	"agressif":      "Malicious",
	"malware":       "Malicious",
	"phishing":      "Malicious",
	"redirector":    "Malicious",
	"warez":         "Malicious",
	"hacking":       "Hacking",
	"cryptojacking": "Malicious",

	// Content categories
	"dating":          "Dating",
	"gambling":        "Gambling",
	"games":           "Gaming",
	"social_networks": "Social Media",
	"streamingmedia":  "Streaming",
	"news":            "News",
	"blog":            "Blogs",
	"forums":          "Forums",
	"chat":            "Chat",
	"press":           "News",
	"radio":           "Media",
	"audio-video":     "Media",

	// Commerce & finance
	"shopping":  "Shopping",
	"bank":      "Finance",
	"bitcoin":   "Cryptocurrency",
	"financial": "Finance",

	// Education & government
	"education":    "Education",
	"government":   "Government",
	"associations": "Non-Profit",
	"religious":    "Religion",
	"science":      "Education",

	// Technology
	"filehosting":    "File Hosting",
	"download":       "Downloads",
	"ddos":           "Malicious",
	"vpn":            "VPN/Proxy",
	"remote-control": "Remote Access",

	// Ads & tracking
	"ads":           "Advertising",
	"tracker":       "Tracking",
	"marketingware": "Tracking",

	// Misc
	"jobsearch":   "Job Search",
	"reaffected":  "Parked Domains",
	"mixed_adult": "Adult",
	"lingerie":    "Adult",
}

// Syncer manages periodic synchronisation of UT1 data into the community DB.
type Syncer struct {
	db           *catdb.CommunityDB
	feedURL      string
	syncInterval time.Duration
	lastSync     atomic.Value // stores time.Time — last SUCCESSFUL sync
	totalDomains atomic.Int64

	// lastAttempt records every round, success or failure. lastSync alone
	// cannot distinguish "syncing cleanly" from "has not run since boot",
	// because it only ever advances on success.
	lastAttempt atomic.Value // stores time.Time

	// consecutiveFailures counts rounds since the last clean one; reset to
	// zero by the first success. Read by the health snapshot.
	consecutiveFailures atomic.Int64

	// lastFailure is the BOUNDED reason class for the most recent failed
	// round ("download", "write", "" when clean) — never a raw error string,
	// which would carry the feed URL into any surface that consumes it.
	lastFailure atomic.Value // stores string

	// loop tracks the goroutine Start launches, so Wait can join it after the
	// caller cancels Start's context.
	loop sync.WaitGroup
}

// Bounded reason classes for a failed round. The verbose cause goes to the log.
// "download" covers the whole fetch-and-parse stage (downloadAndParse), which
// is a single failure mode for the operator: the tarball did not arrive intact.
const (
	failDownload = "download"
	failWrite    = "write"
)

// Backoff bounds for a failed UT1 round. The steady-state interval is 24h, so
// a bare ticker meant one transient fetch error froze category coverage for a
// full DAY. feedsched clamps the ceiling to the interval.
const (
	syncRetryMin = 15 * time.Minute
	syncRetryMax = 2 * time.Hour
)

// Health is a consistent snapshot of the UT1 syncer's state for the metrics
// and diagnostics surfaces.
type Health struct {
	LastAttempt         time.Time
	LastSuccess         time.Time
	ConsecutiveFailures int64
	TotalFailures       int64
	LastFailure         string
	SyncInterval        time.Duration
	Domains             int64
}

// Health returns the current snapshot.
func (fs *Syncer) Health() Health {
	h := Health{
		LastSuccess:         fs.lastSync.Load().(time.Time),
		ConsecutiveFailures: fs.consecutiveFailures.Load(),
		TotalFailures:       syncFailures.Load(),
		SyncInterval:        fs.syncInterval,
		Domains:             fs.totalDomains.Load(),
	}
	if v, ok := fs.lastAttempt.Load().(time.Time); ok {
		h.LastAttempt = v
	}
	if v, ok := fs.lastFailure.Load().(string); ok {
		h.LastFailure = v
	}
	return h
}

// New creates a Syncer for the given DB.
// feedURL defaults to defaultUT1FeedURL when empty.
// syncInterval defaults to 24h when zero.
func New(db *catdb.CommunityDB, feedURL string, syncInterval time.Duration) *Syncer {
	if feedURL == "" {
		feedURL = defaultUT1FeedURL
	}
	if syncInterval <= 0 {
		syncInterval = 24 * time.Hour
	}
	fs := &Syncer{
		db:           db,
		feedURL:      feedURL,
		syncInterval: syncInterval,
	}
	fs.lastSync.Store(time.Time{})
	fs.lastAttempt.Store(time.Time{})
	fs.lastFailure.Store("")
	return fs
}

// Start launches the background sync goroutine.
// An immediate sync is performed on first start when the DB is empty.
//
// The loop is a feedsched.Scheduler, not a bare 24-hour ticker. Two reasons,
// both reachable without any infrastructure fault:
//
//   - a failed round was not retried for a full DAY. The origin is a
//     raw.githubusercontent.com mirror of a 50+ MB tarball; a rate-limit, a
//     GitHub incident, or a proxy restart froze category coverage until the
//     next day. On a node whose community DB is empty (first boot, or after
//     the CHAOS-50 quarantine of a damaged store) that means a full day of
//     Layer-1-only categorisation.
//   - a fixed ticker keeps a fleet in phase forever, and every Culvert
//     deployment pulls that same 50+ MB object from that same host. A
//     synchronised fleet is answered by rate-limiting — which produces exactly
//     the failure the missing backoff then holds for 24 hours.
func (fs *Syncer) Start(ctx context.Context) {
	fs.loop.Add(1)
	go func() {
		defer fs.loop.Done()
		feedsched.New(fs.schedulerConfig()).Run(ctx)
	}()
}

// Wait blocks until the loop Start launched has returned; it returns at once if
// Start was never called. Cancel Start's context first: the loop exits after
// the round in flight, and a round logs through the process logger, so a test
// that swaps that logger must not race a round left over from an earlier test.
func (fs *Syncer) Wait() { fs.loop.Wait() }

// schedulerConfig builds the syncer's cadence configuration. Split out of Start
// so the cadence contract is asserted directly rather than by driving a live
// loop against the third-party mirror.
func (fs *Syncer) schedulerConfig() feedsched.Config {
	return feedsched.Config{
		Name:       "feedsync",
		Interval:   func() time.Duration { return fs.syncInterval },
		BackoffMin: syncRetryMin,
		BackoffMax: syncRetryMax,
		RunNow:     func() bool { return fs.db.Stats() == 0 },
		// CHAOS-24: Sync streams and parses a remote gzip tarball (UT1 mirror).
		// Guard the ROUND so a malformed/hostile archive costs one sync window
		// rather than terminating an in-line gateway; the last-good BadgerDB
		// stays readable throughout, so degradation is already graceful. A
		// panicked round is charged as a failure, so a systematically hostile
		// archive backs off rather than being re-fetched at speed.
		Run: func(ctx context.Context) bool {
			var ok bool
			// CHAOS-93 RT-4: the scheduler's ctx reaches the round. It used to
			// be dropped here, so the 50+ MB tarball fetch ran on
			// context.Background(): a stalled origin could not be interrupted
			// by SIGTERM, and the round went on to a BulkWrite that raced the
			// store close at shutdown order 120.
			if obs.SafeCall("feedsync", func() { ok = fs.syncRound(ctx) }) {
				return false
			}
			return ok
		},
	}
}

// Sync downloads the UT1 tarball, parses all mapped categories, and performs a
// bulk write into CommunityDB. The previous DB contents remain readable during
// the import; BadgerDB's WriteBatch overwrites keys as they arrive.
// Deliberately NOT bound to an admin request's context (see threatfeed's Sync):
// a manual "sync now" should survive the operator closing the tab.
func (fs *Syncer) Sync() { fs.syncRound(context.Background()) }

// syncRound performs one sync and reports success, so the scheduler can pick
// the retry cadence and the health surfaces can report the failure.
func (fs *Syncer) syncRound(ctx context.Context) bool {
	obs.Printf("FeedSync: starting UT1 sync from %s", fs.feedURL)
	start := time.Now()
	fs.lastAttempt.Store(start)

	// CHAOS-74: a store that latched degraded after a contained memory fault
	// refuses every write until restart (catdb.ErrDegraded). Downloading and
	// parsing a 50+ MB tarball only to have BulkWrite refuse it would be waste on
	// every round, so the round fails here, charged as a write failure (the
	// bounded reason set is unchanged), and the scheduler backs off as for any
	// failed round.
	if fs.storeDegraded() {
		fs.noteFailure(failWrite)
		obs.Printf("FeedSync: community category store is degraded after a memory fault; skipping the sync until this node restarts")
		return false
	}

	entries, err := downloadAndParse(ctx, fs.feedURL)
	if err != nil {
		fs.noteFailure(failDownload)
		obs.Printf("FeedSync: download/parse failed: %v", err)
		return false
	}
	obs.Printf("FeedSync: parsed %d domain entries, writing to BadgerDB…", len(entries))

	// CHAOS-93 RT-4: the last checkpoint before the durable write. The round is
	// started by the scheduler and the store is closed by shutdown hook order
	// 120, with the lifecycle ctx cancelled at order 40 — so a round that was
	// still downloading when SIGTERM arrived used to arrive here anyway and
	// issue a 50+ MB BulkWrite into a store that is about to close. Cancelled
	// means do not start the write; it is charged as a failed round, and the
	// last-good DB stays exactly as it was.
	// Charged as failWrite, the existing bounded reason class: the write is what
	// did not happen. No new reason is introduced, so the health snapshot and
	// the metrics surface are unchanged.
	if ctx.Err() != nil {
		fs.noteFailure(failWrite)
		obs.Printf("FeedSync: cancelled before the bulk write; the previous category data is unchanged")
		return false
	}

	if err := fs.db.BulkWrite(entries); err != nil {
		fs.noteFailure(failWrite)
		obs.Printf("FeedSync: bulk write failed: %v", err)
		return false
	}

	fs.lastSync.Store(time.Now())
	fs.totalDomains.Store(int64(len(entries)))
	fs.consecutiveFailures.Store(0)
	fs.lastFailure.Store("")
	obs.Printf("FeedSync: sync complete: %d domains in %s", len(entries), time.Since(start).Round(time.Second))
	return true
}

// storeDegraded reports whether the target store has latched degraded. A nil
// store (the download-only test harness) is not degraded.
func (fs *Syncer) storeDegraded() bool {
	if fs.db == nil {
		return false
	}
	_, _, degraded := fs.db.LookupFaults()
	return degraded
}

// noteFailure records one failed round: the cumulative counter the metrics
// surface already exports, the consecutive run the health snapshot reports,
// and the bounded reason class.
func (fs *Syncer) noteFailure(reason string) {
	syncFailures.Add(1)
	fs.consecutiveFailures.Add(1)
	fs.lastFailure.Store(reason)
}

// SeedStats sets the last-sync timestamp and domain count directly. Test
// support for the metrics surface (production values are set by Sync).
func (fs *Syncer) SeedStats(lastSync time.Time, totalDomains int64) {
	fs.lastSync.Store(lastSync)
	fs.totalDomains.Store(totalDomains)
}

// Stats returns (totalDomains, lastSyncTime, syncInterval) for the metrics endpoint.
func (fs *Syncer) Stats() (int64, time.Time, time.Duration) {
	return fs.totalDomains.Load(), fs.lastSync.Load().(time.Time), fs.syncInterval
}

// ─── Download & parse ─────────────────────────────────────────────────────────

// downloadAndParse fetches the UT1 tarball from url and returns a
// domain → mappedCategory map ready for BulkWrite.
func downloadAndParse(ctx context.Context, url string) (map[string]string, error) {
	client := &http.Client{Timeout: feedSyncHTTPTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	// CHAOS-109: the origin's byte budget. Before this the only limit on how
	// much a third-party mirror could spend was client.Timeout (5 minutes), so
	// the effective bound was "whatever the link delivers in five minutes,
	// times the ~50x live-heap amplification measured below".
	return parseTarball(&boundedReader{r: resp.Body, what: "compressed feed body", limit: maxFeedCompressedBytes})
}

// parseTarball reads a gzip-compressed tar archive from r and extracts all
// "blacklists/<category>/domains" files whose category is in ut1CategoryMap.
// Returns a domain → mappedCategory map.
func parseTarball(r io.Reader) (map[string]string, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("gzip open: %w", err)
	}
	defer gz.Close() //nolint:errcheck // gzip.Reader.Close flushes no data; error is non-actionable in deferred context

	// CHAOS-109: bound the EXPANSION as well as the compressed input. Skipped
	// members still stream through tar.Reader, so this is also what stops an
	// archive of unclassified members from spending the whole 5-minute fetch
	// window on gzip and tar work that can never produce an entry.
	bounded := &boundedReader{r: gz, what: "decompressed feed archive", limit: maxFeedDecompressedBytes}

	entries := make(map[string]string, 500_000)
	tr := tar.NewReader(bounded)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar read: %w", err)
		}
		if truncated, err := ingestTarMember(tr, hdr, entries); err != nil {
			return nil, err
		} else if truncated {
			obs.Printf("FeedSync: aggregate ingest cap of %d domains reached; this import is TRUNCATED and later archive members were not read. Previously categorised domains are unaffected (the bulk write overwrites keys and never deletes).", maxDomainsTotal)
			break
		}
	}
	return entries, nil
}

// ingestTarMember consumes one archive member into out. It reports (true, nil)
// when the aggregate ingest cap was reached, which is a signal to stop reading
// members rather than a failure. Split out of parseTarball so the bound checks
// do not raise that function's measured complexity.
func ingestTarMember(tr io.Reader, hdr *tar.Header, out map[string]string) (truncated bool, err error) {
	if hdr.Typeflag != tar.TypeReg {
		return false, nil
	}
	// Only process "blacklists/<category>/domains" entries.
	mappedCat, ok := classifyTarEntry(hdr.Name)
	if !ok {
		return false, nil
	}
	if len(out) >= maxDomainsTotal {
		return true, nil
	}
	if err := parseDomainFile(tr, mappedCat, out); err != nil {
		switch {
		case errors.Is(err, errIngestCapReached):
			return true, nil
		case errors.Is(err, errBudgetExceeded):
			// NOT a skippable member: the origin overran its budget, which
			// fails the whole round.
			return false, fmt.Errorf("read %s: %w", hdr.Name, err)
		default:
			// Log but continue — a single corrupt category file should not
			// abort the entire import.
			obs.Printf("FeedSync: skipping %s: %v", hdr.Name, err)
		}
	}
	return false, nil
}

// classifyTarEntry returns the mapped URLCategory value for a tar entry path
// of the form "blacklists/<ut1Category>/domains", or ("", false) if it should
// be skipped.
func classifyTarEntry(path string) (string, bool) {
	// Normalise path separators and strip leading "./" if present.
	path = strings.TrimPrefix(strings.ReplaceAll(path, "\\", "/"), "./")

	parts := strings.Split(path, "/")
	// Expect exactly: ["blacklists", "<category>", "domains"]
	if len(parts) != 3 || parts[2] != "domains" {
		return "", false
	}
	ut1Cat := parts[1]
	mappedCat, ok := ut1CategoryMap[ut1Cat]
	return mappedCat, ok
}

// parseDomainFile reads one UT1 "domains" file from tr and adds its entries
// into the shared map (domain → mappedCategory).
func parseDomainFile(r io.Reader, mappedCat string, out map[string]string) error {
	count := 0
	buf := make([]byte, 0, 256)
	scratch := make([]byte, 4096)

	for {
		n, err := r.Read(scratch)
		for _, b := range scratch[:n] {
			if b != '\n' && b != '\r' {
				buf = append(buf, b)
				continue
			}
			aerr := acceptDomainLine(string(buf), mappedCat, out, &count)
			buf = buf[:0]
			if aerr == nil {
				continue
			}
			if errors.Is(aerr, errMemberCapReached) {
				return nil // per-member cap reached; drain remainder silently
			}
			return aerr
		}
		if err == io.EOF {
			// Flush the last line if it didn't end with a newline. It goes
			// through the same accept path as every other line, so the caps
			// apply to it too — before CHAOS-109 this branch duplicated the
			// normalisation and checked neither.
			if aerr := acceptDomainLine(string(buf), mappedCat, out, &count); aerr != nil &&
				!errors.Is(aerr, errMemberCapReached) && !errors.Is(aerr, errIngestCapReached) {
				return aerr
			}
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// acceptDomainLine normalises one raw feed line and records it against both
// caps. Extracted from parseDomainFile's inner loop so the cap checks do not
// deepen a block the nestif linter already measures at the function's
// declaration line — the exact case conventions.md describes, where
// --new-from-rev cannot see complexity added to an unchanged declaration.
//
// Returns errMemberCapReached or errIngestCapReached when a cap is reached;
// the caller decides which of those stops a member and which stops the import.
func acceptDomainLine(raw, mappedCat string, out map[string]string, count *int) error {
	line := strings.TrimSpace(raw)
	if line == "" || line[0] == '#' {
		return nil
	}
	domain := strings.ToLower(line)
	// Basic sanity: must contain at least one dot.
	if !strings.Contains(domain, ".") {
		return nil
	}
	out[domain] = mappedCat
	*count++
	if *count >= maxDomainsPerCategory {
		return errMemberCapReached
	}
	// CHAOS-109: the aggregate cap is what bounds the heap. Checked against the
	// SHARED map, so repeated members cannot each start a fresh budget.
	if len(out) >= maxDomainsTotal {
		return errIngestCapReached
	}
	return nil
}
