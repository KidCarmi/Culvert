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
	maxDomainsPerCategory = 2_000_000
)

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
	// round ("download", "disk_space", "disk_space_unknown", "write", "" when
	// clean) — never a raw error string,
	// which would carry the feed URL into any surface that consumes it.
	lastFailure atomic.Value // stores string

	// loop tracks the goroutine Start launches, so Wait can join it after the
	// caller cancels Start's context.
	loop sync.WaitGroup

	// freeBytes reports the free space on the filesystem holding the store,
	// or nil when unknown. See SetFreeSpaceProbe.
	freeBytes func() (uint64, error)
}

// Bounded reason classes for a failed round. The verbose cause goes to the log.
// "download" covers the whole fetch-and-parse stage (downloadAndParse), which
// is a single failure mode for the operator: the tarball did not arrive intact.
const (
	failDownload         = "download"
	failDiskSpace        = "disk_space"
	failDiskSpaceUnknown = "disk_space_unknown"
	failWrite            = "write"
)

// FailDiskSpace and FailDiskSpaceUnknown are the two reason classes for a
// deferred bulk write, exported so the diagnostics row can name them.
const (
	FailDiskSpace        = failDiskSpace
	FailDiskSpaceUnknown = failDiskSpaceUnknown
)

// Free space a bulk write must find before it starts. BadgerDB backs its
// memtable and value log with SPARSELY-truncated mmapped files
// (ristretto z.OpenMmapFile), so a write into a page the filesystem cannot
// allocate is not an error return but a SIGBUS that kills the whole gateway —
// measured on a full disk mid-sync (`logFile.writeEntry` → `memclr`, fatal
// fault). Refusing to START the write below a floor turns the common case — a
// volume that was already nearly full when the 24h round came due — into a
// counted, bounded failure while the last-good store keeps serving. It does
// NOT cover a disk that fills DURING the write; nothing above badger can.
const (
	syncFreeFloor     = 512 << 20 // fixed headroom: memtables, flush, compaction
	syncBytesPerEntry = 256       // per-entry allowance across WAL, vlog and SST
)

// syncSpaceNeeded is the free space a write of n entries must find.
func syncSpaceNeeded(n int) uint64 {
	if n <= 0 {
		return syncFreeFloor
	}
	return syncFreeFloor + uint64(n)*syncBytesPerEntry // #nosec G115 -- n > 0 checked above
}

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
	// A completed import outlives the process that ran it: restore its time
	// and size from the store's completion record, so a restart does not
	// report a synced store as never synced (F-FEED-1).
	if rec, ok := fs.importRecord(); ok {
		fs.lastSync.Store(rec.CompletedAt)
		fs.totalDomains.Store(rec.Entries)
	}
	return fs
}

// importRecord returns the store's completion record when it is valid AND
// names this syncer's feed.
func (fs *Syncer) importRecord() (catdb.SyncRecord, bool) {
	if fs.db == nil {
		return catdb.SyncRecord{}, false
	}
	rec, err := fs.db.ImportRecord()
	if err != nil || rec.FeedURL != fs.feedURL {
		return catdb.SyncRecord{}, false
	}
	return rec, true
}

// ImportComplete reports whether the store holds a whole, durably certified
// import of this syncer's feed. False for a never-synced store, a legacy
// store written before completion records existed, an interrupted import,
// a damaged record, and a store imported from a different feed.
func (fs *Syncer) ImportComplete() bool {
	_, ok := fs.importRecord()
	return ok
}

// Start launches the background sync goroutine.
// An immediate sync is performed on start unless the store holds a complete,
// certified import of this feed (ImportComplete). Keying it on "the store is
// empty" left a partially imported store unsynced for a full interval: an
// import cut off by a container recreate during first boot left SOME keys,
// so the next process skipped its startup sync (F-FEED-1, PR #1528).
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
		RunNow:     func() bool { return !fs.ImportComplete() },
		// CHAOS-24: Sync streams and parses a remote gzip tarball (UT1 mirror).
		// Guard the ROUND so a malformed/hostile archive costs one sync window
		// rather than terminating an in-line gateway; the last-good BadgerDB
		// stays readable throughout, so degradation is already graceful. A
		// panicked round is charged as a failure, so a systematically hostile
		// archive backs off rather than being re-fetched at speed.
		Run: func(context.Context) bool {
			var ok bool
			if obs.SafeCall("feedsync", func() { ok = fs.syncRound() }) {
				return false
			}
			return ok
		},
	}
}

// SetFreeSpaceProbe installs the free-space probe for the store's filesystem.
// An installed probe is AUTHORITATIVE: when it cannot measure, the write is
// deferred exactly like a write that would not fit — a guess is not a
// measurement, and a wrong guess here is a SIGBUS. Only an ABSENT probe (a
// compatibility platform that cannot measure at all) lets the write proceed
// unmeasured.
func (fs *Syncer) SetFreeSpaceProbe(probe func() (uint64, error)) { fs.freeBytes = probe }

// spaceRefusal reports the bounded class and the reason a write of n entries
// must not start, or ("", "") when it may.
func (fs *Syncer) spaceRefusal(n int) (class, why string) {
	if fs.freeBytes == nil {
		return "", ""
	}
	free, err := fs.freeBytes()
	if err != nil {
		return failDiskSpaceUnknown, "free space on the store's filesystem could not be measured"
	}
	need := syncSpaceNeeded(n)
	if free >= need {
		return "", ""
	}
	return failDiskSpace, fmt.Sprintf("%d MiB free, a %d-entry write needs about %d MiB", free>>20, n, need>>20)
}

// StoreEmpty reports whether the community store holds no entries — on a
// deferred first sync that means NO community category coverage yet, which
// the diagnostics row must say rather than imply the previous data serves.
func (fs *Syncer) StoreEmpty() bool { return fs.db == nil || !fs.db.HasEntries() }

// Sync downloads the UT1 tarball, parses all mapped categories, and performs a
// bulk write into CommunityDB. The previous DB contents remain readable during
// the import; BadgerDB's WriteBatch overwrites keys as they arrive.
func (fs *Syncer) Sync() { fs.syncRound() }

// syncRound performs one sync and reports success, so the scheduler can pick
// the retry cadence and the health surfaces can report the failure.
func (fs *Syncer) syncRound() bool {
	obs.Printf("FeedSync: starting UT1 sync from %s", fs.feedURL)
	start := time.Now()
	fs.lastAttempt.Store(start)

	entries, err := downloadAndParse(fs.feedURL)
	if err != nil {
		fs.noteFailure(failDownload)
		obs.Printf("FeedSync: download/parse failed: %v", err)
		return false
	}
	if len(entries) == 0 {
		// Nothing to certify: a feed with no mapped domains is a broken
		// download, never a successful sync of an empty list.
		fs.noteFailure(failDownload)
		obs.Printf("FeedSync: the feed carried no mapped domains; nothing imported")
		return false
	}
	if class, why := fs.spaceRefusal(len(entries)); class != "" {
		fs.noteFailure(class)
		coverage := "the previous category data keeps serving"
		if fs.StoreEmpty() {
			coverage = "no community category data is loaded yet (admin-managed categories only)"
		}
		obs.Printf("FeedSync: write REFUSED (%s): %s; %s", class, why, coverage)
		return false
	}
	obs.Printf("FeedSync: parsed %d domain entries, writing to BadgerDB…", len(entries))

	// Withdraw the old certificate before any data moves, then write, then
	// certify. Only a fully written AND fsynced import is ever reported (or
	// remembered across a restart) as synced.
	if err := fs.db.BeginImport(); err != nil {
		fs.noteFailure(failWrite)
		obs.Printf("FeedSync: could not begin the import: %v", err)
		return false
	}
	if err := fs.db.BulkWrite(entries); err != nil {
		fs.noteFailure(failWrite)
		obs.Printf("FeedSync: bulk write failed (import NOT complete; it is retried, and redone at the next start): %v", err)
		return false
	}
	rec := catdb.SyncRecord{FeedURL: fs.feedURL, Entries: int64(len(entries)), CompletedAt: time.Now().UTC()}
	if err := fs.db.CompleteImport(rec); err != nil {
		fs.noteFailure(failWrite)
		obs.Printf("FeedSync: import written but could not be certified durable (it is retried): %v", err)
		return false
	}

	fs.lastSync.Store(rec.CompletedAt)
	fs.totalDomains.Store(rec.Entries)
	fs.consecutiveFailures.Store(0)
	fs.lastFailure.Store("")
	obs.Printf("FeedSync: sync complete: %d domains in %s", len(entries), time.Since(start).Round(time.Second))
	return true
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
func downloadAndParse(url string) (map[string]string, error) {
	client := &http.Client{Timeout: feedSyncHTTPTimeout}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
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

	return parseTarball(resp.Body)
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

	entries := make(map[string]string, 500_000)
	tr := tar.NewReader(gz)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar read: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// Only process "blacklists/<category>/domains" entries.
		mappedCat, ok := classifyTarEntry(hdr.Name)
		if !ok {
			continue
		}

		if err := parseDomainFile(tr, mappedCat, entries); err != nil {
			// Log but continue — a single corrupt category file should not
			// abort the entire import.
			obs.Printf("FeedSync: skipping %s: %v", hdr.Name, err)
		}
	}
	return entries, nil
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
func parseDomainFile(r io.Reader, mappedCat string, out map[string]string) error { //nolint:gocognit // byte-level streaming parser; complexity is inherent
	count := 0
	buf := make([]byte, 0, 256)
	scratch := make([]byte, 4096)

	for {
		n, err := r.Read(scratch)
		for _, b := range scratch[:n] {
			if b == '\n' || b == '\r' {
				line := strings.TrimSpace(string(buf))
				buf = buf[:0]
				if line == "" || line[0] == '#' {
					continue
				}
				domain := strings.ToLower(line)
				// Basic sanity: must contain at least one dot.
				if !strings.Contains(domain, ".") {
					continue
				}
				out[domain] = mappedCat
				count++
				if count >= maxDomainsPerCategory {
					return nil // cap reached; drain remainder silently
				}
			} else {
				buf = append(buf, b)
			}
		}
		if err == io.EOF {
			// Flush the last line if it didn't end with a newline.
			if line := strings.TrimSpace(string(buf)); line != "" && line[0] != '#' {
				if domain := strings.ToLower(line); strings.Contains(domain, ".") {
					out[domain] = mappedCat
				}
			}
			return nil
		}
		if err != nil {
			return err
		}
	}
}
