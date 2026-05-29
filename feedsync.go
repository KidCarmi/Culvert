package main

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
	"sync/atomic"
	"time"
)

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
	"adult":           "Adult",
	"agressif":        "Malicious",
	"malware":         "Malicious",
	"phishing":        "Malicious",
	"redirector":      "Malicious",
	"warez":           "Malicious",
	"hacking":         "Hacking",
	"cryptojacking":   "Malicious",

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
	"shopping":        "Shopping",
	"bank":            "Finance",
	"bitcoin":         "Cryptocurrency",
	"financial":       "Finance",

	// Education & government
	"education":       "Education",
	"government":      "Government",
	"associations":    "Non-Profit",
	"religious":       "Religion",
	"science":         "Education",

	// Technology
	"filehosting":     "File Hosting",
	"download":        "Downloads",
	"ddos":            "Malicious",
	"vpn":             "VPN/Proxy",
	"remote-control":  "Remote Access",

	// Ads & tracking
	"ads":             "Advertising",
	"tracker":         "Tracking",
	"marketingware":   "Tracking",

	// Misc
	"jobsearch":       "Job Search",
	"reaffected":      "Parked Domains",
	"mixed_adult":     "Adult",
	"lingerie":        "Adult",
}

// FeedSyncer manages periodic synchronisation of UT1 data into CommunityDB.
type FeedSyncer struct {
	db           *CommunityDB
	feedURL      string
	syncInterval time.Duration
	lastSync     atomic.Value // stores time.Time
	totalDomains atomic.Int64
}

// newFeedSyncer creates a FeedSyncer for the given DB.
// feedURL defaults to defaultUT1FeedURL when empty.
// syncInterval defaults to 24h when zero.
func newFeedSyncer(db *CommunityDB, feedURL string, syncInterval time.Duration) *FeedSyncer {
	if feedURL == "" {
		feedURL = defaultUT1FeedURL
	}
	if syncInterval <= 0 {
		syncInterval = 24 * time.Hour
	}
	fs := &FeedSyncer{
		db:           db,
		feedURL:      feedURL,
		syncInterval: syncInterval,
	}
	fs.lastSync.Store(time.Time{})
	return fs
}

// Start launches the background sync goroutine.
// An immediate sync is performed on first start when the DB is empty.
func (fs *FeedSyncer) Start(ctx context.Context) {
	go func() {
		if fs.db.Stats() == 0 {
			fs.Sync()
		}
		ticker := time.NewTicker(fs.syncInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fs.Sync()
			}
		}
	}()
}

// Sync downloads the UT1 tarball, parses all mapped categories, and performs a
// bulk write into CommunityDB. The previous DB contents remain readable during
// the import; BadgerDB's WriteBatch overwrites keys as they arrive.
func (fs *FeedSyncer) Sync() {
	logger.Printf("FeedSync: starting UT1 sync from %s", fs.feedURL)
	start := time.Now()

	entries, err := downloadAndParse(fs.feedURL)
	if err != nil {
		statCategoryFeedSyncFailures.Add(1)
		logger.Printf("FeedSync: download/parse failed: %v", err)
		return
	}
	logger.Printf("FeedSync: parsed %d domain entries, writing to BadgerDB…", len(entries))

	if err := fs.db.BulkWrite(entries); err != nil {
		statCategoryFeedSyncFailures.Add(1)
		logger.Printf("FeedSync: bulk write failed: %v", err)
		return
	}

	fs.lastSync.Store(time.Now())
	fs.totalDomains.Store(int64(len(entries)))
	logger.Printf("FeedSync: sync complete: %d domains in %s", len(entries), time.Since(start).Round(time.Second))
}

// Stats returns (totalDomains, lastSyncTime, syncInterval) for the metrics endpoint.
func (fs *FeedSyncer) Stats() (int64, time.Time, time.Duration) {
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
	req.Header.Set("User-Agent", feedUserAgent)

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
			logger.Printf("FeedSync: skipping %s: %v", hdr.Name, err)
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
