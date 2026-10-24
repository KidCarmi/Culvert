package main

// urlcat_metrics.go — UC-6 observability for the URL-category feed syncers.
//
// Two feeds back the URL-category subsystem:
//   • the UT1 FeedSyncer (community blacklist tarball → CommunityDB), held on
//     Server.feedSyncer and mirrored into globalUT1FeedSyncer for scraping;
//   • the SaaS category feed (globalSaaSFeed), which merges curated JSON into
//     catStore.
//
// Their freshness/size signals already exist via Stats() but were admin-API-only;
// this surfaces them to /metrics so operators can alert on "feed sync stuck".
//
// Labels are deliberately absent. Per the UC-6 contract, no feed URLs, domains,
// category names, or source names appear in any metric — only timestamps and
// counts. Freshness is the last successful sync as Unix seconds (0 = never).

import (
	"fmt"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/feedsync"
)

// globalUT1FeedSyncer is a package handle to the UT1 FeedSyncer created in
// main.go so the metrics endpoint can read its Stats() without reaching into
// the Server struct. nil when URL categories are not configured — the writer
// renders 0/0 in that case.
var globalUT1FeedSyncer *FeedSyncer

// The UT1 failure counter is package-owned by internal/feedsync
// (feedsync.SyncFailures()). The legacy raw SaaS syncer's metrics were RETIRED in
// F3b-4 (the syncer is no longer armed); the signed SaaS feed's observability is the
// culvert_saasfeed_* family (saas_feed_metrics.go).

// unixOrZero renders t as Unix seconds, or 0 when t is the zero time
// (never-synced), so a freshness alert can use `time() - <metric> > threshold`.
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// urlcatWritePrometheus appends the culvert_category_* / culvert_saas_* feed
// metrics. Called from handleMetrics alongside the per-rule, latency, and CDR
// writers. Reads live state at scrape time; no hot-path cost.
func urlcatWritePrometheus(w *strings.Builder) {
	var (
		catEntries  int64
		catLastSync time.Time
	)
	if globalUT1FeedSyncer != nil {
		catEntries, catLastSync, _ = globalUT1FeedSyncer.Stats()
	}

	w.WriteString("\n# HELP culvert_category_feed_last_sync_timestamp_seconds Unix time of the last successful UT1 category feed sync (0 = never)\n")
	w.WriteString("# TYPE culvert_category_feed_last_sync_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "culvert_category_feed_last_sync_timestamp_seconds %d\n", unixOrZero(catLastSync))

	w.WriteString("\n# HELP culvert_category_feed_entries Domain entries from the last UT1 category feed sync\n")
	w.WriteString("# TYPE culvert_category_feed_entries gauge\n")
	fmt.Fprintf(w, "culvert_category_feed_entries %d\n", catEntries)

	w.WriteString("\n# HELP culvert_category_feed_sync_failures_total UT1 category feed sync failures (download/parse or bulk-write errors)\n")
	w.WriteString("# TYPE culvert_category_feed_sync_failures_total counter\n")
	fmt.Fprintf(w, "culvert_category_feed_sync_failures_total %d\n", feedsync.SyncFailures())

	// F-DISK-RECOVERY-1: an abandoned mid-write import is a process-lifetime
	// latch (no further import runs until restart). The failure counter above
	// keeps rising after it — every refused round counts as a failure — so it
	// looks like an ordinary retrying outage and cannot carry "restart
	// required"; this gauge does. Emitted only when the feed is configured, so
	// the series exists exactly where the paging rule (== 1) can mean something.
	if globalUT1FeedSyncer != nil {
		abandoned := 0
		if globalUT1FeedSyncer.Health().WriteAbandoned {
			abandoned = 1
		}
		w.WriteString("\n# HELP culvert_category_feed_write_abandoned 1 when a community category import was abandoned mid-write; further imports are refused until restart\n")
		w.WriteString("# TYPE culvert_category_feed_write_abandoned gauge\n")
		fmt.Fprintf(w, "culvert_category_feed_write_abandoned %d\n", abandoned)
	}
}
