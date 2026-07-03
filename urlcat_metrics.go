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
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/feedsync"
)

// globalUT1FeedSyncer is a package handle to the UT1 FeedSyncer created in
// main.go so the metrics endpoint can read its Stats() without reaching into
// the Server struct. nil when URL categories are not configured — the writer
// renders 0/0 in that case.
var globalUT1FeedSyncer *FeedSyncer

// Failure counters. The UT1 counter is owned by internal/feedsync
// (read via feedsync.SyncFailures()); the SaaS counter is incremented on the
// error-return paths in SaaSFeedSyncer.Sync (saas_feed.go). Plain atomics —
// no labels, no feed identity.
var statSaaSFeedSyncFailures atomic.Int64

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
	_, saasLastSync, saasEntries, _ := globalSaaSFeed.Stats()

	w.WriteString("\n# HELP culvert_category_feed_last_sync_timestamp_seconds Unix time of the last successful UT1 category feed sync (0 = never)\n")
	w.WriteString("# TYPE culvert_category_feed_last_sync_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "culvert_category_feed_last_sync_timestamp_seconds %d\n", unixOrZero(catLastSync))

	w.WriteString("\n# HELP culvert_category_feed_entries Domain entries from the last UT1 category feed sync\n")
	w.WriteString("# TYPE culvert_category_feed_entries gauge\n")
	fmt.Fprintf(w, "culvert_category_feed_entries %d\n", catEntries)

	w.WriteString("\n# HELP culvert_saas_feed_last_sync_timestamp_seconds Unix time of the last successful SaaS category feed sync (0 = never)\n")
	w.WriteString("# TYPE culvert_saas_feed_last_sync_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "culvert_saas_feed_last_sync_timestamp_seconds %d\n", unixOrZero(saasLastSync))

	w.WriteString("\n# HELP culvert_saas_feed_entries Domains added by the last SaaS category feed sync\n")
	w.WriteString("# TYPE culvert_saas_feed_entries gauge\n")
	fmt.Fprintf(w, "culvert_saas_feed_entries %d\n", saasEntries)

	w.WriteString("\n# HELP culvert_category_feed_sync_failures_total UT1 category feed sync failures (download/parse or bulk-write errors)\n")
	w.WriteString("# TYPE culvert_category_feed_sync_failures_total counter\n")
	fmt.Fprintf(w, "culvert_category_feed_sync_failures_total %d\n", feedsync.SyncFailures())

	w.WriteString("\n# HELP culvert_saas_feed_sync_failures_total SaaS category feed sync failures (request/fetch/read/parse errors)\n")
	w.WriteString("# TYPE culvert_saas_feed_sync_failures_total counter\n")
	fmt.Fprintf(w, "culvert_saas_feed_sync_failures_total %d\n", statSaaSFeedSyncFailures.Load())
}
