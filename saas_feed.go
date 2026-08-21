package main

// saas_feed.go — package-main glue for the SaaS category feed syncer, moved
// to internal/saasfeed (ADR-0002, five-seam design). The alias shim keeps the
// urlcategories startup slice, admin-settings persistence, and the metrics
// surface using the original unqualified names. main owns the merge closure
// (the category store lives in internal/urlcat), the lifecycle
// provider, and the SSRF-safe client; the sync-failure counter is
// package-owned (saasfeed.SyncFailures, read by urlcat_metrics.go).

import (
	"net/http"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/saasfeed"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// SaaSFeedSyncer is re-exposed unqualified (engine type is saasfeed.Syncer).
type SaaSFeedSyncer = saasfeed.Syncer

// defaultSaaSFeedURL is re-exposed for the urlcategories startup slice.
const defaultSaaSFeedURL = saasfeed.DefaultFeedURL

// globalSaaSFeed is the process-wide SaaS feed syncer: SSRF-safe client,
// main-owned catStore merge, sync loop parented to the app lifecycle.
var globalSaaSFeed = saasfeed.New(saasfeed.Deps{
	Client: &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{DialContext: ssrf.SafeDialContext},
	},
	Merge:     mergeSaaSCategories,
	Lifecycle: resolveLifecycleCtx,
})

// mergeSaaSCategories folds parsed feed categories into catStore: new
// categories are created with all hosts; existing categories get only new
// hosts (additive merge — admin-removed domains are never re-added). Saves
// the store when anything was added. Returns the number of hosts added.
func mergeSaaSCategories(categories []saasfeed.Category) int {
	// Single-writer guard (F3b-3): once the signed activation coordinator owns the live
	// SaaS category store, the legacy RAW syncer must NOT write it — there is exactly one
	// writer, no signed→raw fallback, and no dual writer. While the coordinator is
	// dormant this flag is false and behavior is byte-identical to before.
	if signedFeedOwnsLive() {
		return 0
	}
	added := 0
	for _, feedCat := range categories {
		name := strings.TrimSpace(feedCat.Name)
		if name == "" {
			continue
		}
		existing := catStore.GetByName(name)
		if existing == nil {
			// New category — create it with all hosts.
			_ = catStore.Set(name, feedCat.Hosts, true)
			added += len(feedCat.Hosts)
		} else {
			// Existing category — add only new hosts (additive merge).
			existingSet := make(map[string]bool, len(existing.Hosts))
			for _, h := range existing.Hosts {
				existingSet[strings.ToLower(h)] = true
			}
			var newHosts []string
			for _, h := range feedCat.Hosts {
				if !existingSet[strings.ToLower(h)] {
					newHosts = append(newHosts, h)
				}
			}
			for _, h := range newHosts {
				_ = catStore.AddHost(name, h)
				added++
			}
		}
	}
	if added > 0 {
		catStore.Save()
	}
	return added
}

// GetByName moved home to internal/urlcat with the CategoryStore extraction
// (ADR-0002, policy.go decomposition Phase A).
