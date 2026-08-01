package main

// saas_feed_settings.go — F3a-1 node-local durable holder for the new SaaS
// feed-config fields (roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md §A.2).
//
// SaveAdminSettings rebuilds the whole AdminSettings from live runtime on EVERY
// admin mutation (admin_settings.go:506-508), so any durable field without a live
// owner is silently dropped on the next unrelated save. This holder is that live
// owner for SaaSFeedManaged/Enabled/Protocol/RefreshSeconds and the schema marker:
// it is populated at load (applyAdminServices) and read back into AdminSettings by
// the omnibus save, so an explicit disable survives and the schema marker is not
// reset (which would otherwise re-trigger the migration + a fresh backup on the
// next restart). It is INERT config storage — nothing in F3a-1 consumes it to
// change proxy behavior; the URL stays owned by the legacy syncer.

import "sync"

// saasFeedDurable is the durable feed-config ownership state (excluding the URL,
// which the legacy syncer owns in F3a-1).
type saasFeedDurable struct {
	Managed        bool
	Enabled        bool
	Protocol       string
	RefreshSeconds int64
	SchemaVersion  int
}

var (
	saasFeedDurableMu sync.RWMutex
	// Default: schema at the current version so a FRESH install (no settings file,
	// applyAdminServices never called) persists the current marker on its first
	// save and never spuriously migrates.
	saasFeedDurableState = saasFeedDurable{SchemaVersion: saasStoreSchemaVersion}
)

// setSaaSFeedDurable publishes the durable feed-config state (called at load from
// the resolved+migrated AdminSettings).
func setSaaSFeedDurable(d saasFeedDurable) {
	saasFeedDurableMu.Lock()
	saasFeedDurableState = d
	saasFeedDurableMu.Unlock()
}

// getSaaSFeedDurable returns the current durable feed-config state.
func getSaaSFeedDurable() saasFeedDurable {
	saasFeedDurableMu.RLock()
	defer saasFeedDurableMu.RUnlock()
	return saasFeedDurableState
}

// snapshotSaaSFeedDurable writes the holder's durable fields into s during the
// omnibus SaveAdminSettings rebuild, preserving them across unrelated mutations.
func snapshotSaaSFeedDurable(s *AdminSettings) {
	d := getSaaSFeedDurable()
	s.SaaSFeedManaged = d.Managed
	s.SaaSFeedEnabled = d.Enabled
	s.SaaSFeedProtocol = d.Protocol
	s.SaaSFeedRefreshSeconds = d.RefreshSeconds
	s.SaaSStoreSchemaVersion = d.SchemaVersion
}
