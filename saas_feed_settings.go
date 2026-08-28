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

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
)

// saasFeedDurable is the durable feed-config ownership state. As of F3a-2 it OWNS
// the URL too: the signed-feed manifest URL is deliberately decoupled from the
// legacy additive syncer (globalSaaSFeed) so that configuring the signed feed
// never points the legacy syncer at manifest.sigstore.json nor triggers a fetch
// (the "critical separation from the legacy SaaS syncer" contract). The legacy
// syncer keeps its own startup URL; nothing here feeds it.
type saasFeedDurable struct {
	Managed        bool
	Enabled        bool
	URL            string
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
// It is the SOLE writer of s.SaaSFeedURL (F3a-2): the legacy syncer no longer
// owns the field, so the signed-feed URL round-trips through the holder alone.
func snapshotSaaSFeedDurable(s *AdminSettings) {
	snapshotSaaSFeedDurableFrom(s, getSaaSFeedDurable())
}

// snapshotSaaSFeedDurableFrom writes an EXPLICIT durable value into s — the
// 2D-B.0c persist-before-apply seam: the fenced settings PUT persists its
// TARGET configuration while the live holder still carries the old one.
func snapshotSaaSFeedDurableFrom(s *AdminSettings, d saasFeedDurable) {
	s.SaaSFeedManaged = d.Managed
	s.SaaSFeedEnabled = d.Enabled
	s.SaaSFeedURL = d.URL
	s.SaaSFeedProtocol = d.Protocol
	s.SaaSFeedRefreshSeconds = d.RefreshSeconds
	s.SaaSStoreSchemaVersion = d.SchemaVersion
}

// saasFeedSettingsRevision is the narrow content-derived optimistic-concurrency
// revision of the signed-feed CONFIGURATION (2D-B §25): managed, enabled, the
// RESOLVED official URL (an unset URL and the explicit official endpoint hash
// identically — they are the same configuration), protocol, refresh, and the
// schema marker. Nothing else — runtime status never moves it. Length-framed
// so field boundaries are unambiguous.
func saasFeedSettingsRevision(d saasFeedDurable) string {
	resolvedURL := d.URL
	if u, err := resolveFeedURL(d.URL); err == nil {
		resolvedURL = u
	}
	h := sha256.New()
	frame := func(field string) {
		_, _ = fmt.Fprintf(h, "%d:%s|", len(field), field)
	}
	frame(fmt.Sprintf("managed=%t", d.Managed))
	frame(fmt.Sprintf("enabled=%t", d.Enabled))
	frame("url=" + resolvedURL)
	frame("protocol=" + d.Protocol)
	frame(fmt.Sprintf("refresh=%d", d.RefreshSeconds))
	frame(fmt.Sprintf("schema=%d", d.SchemaVersion))
	return hex.EncodeToString(h.Sum(nil))
}

// resolvedSaaSFeedConfig applies the F0 §3 single-source rule to the current
// durable holder, returning the effective (managed, enabled, url, protocol,
// refresh) feed configuration. Pure/read-only — it neither fetches nor arms
// anything. Shared by the admin API read path and the CP→DP capture so both
// agree on the resolved values.
func resolvedSaaSFeedConfig() (SaaSFeedConfig, error) {
	return resolveSaaSFeedConfigFrom(getSaaSFeedDurable())
}

// resolveSaaSFeedConfigFrom resolves the effective feed configuration from an
// ALREADY-CAPTURED durable value, so a view that has captured `d` can render
// raw fields, revision, and the resolved block from the SAME state — calling
// resolvedSaaSFeedConfig() after capturing `d` is a second holder read a
// concurrent writer can land between, pairing one configuration's raw fields
// with another's resolution (POST-2D-A COHERENT-READ CORRECTION DISCOVERED
// DURING 2D-B REVIEW). Pure/read-only.
func resolveSaaSFeedConfigFrom(d saasFeedDurable) (SaaSFeedConfig, error) {
	return ResolveSaaSFeedConfig(&AdminSettings{
		SaaSFeedManaged:        d.Managed,
		SaaSFeedEnabled:        d.Enabled,
		SaaSFeedURL:            d.URL,
		SaaSFeedProtocol:       d.Protocol,
		SaaSFeedRefreshSeconds: d.RefreshSeconds,
	})
}

// installSaaSFeedDurable is the ONE runtime install path for the signed-feed
// configuration on an authoritative (CP/standalone) node outside the settings
// PUT itself (2D-B final correction, Blocker E — §§17–19). The derivation
// from the current holder, the durable AdminSettings write, and the runtime
// holder publish all run inside ONE adminSettingsMu critical section — the
// same transaction shape as the fenced PUT — so no writer can land between
// another writer's precondition and its apply, and the runtime holder, the
// GET revision, and the durable file can never disagree about which write
// won.
//
// WRITER DOMAIN (audited §17):
//   - putSaaSFeedSettings (v2 fenced + legacy): adminSaveOverrides with
//     precondition + saasFeed target + applyOnSuccess — in the domain.
//   - config import (importSaaSFeedConfig): THIS helper — in the domain.
//   - config-version rollback (applyPACFromBackup's feed block): THIS helper —
//     in the domain (called under configRollbackMu; lock order is
//     configRollbackMu → adminSettingsMu, acyclic — nothing acquires
//     configRollbackMu while holding adminSettingsMu, and the signed-feed
//     scheduler's runMu is never taken by any of these writers).
//   - CP→DP snapshot apply (applySnapshotSaaSFeed): SEPARATE ownership
//     domain by design — on a managed data plane the CP is authoritative,
//     every local feed writer above refuses (isManagedDataPlane), and the
//     apply is deliberately holder-only/in-memory (never admin_settings.json,
//     see its comment), so it shares no writers to serialize against.
//   - startup (applyAdminServices via LoadAdminSettings): pre-listener, before
//     any runtime writer exists — exempt by ordering.
//
// The overlay runs INSIDE the critical section against the holder state
// current at that moment (never a stale pre-lock read), must be pure, and
// returns the full target state. A persist failure means the target was never
// applied — runtime and disk stay in agreement.
func installSaaSFeedDurable(overlay func(cur saasFeedDurable) saasFeedDurable) error {
	var next saasFeedDurable
	return saveAdminSettingsWithOverrides(adminSaveOverrides{
		saasFeed: &next,
		precondition: func() error {
			next = overlay(getSaaSFeedDurable())
			return nil
		},
		applyOnSuccess: func() { setSaaSFeedDurable(next) },
	})
}

// errSaaSSettingsRevisionConflict marks a failed settings revision fence: the
// asserted revision no longer matches inside the serialized save domain. The
// handler renders it as the structured 409.
var errSaaSSettingsRevisionConflict = errSentinel("saas feed settings revision conflict")

// errSentinel builds a simple sentinel error value.
type errSentinel string

func (e errSentinel) Error() string { return string(e) }
