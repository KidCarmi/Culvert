package main

// saas_feed_authority_resolve.go — F3b-4: effective-configuration AUTHORITY resolution
// and the managed-DP mirror write-point.
//
// The runtime lifecycle "loads and classifies effective configuration authority" here,
// BEFORE any recovery or scheduling. On a standalone or control-plane node the authority
// is the node-local durable settings (getSaaSFeedDurable) — the operator/CP edits them
// directly. On a MANAGED data plane the authority is CP-provided and must survive a
// restart with NO live CP: it is read from the durable authority mirror
// (saas_feed_authority.go), fenced against the HA epoch ratchet, and cross-checked
// against the durable override set — never rebuilt from node-local/default settings, and
// never allowed to silently drop CP overrides.

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/KidCarmi/Culvert/internal/catoverride"
)

// globalSaaSFeedAuthorityStore is the process-wide managed-DP authority mirror store. It is
// wired EARLY — before a data plane replays its last-good ConfigSnapshot (F3b-4 finding #2) —
// and re-used by the signed-feed runtime. Nil while unwired (tests / pre-wiring), in which
// case the mirror write-point is a safe no-op.
var globalSaaSFeedAuthorityStore *saasFeedAuthorityStore

// saasFeedDir is the on-disk root for the signed-feed durable stores (generations, floor,
// activation, authority mirror). It mirrors the urlcategories startup slice's derivation
// (filepath.Dir(CategoryOverridesPath)) so the early authority wiring and the later runtime
// wiring target the same directory.
func saasFeedDir() string { return filepath.Join(dataDir, "saas_feed") }

// wireSaaSFeedAuthorityStore constructs + publishes the managed-DP authority mirror store if
// not already wired. It MUST run before startDataPlane replays the last-good snapshot so that
// replay persists the authoritative feed config on the first restart after upgrade — closing
// the finding-#2 window where the store was wired only later (in initURLCategories) and the
// replay's mirror write silently no-op'd, leaving the node waiting_for_authority until the CP
// bumped its config version. Idempotent; the signed-feed runtime re-uses this same instance.
func wireSaaSFeedAuthorityStore() {
	if globalSaaSFeedAuthorityStore != nil {
		return
	}
	dir := saasFeedDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		logger.Printf("SaaSFeedAuthority: cannot create authority store dir: %s", sanitizeLog(err.Error()))
		return
	}
	store, err := newSaaSFeedAuthorityStore(dir)
	if err != nil {
		logger.Printf("SaaSFeedAuthority: cannot wire authority store: %s", sanitizeLog(err.Error()))
		return
	}
	globalSaaSFeedAuthorityStore = store
}

// currentFeedAuthority maps the cluster role to the feed's ownership domain. Read under
// clusterRoleMu to stay race-safe against a control-plane enable/join transition.
func currentFeedAuthority() feedAuthority {
	clusterRoleMu.RLock()
	role := clusterRole.role
	clusterRoleMu.RUnlock()
	switch role {
	case "data-plane":
		return authorityManagedDP
	case "control-plane":
		return authorityControlPlane
	default:
		return authorityStandalone
	}
}

// feedAuthorityResolution is the startup classification of the feed's effective
// configuration authority. It carries the resolved config, the authoritative override
// set + its revision, and the managed-DP readiness verdict.
type feedAuthorityResolution struct {
	Authority feedAuthority // standalone / control-plane / managed-DP

	Config           SaaSFeedConfig        // resolved effective configuration (Enabled=false when not authoritative)
	Overrides        catoverride.Overrides // the authoritative override set to compose
	OverrideRevision string                // override fingerprint (the coordinator's ConfigRevision)

	// Ready reports that authoritative configuration is available and may drive the
	// scheduler when Config.Enabled. WaitingForAuthority is the managed-DP state where
	// the durable authority mirror is missing/corrupt/ambiguous — no network refresh, no
	// policy rebuild from local/default settings; the embedded/fail-closed baseline
	// serves and the operator sees a critical "waiting for authority" state.
	Ready               bool
	WaitingForAuthority bool

	MirrorStatus  saasFeedAuthorityReadStatus // absent for non-managed / unread
	Epoch         int64
	ConfigVersion int64
	CPFingerprint string
	Detail        string
}

// resolveFeedAuthorityInput carries the (pre-read, testable) inputs so the resolver is
// pure: no globals, no I/O beyond the injected mirror read result.
type resolveFeedAuthorityInput struct {
	Authority    feedAuthority
	Durable      saasFeedDurable       // node-local settings (standalone/CP authority)
	Overrides    catoverride.Overrides // the durable override set (overrides.json)
	MirrorRecord saasFeedAuthorityRecord
	MirrorStatus saasFeedAuthorityReadStatus
	EpochFloor   int64 // dpLastSeenEpoch.Load() — the durable fencing floor
}

// resolveFeedAuthority classifies the effective configuration authority. It is PURE
// (all inputs injected) so the full matrix is deterministically testable.
func resolveFeedAuthority(in resolveFeedAuthorityInput) feedAuthorityResolution {
	if in.Authority == authorityManagedDP {
		return resolveManagedDPAuthority(in)
	}
	// Standalone / control-plane: node-local durable settings are authoritative.
	res := feedAuthorityResolution{
		Authority: in.Authority, Ready: true,
		Overrides: in.Overrides, OverrideRevision: saasFeedOverridesFingerprint(in.Overrides),
		MirrorStatus: saasFeedAuthorityAbsent,
	}
	cfg, err := ResolveSaaSFeedConfig(&AdminSettings{
		SaaSFeedManaged:        in.Durable.Managed,
		SaaSFeedEnabled:        in.Durable.Enabled,
		SaaSFeedURL:            in.Durable.URL,
		SaaSFeedProtocol:       in.Durable.Protocol,
		SaaSFeedRefreshSeconds: in.Durable.RefreshSeconds,
	})
	if err != nil {
		// An invalid local configuration is treated as a disabled feed (never a fetch).
		res.Config = SaaSFeedConfig{Protocol: saasFeedProtocolV1}
		res.Detail = "invalid local feed configuration: " + err.Error()
		return res
	}
	res.Config = cfg
	res.Detail = "node-local configuration authority"
	return res
}

// resolveManagedDPAuthority is the managed-DP branch: the durable authority mirror is
// the sole source of the effective configuration; a missing/corrupt/ambiguous mirror is
// WaitingForAuthority (no network, no local-default rebuild).
func resolveManagedDPAuthority(in resolveFeedAuthorityInput) feedAuthorityResolution {
	res := feedAuthorityResolution{
		Authority: authorityManagedDP, MirrorStatus: in.MirrorStatus,
		Config: SaaSFeedConfig{Protocol: saasFeedProtocolV1}, // disabled until authority resolves
	}
	if in.MirrorStatus != saasFeedAuthorityValid {
		res.WaitingForAuthority = true
		res.Detail = fmt.Sprintf("managed data plane: no valid authoritative CP feed configuration (mirror %s); awaiting control-plane snapshot", in.MirrorStatus)
		return res
	}
	rec := in.MirrorRecord
	res.Epoch, res.ConfigVersion, res.CPFingerprint = rec.Epoch, rec.ConfigVersion, rec.CPFingerprint

	// Fencing: the mirror must not sit BELOW the durable epoch floor. A mirror whose
	// epoch trails a later-observed fencing epoch is a stale/conflicting authority — do
	// not act on it; wait for a fresh authoritative snapshot.
	if in.EpochFloor > 0 && rec.Epoch < in.EpochFloor {
		res.WaitingForAuthority = true
		res.Detail = fmt.Sprintf("managed data plane: authority mirror epoch %d is behind the fencing floor %d (CP identity/epoch conflict); awaiting a newer authoritative snapshot", rec.Epoch, in.EpochFloor)
		return res
	}

	// Overrides must be consistent with the epoch the mirror witnessed — otherwise the
	// override data on disk does not match the authoritative policy and composing it
	// would silently apply the wrong (or drop the right) overrides.
	fp := saasFeedOverridesFingerprint(in.Overrides)
	if fp != rec.OverridesFingerprint {
		res.WaitingForAuthority = true
		res.Detail = "managed data plane: durable overrides are inconsistent with the authoritative mirror (ambiguous); awaiting a newer authoritative snapshot"
		return res
	}

	cfg, err := ResolveSaaSFeedConfig(&AdminSettings{
		SaaSFeedManaged:        rec.Managed,
		SaaSFeedEnabled:        rec.Enabled,
		SaaSFeedURL:            rec.URL,
		SaaSFeedProtocol:       rec.Protocol,
		SaaSFeedRefreshSeconds: rec.RefreshSeconds,
	})
	if err != nil {
		// The authoritative configuration itself failed to resolve (should not happen —
		// the mirror was validated on write). Do not fetch; surface it as waiting.
		res.WaitingForAuthority = true
		res.Detail = "managed data plane: authoritative feed configuration is invalid: " + err.Error()
		return res
	}
	res.Config = cfg
	res.Overrides = in.Overrides
	res.OverrideRevision = fp
	res.Ready = true
	res.Detail = fmt.Sprintf("managed data plane: authoritative CP configuration (epoch %d, config v%d)", rec.Epoch, rec.ConfigVersion)
	return res
}

// buildSaaSFeedAuthorityRecord assembles the durable mirror from the current resolved
// authoritative feed config + override set + the accepted snapshot's fencing identity.
// The stored URL is the RESOLVED official URL (never the empty/legacy sentinel).
func buildSaaSFeedAuthorityRecord(d saasFeedDurable, overrides catoverride.Overrides, epoch, configVersion int64, cpFingerprint string) (saasFeedAuthorityRecord, error) {
	resolvedURL, err := resolveFeedURL(d.URL)
	if err != nil {
		return saasFeedAuthorityRecord{}, fmt.Errorf("resolve url: %w", err)
	}
	protocol, err := resolveFeedProtocol(d.Protocol)
	if err != nil {
		return saasFeedAuthorityRecord{}, fmt.Errorf("resolve protocol: %w", err)
	}
	return saasFeedAuthorityRecord{
		SchemaVersion:        saasFeedAuthoritySchemaVersion,
		Protocol:             protocol,
		URL:                  resolvedURL,
		Managed:              d.Managed,
		Enabled:              d.Enabled,
		RefreshSeconds:       d.RefreshSeconds,
		OverridesFingerprint: saasFeedOverridesFingerprint(overrides),
		Epoch:                epoch,
		ConfigVersion:        configVersion,
		CPFingerprint:        cpFingerprint,
	}, nil
}

// persistSaaSFeedAuthorityMirror writes the durable authority mirror on a managed DP
// AFTER an authenticated, fenced, validated CP snapshot has been accepted and applied —
// including the last-good snapshot REPLAYED at startup, because the store is now wired
// early (wireSaaSFeedAuthorityStore, before startDataPlane's replay). So the first restart
// after upgrade durably mirrors the authoritative config without depending on the CP
// bumping its version. It is a no-op on a non-managed node or when the store is still
// unwired. A genuine write failure is logged (non-fatal): the in-memory authoritative
// config still drives this run, the next accepted/replayed snapshot retries, and only a
// managed DP whose mirror write keeps failing falls to WaitingForAuthority on a later
// restart (fail-closed) — never to local defaults.
func persistSaaSFeedAuthorityMirror(snap ConfigSnapshot) {
	if currentFeedAuthority() != authorityManagedDP {
		return
	}
	store := globalSaaSFeedAuthorityStore
	if store == nil {
		return
	}
	rec, err := buildSaaSFeedAuthorityRecord(getSaaSFeedDurable(), globalCategoryOverrides.Get(), snap.Epoch, snap.Version, snap.CAFingerprint)
	if err != nil {
		logger.Printf("SaaSFeedAuthority: cannot build authority mirror (config unresolved, not persisted): %s", sanitizeLog(err.Error()))
		return
	}
	if err := store.Commit(rec); err != nil {
		logger.Printf("SaaSFeedAuthority: durable authority mirror write failed: %s", sanitizeLog(err.Error()))
	}
}
