package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/session"
)

// ─── ConfigSnapshot ───────────────────────────────────────────────────────────

// ConfigSnapshot is the canonical, immutable view of proxy configuration that
// the Control Plane distributes to Data Plane nodes.
type ConfigSnapshot struct {
	Version int64 `json:"version"`
	// Epoch is the issuing CP's fencing epoch (ADR-0005 S3; 0 = legacy).
	// DPs reject snapshots below their last-seen epoch and ratchet forward
	// otherwise, so a fenced-out zombie CP cannot roll a DP's config back.
	Epoch                 int64    `json:"epoch,omitempty"`
	BlockedHosts          []string `json:"blocked_hosts"`
	IPFilterMode          string   `json:"ip_filter_mode"`
	IPList                []string `json:"ip_list"`
	RateLimitRPM          int      `json:"rate_limit_rpm"`
	RateLimitExempt       []string `json:"rate_limit_exempt"` // IP/CIDR rate-limit exempt list; nil→skip, []→clear on DP. NO omitempty: an empty list must serialize as [] so removing the last exemption propagates as a clear, not a skip.
	AuthEnabled           bool     `json:"auth_enabled"`
	DefaultAuthOutcome    string   `json:"default_auth_outcome"` // "Default" | "Exempt"; informational (DP does not apply it)
	ProxyBaseURL          string   `json:"proxy_base_url,omitempty"`
	TrustForwardedHeaders bool     `json:"trust_forwarded_headers,omitempty"`
	UpdatedAt             string   `json:"updated_at"`
	CAFingerprint         string   `json:"ca_fingerprint,omitempty"` // cluster CA SHA-256 fingerprint; DP triggers renewal when this changes

	// Full policy sync — all policy state pushed from CP to DP.
	DefaultAction     string           `json:"default_action"`         // "allow" or "deny"
	PolicyRules       []PolicyRule     `json:"policy_rules,omitempty"` // ordered policy rules
	PolicyVersion     int64            `json:"policy_version"`         // monotonic policy version
	SSLBypassPatterns []string         `json:"ssl_bypass_patterns,omitempty"`
	URLCategories     []CategoryEntry  `json:"url_categories,omitempty"`
	FileProfiles      []FileExtProfile `json:"file_profiles,omitempty"`
	RewriteRules      []RewriteRule    `json:"rewrite_rules,omitempty"`
	DPIPatterns       []string         `json:"dpi_patterns,omitempty"`
	MaxConnsPerIP     int              `json:"max_conns_per_ip"`

	// HA: CP addresses that DPs should know about for automatic failover.
	// Populated by the leader with its own address + standby address.
	// DPs update their connection list on every config sync — no manual
	// --dp-cp-addr configuration needed.
	CPAddresses []string `json:"cp_addresses,omitempty"`

	// PAC distribution: sync PAC exclusions from CP to DPs.
	PACExclusions []string `json:"pac_exclusions,omitempty"`

	// Threat feed sync: include feed data so DPs don't fetch independently.
	// ThreatDomainAllowlist deliberately has NO omitempty: an admin-cleared
	// (zero-entry) allowlist must serialize as `[]` and propagate as an
	// explicit wipe — the allowlist now gates CheckURL/CheckDomain verdicts
	// at lookup time, so a DP left holding a stale allowlist would keep
	// masking domains the CP no longer exempts (fail-open). Mirrors the
	// RateLimitExempt WireWipeCapable precedent and the feedDB
	// DomainAllowlist no-omitempty fix (§3.3).
	ThreatFeedURLs        map[string]int64 `json:"threat_feed_urls,omitempty"`
	ThreatFeedDomains     map[string]int64 `json:"threat_feed_domains,omitempty"`
	ThreatDomainAllowlist []string         `json:"threat_domain_allowlist"`

	// Session secret sync: shared HMAC key so sessions are valid across nodes.
	SessionHMAC string `json:"session_hmac,omitempty"`

	// IdP profile sync: full OIDC/SAML provider config for DP-local auth.
	// Redacted from unauthenticated GetConfig callers alongside SessionHMAC.
	IdPProfiles []*IdPProfile `json:"idp_profiles,omitempty"`

	// Bandwidth / QoS policies synced from CP to DP.
	BandwidthPolicies []BandwidthPolicy `json:"bandwidth_policies,omitempty"`

	// Node group definitions synced from CP to DP.
	NodeGroups []NodeGroup `json:"node_groups,omitempty"`

	// Category groups for policy rules.
	CategoryGroups []CategoryGroup `json:"category_groups,omitempty"`

	// Global file-block extension list (day-3 audit CRIT-2).
	FileBlockExtensions []string `json:"file_block_extensions,omitempty"`

	// OTLP endpoint for metrics + traces export (day-3 audit CRIT-3).
	OTLPEndpoint string `json:"otlp_endpoint,omitempty"`
}

// ConfigSnapshot per-slice size caps (H5 fix).
//
// Each cap is a hard upper bound on the number of entries a single
// ConfigSnapshot may carry. Sized well above realistic deployments to
// avoid breaking legitimate clusters; a malicious or compromised
// Control Plane that pushes a snapshot exceeding ANY one of these
// causes the entire snapshot to be rejected (no partial application).
//
// Without these caps, a CP could pack the gRPC frame (4 MiB by
// default) full of small entries — ~200 k blocked-host strings, or
// many policy rules — and force every DP to allocate proportional
// memory + CPU on every poll cycle.
const (
	maxSnapBlockedHosts        = 200_000
	maxSnapIPList              = 200_000
	maxSnapPolicyRules         = 10_000
	maxSnapSSLBypassPatterns   = 10_000
	maxSnapURLCategories       = 200_000
	maxSnapFileProfiles        = 1_000
	maxSnapFileBlockExtensions = 10_000
	maxSnapRewriteRules        = 5_000
	maxSnapDPIPatterns         = 5_000
	maxSnapCPAddresses         = 100
	maxSnapPACExclusions       = 10_000
	maxSnapRateLimitExempt     = 10_000
	maxSnapThreatFeedURLs      = 500_000
	maxSnapThreatFeedDomains   = 500_000
	maxSnapDomainAllowlist     = 10_000
	maxSnapBandwidthPolicies   = 1_000
	maxSnapNodeGroups          = 1_000
	maxSnapCategoryGroups      = 1_000
	maxSnapIdPProfiles         = 1_000
)

// validateConfigSnapshot enforces the per-slice caps above. Returns an
// error naming the first field that overflows; nil when the snapshot is
// within bounds. Callers must reject the whole snapshot on error — the
// goal is to prevent partial application of an attacker-shaped payload.
func validateConfigSnapshot(snap ConfigSnapshot) error {
	checks := []struct {
		name  string
		size  int
		limit int
	}{
		{"blocked_hosts", len(snap.BlockedHosts), maxSnapBlockedHosts},
		{"ip_list", len(snap.IPList), maxSnapIPList},
		{"policy_rules", len(snap.PolicyRules), maxSnapPolicyRules},
		{"ssl_bypass_patterns", len(snap.SSLBypassPatterns), maxSnapSSLBypassPatterns},
		{"url_categories", len(snap.URLCategories), maxSnapURLCategories},
		{"file_profiles", len(snap.FileProfiles), maxSnapFileProfiles},
		{"file_block_extensions", len(snap.FileBlockExtensions), maxSnapFileBlockExtensions},
		{"rewrite_rules", len(snap.RewriteRules), maxSnapRewriteRules},
		{"dpi_patterns", len(snap.DPIPatterns), maxSnapDPIPatterns},
		{"cp_addresses", len(snap.CPAddresses), maxSnapCPAddresses},
		{"pac_exclusions", len(snap.PACExclusions), maxSnapPACExclusions},
		{"rate_limit_exempt", len(snap.RateLimitExempt), maxSnapRateLimitExempt},
		{"threat_feed_urls", len(snap.ThreatFeedURLs), maxSnapThreatFeedURLs},
		{"threat_feed_domains", len(snap.ThreatFeedDomains), maxSnapThreatFeedDomains},
		{"threat_domain_allowlist", len(snap.ThreatDomainAllowlist), maxSnapDomainAllowlist},
		{"bandwidth_policies", len(snap.BandwidthPolicies), maxSnapBandwidthPolicies},
		{"node_groups", len(snap.NodeGroups), maxSnapNodeGroups},
		{"category_groups", len(snap.CategoryGroups), maxSnapCategoryGroups},
		{"idp_profiles", len(snap.IdPProfiles), maxSnapIdPProfiles},
	}
	for _, c := range checks {
		if c.size > c.limit {
			return fmt.Errorf("config snapshot %s=%d exceeds cap %d", c.name, c.size, c.limit)
		}
	}
	return nil
}

// ─── ConfigStore ──────────────────────────────────────────────────────────────

// ConfigStore holds the current ConfigSnapshot and notifies subscribers when
// it changes.  Used by the Control Plane to publish updates.
type ConfigStore struct {
	mu      sync.RWMutex
	snap    ConfigSnapshot
	version int64
	// versionPath, when non-empty, is the durable floor file for version
	// (CHAOS-01). Armed by armVersionPersistence at CP activation; empty in
	// DP-only processes and in tests that build a bare ConfigStore.
	versionPath string
	subs        []chan struct{}
}

var globalConfigStore = &ConfigStore{}

// cpConfigVersionFile persists the CP's published config-version counter
// (CHAOS-01). Without it, ConfigStore.version restarted at 0 on every CP
// restart while long-running DPs still held the pre-restart value — the
// DP-side "snap.Version <= lastVersion" short-circuit then silently
// suppressed ALL post-restart config changes (new blocks included) until
// the counter caught back up, with no log line or metric on either side.
const cpConfigVersionFile = "cp_config_version.json"

type cpConfigVersionState struct {
	Version int64 `json:"version"`
}

// replicatedLeaderConfigVersion is the highest config-snapshot Version an HA
// standby has replicated from its leader (CHAOS-01 — HA-promotion follow-up).
// applyHABundle ratchets it forward; armVersionPersistence folds it into the
// version-floor seed so a freshly promoted standby publishes strictly above
// every version the old leader ever issued.
//
// Why the wall-clock seed alone is not enough on promotion: the promoted node
// was a standby, so its own cp_config_version.json floor is absent/stale and
// its ConfigStore.version never advanced (applyConfigSnapshot does not touch
// it). If the standby's clock lags the old leader, OR the leader's counter
// outran elapsed seconds (many rapid config updates), the reseed would land at
// or below the DPs' lastVersion and each DP's fetchAndApply would silently
// short-circuit (snap.Version <= lastVersion), applying NO post-failover config.
var replicatedLeaderConfigVersion atomic.Int64

// noteReplicatedLeaderVersion raises the replicated-leader-version watermark
// (monotonic; never lowers). Called by applyHABundle with the leader's bundle
// Version so a later promotion can seed the version floor above it.
func noteReplicatedLeaderVersion(v int64) {
	for {
		cur := replicatedLeaderConfigVersion.Load()
		if v <= cur {
			return
		}
		if replicatedLeaderConfigVersion.CompareAndSwap(cur, v) {
			return
		}
	}
}

// armVersionPersistence seeds the version counter with
// max(current, persisted floor, wall clock, replicated leader version) and
// enables floor persistence on every subsequent Update. The seeds are
// complementary fail-safes: the persisted floor survives clock rollback (VM
// snapshot restore, NTP step-back); the wall-clock seed survives a deleted or
// corrupt floor file; and the replicated-leader-version seed makes a freshly
// promoted HA standby publish above the old leader's independent counter even
// when the standby's own floor is absent/stale and its clock lags the leader.
// A corrupt/unreadable floor is therefore recoverable, not fatal.
func (s *ConfigStore) armVersionPersistence(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.versionPath = path
	seed := time.Now().Unix()
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		var st cpConfigVersionState
		if jerr := json.Unmarshal(data, &st); jerr != nil {
			logger.Printf("ControlPlane: config-version floor %s corrupt (%v) — reseeding from clock", path, jerr)
		} else if st.Version > seed {
			seed = st.Version
		}
	case !os.IsNotExist(err):
		logger.Printf("ControlPlane: config-version floor read failed (%v) — reseeding from clock", err)
	}
	// Fold in the leader version this node replicated as a standby (0 when it
	// never was one) so a promotion's first publish clears everything the old
	// leader issued — the DP short-circuit guard depends on it.
	if rv := replicatedLeaderConfigVersion.Load(); rv > seed {
		seed = rv
	}
	if seed > s.version {
		s.version = seed
	}
}

// persistVersionLocked writes the version floor. Called with s.mu held so
// floors are written in version order (a lower version can never land after
// a higher one). Config updates are admin-action-rate, so the fsync under
// the lock is not a hot-path cost. Failure is non-fatal: the wall-clock
// seed in armVersionPersistence recovers monotonicity on the next restart.
func (s *ConfigStore) persistVersionLocked() {
	if s.versionPath == "" {
		return
	}
	data, err := json.Marshal(cpConfigVersionState{Version: s.version})
	if err == nil {
		err = atomicWriteFile(s.versionPath, data, 0o600)
	}
	if err != nil {
		logger.Printf("ControlPlane: config-version floor persist failed: %v", err)
	}
}

const dpLastGoodConfigSnapshotFile = "dp_last_config_snapshot.json"

type dpLastGoodConfigSnapshotStatus struct {
	Loaded       bool
	LoadError    string
	SavedVersion int64
	SaveError    string
}

var dpLastGoodConfigSnapshotState atomic.Value // dpLastGoodConfigSnapshotStatus
var dpControlPlanePollFailing atomic.Bool

// Update atomically replaces the snapshot and notifies all subscribers.
func (s *ConfigStore) Update(snap ConfigSnapshot) {
	s.mu.Lock()
	s.version++
	snap.Version = s.version
	snap.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	s.snap = snap
	s.persistVersionLocked()
	subs := append([]chan struct{}{}, s.subs...)
	s.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	logger.Printf("ControlPlane: config v%d published", snap.Version)
}

func publishCurrentConfigSnapshot() {
	globalConfigStore.Update(CurrentConfigSnapshot())
}

// Get returns the current snapshot.
func (s *ConfigStore) Get() ConfigSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap
}

// Subscribe returns a channel that receives a signal on every config update.
func (s *ConfigStore) Subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	s.mu.Lock()
	s.subs = append(s.subs, ch)
	s.mu.Unlock()
	return ch
}

// lastSeenCAFingerprint tracks the most recent cluster CA fingerprint the DP has seen.
// When this changes, the DP knows the CP rotated the CA and triggers immediate cert renewal.
var lastSeenCAFingerprint atomic.Value // string

// caRotationNotify is signaled when the DP detects a CA rotation from the CP.
// The dpCertRenewalLoop listens on this channel to trigger immediate renewal.
var caRotationNotify = make(chan struct{}, 1)

// applyConfigSnapshot updates all local proxy state from a received snapshot.
func applyConfigSnapshot(snap ConfigSnapshot) {
	// ADR-0005 S3: reject snapshots from a fenced-out (stale-epoch) CP
	// before ANY state mutation; ratchet the last-seen epoch forward
	// otherwise. Epoch 0 is accepted only while the ratchet is unseeded
	// (pure-legacy cluster). The DP poller (fetchAndApply) runs this same
	// check EARLIER — before its external-auth/IdP application, last-good
	// persist, and version advance — this one covers the other callers.
	if !dpObserveEpoch("config snapshot", snap.Epoch) {
		return
	}
	// H5: reject the entire snapshot if any per-slice cap is exceeded.
	// Logged at info; the next CP poll cycle will retry with a fresh
	// snapshot once the operator corrects the CP-side input. No partial
	// state mutation occurs on rejection.
	if err := validateConfigSnapshot(snap); err != nil {
		logger.Printf("DataPlane: rejecting config snapshot v%d: %v", snap.Version, err)
		return
	}

	applySnapshotPolicyAndTraffic(snap)
	applySnapshotClusterRuntime(snap)

	// IdP profiles. ReplaceAll compiles every enabled provider before swapping
	// the live registry, so a bad CP-side IdP update does not break the DP's
	// currently working SAML/OIDC providers. A rejection ABORTS the remaining
	// (extended) state below — pre-existing ordering, preserved by the split.
	if err := syncSnapshotIdPProfiles(snap); err != nil {
		logger.Printf("DataPlane: IdP profile sync rejected: %v", err)
		return
	}

	applySnapshotExtendedState(snap)

	logger.Printf("DataPlane: applied config v%d (%d blocked hosts, %d rules, ip_mode=%s, rate=%d rpm)",
		snap.Version, len(snap.BlockedHosts), len(snap.PolicyRules), snap.IPFilterMode, snap.RateLimitRPM)
}

// applySnapshotPolicyAndTraffic applies the traffic-control and policy
// slices of a snapshot (split from applyConfigSnapshot for gocognit; order
// preserved verbatim).
func applySnapshotPolicyAndTraffic(snap ConfigSnapshot) {
	// Blocklist — in-place feed-entry replacement preserves the
	// package-global bl's path / mode / manual / exceptions (the
	// DP-local state that isn't in the cluster snapshot). The
	// previous wholesale `bl = newBL` pattern zeroed those local
	// fields and orphaned the persistence path so caller-side Save
	// became a no-op (CL-1 final gap, P3.4). ReplaceFeedEntries
	// touches only exact + wildcards under bl.mu.Lock; bl.Save()
	// then persists via the Bucket-4-hardened atomicWriteFile path.
	bl.ReplaceFeedEntries(snap.BlockedHosts)
	bl.Save()

	// IP filter.
	newIPF := &IPFilter{single: map[string]bool{}}
	newIPF.SetMode(snap.IPFilterMode)
	for _, ip := range snap.IPList {
		if err := newIPF.Add(ip); err != nil {
			logger.Printf("DataPlane: invalid IP %q: %v", ip, err)
		}
	}
	ipf = newIPF

	// Rate limiter.
	if snap.RateLimitRPM != rl.Limit() {
		rl.Configure(snap.RateLimitRPM, time.Minute)
	}
	// Rate-limit exemptions. nil→skip (older CP / field absent), []→clear,
	// populated→replace — mirrors the config-version rollback surface
	// (configversion.go applyConfigBackup). CurrentConfigSnapshot always
	// sends a non-nil slice, so a steady-state CP push keeps DP exemptions in
	// lock-step with the CP whitelist instead of silently leaving DP nodes
	// enforcing rate limits the operator exempted on the CP.
	if snap.RateLimitExempt != nil {
		rl.ReplaceExemptions(snap.RateLimitExempt)
	}

	applyExternalAuthSnapshotSettings(snap)

	// Default policy action.
	if snap.DefaultAction != "" {
		setDefaultPolicyAction(snap.DefaultAction)
	}

	// Policy rules.
	if snap.PolicyRules != nil {
		policyStore.ReplaceAll(snap.PolicyRules)
		policyStore.Save()
	}

	// SSL bypass patterns.
	if snap.SSLBypassPatterns != nil {
		if err := sslBypass.Set(snap.SSLBypassPatterns); err != nil {
			logger.Printf("DataPlane: SSL bypass patterns: %v", err)
		} else {
			// P3.4 caller-side persist (Bucket-4 fsync-safe Save
			// hardened in PR #246).
			sslBypass.Save()
		}
	}

	// URL categories.
	if snap.URLCategories != nil {
		catStore.ReplaceAll(snap.URLCategories)
		// P3.4 caller-side persist (Bucket-4 fsync-safe Save
		// hardened in PR #246).
		catStore.Save()
	}

	// File profiles.
	if snap.FileProfiles != nil {
		globalProfileStore.ReplaceAll(snap.FileProfiles)
	}

	// Rewrite rules.
	if snap.RewriteRules != nil {
		rewriter.SetRules(snap.RewriteRules)
	}

	// DPI patterns.
	if snap.DPIPatterns != nil {
		if err := dpiScanner.Set(snap.DPIPatterns); err != nil {
			logger.Printf("DataPlane: DPI patterns: %v", err)
		} else {
			// P3.4 caller-side persist (Bucket-4 fsync-safe Save
			// hardened in PR #246).
			dpiScanner.Save()
		}
	}

	// Connection limits.
	if snap.MaxConnsPerIP > 0 {
		connLimiter.Enable(snap.MaxConnsPerIP)
	}
}

// applySnapshotClusterRuntime applies the cluster-runtime slices of a
// snapshot: CA-rotation detection, CP addresses, PAC, threat feed, and the
// session secret (split from applyConfigSnapshot for gocognit; order
// preserved verbatim).
func applySnapshotClusterRuntime(snap ConfigSnapshot) {
	// Detect cluster CA rotation: if the fingerprint changed, trigger immediate cert renewal.
	if snap.CAFingerprint != "" {
		prev, _ := lastSeenCAFingerprint.Load().(string)
		if prev != "" && prev != snap.CAFingerprint {
			logger.Printf("DataPlane: cluster CA rotated (fingerprint changed) — triggering immediate cert renewal")
			select {
			case caRotationNotify <- struct{}{}:
			default:
			}
		}
		lastSeenCAFingerprint.Store(snap.CAFingerprint)
	}

	// HA: update DP's CP address list for automatic failover discovery.
	if len(snap.CPAddresses) > 0 {
		updateDPAddresses(snap.CPAddresses)
	}

	// PAC exclusions.
	if snap.PACExclusions != nil {
		cur := pacStore.Get()
		cur.Exclusions = snap.PACExclusions
		if err := pacStore.Set(cur); err != nil {
			logger.Printf("DataPlane: PAC exclusions: %v", err)
		}
	}

	if snap.ThreatDomainAllowlist != nil {
		// Allowlist masking happens at LOOKUP time (CheckURL/CheckDomain);
		// ImportFeedData does not consult the allowlist. Applying the
		// allowlist first merely closes the transient window where a
		// freshly imported domain could block before its exemption lands.
		// The nil-guard keeps snapshots from an older CP (field omitted)
		// from wiping the DP's allowlist; a new CP always sends the field
		// (no omitempty), so an explicit `[]` clear DOES propagate.
		if err := globalThreatFeed.SetDomainAllowlist(snap.ThreatDomainAllowlist); err != nil {
			logger.Printf("DataPlane: threat feed domain allowlist applied in memory but failed to persist: %v", err)
		}
	}

	// Threat feed data (only if populated — can be large).
	if len(snap.ThreatFeedURLs) > 0 || len(snap.ThreatFeedDomains) > 0 {
		globalThreatFeed.ImportFeedData(snap.ThreatFeedURLs, snap.ThreatFeedDomains)
		// P3.4 caller-side persist (Bucket-4 fsync-safe Save hardened
		// in PR #246). ImportFeedData does NOT auto-persist;
		// SetDomainAllowlist above DOES, so the Save call is paired
		// only with ImportFeedData here.
		globalThreatFeed.Save()
		logger.Printf("DataPlane: imported threat feed (%d URLs, %d domains)",
			len(snap.ThreatFeedURLs), len(snap.ThreatFeedDomains))
	}

	applySnapshotSessionSecret(snap)
}

// applySnapshotSessionSecret installs the CP-synced session HMAC when it is
// present and well-formed (hex, ≥32 bytes).
func applySnapshotSessionSecret(snap ConfigSnapshot) {
	if snap.SessionHMAC == "" {
		return
	}
	key, err := hex.DecodeString(snap.SessionHMAC)
	switch {
	case err != nil:
		logger.Printf("DataPlane: invalid session secret hex: %v", err)
	case len(key) >= 32:
		// Synchronized setter — this runs at runtime while concurrent
		// requests compute session MACs (internal/session owns the lock).
		session.SetSigningKey(key)
		logger.Printf("DataPlane: session secret synced from control plane")
	}
}

// applySnapshotExtendedState applies the post-IdP slices of a snapshot —
// everything the IdP-sync early return is allowed to abort (split from
// applyConfigSnapshot for gocognit; order preserved verbatim).
func applySnapshotExtendedState(snap ConfigSnapshot) {
	// Bandwidth / QoS policies.
	if snap.BandwidthPolicies != nil && globalBandwidth != nil {
		globalBandwidth.ReplaceAll(snap.BandwidthPolicies)
	}

	// Category groups.
	if snap.CategoryGroups != nil {
		globalCategoryGroups.ReplaceAll(snap.CategoryGroups)
		// P3.4 caller-side persist (Bucket-4 fsync-safe Save
		// hardened in PR #246).
		globalCategoryGroups.Save()
	}

	// Global file-block extensions (CRIT-2).
	// CL-13: ReplaceAll triggers exactly one atomicWriteFile call
	// regardless of len(snap.FileBlockExtensions). The previous
	// ClearAll + per-extension Add loop produced N+1 fsynced writes
	// per snapshot apply (cap 10_000 per maxSnapFileBlockExtensions).
	if snap.FileBlockExtensions != nil {
		fileBlocker.ReplaceAll(snap.FileBlockExtensions)
	}

	// OTLP endpoint (CRIT-3).
	if snap.OTLPEndpoint != "" {
		if !globalOTLP.Enabled() || globalOTLP.Endpoint() != snap.OTLPEndpoint {
			globalOTLP.Configure(snap.OTLPEndpoint, nil)
			globalOTLPTraces.Configure(snap.OTLPEndpoint, nil)
		}
	} else if globalOTLP.Enabled() {
		globalOTLP.Stop()
		globalOTLPTraces.Stop()
	}

	// Node groups.
	if snap.NodeGroups != nil && globalNodeGroups != nil {
		globalNodeGroups.ReplaceAll(snap.NodeGroups)
	}
}

func applyExternalAuthSnapshotSettings(snap ConfigSnapshot) {
	// These must be applied before IdP profiles compile so SAML SP metadata
	// and OIDC redirect URIs use the same public origin on every DP.
	SetProxyBaseURL(snap.ProxyBaseURL)
	trustForwardedHeaders = snap.TrustForwardedHeaders
}

func syncSnapshotIdPProfiles(snap ConfigSnapshot) error {
	if snap.IdPProfiles == nil {
		return nil
	}
	if err := idpRegistry.ReplaceAll(snap.IdPProfiles); err != nil {
		return fmt.Errorf("idp profile sync: %w", err)
	}
	logger.Printf("DataPlane: synced %d IdP profile(s) from control plane", len(snap.IdPProfiles))
	return nil
}

func dpLastGoodConfigSnapshotPath() string {
	return filepath.Join(dataDir, dpLastGoodConfigSnapshotFile)
}

func loadDPLastGoodConfigSnapshot() (ConfigSnapshot, error) {
	path := dpLastGoodConfigSnapshotPath()
	data, err := os.ReadFile(path)
	if err != nil {
		dpLastGoodConfigSnapshotState.Store(dpLastGoodConfigSnapshotStatus{LoadError: err.Error()})
		return ConfigSnapshot{}, err
	}
	var snap ConfigSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		dpLastGoodConfigSnapshotState.Store(dpLastGoodConfigSnapshotStatus{LoadError: err.Error()})
		return ConfigSnapshot{}, err
	}
	if err := validateConfigSnapshot(snap); err != nil {
		dpLastGoodConfigSnapshotState.Store(dpLastGoodConfigSnapshotStatus{LoadError: err.Error()})
		return ConfigSnapshot{}, err
	}
	dpLastGoodConfigSnapshotState.Store(dpLastGoodConfigSnapshotStatus{Loaded: true, SavedVersion: snap.Version})
	return snap, nil
}

func applyDPLastGoodConfigSnapshot() (ConfigSnapshot, error) {
	snap, err := loadDPLastGoodConfigSnapshot()
	if err != nil {
		return ConfigSnapshot{}, err
	}
	applyExternalAuthSnapshotSettings(snap)
	if err := syncSnapshotIdPProfiles(snap); err != nil {
		return ConfigSnapshot{}, err
	}
	snapForApply := snap
	snapForApply.IdPProfiles = nil
	applyConfigSnapshot(snapForApply)
	logger.Printf("DataPlane: applied last-known-good config snapshot v%d from %s", snap.Version, dpLastGoodConfigSnapshotPath())
	return snap, nil
}

func mergeCPAddresses(primary string, peers []string) string {
	addrs := make([]string, 0, 1+len(peers))
	seen := make(map[string]bool, 1+len(peers))
	for _, addr := range append([]string{primary}, peers...) {
		addr = strings.TrimSpace(addr)
		if addr == "" || seen[addr] {
			continue
		}
		seen[addr] = true
		addrs = append(addrs, addr)
	}
	return strings.Join(addrs, ",")
}

func persistDPLastGoodConfigSnapshot(snap ConfigSnapshot) {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		setDPLastGoodConfigSnapshotSaveError(snap.Version, err)
		logger.Printf("DataPlane: last-known-good config marshal failed: %v", err)
		return
	}
	path := dpLastGoodConfigSnapshotPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		setDPLastGoodConfigSnapshotSaveError(snap.Version, err)
		logger.Printf("DataPlane: last-known-good config mkdir failed: %v", err)
		return
	}
	if err := atomicWriteFile(path, data, 0o600); err != nil {
		setDPLastGoodConfigSnapshotSaveError(snap.Version, err)
		logger.Printf("DataPlane: last-known-good config persist failed: %v", err)
		return
	}
	dpLastGoodConfigSnapshotState.Store(dpLastGoodConfigSnapshotStatus{Loaded: true, SavedVersion: snap.Version})
}

func setDPLastGoodConfigSnapshotSaveError(version int64, err error) {
	st, _ := dpLastGoodConfigSnapshotState.Load().(dpLastGoodConfigSnapshotStatus)
	st.SavedVersion = version
	st.SaveError = err.Error()
	dpLastGoodConfigSnapshotState.Store(st)
}

// CurrentConfigSnapshot builds a ConfigSnapshot from the current live state.
// Used by the Control Plane to serve the initial configuration.
func CurrentConfigSnapshot() ConfigSnapshot {
	snap := ConfigSnapshot{
		Epoch:                 globalHA.CurrentEpoch(), // ADR-0005 S3: DP-side fence input
		BlockedHosts:          bl.List(),
		IPFilterMode:          ipf.Mode(),
		IPList:                ipf.List(),
		RateLimitRPM:          rl.Limit(),
		AuthEnabled:           cfg.AuthEnabled(),
		DefaultAuthOutcome:    string(cfg.DefaultAuthOutcome()),
		ProxyBaseURL:          cfg.ProxyBaseURL(),
		TrustForwardedHeaders: trustForwardedHeaders,
	}
	if fp := globalClusterCA.CACertFingerprint(); fp != "" {
		snap.CAFingerprint = fp
	}

	// Full policy sync.
	snap.DefaultAction = defaultPolicyAction()
	snap.PolicyRules = policyStore.List()
	pv, _ := policyStore.policyVersion()
	snap.PolicyVersion = pv
	snap.SSLBypassPatterns = sslBypass.List()
	cats := catStore.All()
	snap.URLCategories = cats
	profiles := globalProfileStore.List()
	fpSnap := make([]FileExtProfile, len(profiles))
	for i, p := range profiles {
		fpSnap[i] = *p
	}
	snap.FileProfiles = fpSnap
	snap.RewriteRules = rewriter.List()
	snap.DPIPatterns = dpiScanner.List()
	snap.MaxConnsPerIP = connLimiter.MaxPerIP()

	// HA: include all CP addresses so DPs auto-discover failover targets.
	snap.CPAddresses = buildCPAddressList()

	// PAC exclusions.
	pacCfg := pacStore.Get()
	snap.PACExclusions = pacCfg.Exclusions
	snap.RateLimitExempt = rl.ListExemptions()

	// Threat feed data.
	if globalThreatFeed.Enabled() {
		snap.ThreatFeedURLs = globalThreatFeed.ExportURLs()
		snap.ThreatFeedDomains = globalThreatFeed.ExportDomains()
		snap.ThreatDomainAllowlist = globalThreatFeed.DomainAllowlist()
	}

	// Session secret (hex-encoded for safe JSON transport).
	if key := session.SigningKey(); len(key) > 0 {
		snap.SessionHMAC = hex.EncodeToString(key)
	}
	snap.IdPProfiles = idpRegistry.All()

	// Bandwidth / QoS policies.
	if globalBandwidth != nil {
		snap.BandwidthPolicies = globalBandwidth.List()
	}

	// Node groups.
	if globalNodeGroups != nil {
		snap.NodeGroups = globalNodeGroups.List()
	}

	// Category groups.
	snap.CategoryGroups = globalCategoryGroups.List()

	// Global file-block extensions (CRIT-2: DP nodes need the blocklist).
	snap.FileBlockExtensions = fileBlocker.List()

	// OTLP endpoint (CRIT-3: DP nodes need the endpoint to export spans/metrics).
	snap.OTLPEndpoint = globalOTLP.Endpoint()

	return snap
}

// buildCPAddressList returns the list of all CP gRPC addresses for DP failover.
// Includes this leader's address + the HA standby address (if HA is enabled).
func buildCPAddressList() []string {
	haStatus := globalHA.Status()
	if !haStatus.Enabled {
		return nil // no HA = no address list needed
	}
	clusterRoleMu.RLock()
	myAddr := clusterRole.grpcAddr
	clusterRoleMu.RUnlock()

	// haStatus.PeerAddr is the leader's externally reachable address (set during Enable HA).
	// For the leader, we include: [leader_addr, standby_addr]
	// The leader's reachable addr is stored as peerAddr in the HA state.
	addrs := []string{haStatus.PeerAddr}
	// Also include the local listen addr if it's different and looks reachable.
	if myAddr != "" && myAddr != haStatus.PeerAddr {
		addrs = append(addrs, myAddr)
	}
	return addrs
}
