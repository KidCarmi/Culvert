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

	"github.com/KidCarmi/Culvert/internal/catoverride"
	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/pac"
	"github.com/KidCarmi/Culvert/internal/session"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// categoryOverrideHostCount returns the aggregate number of host-keys in an
// override set (added + recategorized + tombstones) — the DoS bound axis for
// maxSnapCategoryOverrides.
func categoryOverrideHostCount(o CategoryOverrides) int {
	return len(o.Added) + len(o.Recategorized) + len(o.Tombstones)
}

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
	// NO omitempty (WireWipeCapable): an admin-cleared empty list must
	// serialize as [] and propagate as an explicit wipe — pac.Store.Get
	// returns nil-for-empty, so capture forces non-nil (mirrors
	// RateLimitExempt; closes the stale-DP-exclusions gap).
	PACExclusions []string `json:"pac_exclusions"`
	// PAC steering profiles/pools (PAC initiative PR 2): NO omitempty
	// (WireWipeCapable) — a last-object delete must clear DP state
	// (mirrors decryption_profiles).
	PACProfiles []pac.Profile `json:"pac_profiles"`
	PACPools    []pac.Pool    `json:"pac_pools"`

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

	// Named decryption profiles referenced per policy rule. NO omitempty
	// (WireWipeCapable): unlike category_groups, an empty set MUST propagate CP→DP so
	// deleting the last profile clears stale copies on data-plane nodes. These
	// profiles govern security-relevant settings (cert verification, native H2, TLS
	// floor) — a DP that retained a stale profile would apply looser settings than
	// the CP intends (a rule re-referencing the deleted name resolves the ghost on
	// the DP instead of the fail-safe fallback). The security-sensitivity justifies
	// diverging from the siblings' wire-dead []-wipe posture.
	DecryptionProfiles []DecryptionProfile `json:"decryption_profiles"`

	// Global file-block extension list (day-3 audit CRIT-2).
	FileBlockExtensions []string `json:"file_block_extensions,omitempty"`

	// OTLP endpoint for metrics + traces export (day-3 audit CRIT-3).
	OTLPEndpoint string `json:"otlp_endpoint,omitempty"`

	// SaaS signed category-feed configuration (F3a-2). CP-authoritative,
	// fleet-uniform: the CP resolves + validates the feed config and pushes it so
	// the whole fleet agrees where the feed comes from and whether it is on. This
	// is transport ADDRESSING + management policy only — the DP still verifies
	// every fetched byte in-binary against the pinned identity + baked Sigstore
	// root (no unsigned/raw fallback), so a hostile CP URL can only cause a verify
	// failure, never unsigned data (design §A.0). SaaSFeedManaged/SaaSFeedEnabled
	// are *bool PRESENCE fields (nil ⇒ absent ⇒ DP keeps its local resolution;
	// non-nil ⇒ authoritative even when false). A plain bool could not tell a
	// rolled-back/older CP that OMITTED the field from a CP that explicitly set
	// false — and the latter would silently re-enable a durably-disabled DP (the
	// §A.2.2 mixed-version hazard, Codex P1). A current CP always sets both
	// pointers. The value fields keep omitempty (empty/0 ⇒ CP has not set it ⇒
	// skip). Not secrets ⇒ not redacted.
	SaaSFeedManaged        *bool  `json:"saas_feed_managed,omitempty"`
	SaaSFeedEnabled        *bool  `json:"saas_feed_enabled,omitempty"`
	SaaSFeedURL            string `json:"saas_feed_url,omitempty"`
	SaaSFeedProtocol       string `json:"saas_feed_protocol,omitempty"`
	SaaSFeedRefreshSeconds int64  `json:"saas_feed_refresh_seconds,omitempty"`

	// Admin category overrides (F3a-2). CP-authoritative fleet policy layered on
	// top of the feed snapshot. POINTER for presence + NO omitempty
	// (WireWipeCapable): nil ⇒ absent (older/rolled-back CP ⇒ DP keeps local, never
	// wiped — "absence is not deletion"); a non-nil value (even an empty
	// Overrides{}) ⇒ authoritative replacement, so an admin CLEARING the last
	// override propagates as an explicit wipe to every DP (a stale tombstone left
	// on a DP would keep a host suppressed after the fleet un-suppressed it — the
	// DecryptionProfiles delete-propagation rationale, §A.3.2). A current CP always
	// sends non-nil. Bounded by maxSnapCategoryOverrides (host-aggregate, enforced
	// in validateConfigSnapshot). Not a secret ⇒ not redacted.
	CategoryOverrides *CategoryOverrides `json:"category_overrides"`

	// MCPGatewaySnapshot / MCPManagementSnapshot are the OPTIONAL signed, immutable
	// MCP CP→DP snapshots (PR-10, MCP-CPDP-001). They ride the existing SWG
	// ConfigSnapshot channel but are independently signed + validated: presence
	// (non-nil) means "an authoritative signed MCP snapshot for this capability is
	// attached, apply it whole after signature/epoch/version validation"; absence
	// (nil, omitempty ⇒ not on the wire) means "no MCP change — an older/rolled-back
	// CP that predates MCP never wipes valid DP-local MCP state" (absence is not
	// deletion; an intended MCP removal is an explicit signed rollback, not an empty
	// snapshot). A malformed present envelope rejects the MCP capability WHOLE and
	// never corrupts the SWG apply (the two are applied independently). The envelope
	// carries only public integrity material (content hash + ed25519 signature) and
	// secret-free reviewed payload — NO signing private key and NO credential value
	// ever enter it, so it is not redacted. kindMeta / AppliesOnDP in the
	// config-surface registry (like Epoch): a derived signed artifact, consumed on
	// the DP but not applied as an operator config value.
	MCPGatewaySnapshot    *cpdp.Envelope `json:"mcp_gateway_snapshot,omitempty"`
	MCPManagementSnapshot *cpdp.Envelope `json:"mcp_management_snapshot,omitempty"`
}

// ConfigSnapshot per-slice size caps (H5 fix).
//
// Each cap is a hard upper bound on the number of entries a single
// ConfigSnapshot may carry. Sized well above realistic deployments to
// avoid breaking legitimate clusters; a malicious or compromised
// Control Plane that pushes a snapshot exceeding ANY one of these
// causes the entire snapshot to be rejected (no partial application).
//
// The blocklist/IP caps are 2 M (raised from 200 k) so the cluster keeps
// pace with enterprise-scale aggregated threat feeds and exceeds the largest
// single-list limits of comparable appliances (PAN-OS domain EDLs top out
// ~4 M box-wide; a single feed there is far under 2 M). URLhaus + abuse.ch +
// firebog-class aggregations routinely reach 500 k–1 M hosts, so 2 M leaves
// genuine headroom. url_categories is host-scale via its inner Hosts lists
// (maxSnapURLCategoryHosts), not its entry count. The cap remains
// a real memory-DoS bound: the CP↔DP gRPC channel is sized to
// maxClusterGRPCMsgSize (below) and the config stream is gzip-compressed,
// so a 2 M-host snapshot (~60 MiB JSON, ~6–8 MiB on the wire) transfers
// inside the frame instead of tripping the old 4 MiB default. Local
// blocklist matching is an O(1) map[string]bool (internal/blocklist), so
// these sizes cost lookups nothing at request time.
const (
	maxSnapBlockedHosts = 2_000_000
	maxSnapIPList       = 2_000_000
	maxSnapPolicyRules  = 10_000
	// url_categories is a list of category DEFINITIONS (named groups), not hosts —
	// the realistic entry count is hundreds to low-thousands. The host volume
	// lives in each entry's Hosts list and is bounded separately by
	// maxSnapURLCategoryHosts, so the entry cap is a modest structural bound
	// (a 2 M entry cap was an over-broad copy of the host-scale slices).
	maxSnapURLCategories       = 200_000
	maxSnapSSLBypassPatterns   = 10_000
	maxSnapFileProfiles        = 1_000
	maxSnapFileBlockExtensions = 10_000
	maxSnapRewriteRules        = 5_000
	maxSnapDPIPatterns         = 5_000
	maxSnapCPAddresses         = 100
	maxSnapPACExclusions       = 10_000
	maxSnapPACProfiles         = 64
	maxSnapPACPools            = 64
	maxSnapRateLimitExempt     = 10_000
	maxSnapThreatFeedURLs      = 500_000
	maxSnapThreatFeedDomains   = 500_000
	maxSnapDomainAllowlist     = 10_000
	maxSnapBandwidthPolicies   = 1_000
	maxSnapNodeGroups          = 1_000
	maxSnapCategoryGroups      = 1_000
	maxSnapDecryptionProfiles  = 1_000
	maxSnapIdPProfiles         = 1_000
	// maxSnapCategoryOverrides bounds the AGGREGATE host-keys across the admin
	// override set (added + recategorized + tombstones). CategoryOverrides is a
	// pointer-to-struct, not a len()-able slice, so it is NOT one of the
	// configSnapshotSliceCaps rows (SnapshotCapParity counts only slice/map
	// bindings); its cap is enforced by the dedicated host-aggregate check in
	// validateConfigSnapshot, mirroring the maxSnapURLCategoryHosts inner bound.
	maxSnapCategoryOverrides = 100_000
)

// maxClusterGRPCMsgSize is the CP↔DP gRPC max message size (send + recv on
// both peers). gRPC's default receive limit is 4 MiB, which capped a config
// snapshot at ~200 k hostname strings; raising it to 128 MiB lets an
// enterprise-scale snapshot whose dominant slice is at the 2 M cap (~60 MiB
// uncompressed JSON) transfer with ~2× headroom while still bounding a single
// frame to a memory-safe size (a hostile CP cannot force an unbounded DP
// allocation). grpc-go enforces this bound on the DECOMPRESSED message, so it
// also caps a gzip decompression bomb. The frame alone carries the uncompressed
// snapshot; gzip on the config stream (~10:1 for host lists) is an OPT-IN
// bandwidth optimization (CULVERT_CLUSTER_GRPC_COMPRESSION, default off) rather
// than a correctness requirement, so a mixed-version fleet is never forced onto
// compression. The per-slice validateConfigSnapshot caps remain the primary
// entry-count DoS bound; this is the independent transport-frame bound.
const maxClusterGRPCMsgSize = 128 << 20 // 128 MiB

// maxClusterInboundMsgSize bounds every CP↔DP message in the SMALL direction:
// the CP server's inbound RPCs (GetConfig req, PushMetrics, PushAuditEvents,
// Enroll, SyncRateLimits/Revocations, RenewCert, HASync req) are all tiny —
// none carries a snapshot (the big config only flows OUTBOUND as a response).
// So the server's receive limit and the client's send limit are pinned tight
// here (16 MiB, ~60× the largest observed inbound batch) instead of inheriting
// the 128 MiB frame — shrinking the CP's inbound allocation surface. Only the
// snapshot-carrying direction (server send / client receive) uses the full
// maxClusterGRPCMsgSize.
const maxClusterInboundMsgSize = 16 << 20 // 16 MiB

// maxSnapshotWireBytes is the commit-time BYTE budget for a published snapshot,
// set safely below maxClusterGRPCMsgSize (128 MiB) to leave room for gRPC
// framing. The per-slice/aggregate ENTRY caps bound counts, but a count-valid
// snapshot with long strings (max-length hostnames, long threat-feed keys) can
// still marshal past the frame — it would then commit on the CP and fail EVERY
// DP fetch with an opaque ResourceExhausted, freezing the fleet on stale config
// with no signal (fail-open on new threats). ConfigStore.Update measures the
// marshaled size and rejects over-budget publishes here so the byte overflow is
// caught at commit with a named error, exactly like the count gate.
const maxSnapshotWireBytes = 120 << 20 // 120 MiB

// maxSnapURLCategoryHosts bounds the AGGREGATE hosts across all url_categories
// entries. The entry count is small (maxSnapURLCategories), but each entry
// carries a Hosts list; without this a handful of categories could smuggle
// millions of hosts past the per-entry cap. Sized host-scale (matches the
// blocked-host order) so category-based blocking stays enterprise-capable.
const maxSnapURLCategoryHosts = 2_000_000

// maxSnapAggregateEntries bounds the SUM of the memory-dominant host-scale
// slices. Each per-slice cap fits the frame alone, but several maxed slices
// together exceed the 128 MiB CP↔DP frame and would overflow it as an opaque
// gRPC ResourceExhausted. This makes the 3×2 M-class case infeasible-by-design
// and, more usefully, rejected at commit with a clear named error. Sized just
// under the frame's physical entry capacity (~128 MiB / ~35 B per entry) so it
// admits the largest configs that CAN sync (e.g. a 2 M blocklist plus threat
// feeds) and only rejects those that genuinely cannot.
const maxSnapAggregateEntries = 3_000_000

// snapshotSliceCap is the live size and hard cap of one capped ConfigSnapshot
// slice/map. It is the single source of truth shared by validateConfigSnapshot
// (the DoS gate), the diagnose/health surface, and the Prometheus utilization
// gauges — so the cap table can never drift between enforcement and reporting.
type snapshotSliceCap struct {
	Name string `json:"name"`
	Size int    `json:"size"`
	Cap  int    `json:"cap"`
}

// configSnapshotSliceCaps returns the (size, cap) of every capped slice in snap,
// in a stable order. Callers that only need the pass/fail verdict should use
// validateConfigSnapshot; this exists for utilization reporting.
func configSnapshotSliceCaps(snap ConfigSnapshot) []snapshotSliceCap {
	return []snapshotSliceCap{
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
		{"pac_profiles", len(snap.PACProfiles), maxSnapPACProfiles},
		{"pac_pools", len(snap.PACPools), maxSnapPACPools},
		{"rate_limit_exempt", len(snap.RateLimitExempt), maxSnapRateLimitExempt},
		{"threat_feed_urls", len(snap.ThreatFeedURLs), maxSnapThreatFeedURLs},
		{"threat_feed_domains", len(snap.ThreatFeedDomains), maxSnapThreatFeedDomains},
		{"threat_domain_allowlist", len(snap.ThreatDomainAllowlist), maxSnapDomainAllowlist},
		{"bandwidth_policies", len(snap.BandwidthPolicies), maxSnapBandwidthPolicies},
		{"node_groups", len(snap.NodeGroups), maxSnapNodeGroups},
		{"category_groups", len(snap.CategoryGroups), maxSnapCategoryGroups},
		{"decryption_profiles", len(snap.DecryptionProfiles), maxSnapDecryptionProfiles},
		{"idp_profiles", len(snap.IdPProfiles), maxSnapIdPProfiles},
	}
}

// validateConfigSnapshot enforces the per-slice caps above. Returns an
// error naming the first field that overflows; nil when the snapshot is
// within bounds. Callers must reject the whole snapshot on error — the
// goal is to prevent partial application of an attacker-shaped payload.
func validateConfigSnapshot(snap ConfigSnapshot) error {
	for _, c := range configSnapshotSliceCaps(snap) {
		if c.Size > c.Cap {
			return fmt.Errorf("config snapshot %s=%d exceeds cap %d", c.Name, c.Size, c.Cap)
		}
	}
	// Inner-dimension bound: url_categories has a small entry cap, but each entry
	// carries a Hosts list — bound the aggregate so a few categories cannot
	// smuggle millions of hosts past the per-entry cap.
	urlCatHosts := 0
	for i := range snap.URLCategories {
		urlCatHosts += len(snap.URLCategories[i].Hosts)
	}
	if urlCatHosts > maxSnapURLCategoryHosts {
		return fmt.Errorf("config snapshot url_category_hosts=%d exceeds cap %d", urlCatHosts, maxSnapURLCategoryHosts)
	}
	// Category-override aggregate host-key bound (F3a-2). CategoryOverrides is a
	// pointer-to-struct, not a capped slice, so bound its host-keys here (added +
	// recategorized + tombstones), mirroring url_category_hosts. Also VALIDATE the
	// CP-provided overrides on the DP before accepting them (design §A.3): a
	// structurally-invalid override set (bad host/category, tombstone clash,
	// ancestor/descendant conflict) rejects the WHOLE snapshot — never a partial
	// apply. Protocol / URL / refresh are validated below.
	if snap.CategoryOverrides != nil {
		if n := categoryOverrideHostCount(*snap.CategoryOverrides); n > maxSnapCategoryOverrides {
			return fmt.Errorf("config snapshot category_overrides host-keys=%d exceeds cap %d", n, maxSnapCategoryOverrides)
		}
		if _, err := catoverride.Normalize(*snap.CategoryOverrides); err != nil {
			return fmt.Errorf("config snapshot category_overrides invalid: %w", err)
		}
	}
	// SaaS feed configuration (F3a-2). Re-validate CP-provided feed config on the
	// DP through the SAME F3a-1 boundary the CP write path uses (no weaker
	// duplicate): reject an unsupported protocol, a non-official URL, or a
	// malformed refresh interval so the whole snapshot is refused, never partially
	// applied. Empty values are "CP has not set it" (skip at apply), so they are
	// not validated here.
	if snap.SaaSFeedProtocol != "" {
		if _, err := resolveFeedProtocol(snap.SaaSFeedProtocol); err != nil {
			return fmt.Errorf("config snapshot saas_feed_protocol invalid: %w", err)
		}
	}
	if snap.SaaSFeedURL != "" {
		if _, err := resolveFeedURL(snap.SaaSFeedURL); err != nil {
			return fmt.Errorf("config snapshot saas_feed_url invalid: %w", err)
		}
	}
	if _, err := resolveFeedRefresh(snap.SaaSFeedRefreshSeconds); err != nil {
		return fmt.Errorf("config snapshot saas_feed_refresh_seconds invalid: %w", err)
	}
	// Aggregate bound: several individually-valid host-scale slices can together
	// exceed the CP↔DP frame. Reject the sum here with a clear named error rather
	// than letting the wire fail with an opaque ResourceExhausted.
	agg := len(snap.BlockedHosts) + len(snap.IPList) + len(snap.SSLBypassPatterns) +
		len(snap.PACExclusions) + len(snap.RateLimitExempt) + len(snap.DPIPatterns) +
		len(snap.ThreatFeedURLs) + len(snap.ThreatFeedDomains) + len(snap.ThreatDomainAllowlist) +
		urlCatHosts
	if agg > maxSnapAggregateEntries {
		return fmt.Errorf("config snapshot aggregate host-scale entries=%d exceeds cap %d (too large to sync in one CP↔DP frame)", agg, maxSnapAggregateEntries)
	}
	// Per-category host cap (§19, whole-snapshot 10k gate): the DP apply used
	// to reject only the URL-category SLICE (ReplaceAllChecked), so a snapshot
	// carrying one over-cap category applied MIXED — new rulebase against the
	// old taxonomy, the exact torn state a whole-snapshot contract exists to
	// prevent. Judged here so callers reject the ENTIRE snapshot before any
	// slice applies; ReplaceAllChecked stays in applySnapshotURLCategories as
	// defense in depth.
	if err := urlcat.ValidateEntries(snap.URLCategories); err != nil {
		return fmt.Errorf("config snapshot url_categories invalid: %w", err)
	}
	// Object-reference graph (§18): deterministic both-sides-carried checks —
	// PolicyRules↔CategoryGroups, PolicyRules↔DecryptionProfiles, and the
	// category-name edges (group members + direct DestCategory) against the
	// carried taxonomy plus the applying node's live view/UT1 layers. A
	// dangling reference rejects the WHOLE snapshot: the fleet keeps its last
	// valid config instead of installing a rulebase whose DENY/DROP rules
	// silently stop matching.
	if err := validateSnapshotRefGraph(snap); err != nil {
		return fmt.Errorf("config snapshot reference graph invalid: %w", err)
	}
	// Rewrite stable-identity uniqueness (2D-C §22/§39): duplicate stable IDs
	// in the synced rule set reject the ENTIRE snapshot — the DP must never
	// silently re-identify one of two claimants of a CP identity.
	if err := validateRewriteStableIDs(snap.RewriteRules); err != nil {
		return fmt.Errorf("config snapshot rewrite_rules invalid: %w", err)
	}
	// File-profile identity invariants (2D-C final §13–§15): FileProfile IDs
	// are enforcement-authoritative, so a snapshot carrying a duplicate or
	// missing ID (or duplicate names) is ambiguous identity — reject the
	// ENTIRE snapshot before ANY slice applies.
	if err := validateFileProfiles(snap.FileProfiles); err != nil {
		return fmt.Errorf("config snapshot file_profiles invalid: %w", err)
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
	// lastPublishErr records the reason the most recent Update was REJECTED at
	// commit (P1 commit-time validation) — an over-cap snapshot is not published,
	// so the fleet stays on the last valid config instead of every DP silently
	// rejecting a bad one. Empty when the last publish succeeded. Surfaced to
	// operators via LastPublishError() (diagnose/health).
	lastPublishErr string
	lastPublishTS  string
	// published is true once a VALID snapshot has been published at least once.
	// It stays false if the CP's initial publish was rejected at commit — in
	// which case s.snap is still the zero ConfigSnapshot and the cluster RPCs
	// must refuse rather than distribute an empty config (see ServableConfig).
	published bool
	// deltaRing retains recent per-version blocklist deltas so a lagging DP can
	// catch up incrementally via GetConfigDelta (T3 P1). The zero value is
	// ready; a swapped-in test store gets a fresh ring automatically.
	deltaRing blocklistDeltaRing
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

// Update validates the snapshot at COMMIT time and, if it passes, atomically
// replaces the published snapshot and notifies all subscribers. Returns the
// validation error WITHOUT publishing when the snapshot exceeds a per-slice cap
// (P1 commit-time validation): the CP is the point of truth, so an over-cap
// config is rejected here with a named-field error and the fleet stays on the
// last valid snapshot — instead of committing a snapshot that every DP would
// then silently reject wholesale, freezing the fleet on stale config with no
// clear signal (fail-open on new threats). The CP's own local proxying is
// unaffected (its stores already hold the data); only distribution is gated.
func (s *ConfigStore) Update(snap ConfigSnapshot) error {
	// Gate 0 — rewrite management-identity degradation: while the latch is
	// set, CurrentConfigSnapshot has captured KNOWN-ephemeral rewrite
	// StableIDs that must not be distributed to the fleet as authoritative
	// identity (a DP applies them verbatim, and they re-mint on the CP's next
	// restart). Reuses the existing commit-time rejection contract — logged,
	// alerted, LastPublishError; the fleet stays on the last valid snapshot —
	// rather than silently omitting or re-minting the rewrite slice.
	if d := rewriteIdentityDegraded(); d != nil {
		return s.rejectPublish(fmt.Errorf("rewrite management identity degraded (%s): refusing to publish ephemeral rewrite StableIDs as authoritative fleet identity", d.reason))
	}
	// Gate 1 — entry counts (fast pre-check).
	if err := validateConfigSnapshot(snap); err != nil {
		return s.rejectPublish(err)
	}
	// Gate 2 — marshaled BYTE budget. Counts can pass while long strings push
	// the snapshot past the frame; measuring the real wire size here stops a
	// byte-oversized config from committing and then failing every DP fetch.
	b, err := json.Marshal(snap)
	if err != nil {
		return s.rejectPublish(fmt.Errorf("config snapshot marshal failed: %w", err))
	}
	if len(b) > maxSnapshotWireBytes {
		return s.rejectPublish(fmt.Errorf("config snapshot wire size=%d bytes exceeds budget %d (too large to sync in one CP↔DP frame)", len(b), maxSnapshotWireBytes))
	}

	recordPublishedSnapshotSizes(snap) // for the utilization metrics (cheap; no per-scrape rebuild)

	s.mu.Lock()
	// Capture the pre-publish blocklist + version for the delta ring. oldHosts
	// still references the outgoing snapshot's slice (safe — s.snap is replaced,
	// not mutated in place).
	oldHosts := s.snap.BlockedHosts
	base := s.version
	s.version++
	snap.Version = s.version
	snap.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	newHosts := snap.BlockedHosts
	target, epoch := s.version, snap.Epoch
	s.snap = snap
	s.published = true
	s.lastPublishErr = ""
	s.lastPublishTS = ""
	s.persistVersionLocked()
	subs := append([]chan struct{}{}, s.subs...)
	s.mu.Unlock()

	// Record the blocklist delta OUTSIDE the store lock: the O(N) diff +
	// fingerprint over up to 2 M hosts must not stall config readers/pollers.
	// Config publishes are admin-action-rate, so the cost is not hot-path.
	s.deltaRing.record(base, target, oldHosts, newHosts, blocklistSyncedFingerprint(newHosts), epoch)

	for _, ch := range subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	logger.Printf("ControlPlane: config v%d published", snap.Version)
	return nil
}

// rejectPublish records a commit-time rejection (count OR byte gate): it does
// NOT publish, stamps LastPublishError, logs, and fires the operator alert.
// Returns err so callers can surface it inline too.
func (s *ConfigStore) rejectPublish(err error) error {
	s.mu.Lock()
	s.lastPublishErr = err.Error()
	s.lastPublishTS = time.Now().UTC().Format(time.RFC3339)
	curVer := s.version
	s.mu.Unlock()
	logWarnf("ControlPlane: REJECTING config publish (fleet stays on v%d): %v", curVer, err)
	fireAlert("config_snapshot_rejected", AlertPayload{
		Event:  "config_snapshot_rejected",
		Actor:  "culvert",
		Source: "cluster",
		Detail: "config publish rejected at commit: " + err.Error() + " — the cluster stays on the last valid config; reduce the oversized collection to resume sync",
	})
	return err
}

// publishedSnapshotSizes is the per-slice utilization of the last published
// snapshot, cached so the /metrics scrape emits all-slice gauges without
// rebuilding (and re-allocating) a full ~60 MiB snapshot each time.
type publishedSnapshotSizes struct {
	Slices         []snapshotSliceCap // every capped slice: name/size/cap
	URLCatHosts    int                // aggregate hosts across url_categories
	URLCatHostsCap int
	Aggregate      int // sum of host-scale slices (matches validateConfigSnapshot)
	AggregateCap   int
}

var lastPublishedSnapshotSizes atomic.Value // publishedSnapshotSizes

// recordPublishedSnapshotSizes captures snap's slice sizes at publish time.
func recordPublishedSnapshotSizes(snap ConfigSnapshot) {
	slices := configSnapshotSliceCaps(snap)
	urlCatHosts := 0
	for i := range snap.URLCategories {
		urlCatHosts += len(snap.URLCategories[i].Hosts)
	}
	agg := len(snap.BlockedHosts) + len(snap.IPList) + len(snap.SSLBypassPatterns) +
		len(snap.PACExclusions) + len(snap.RateLimitExempt) + len(snap.DPIPatterns) +
		len(snap.ThreatFeedURLs) + len(snap.ThreatFeedDomains) + len(snap.ThreatDomainAllowlist) +
		urlCatHosts
	lastPublishedSnapshotSizes.Store(publishedSnapshotSizes{
		Slices:         slices,
		URLCatHosts:    urlCatHosts,
		URLCatHostsCap: maxSnapURLCategoryHosts,
		Aggregate:      agg,
		AggregateCap:   maxSnapAggregateEntries,
	})
}

// ServableConfig reports whether the store holds a config the cluster RPCs may
// distribute. It is false ONLY in the rejected-initial-publish case: a publish
// was attempted and rejected AND nothing valid was ever published, so s.snap is
// still the zero ConfigSnapshot. In that state GetConfig/HASync must refuse
// rather than serve an empty config to a fresh DP or HA standby (which would
// apply the empty state). After any successful publish, a later rejection keeps
// the last valid snapshot in s.snap, which stays servable (the "fleet stays on
// last valid config" contract). Returns the rejection reason for the caller's
// error message.
func (s *ConfigStore) ServableConfig() (ok bool, reason string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.published && s.lastPublishErr != "" {
		return false, s.lastPublishErr
	}
	return true, ""
}

// LastPublishError returns the reason the most recent config publish was
// rejected at commit (over-cap), plus the timestamp — empty when the last
// publish succeeded. Read-only; used by the diagnose/health surface so an
// operator sees "publish rejected, fleet on stale config" as a named error.
func (s *ConfigStore) LastPublishError() (msg, ts string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastPublishErr, s.lastPublishTS
}

// publishCurrentConfigSnapshot publishes the live config to the fleet. Returns
// the commit-time validation error when the snapshot is over-cap (not
// published). Most callers mutate a store then publish fire-and-forget — the
// rejection is logged, alerted, and surfaced via LastPublishError — but the
// error is returned so an admin handler can also report it inline.
func publishCurrentConfigSnapshot() error {
	return globalConfigStore.Update(CurrentConfigSnapshot())
}

// seedReplicatedSnapshot sets the in-memory snapshot from a replicated HA bundle
// WITHOUT advancing the version, marking published, or notifying subscribers. Its
// sole purpose is to give the delta ring a correct oldHosts baseline for the
// first post-promotion Update (Dur-F4). A promoted standby's version is still
// established by armVersionPersistence (seeded above the replicated leader
// version), and distribution is still gated by ServableConfig/published.
func (s *ConfigStore) seedReplicatedSnapshot(snap ConfigSnapshot) {
	s.mu.Lock()
	s.snap = snap
	s.mu.Unlock()
}

// Get returns the current snapshot.
func (s *ConfigStore) Get() ConfigSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap
}

// Version returns the current published config version without copying the
// whole snapshot. Used by the version-conditional GetConfig fast path so an
// unchanged poll never materializes or marshals the (up to ~60 MiB) snapshot.
func (s *ConfigStore) Version() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
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
// applyConfigSnapshot applies snap to the local proxy state and returns an
// error when the snapshot is REJECTED (stale epoch, over-cap, or IdP-sync
// failure) so callers can react. The DP poller pre-validates and treats a
// non-nil error as defensive; the HA resync path (applyHABundle) MUST fail
// closed on it — otherwise a standby that silently drops an over-cap bundle's
// config marks sync-OK and, once promoted, serves stale/empty config. No
// partial state mutation occurs on rejection.
func applyConfigSnapshot(snap ConfigSnapshot) error {
	// ADR-0005 S3: reject snapshots from a fenced-out (stale-epoch) CP
	// before ANY state mutation; ratchet the last-seen epoch forward
	// otherwise. Epoch 0 is accepted only while the ratchet is unseeded
	// (pure-legacy cluster). The DP poller (fetchAndApply) runs this same
	// check EARLIER — before its external-auth/IdP application, last-good
	// persist, and version advance — this one covers the other callers.
	if !dpObserveEpoch("config snapshot", snap.Epoch) {
		return fmt.Errorf("config snapshot v%d rejected: stale epoch %d", snap.Version, snap.Epoch)
	}
	// H5: reject the entire snapshot if any per-slice cap is exceeded.
	// Logged at info; the next CP poll cycle will retry with a fresh
	// snapshot once the operator corrects the CP-side input. No partial
	// state mutation occurs on rejection.
	if err := validateConfigSnapshot(snap); err != nil {
		logger.Printf("DataPlane: rejecting config snapshot v%d: %v", snap.Version, err)
		return fmt.Errorf("config snapshot v%d rejected: %w", snap.Version, err)
	}

	// Blocker B (exclusive side): a snapshot apply both REMOVES shared
	// objects and INSTALLS references wholesale, so the whole apply holds the
	// reference-integrity gate exclusively — a node-local rule/group write or
	// object delete cannot interleave with it. Acquired OUTERMOST; nothing
	// under the apply acquires the gate.
	refScanDeleteLock()
	defer refScanDeleteUnlock()

	applySnapshotPolicyAndTraffic(snap)
	applySnapshotClusterRuntime(snap)

	// IdP profiles. ReplaceAll compiles every enabled provider before swapping
	// the live registry, so a bad CP-side IdP update does not break the DP's
	// currently working SAML/OIDC providers. A rejection ABORTS the remaining
	// (extended) state below — pre-existing ordering, preserved by the split.
	if err := syncSnapshotIdPProfiles(snap); err != nil {
		logger.Printf("DataPlane: IdP profile sync rejected: %v", err)
		return fmt.Errorf("config snapshot v%d IdP sync rejected: %w", snap.Version, err)
	}

	applySnapshotExtendedState(snap)
	applySnapshotSaaSFeed(snap)

	// Optional signed MCP CP→DP snapshots (PR-10). Applied AFTER the SWG apply and
	// only touching MCP state: a malformed/rejected MCP envelope never corrupts the
	// SWG config above, and each capability applies independently. A no-op when MCP
	// distribution is disabled (the default).
	applySnapshotMCP(snap)

	logger.Printf("DataPlane: applied config v%d (%d blocked hosts, %d rules, ip_mode=%s, rate=%d rpm)",
		snap.Version, len(snap.BlockedHosts), len(snap.PolicyRules), snap.IPFilterMode, snap.RateLimitRPM)
	return nil
}

// applySnapshotPolicyAndTraffic applies the traffic-control and policy
// slices of a snapshot (split from applyConfigSnapshot for gocognit; order
// preserved verbatim).
func applySnapshotPolicyAndTraffic(snap ConfigSnapshot) {
	applySnapshotBlocklist(snap)
	applySnapshotTrafficExceptBlocklist(snap)
}

// applySnapshotBlocklist replaces the feed-pushed blocklist entries from a FULL
// snapshot. Split from applySnapshotPolicyAndTraffic (T3 P1) so the incremental
// delta path can substitute bl.ApplyDelta for this wholesale replace while
// reusing applySnapshotTrafficExceptBlocklist for everything else. The full
// path's order and semantics are byte-identical to before the split.
func applySnapshotBlocklist(snap ConfigSnapshot) {
	// In-place feed-entry replacement preserves the package-global bl's path /
	// mode / manual / exceptions (the DP-local state that isn't in the cluster
	// snapshot). The previous wholesale `bl = newBL` pattern zeroed those local
	// fields and orphaned the persistence path so caller-side Save became a
	// no-op (CL-1 final gap, P3.4). ReplaceFeedEntries touches only exact +
	// wildcards under bl.mu.Lock (and resets the synced fingerprint to the CP
	// list's fingerprint); bl.Save() then persists via the Bucket-4-hardened
	// atomicWriteFile path.
	bl.ReplaceFeedEntries(snap.BlockedHosts)
	bl.Save()
}

// applySnapshotTrafficExceptBlocklist applies every traffic/policy slice EXCEPT
// the blocklist (IP filter, rate limiter + exemptions, external auth, default
// action, policy rules, SSL bypass, URL categories, file profiles, rewrite, DPI,
// connection limits). Shared by the full-snapshot path and the delta path.
func applySnapshotTrafficExceptBlocklist(snap ConfigSnapshot) {
	// IP filter.
	newIPF := &IPFilter{single: map[string]bool{}}
	newIPF.SetMode(snap.IPFilterMode)
	// Bulk load: one pass, one view publish. An Add loop is quadratic in the
	// entry count, and this list's snapshot cap is maxSnapIPList (2,000,000),
	// so a large allowlist would stall the snapshot apply. Invalid entries are
	// reported after the lock is released.
	for _, bad := range newIPF.AddAll(snap.IPList) {
		logger.Printf("DataPlane: invalid IP %q: %v", bad.Entry, bad.Err)
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
	// lock-step with the CP exempt list instead of silently leaving DP nodes
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

	// URL categories. Checked install (Blocker C): the whole pushed taxonomy
	// is judged against the canonical per-category host cap BEFORE anything
	// installs — an over-cap candidate is rejected wholesale (logged; the node
	// keeps serving its current taxonomy), never truncated or partially
	// applied. Same per-field reject-and-continue posture as the SSL-bypass
	// Set above; the aggregate maxSnapURLCategoryHosts snapshot cap is NOT
	// this invariant.
	if snap.URLCategories != nil {
		if err := catStore.ReplaceAllChecked(snap.URLCategories); err != nil {
			logger.Printf("DataPlane: URL categories rejected (taxonomy unchanged): %v", err)
		} else {
			// P3.4 caller-side persist (Bucket-4 fsync-safe Save
			// hardened in PR #246).
			catStore.Save()
			// The CP-pushed taxonomy's BuiltIn entries are served to policy from the
			// effective view, not catStore, so without this recompose a CP taxonomy
			// change that carries no override change is silently unenforced on EVERY
			// data-plane node until it restarts. applySnapshotSaaSFeed's recompose is
			// gated on an override-fingerprint change and does not cover this.
			recomposeSignedFeedTaxonomy()
		}
	}

	// File profiles. The preflight (validateConfigSnapshot) already rejected
	// ambiguous identity with the whole snapshot; the store-boundary refusal
	// is defense-in-depth and must never install a set the preflight would
	// have refused.
	if snap.FileProfiles != nil {
		if err := globalProfileStore.ReplaceAll(snap.FileProfiles); err != nil {
			logger.Printf("ConfigSnapshot: file profiles NOT applied: %v", err)
		}
	}

	// Rewrite rules. FOLLOWER semantics (2D-C §39): the CP is authoritative —
	// its stable rule identities are preserved verbatim (SetRules keeps
	// non-empty stableIds; uniqueness was validated with the whole snapshot),
	// published under the settings writer domain so the bulk publish cannot
	// interleave with a node-local interactive mutation, and deliberately NOT
	// written to the follower's admin_settings (the CP re-syncs on every
	// version bump — same posture as the file-profile / feed-config slices).
	if snap.RewriteRules != nil {
		publishRewriteRules(snap.RewriteRules)
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
	// PAC profiles/pools (PAC initiative PR 2): nil-skip (old CP), non-nil
	// replace — [] is an explicit wipe. Tolerant Set (never rejects).
	// 2F-E correction round 4: inside the shared PAC writer transaction
	// boundary (pacProfilesWriterLock — lock order gate → pacProfilesAPIMu).
	if snap.PACProfiles != nil || snap.PACPools != nil {
		unlock := pacProfilesWriterLock()
		cur := pacProfiles.Get()
		if snap.PACProfiles != nil {
			cur.Profiles = snap.PACProfiles
		}
		if snap.PACPools != nil {
			cur.Pools = snap.PACPools
		}
		if err := pacProfiles.Set(cur); err != nil {
			logger.Printf("DataPlane: PAC profiles: %v", err)
		}
		unlock()
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

	// Named decryption profiles (nil-skip; applied here alongside category groups —
	// both are named objects the policy rules reference by name).
	if snap.DecryptionProfiles != nil {
		globalDecryptionProfiles.ReplaceAll(snap.DecryptionProfiles)
		globalDecryptionProfiles.Save()
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

// applySnapshotSaaSFeed applies the CP-authoritative SaaS signed category-feed
// configuration + admin category overrides on a Data Plane node (F3a-2). It is
// pure configuration plumbing: it updates the node-local durable feed holder and
// the override store — it NEVER fetches, verifies, activates, or arms any loop
// (no downloader exists until F3b). The snapshot was already whole-validated in
// validateConfigSnapshot, so applying here cannot fail or partially apply.
//
// Presence semantics (§A.2.2/§A.3.2): each feed field is nil/empty-skip so an
// older or rolled-back CP that omits a field leaves the DP's local resolution
// untouched (absence is never turned into false/default/deletion). The
// *bool managed/enabled are the load-bearing case — a nil pointer keeps the DP's
// durable state, a non-nil one is authoritative even when false. CategoryOverrides
// is nil-skip / non-nil-replace: a non-nil (even empty) set is an authoritative
// replacement so an admin clearing the last override wipes it fleet-wide.
func applySnapshotSaaSFeed(snap ConfigSnapshot) {
	// Feed config: overlay only the CP-set fields onto the DP's durable holder.
	d := getSaaSFeedDurable()
	changed := false
	if snap.SaaSFeedManaged != nil {
		d.Managed = *snap.SaaSFeedManaged
		changed = true
	}
	if snap.SaaSFeedEnabled != nil {
		d.Enabled = *snap.SaaSFeedEnabled
		changed = true
	}
	if snap.SaaSFeedURL != "" {
		d.URL = snap.SaaSFeedURL
		changed = true
	}
	if snap.SaaSFeedProtocol != "" {
		d.Protocol = snap.SaaSFeedProtocol
		changed = true
	}
	if snap.SaaSFeedRefreshSeconds != 0 {
		d.RefreshSeconds = snap.SaaSFeedRefreshSeconds
		changed = true
	}
	if changed {
		// A managed DP must not retain a conflicting local feed policy: publish the
		// CP-overlaid state so it wins. In-memory only, BYTE-IDENTICAL to the
		// existing ProxyBaseURL snapshot field (applyExternalAuthSnapshotSettings):
		// the CP is authoritative and re-syncs on every version bump, and the DP
		// re-applies the last-good snapshot on restart. A follower DP's node-local
		// admin_settings.json is NOT the source of truth for CP-pushed config, so
		// (like ProxyBaseURL) it is deliberately not written here — avoiding an
		// admin-settings write on the hot sync path.
		setSaaSFeedDurable(d)
	}

	// Category overrides: nil ⇒ CP did not send them (older/rolled-back) ⇒ keep
	// the DP's local copy; non-nil ⇒ authoritative replacement (empty ⇒ wipe).
	// ReplaceAll re-validates + persists overrides.json; the snapshot was already
	// validated, so this cannot reject.
	overridesChanged := false
	if snap.CategoryOverrides != nil {
		beforeFP := saasFeedOverridesFingerprint(globalCategoryOverrides.Get())
		if err := globalCategoryOverrides.ReplaceAll(*snap.CategoryOverrides); err != nil {
			logger.Printf("DataPlane: category overrides apply rejected: %v", err)
		} else {
			if serr := globalCategoryOverrides.Save(); serr != nil {
				logger.Printf("DataPlane: category overrides save: %v", serr)
			}
			overridesChanged = saasFeedOverridesFingerprint(globalCategoryOverrides.Get()) != beforeFP
		}
	}

	// F3b-4: close the deferred managed-DP persistence finding. The scalar overlay
	// above stays in-memory only (like ProxyBaseURL), but the F3b lifecycle IS the
	// runtime consumer, so on a managed DP we now durably mirror the last authoritative
	// CP feed configuration + fencing identity to a node-local, off-every-config-surface
	// record. This runs AFTER the durable holder + overrides are updated so the mirror
	// (incl. the overrides fingerprint) reflects the just-accepted snapshot. The snapshot
	// reached here only after dpObserveEpoch (fencing) + validateConfigSnapshot passed,
	// so the mirror is written only for authenticated, fenced, validated authority. A
	// no-op on a non-managed node or before the lifecycle wires the store.
	persistSaaSFeedAuthorityMirror(snap)

	// F3b-4 finding #5: when the CP snapshot changed ONLY the overrides (manifest unchanged),
	// a scheduler wake would fetch and 304 without recomposing. Apply the new authoritative
	// overrides to the policy hot path directly via a local, no-network recompose. Gated on a
	// real fingerprint change so an unchanged-override snapshot does no needless work.
	if overridesChanged {
		recomposeSignedFeedOverrides()
	}

	// A fresh authoritative snapshot (new epoch / enable / interval change) requires the
	// scheduler to re-evaluate now rather than waiting for its next tick.
	wakeSignedFeedScheduler()
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
	// A synced enabled LDAP profile makes the registry the sole operational
	// LDAP authority on this DP too (ADR-0027) — a node-local legacy YAML
	// ldap provider must not remain a second authenticator.
	enforceLegacyLDAPShadowing()
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
	// Seed the poll-deadline size predictor from the on-disk snapshot so a
	// cold-started DP's very FIRST poll already budgets time for a full transfer
	// of roughly this size — otherwise a large config on a thin WAN times out at
	// the 15s base and loops (the failover-churn pathology P1 #4 fixes for
	// running DPs but not, without this, at boot). len(data) ≈ the wire size.
	if len(data) > 0 {
		dpLastFullSnapshotBytes.Store(int64(len(data)))
	}
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
	if err := applyConfigSnapshot(snapForApply); err != nil {
		return ConfigSnapshot{}, fmt.Errorf("apply last-known-good config: %w", err)
	}
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
	// Compact Marshal, not MarshalIndent: this runs at the peak-overlap moment of
	// a config apply (new blocklist maps built while the old are still live), and
	// MarshalIndent double-buffers (compact + indented copies) a snapshot that can
	// be ~60 MiB at 2 M hosts — needless transient memory on the exact path P0-2
	// hardens against OOM. The last-good file is machine-read, not human-edited.
	data, err := json.Marshal(snap)
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

	// Full policy sync. Rules + version come from ONE running-store snapshot
	// (§13 fenced-read audit): List() then policyVersion() as two reads let a
	// concurrent mutation pair generation-P rules with a generation-P+1
	// version in the published snapshot.
	snap.DefaultAction = defaultPolicyAction()
	ps := policyStore.SnapshotWithVersion()
	snap.PolicyRules = ps.Rules
	snap.PolicyVersion = ps.Version
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

	// PAC exclusions + profiles/pools. All three are WireWipeCapable: force
	// non-nil so an admin-cleared empty state serializes as [] and reaches
	// DPs as an explicit wipe.
	pacCfg := pacStore.Get()
	snap.PACExclusions = pacCfg.Exclusions
	if snap.PACExclusions == nil {
		snap.PACExclusions = []string{}
	}
	pacProfCfg := pacProfiles.Get()
	snap.PACProfiles = nonNilProfiles(pacProfCfg.Profiles)
	snap.PACPools = nonNilPools(pacProfCfg.Pools)
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
	snap.DecryptionProfiles = globalDecryptionProfiles.List()

	// Global file-block extensions (CRIT-2: DP nodes need the blocklist).
	snap.FileBlockExtensions = fileBlocker.List()

	// OTLP endpoint (CRIT-3: DP nodes need the endpoint to export spans/metrics).
	snap.OTLPEndpoint = globalOTLP.Endpoint()

	// SaaS feed configuration (F3a-2). A current CP always sets both presence
	// pointers (managed/enabled) from its resolved durable state, so a live fleet
	// always propagates an explicit disable; only a pre-F3a-2 / rolled-back CP
	// omits them, and then the DP correctly keeps its local durable resolution
	// instead of re-enabling (§A.2.2). The URL is captured RESOLVED (built-in
	// official envelope when unset / a historical URL rewritten), so the DP never
	// re-derives it. Protocol canonicalizes to signed_manifest_v1.
	feedDurable := getSaaSFeedDurable()
	managed := feedDurable.Managed
	enabled := feedDurable.Enabled
	snap.SaaSFeedManaged = &managed
	snap.SaaSFeedEnabled = &enabled
	if resolved, err := resolvedSaaSFeedConfig(); err == nil {
		snap.SaaSFeedURL = resolved.URL
		snap.SaaSFeedProtocol = resolved.Protocol
		snap.SaaSFeedRefreshSeconds = int64(resolved.Refresh / time.Second)
	}

	// Admin category overrides (F3a-2). Always non-nil on a current CP so an
	// admin-cleared (empty) set propagates as an explicit wipe; a rolled-back CP
	// that predates the field sends nothing and the DP keeps its local copy.
	ov := globalCategoryOverrides.Get()
	snap.CategoryOverrides = &ov

	// Optional signed MCP CP→DP snapshots (PR-10). nil when MCP distribution is
	// disabled (the default) ⇒ omitempty ⇒ the snapshot is byte-identical to the
	// pre-PR-10 SWG snapshot. A published capability stamps its signed envelope here.
	snap.MCPGatewaySnapshot = mcpCapturedGateway()
	snap.MCPManagementSnapshot = mcpCapturedManagement()

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
