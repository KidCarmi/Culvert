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
	// NO omitempty (WireWipeCapable): since CHAOS-88 the stored+enabled
	// profile set IS the revocation lever for a federation, so deleting the
	// LAST profile must reach every DP. With omitempty an empty registry
	// serialized to nothing, the DP read nil and syncSnapshotIdPProfiles
	// SKIPPED — leaving the removed federation stored, enabled and live on
	// every DP, still minting policy groups and still accepting new logins
	// (§50.6d). Same security argument as decryption_profiles below.
	//
	// nil still means ABSENT and must keep skipping: redactUnenrolledSnapshot
	// sets this field to nil for an unenrolled caller, and GetConfig is polled
	// by a DP BEFORE enrollment completes, so treating a null as a wipe would
	// clear the registry of every enrolling node.
	IdPProfiles []*IdPProfile `json:"idp_profiles"`

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
//
// AU-50: "all tiny" was false for ONE of them. A SyncRevocations request
// carries the node's live revocation list, which includes every fleet entry it
// merged, so it grows with the fleet rather than staying tiny — past this
// bound every sync failed with ResourceExhausted. That request is now budgeted
// below this limit (maxRevocationSyncRequestBytes, revocation_sync_budget.go);
// a new inbound RPC whose body can grow must be budgeted the same way rather
// than relying on this paragraph.
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

// haBundleFrameReserve is the margin between the HA bundle's byte budget and
// the gRPC frame, and it is MEASURED rather than inherited.
//
// The bundle rides rawCodec (controlplane_codec.go), which treats the
// json.RawMessage as OPAQUE BYTES — no protobuf wrapper — so the marshalled
// bundle IS the gRPC message payload. grpc-go bounds the payload and nothing
// else: the send path compares `payloadLen > maxSendMessageSize` and the
// receive path `length > maxReceiveMessageSize`, where `length` is the value
// in the 5-byte message header (verified against v1.83.2). The header itself,
// the HTTP/2 DATA frame headers (9 bytes per 16 KiB frame, so ~72 KiB across a
// 128 MiB message) and HPACK are all OUTSIDE that comparison.
//
// So the true accounting overhead is under 100 KiB and this reserve is
// defensive headroom — ~14x the computed worst case — not a framing tax.
const haBundleFrameReserve = 1 << 20 // 1 MiB

// maxHABundleWireBytes is the byte budget for the HA state bundle. It is a
// SEPARATE bound rather than a reuse of maxSnapshotWireBytes because the bundle
// CONTAINS a published config plus the cluster state, the CA material and —
// since CHAOS-68 — the leader's live revocation set. The config's own gate
// therefore says nothing about the bundle's size: a snapshot admitted at
// exactly maxSnapshotWireBytes leaves the bundle's other members to overflow
// the frame on their own.
//
// **It is DERIVED FROM THE FRAME, never from the config cap** (AU-44). The
// first shipped value was a literal 120 MiB — numerically identical to
// maxSnapshotWireBytes, which is the cap on a member this bundle CONTAINS — so
// a config published at its own limit consumed the entire bundle budget and
// `budget - (len(resp) - len(revJSON))` handed fitRevocationsToBudget zero or
// less. Every revocation was dropped, on exactly the enterprise estate whose
// config is large enough to matter, while ~8 MiB of frame sat unused and a
// promotion admitted sessions the leader had revoked. The prose above computed
// the right headroom and the constant gave it away: **a budget for a container
// must be derived from what holds the container, not from what it holds.**
//
// What differs from the config's gate is the REMEDY: an over-budget config is
// refused at publish, because a config the fleet cannot fetch must never
// commit; an over-budget bundle is TRIMMED (see fitRevocationsToBudget),
// because refusing it would take down HA replication entirely — config, CA,
// cluster state and every revocation — to protect the one member that grew.
const maxHABundleWireBytes = maxClusterGRPCMsgSize - haBundleFrameReserve // 127 MiB

// snapshotWireBudget is the budget validateSnapshotForPublish enforces —
// maxSnapshotWireBytes in production. A variable only so a gate can exercise
// the near-limit edge without marshalling a 120 MiB snapshot.
var snapshotWireBudget = maxSnapshotWireBytes

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
	// The ADDRESS-publish rejection latch (error text, page-once-per-episode
	// latch, episode number) is NOT here: it is part of addrPub below, under
	// the publish generation, written only by noteCPAddrPublish /
	// resetCPAddrPublish (Codex review of #1556: as store state under s.mu,
	// a stale up-to-date or commit cleared a newer failure's latch).
	// published is true once a VALID snapshot has been published at least once.
	// It stays false if the CP's initial publish was rejected at commit — in
	// which case s.snap is still the zero ConfigSnapshot and the cluster RPCs
	// must refuse rather than distribute an empty config (see ServableConfig).
	published bool
	// deltaRing retains recent per-version blocklist deltas so a lagging DP can
	// catch up incrementally via GetConfigDelta (T3 P1). The zero value is
	// ready; a swapped-in test store gets a fresh ring automatically.
	deltaRing blocklistDeltaRing
	// cpAddrSource, once set (setCPAddressSource, at Control Plane
	// activation), makes the CP address list OWNED by UpdateCPAddressesFrom:
	// a full Update keeps the committed list instead of the one its caller
	// captured, then reconciles it from this source. Nil on bare/test stores
	// and on non-CP nodes. Guarded by mu.
	cpAddrSource func() []string
	// cpAddrWithdrawal, when non-empty, is the address of a Control Plane
	// whose supervisor exited terminally while the fleet's list still named
	// it: cpAddrSource is then a WITHDRAWAL source (the live list without
	// it), and ownership is released only once a publish from it commits
	// (cp_addr_publish.go, Codex review of #1556). Cleared by
	// setCPAddressSource and releaseCPAddressSource. Guarded by mu.
	cpAddrWithdrawal string
	// cpAddrOwnerGen is the address-list OWNERSHIP generation: bumped by every
	// change of cpAddrSource/cpAddrWithdrawal (a new owner, a withdrawal
	// installed, a release), all of which go through setCPAddrOwnerLocked. A
	// publish captures it with the source it builds from (cpAddrOwner) and
	// commits only while it is unchanged (commitPublish), so a source captured
	// before an ownership change can never commit after it (Codex review of
	// #1556). Never reset. Guarded by mu.
	cpAddrOwnerGen uint64
	// addrPub is the owned address list's pending-republish record
	// (cp_addr_publish.go): set when an owned republish fails, cleared by the
	// retry loop or the next success. Guarded by addrPubMu, which is never held
	// while taking mu.
	addrPubMu sync.Mutex
	addrPub   cpAddrPublishState
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
	// CHAOS-71: a full publish NEVER decides the CP address list. The list has
	// exactly one writer, the owned address publish (updateCPAddressesBound,
	// bound to the ownership generation); a full publish carries the COMMITTED
	// list forward unchanged, owned or not.
	//
	// The snapshot was built BEFORE reaching here, so its CPAddresses can
	// predate a delayed CP activation that has since published a new list
	// (CodeRabbit review of #1556) — or a terminal exit that withdrew a dead
	// Control Plane and released ownership, after which a list derived from HA
	// state would re-add that endpoint with nothing left to remove it (Codex
	// P2 4307107242). The carry-forward is read from the committed view inside
	// the CAS: commitPublish commits only onto the exact base it built from,
	// so a retry after a withdrawal rebuilds from the post-withdrawal list. It
	// precedes validation, so what commits is exactly what passed the
	// wire-size gate. A legitimate change while owned is applied by the
	// reconcile below; an unowned node's list changes only through ownership.
	_, err := s.commitPublish(publishPlan{
		kind: publishFull,
		build: func(cur committedView) (ConfigSnapshot, publishAct) {
			cand := snap
			cand.CPAddresses = cur.snap.CPAddresses
			return cand, publishCommit
		},
		beforeCommit: func() {
			if hook := configPublishBeforeCommit; hook != nil {
				hook()
			}
		},
		exhausted: fmt.Errorf("config publish lost the commit race against concurrent publishes %d times in a row", cpAddrMergeAttempts),
	})
	if err != nil {
		return err
	}
	if own := s.currentCPAddrOwner(); own.owned() {
		// Propagate an address change this publish was carrying. A failure is
		// logged and alerted by rejectPublish and latched pending (with a
		// retry) by publishOwnedCPAddresses; this publish itself already
		// succeeded. Bound to the ownership read here: if a withdrawal or a
		// release lands before it commits, it rebuilds from the new owner or
		// stops, never committing this owner's list.
		_, _ = s.publishOwnedCPAddressesAs("config_publish", own, nil)
	}
	return nil
}

// configPublishBeforeCommit, when non-nil, runs between Update's validation and
// its commit. Test seam only (nil in production): it opens the "owned list
// changed after validation" window deterministically.
var configPublishBeforeCommit func()

// reconcileCPAddressesFrom republishes the CP address list from build when
// this store's list is owned (an active Control Plane set a source); a no-op
// otherwise, so a standby or a Data Plane never publishes one. A failure is
// recorded pending and retried (publishOwnedCPAddresses).
func (s *ConfigStore) reconcileCPAddressesFrom(trigger string, build func() []string) error {
	own := s.currentCPAddrOwner()
	if !own.owned() {
		return nil
	}
	// A withdrawal owning the list replaces build (cpAddrOwner.builder): an HA
	// transition re-derives it from the withdrawal source, never from a
	// builder that may still name the Control Plane being withdrawn.
	_, err := s.publishOwnedCPAddressesAs(trigger, own, build)
	return err
}

// releaseCPAddressSource gives up ownership of the CP address list: a
// SYNCHRONOUS activation (admin or promote) that was refused leaves no Control
// Plane behind, so nothing may keep reporting or reconciling one (Codex review
// of #1556). The pending-republish state and the address rejection latch go
// with it; a running retry loop sees no source and exits clean.
func (s *ConfigStore) releaseCPAddressSource() {
	s.mu.Lock()
	s.setCPAddrOwnerLocked(nil, "")
	s.mu.Unlock()
	s.resetCPAddrPublish()
}

// setCPAddressSource hands ownership of the CP address list to build (see
// cpAddrSource). Called once at Control Plane activation.
func (s *ConfigStore) setCPAddressSource(build func() []string) {
	s.mu.Lock()
	s.setCPAddrOwnerLocked(build, "") // a new owner ends any withdrawal
	s.mu.Unlock()
	s.resetCPAddrPublish() // a new owner starts a new episode
}

// validatePublishCandidate runs the commit-time gates for one publish kind.
// Returns the RAW error; commitPublish routes it through rejectPublish.
//
// A FULL publish passes every gate (validateSnapshotForPublish). An
// address-only candidate passes the size gates but NOT Gate 0 (Codex P1
// 4314031064 on #1556): it is the COMMITTED snapshot with only CPAddresses
// replaced (updateCPAddressesBound, or a same-content restamp), so it carries
// no rewrite StableID that is not already committed and served; Gate 0 exists
// to stop a publish that CAPTURES the live, known-ephemeral ones
// (CurrentConfigSnapshot). Applying the process-global latch to it instead
// refused every CP activation and HA promotion on a node whose store had
// already published, rolling the role back on each attempt until a restart —
// an unrelated rewrite-persistence fault disabling failover. Full publishes
// are still refused while the latch is set
// (TestChaos71_RewriteDegradationStillRefusesFullPublishes).
//
// An epoch restamp (RestampFenceEpoch) is the same case: the COMMITTED
// snapshot, content unchanged, with only the fencing epoch replaced — the
// commit every fenced HA transition makes before it advertises a new epoch
// (commitGrant). Through Gate 0 it refused every fenced promote while the
// latch was set (TestChaos71_FencedPromotionRestampsTheEpochWhileRewriteIdentityDegraded).
// A promote's FIRST publish is a full one and stays gated
// (preflightFirstPublish). Any other kind takes every gate: the exemption is
// listed, never inferred.
func validatePublishCandidate(kind publishKind, cand ConfigSnapshot) error {
	switch kind {
	case publishAddresses, publishEpoch:
		return validateSnapshotWireForPublish(cand)
	default:
		return validateSnapshotForPublish(cand)
	}
}

// validateSnapshotForPublish runs every commit-time gate a FULL publish passes
// (Update). Returns the RAW error; the caller routes it through rejectPublish.
func validateSnapshotForPublish(snap ConfigSnapshot) error {
	// Gate 0 — rewrite management-identity degradation: while the latch is
	// set, CurrentConfigSnapshot has captured KNOWN-ephemeral rewrite
	// StableIDs that must not be distributed to the fleet as authoritative
	// identity (a DP applies them verbatim, and they re-mint on the CP's next
	// restart). Reuses the existing commit-time rejection contract — logged,
	// alerted, LastPublishError; the fleet stays on the last valid snapshot —
	// rather than silently omitting or re-minting the rewrite slice.
	if d := rewriteIdentityDegraded(); d != nil {
		return fmt.Errorf("rewrite management identity degraded (%s): refusing to publish ephemeral rewrite StableIDs as authoritative fleet identity", d.reason)
	}
	return validateSnapshotWireForPublish(snap)
}

// validateSnapshotWireForPublish is the size gates every publish kind passes:
// an address-only candidate can still grow the snapshot past the frame.
func validateSnapshotWireForPublish(snap ConfigSnapshot) error {
	// Gate 1 — entry counts (fast pre-check).
	if err := validateConfigSnapshot(snap); err != nil {
		return err
	}
	// Gate 2 — marshaled BYTE budget. Counts can pass while long strings push
	// the snapshot past the frame; measuring the real wire size here stops a
	// byte-oversized config from committing and then failing every DP fetch.
	b, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("config snapshot marshal failed: %w", err)
	}
	if len(b) > snapshotWireBudget {
		return fmt.Errorf("config snapshot wire size=%d bytes exceeds budget %d (too large to sync in one CP↔DP frame)", len(b), snapshotWireBudget)
	}
	return nil
}

// configCommit carries what afterCommit needs from a commit made under s.mu.
type configCommit struct {
	base, target       int64
	epoch              int64
	oldHosts, newHosts []string
	subs               []chan struct{}
}

// commitLocked stamps and installs snap as the published snapshot. Caller
// holds s.mu (write) and has already validated snap. Called ONLY by
// commitPublish (TestChaos71_Wall_OnlyCommitPublishCommits). It clears the
// rejection latch of its OWN kind: an address-only commit carries none of a
// rejected full publish's policy, so the fleet is still frozen on it (Codex
// review of #1556).
func (s *ConfigStore) commitLocked(kind publishKind, snap ConfigSnapshot) configCommit {
	// Capture the pre-publish blocklist + version for the delta ring. oldHosts
	// still references the outgoing snapshot's slice (safe — s.snap is replaced,
	// not mutated in place).
	c := configCommit{oldHosts: s.snap.BlockedHosts, base: s.version}
	// Strictly above everything this store has served or been seeded with: the
	// counter and the committed snapshot's own version (a replicated leader
	// snapshot is folded in by seedReplicatedSnapshot; the max is the backstop).
	s.version = max(s.version, s.snap.Version) + 1
	snap.Version = s.version
	snap.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	c.newHosts = snap.BlockedHosts
	c.target, c.epoch = s.version, snap.Epoch
	s.snap = snap
	s.published = true
	s.clearPublishErrLocked(kind)
	s.persistVersionLocked()
	// Claim this commit's delta slot under the commit lock, so the deltas
	// computed outside it are applied in commit order (afterCommit).
	s.deltaRing.reserve(c.target)
	c.subs = append([]chan struct{}{}, s.subs...)
	return c
}

// publishKind names which publish path a commit or rejection belongs to. The
// rejection latch is keyed by it: a full-publish rejection ("the fleet is
// frozen on stale policy") is cleared only by a successful FULL publish, an
// address-list rejection only by a successful address publish.
type publishKind int

const (
	publishFull      publishKind = iota // Update: the whole config
	publishAddresses                    // UpdateCPAddressesFrom: the CP address list only
	publishEpoch                        // RestampFenceEpoch: the committed content, new fencing epoch
)

// publishAct is a plan's verdict on one attempt.
type publishAct int

const (
	publishCommit       publishAct = iota // validate and commit the candidate
	publishUpToDate                       // the committed snapshot already says this
	publishNotYet                         // nothing published yet: nothing to correct
	publishOwnerChanged                   // the address-list owner this publish was bound to is gone
)

// committedView is the committed state one publish attempt builds from, read
// under s.mu.
type committedView struct {
	snap      ConfigSnapshot
	version   int64
	published bool
	ownerGen  uint64 // the ownership generation (cpAddrOwnerGen) at this read
}

// publishPlan is the per-kind part of a publish; commitPublish is the rest.
type publishPlan struct {
	kind publishKind
	// build derives the candidate from the committed view. Re-run on every
	// attempt, after the view it builds from was read.
	build        func(cur committedView) (ConfigSnapshot, publishAct)
	beforeCommit func() // test seam window between validation and commit
	exhausted    error  // reported when every attempt lost the race
}

// publishFenceEpoch is the fencing epoch every publish is stamped with: the
// node's CURRENT epoch, read lock-free (PublishedFenceEpoch) so a publish
// never needs HAState.mu (no publish runs under it, and none may wait on it
// either: TestChaos71_Wall_NoSnapshotPublishUnderTheHALock). It reads the same
// HAState the CP address list derives from (haTopologySource: globalHA in
// production). Test seam.
var publishFenceEpoch = func() int64 { return haTopologySource().PublishedFenceEpoch() }

// commitPublish is the ONE way a snapshot is committed (CHAOS-71, Codex review
// of #1556). Rounds 4, 5, 7 and 8 of that review each found the address-only
// path skipping an invariant the full path kept; both now share this, so each
// invariant holds for every commit by construction:
//
//   - Optimistic concurrency, one rule for every kind: an attempt records the
//     committed version it built from (base) and commits ONLY if, under the
//     lock, the committed state is still exactly that base. Anything else —
//     another publish, a replicated snapshot seeded in — means the candidate is
//     stale: rebuild, revalidate, within the bounded retry; then reject via
//     rejectPublish. (A partial check let a full publish built before a
//     promotion's restamp commit over it — Codex review of #1556.)
//   - Epoch is the fencing epoch CURRENT AT COMMIT: stamped before validation
//     and re-read under the lock, and a change since is the same stale-base
//     outcome. A DP that learned a new epoch on heartbeat is never handed a
//     snapshot carrying the previous one (dpObserveEpoch would reject it).
//   - What commits is what was validated (outside the lock: a full marshal
//     must not stall DP pollers), the version strictly exceeds every version
//     served or seeded (commitLocked), sizes are recorded under the commit
//     lock, and the rejection latch is keyed by kind.
func (s *ConfigStore) commitPublish(p publishPlan) (committed bool, err error) {
	for attempt := 0; attempt < cpAddrMergeAttempts; attempt++ {
		s.mu.RLock()
		own := s.cpAddrOwnerLocked()
		cur := committedView{snap: s.snap, version: s.version, published: s.published, ownerGen: own.gen}
		s.mu.RUnlock()

		epoch := publishFenceEpoch()
		cand, act := p.build(cur)
		if act == publishUpToDate && cur.snap.Epoch != epoch {
			// Same content, stale stamp: restamp it (a promotion or a new grant
			// changes the epoch without changing the list).
			cand, act = cur.snap, publishCommit
		}
		switch act {
		case publishNotYet:
			return false, nil
		case publishOwnerChanged:
			return false, errCPAddrOwnerChanged // the caller rebuilds from the new owner, or stops
		case publishUpToDate:
			// What this kind would publish is already committed. Only the FULL
			// latch is the store's to clear; the address latch is cleared by
			// noteCPAddrPublish under the publish generation.
			s.mu.Lock()
			s.clearPublishErrLocked(p.kind)
			s.mu.Unlock()
			return false, nil
		}
		cand.Epoch = epoch
		if verr := validatePublishCandidate(p.kind, cand); verr != nil {
			return false, s.rejectPublish(p.kind, verr)
		}
		if p.beforeCommit != nil {
			p.beforeCommit()
		}

		s.mu.Lock()
		if !s.committedIsLocked(cur) || publishFenceEpoch() != epoch {
			s.mu.Unlock()
			continue // stale base or stale stamp: rebuild, revalidate
		}
		c := s.commitLocked(p.kind, cand)
		recordPublishedSnapshotSizes(cand) // under the commit lock: the record matches the last commit
		s.mu.Unlock()
		s.afterCommit(c)
		return true, nil
	}
	// Reported through the ordinary rejection path (logged, alerted, latched).
	return false, s.rejectPublish(p.kind, p.exhausted)
}

// committedIsLocked reports whether the committed state is still exactly the
// base an attempt built from. Caller holds s.mu. Any address-list ownership
// change (the generation) is a changed base too: the attempt rebuilds, and an
// attempt bound to the previous owner then stops (publishOwnerChanged).
func (s *ConfigStore) committedIsLocked(base committedView) bool {
	return s.version == base.version && s.snap.Version == base.snap.Version &&
		s.published == base.published && s.cpAddrOwnerGen == base.ownerGen
}

// clearPublishErrLocked clears the rejection latch of one kind. Caller holds
// s.mu (write).
func (s *ConfigStore) clearPublishErrLocked(kind publishKind) {
	if kind == publishFull {
		s.lastPublishErr, s.lastPublishTS = "", ""
		return
	}
	// publishAddresses: nothing here — its latch is the address-publish
	// record's (noteCPAddrPublish), guarded by the publish generation.
	// publishEpoch: nothing either — a restamp carries none of a rejected full
	// publish's policy, and its refusal is the HA transition's to report
	// (commitGrant).
}

// afterCommit records the blocklist delta and notifies subscribers OUTSIDE the
// store lock: the O(N) diff + fingerprint over up to 2 M hosts must not stall
// config readers/pollers. Config publishes are admin-action-rate, so the cost
// is not hot-path. Concurrent commits may finish this in any order; the ring
// applies their deltas in commit order (the slot commitLocked reserved).
func (s *ConfigStore) afterCommit(c configCommit) {
	s.recordCommitDelta(c)
	for _, ch := range c.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	logger.Printf("ControlPlane: config v%d published", c.target)
}

// recordCommitDelta computes c's delta and completes its reserved slot. The
// slot is completed even if the computation panics (as a resync marker), so
// one failed commit can never stall every later delta behind it.
func (s *ConfigStore) recordCommitDelta(c configCommit) {
	d := blocklistDelta{Version: c.target, Base: c.base, Epoch: c.epoch, Resync: true}
	defer func() { s.deltaRing.complete(d) }()
	if hook := afterCommitBeforeDelta; hook != nil {
		hook(c.target)
	}
	d = buildBlocklistDelta(c.base, c.target, c.oldHosts, c.newHosts, blocklistSyncedFingerprint(c.newHosts), c.epoch)
}

// afterCommitBeforeDelta, when non-nil, runs before a commit's delta is
// computed. Test seam only (nil in production): it makes one commit's delta
// slow so a later commit's finishes first.
var afterCommitBeforeDelta func(target int64)

// cpAddrMergeAttempts bounds UpdateCPAddresses' optimistic retries. Publishes
// are admin-action-rate, so losing the race this many times in a row means
// something is publishing in a tight loop — reported, not spun on.
const cpAddrMergeAttempts = 8

// cpAddrMergeBeforeCommit, when non-nil, runs between UpdateCPAddresses'
// validation and its compare-and-swap commit. Test seam only (nil in
// production): it lets a gate commit a competing publish inside that window
// deterministically.
var cpAddrMergeBeforeCommit func()

// UpdateCPAddressesFrom publishes build() as the fleet's CP address list by
// MERGING onto the latest COMMITTED snapshot — never onto a snapshot captured
// earlier (CHAOS-71, Codex review of #1556).
//
// build is re-run on EVERY attempt, after reading the version it will
// compare-and-swap against: a list computed before a role change could
// otherwise be committed after a fresher one, so each committed list is
// computed after the commit it replaces. build must not need s.mu (it runs
// outside it) — buildCPAddressList takes globalHA.mu and clusterRoleMu only.
//
// It exists for the Control Plane's post-bind activation. A full
// Update(CurrentConfigSnapshot()) whose snapshot was built just before an admin
// publish committed would republish the OLDER state at a higher version merely
// to add the address list, rolling the admin change back on every Data Plane.
// Instead this reads (snapshot, version) under the store lock, validates the
// merged copy with Update's size gates (not its rewrite-identity Gate 0: the
// merged copy captures no live state; see validatePublishCandidate), and
// commits only if
// the version is still the one it read — a compare-and-swap on s.version under
// the same s.mu every publish commits under, not a second lock. A lost race
// re-reads and re-merges onto the newer commit.
//
// Returns changed=false with no publish when nothing has been published yet
// (there is no committed snapshot to correct, and the first full publish will
// carry the address list) or when the committed list already equals addrs. A
// gate rejection goes through rejectPublish (logged, alerted,
// LastPublishError) and is RETURNED so activation can refuse to succeed.
//
// It is bound to the address-list ownership current at the call; see
// updateCPAddressesBound.
func (s *ConfigStore) UpdateCPAddressesFrom(build func() []string) (changed bool, err error) {
	return s.updateCPAddressesBound(s.currentCPAddrOwner(), build)
}

// updateCPAddressesBound is UpdateCPAddressesFrom bound to own: build commits
// only while the ownership generation is still own's, checked on the view
// every attempt builds from and again, under s.mu, at the commit
// (committedIsLocked). An ownership change since own was read returns
// errCPAddrOwnerChanged with nothing committed (Codex review of #1556: a
// source captured before a withdrawal committed and released ownership
// re-added the dead Control Plane at a higher version).
func (s *ConfigStore) updateCPAddressesBound(own cpAddrOwner, build func() []string) (changed bool, err error) {
	return s.commitPublish(publishPlan{
		kind: publishAddresses,
		build: func(cur committedView) (ConfigSnapshot, publishAct) {
			if cur.ownerGen != own.gen {
				return ConfigSnapshot{}, publishOwnerChanged
			}
			if !cur.published {
				return ConfigSnapshot{}, publishNotYet
			}
			addrs := build()
			if slicesEqual(cur.snap.CPAddresses, addrs) {
				return ConfigSnapshot{}, publishUpToDate
			}
			merged := cur.snap // shallow copy: published snapshots are never mutated in place
			merged.CPAddresses = append([]string(nil), addrs...)
			return merged, publishCommit
		},
		beforeCommit: func() {
			if hook := cpAddrMergeBeforeCommit; hook != nil {
				hook()
			}
		},
		exhausted: fmt.Errorf("%w %d times in a row", errCPAddrCommitRace, cpAddrMergeAttempts),
	})
}

// RestampFenceEpoch commits the COMMITTED snapshot, content unchanged,
// restamped with the current stamp epoch (publishFenceEpoch) — the commit an
// authority-gaining HA transition makes BEFORE it advertises a new fencing
// epoch (commitGrant, ha_epoch_commit.go). The candidate is the
// committed snapshot plus the epoch digits, through the same commit-time gates
// and optimistic concurrency as every publish. An already-current stamp is
// success.
//
// Nothing published yet is NOT success: it returns errNoSnapshotToRestamp
// (Codex P1 4302217586 on #1645). A Control Plane whose initial publish was
// rejected has no distributable snapshot, so no commit carries the epoch, and
// the transition must not advertise it on that strength. commitGrant decides
// what follows: a refusal, or for a promote a first publish its activation
// makes, verified before the epoch is exposed.
func (s *ConfigStore) RestampFenceEpoch() error {
	notYet := false
	_, err := s.commitPublish(publishPlan{
		kind: publishEpoch,
		build: func(cur committedView) (ConfigSnapshot, publishAct) {
			notYet = !cur.published
			if notYet {
				return ConfigSnapshot{}, publishNotYet
			}
			// Content unchanged: commitPublish restamps an up-to-date snapshot
			// whose epoch is stale, and commits nothing when it is current.
			return ConfigSnapshot{}, publishUpToDate
		},
		exhausted: fmt.Errorf("fencing-epoch restamp lost the commit race %d times in a row", cpAddrMergeAttempts),
	})
	if err == nil && notYet {
		return errNoSnapshotToRestamp
	}
	return err
}

// preflightFirstPublish runs the commit-time gates over snap stamped with the
// current stamp epoch, committing nothing: whether a first publish of snap,
// made now, would be accepted. A promote whose store has published nothing
// uses it before its activation starts the Control Plane listener
// (commitGrant): an activation whose first publish would be rejected must be
// refused before that listener exists, not after.
func preflightFirstPublish(snap ConfigSnapshot) error {
	snap.Epoch = publishFenceEpoch()
	return validatePublishCandidate(publishFull, snap) // the activation's first publish is a full one (Update)
}

// keepEpochStampIfCommitted reports whether the committed snapshot already
// carries epoch e (a concurrent publish committed it); if not it runs revert —
// the stamp mirror's rollback — under s.mu, the lock every commit re-checks
// the mirror under, so no publish can commit e after the revert.
func (s *ConfigStore) keepEpochStampIfCommitted(e int64, revert func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.published && s.snap.Epoch == e {
		return true
	}
	revert()
	return false
}

// revertEpochStamp runs revert — an abandoned install's stamp-mirror rollback
// (abandonGrantLocked) — under s.mu, the lock every commit re-checks the
// mirror under, telling it whether the committed snapshot carries epoch e. So
// the check and the rollback are one step: no publish commits e between them.
func (s *ConfigStore) revertEpochStamp(e int64, revert func(committed bool)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	revert(s.published && s.snap.Epoch == e)
}

// rejectPublish records a commit-time rejection (count OR byte gate): it does
// NOT publish, stamps LastPublishError, logs, and fires the operator alert.
// Returns err so callers can surface it inline too.
func (s *ConfigStore) rejectPublish(kind publishKind, err error) error {
	s.mu.Lock()
	ts := time.Now().UTC().Format(time.RFC3339)
	if kind == publishFull {
		s.lastPublishErr, s.lastPublishTS = err.Error(), ts
	}
	curVer := s.version
	s.mu.Unlock()
	// The log line still records EVERY rejection (and the pending state counts
	// each attempt); only the page is latched.
	logWarnf("ControlPlane: REJECTING config publish (fleet stays on v%d): %v", curVer, err)
	if kind != publishFull {
		// The address kind's latch and its page (once per episode, queued
		// before the webhooks load) belong to the generation-guarded record:
		// the caller's noteCPAddrPublish decides and pageCPAddrRejection
		// delivers. The epoch kind's refusal is paged, once per episode, by
		// the HA transition that needed it (commitGrant).
		return err
	}
	payload := AlertPayload{
		Event:  "config_snapshot_rejected",
		Actor:  "culvert",
		Source: "cluster",
		Detail: "config publish rejected at commit: " + err.Error() + " — the cluster stays on the last valid config; reduce the oversized collection to resume sync",
	}
	fireAlert("config_snapshot_rejected", payload)
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
//
// The two latches are separate (publishKind): the full one — the fleet is on
// stale POLICY — wins; otherwise an address-list rejection is reported, since
// the fleet's failover list is behind.
func (s *ConfigStore) LastPublishError() (msg, ts string) {
	s.mu.RLock()
	msg, ts = s.lastPublishErr, s.lastPublishTS
	s.mu.RUnlock()
	if msg != "" {
		return msg, ts
	}
	st := s.cpAddrPublishSnapshot()
	return st.rejectErr, st.rejectErrTS
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
// WITHOUT marking published or notifying subscribers. It gives the delta ring a
// correct oldHosts baseline for the first post-promotion Update (Dur-F4).
//
// It FOLDS the replicated version into the store's counter (never lowering
// it): the counter is the one source of truth for the next version, and a
// self-fenced ex-leader that resynced v200 from the new leader while its own
// counter said v100 would otherwise republish at v101 on re-promotion — the
// no-op onPromote path never re-runs armVersionPersistence — and DPs at v200
// would read "unchanged" (Codex review of #1556). Distribution is still gated
// by ServableConfig/published and, with HA on, by the leader gate.
func (s *ConfigStore) seedReplicatedSnapshot(snap ConfigSnapshot) {
	s.mu.Lock()
	s.snap = snap
	if snap.Version > s.version {
		s.version = snap.Version
	}
	s.mu.Unlock()
}

// committedCPAddresses is the committed snapshot's CP address list.
func (s *ConfigStore) committedCPAddresses() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap.CPAddresses
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

// committedVersionEpoch returns the committed version and the fencing epoch
// the committed snapshot is stamped with (0 before the first publish), read
// together under one lock: the epoch a reply describing that version must
// carry (GetConfigDelta).
func (s *ConfigStore) committedVersionEpoch() (version, epoch int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.published {
		epoch = s.snap.Epoch
	}
	return s.version, epoch
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

// applySnapshotAdmission applies the IP filter and rate-limit settings before
// the remaining traffic configuration, shared by full and delta snapshots.
func applySnapshotAdmission(snap ConfigSnapshot) {
	// IP filter: replace the live owner's contents IN PLACE. The request path
	// (proxy.go / socks5.go) reads the ipf composition handle with no
	// synchronisation, so the previous `ipf = newIPF` swap was a data race on
	// the first admission gate (RISK-030); the owner already publishes an
	// immutable view through an atomic pointer, which is the synchronisation
	// the readers rely on. Replace is one pass, one lock, one view publish: an
	// Add loop is quadratic in the entry count, and this list's snapshot cap is
	// maxSnapIPList (2,000,000), so a large allowlist would stall the apply.
	// Invalid entries are reported after the lock is released. Pinned by
	// TestRISK030_* (controlplane_snapshot_ipf_race_test.go).
	for _, bad := range ipf.Replace(snap.IPFilterMode, snap.IPList) {
		logger.Printf("DataPlane: invalid IP %q: %v", bad.Entry, bad.Err)
	}

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
}

// applySnapshotTrafficExceptBlocklist applies every traffic/policy slice EXCEPT
// the blocklist (IP filter, rate limiter + exemptions, external auth, default
// action, policy rules, SSL bypass, URL categories, file profiles, rewrite, DPI,
// connection limits). Shared by the full-snapshot path and the delta path.
func applySnapshotTrafficExceptBlocklist(snap ConfigSnapshot) {
	applySnapshotAdmission(snap)

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

	// PAC exclusions. Store.Set is a persist-before-swap commit (CHAOS-77),
	// so a write that cannot land leaves the live exclusions untouched: the
	// slice is DEFERRED, exactly like the PAC profiles slice below, and the
	// rest of the snapshot still applies. Saying so matters because
	// fetchAndApply goes on to persist last-good, mark the apply healthy and
	// ratchet lastVersion, after which the CP answers every later poll
	// "unchanged" — so this line is the only notice that the node is
	// converged on paper while serving the previous exclusions.
	if snap.PACExclusions != nil {
		cur := pacStore.Get()
		cur.Exclusions = snap.PACExclusions
		if err := pacStore.Set(cur); err != nil {
			// sanitizeLog + %q per the CWE-117 rule in conventions.md: CodeQL
			// traces a user-provided value into this sink (alert 420). The
			// error carries the store path, and Store.Set now reaches its
			// durable write through the storeAtomicWrite seam, so CodeQL can
			// no longer prove the returned error is independent of the
			// snapshot-derived config it was handed. Sanitising at the sink
			// is correct either way and is the barrier CodeQL recognises.
			logger.Printf("DataPlane: PAC exclusions NOT applied this sync (deferred, previous list still live): %q",
				sanitizeLog(err.Error()))
		}
	}
	// PAC profiles/pools (PAC initiative PR 2): nil-skip (old CP), non-nil
	// replace — [] is an explicit wipe. Tolerant Set (never rejects).
	// 2F-E correction round 4: inside the shared PAC writer transaction
	// boundary (pacProfilesWriterLock — lock order gate → pacProfilesAPIMu).
	// 2F-E correction round 7: a pending lifecycle intent of every profile
	// the snapshot CHANGES is settled durably before the write
	// (pacSettlePendingBeforeWrite); if that cannot be persisted the PAC
	// profiles slice is deferred to the next sync (the rest of the snapshot
	// still applies).
	if snap.PACProfiles != nil || snap.PACPools != nil {
		unlock := pacProfilesWriterLock()
		before := pacProfiles.Get()
		cur := pacProfiles.Get()
		if snap.PACProfiles != nil {
			cur.Profiles = snap.PACProfiles
		}
		if snap.PACPools != nil {
			cur.Pools = snap.PACPools
		}
		if err := pacSettlePendingBeforeWrite(before, cur); err != nil {
			logger.Printf("DataPlane: PAC profiles not applied this sync (deferred): %v", err)
		} else if err := pacProfiles.Set(cur); err != nil {
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

	// HA: the CP addresses DPs auto-discover failover targets from. Carried
	// from the COMMITTED snapshot, never derived from HA state here: the owned
	// address publish is the list's only writer, and Update substitutes the
	// committed list again inside its CAS (Codex P2 4307107242 on #1556).
	snap.CPAddresses = globalConfigStore.committedCPAddresses()

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
//
// haStatus.PeerAddr is the leader's externally reachable address (set during
// Enable HA); the local listen address is added when it differs. The
// derivation itself is cpAddressListFor (ha_topology.go), shared with the HA
// topology writer that republishes on every transition.
func buildCPAddressList() []string {
	haStatus := haTopologySource().Status()
	if !haStatus.Enabled {
		return nil // no HA = no address list needed (clusterRoleMu deliberately not touched)
	}
	return cpAddressListFor(true, haStatus.PeerAddr, clusterRoleSnapshot().grpcAddr)
}
