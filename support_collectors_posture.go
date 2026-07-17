package main

import (
	"context"
	"time"

	"github.com/KidCarmi/Culvert/internal/ca"
	"github.com/KidCarmi/Culvert/internal/redaction"
	"github.com/KidCarmi/Culvert/internal/support"
)

// M2 breadth collectors (tls, config_versions, governance). Same fail-closed
// pattern as support_collectors_reused.go: a purpose-built, fully redact:-tagged
// section struct fed from an existing side-effect-free accessor. Private-key /
// credential material is unreachable by construction (the CA key provider is
// never called; only public cert metadata + posture counts are surfaced).

const supportMaxConfigVersions = 50 // store cap; the list is already bounded

// ── tls / CA posture ─────────────────────────────────────────────────────────

// tlsSection is the non-secret MITM-CA posture: public cert metadata, expiry,
// rotation/dual-CA state, key-provider NAME (never the key), and leaf-cache stats.
type tlsSection struct {
	CAReady         bool   `json:"ca_ready" redact:"public"`
	CASubject       string `json:"ca_subject,omitempty" redact:"internal"`
	CAIssuer        string `json:"ca_issuer,omitempty" redact:"internal"`
	CAFingerprint   string `json:"ca_fingerprint_sha256,omitempty" redact:"internal"`
	CANotBefore     string `json:"ca_not_before,omitempty" redact:"internal"`
	CANotAfter      string `json:"ca_not_after,omitempty" redact:"internal"`
	CAExpiresInDays int    `json:"ca_expires_in_days" redact:"internal"`
	RotationDueSoon bool   `json:"rotation_due_soon" redact:"internal"`
	KeyProvider     string `json:"key_provider,omitempty" redact:"internal"`
	SecondaryActive bool   `json:"secondary_ca_active" redact:"internal"`
	LeafCacheSize   int    `json:"leaf_cache_size" redact:"public"`
	LeafCacheHits   int64  `json:"leaf_cache_hits" redact:"public"`
	LeafCacheMisses int64  `json:"leaf_cache_misses" redact:"public"`
	LeafCacheTTLSec int    `json:"leaf_cache_ttl_seconds" redact:"public"`
	LeafCacheMax    int    `json:"leaf_cache_max_size" redact:"public"`
}

type tlsCollector struct{}

func (tlsCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "tls", Path: "sections/tls.json", Owner: "security", SchemaVersion: 1,
		Description: "MITM CA + leaf-cache posture (public cert metadata only, never keys)", Timeout: 2 * time.Second,
		ByteBudget: 16 << 10, Mandatory: false, MinLevel: support.L1,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (tlsCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	info := certMgr.CACertInfo() // secret-free public cert metadata (no private key)
	str := func(k string) string {
		if v, ok := info[k].(string); ok {
			return v
		}
		return ""
	}
	sec := tlsSection{
		CAReady:       certMgr.Ready(),
		CASubject:     str("subject"),
		CAIssuer:      str("issuer"),
		CAFingerprint: str("fingerprint"),
		CANotBefore:   str("notBefore"),
		CANotAfter:    str("notAfter"),
		KeyProvider:   certMgr.KeyProviderName(),
	}
	if exp := certMgr.CAExpiry(); !exp.IsZero() {
		d := time.Until(exp)
		sec.CAExpiresInDays = int(d.Hours() / 24)
		sec.RotationDueSoon = d <= 30*24*time.Hour
	}
	sec.SecondaryActive = certMgr.SecondaryCAActive()
	hits, misses, size := certMgr.CacheStats()
	sec.LeafCacheHits, sec.LeafCacheMisses, sec.LeafCacheSize = hits, misses, size
	sec.LeafCacheTTLSec = int(ca.CacheTTL.Seconds())
	sec.LeafCacheMax = ca.CacheMaxSize

	res := in.Redactor.Classify(sec)
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

// ── config versions ──────────────────────────────────────────────────────────

type supportCfgVerSummary struct {
	Version   int    `json:"version" redact:"public"`
	CreatedAt string `json:"created_at" redact:"public"`
	Actor     string `json:"actor,omitempty" redact:"sensitive"` // admin identity → masked
	Action    string `json:"action,omitempty" redact:"internal"`
}

type configVersionsSection struct {
	Seq      int                    `json:"seq" redact:"public"` // high-water version number
	Count    int                    `json:"count" redact:"public"`
	Versions []supportCfgVerSummary `json:"versions" redact:"internal"`
}

type configVersionsCollector struct{}

func (configVersionsCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "config_versions", Path: "sections/config_versions.json", Owner: "core", SchemaVersion: 1,
		Description: "Config-version history metadata (version/time/actor/action; no snapshot bodies)", Timeout: 3 * time.Second,
		ByteBudget: 64 << 10, Mandatory: false, MinLevel: support.L1,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (configVersionsCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	metas := configVersions.ListMeta() // metadata only — config bodies are never read into memory
	sec := configVersionsSection{Seq: configVersions.Seq(), Count: len(metas)}
	if len(metas) > supportMaxConfigVersions {
		metas = metas[:supportMaxConfigVersions]
	}
	sec.Versions = make([]supportCfgVerSummary, 0, len(metas))
	for i := range metas {
		sec.Versions = append(sec.Versions, supportCfgVerSummary{
			Version: metas[i].Version, CreatedAt: metas[i].CreatedAt,
			Actor: metas[i].Actor, Action: metas[i].Action,
		})
	}
	res := in.Redactor.Classify(sec)
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

// ── governance (C2/C3 control-plane) ─────────────────────────────────────────

// governanceSection is a purpose-built, tagged copy of the non-secret C2/C3
// governance snapshot (mode + six counters + route counts + four health axes).
type governanceSection struct {
	C2Mode               string `json:"c2_mode" redact:"internal"`
	KillSwitchActive     bool   `json:"kill_switch_active" redact:"internal"`
	RouteTotal           int    `json:"route_total" redact:"public"`
	RoutePublic          int    `json:"route_public" redact:"public"`
	RouteProtected       int    `json:"route_protected" redact:"public"`
	WouldDeny            int64  `json:"would_deny" redact:"internal"`
	EnforceDenied        int64  `json:"enforce_denied" redact:"internal"`
	MissingMeta          int64  `json:"missing_meta" redact:"internal"`
	NoPolicy             int64  `json:"no_policy" redact:"internal"`
	AuditMissing         int64  `json:"audit_missing" redact:"internal"`
	RoleDivergence       int64  `json:"role_divergence" redact:"internal"`
	HealthStatus         string `json:"health_status" redact:"internal"`
	MetadataParity       string `json:"metadata_parity" redact:"internal"`
	AuditCompletion      string `json:"audit_completion" redact:"internal"`
	EnforceConsistency   string `json:"enforce_consistency" redact:"internal"`
	HealthRoleDivergence string `json:"health_role_divergence" redact:"internal"`
}

type governanceCollector struct{}

func (governanceCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "governance", Path: "sections/governance.json", Owner: "governance", SchemaVersion: 1,
		Description: "Admin control-plane governance snapshot (C2 mode, counters, route counts, health)", Timeout: 2 * time.Second,
		ByteBudget: 16 << 10, Mandatory: false, MinLevel: support.L1,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (governanceCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	gs := buildGovernanceSnapshot() // pure, side-effect-free, no secrets
	sec := governanceSection{
		C2Mode: gs.C2.Mode, KillSwitchActive: gs.C2.KillSwitchActive,
		RouteTotal: gs.Routes.Total, RoutePublic: gs.Routes.Public, RouteProtected: gs.Routes.Protected,
		WouldDeny: gs.Counters.WouldDeny, EnforceDenied: gs.Counters.EnforceDenied,
		MissingMeta: gs.Counters.MissingMeta, NoPolicy: gs.Counters.NoPolicy,
		AuditMissing: gs.Counters.AuditMissing, RoleDivergence: gs.Counters.RoleDivergence,
		HealthStatus: gs.Health.Status, MetadataParity: gs.Health.MetadataParity,
		AuditCompletion: gs.Health.AuditCompletion, EnforceConsistency: gs.Health.EnforceConsistency,
		HealthRoleDivergence: gs.Health.RoleDivergence,
	}
	res := in.Redactor.Classify(sec)
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

func init() {
	support.Register(tlsCollector{})
	support.Register(configVersionsCollector{})
	support.Register(governanceCollector{})
}
