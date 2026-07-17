package main

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/redaction"
	"github.com/KidCarmi/Culvert/internal/reqlog"
	"github.com/KidCarmi/Culvert/internal/support"
)

// M1 reused-accessor collectors (config, policy, audit, metrics, logs). Each is a
// thin adapter over an EXISTING side-effect-free accessor that snapshots in-memory
// state, mapped into a purpose-built, fully `redact:`-tagged section struct. The
// mapping is deliberately fail-closed: a section surfaces ONLY the fields it
// explicitly classifies, so a new field on an upstream struct (a policy rule, a
// log entry) can never silently leak into a bundle — it simply isn't mapped until
// someone classifies it here. All sections cap the number of rows so a large ring
// cannot blow the byte budget; the runner enforces the budget regardless.
//
// Live-traffic identifiers (client IP, authenticated identity, destination host,
// full URI) and free-form audit detail are classified SENSITIVE → masked to a
// per-bundle salted token. The proper masking PROFILE (partial reveal, custom
// exclusions) is M2; masking-to-token is the conservative M1 posture.

const (
	supportMaxPolicyRules = 500 // rules mapped into the policy section
	supportMaxAuditRows   = 200 // newest audit-ring rows mapped
	supportMaxLogRows     = 200 // newest request-log rows mapped
)

// ── config ───────────────────────────────────────────────────────────────────

// configSection is a non-secret summary of the running configuration: ports,
// modes, feature toggles, and object COUNTS — never raw values that could carry a
// secret. Secret material (session HMAC, upstream/webhook creds, IdP secrets, CA
// passphrase, metrics token) is reported only as a presence bool, never a value.
type configSection struct {
	Version                int    `json:"version" redact:"public"`
	ProxyPort              int    `json:"proxy_port" redact:"public"`
	UIPort                 int    `json:"ui_port" redact:"public"`
	AuthEnabled            bool   `json:"auth_enabled" redact:"public"`
	MetricsTokenSet        bool   `json:"metrics_token_set" redact:"public"`
	DefaultAction          string `json:"default_action" redact:"internal"`
	BlocklistMode          string `json:"blocklist_mode" redact:"internal"`
	BlocklistCount         int    `json:"blocklist_count" redact:"internal"`
	PolicyRuleCount        int    `json:"policy_rule_count" redact:"internal"`
	RewriteRuleCount       int    `json:"rewrite_rule_count" redact:"internal"`
	SSLBypassCount         int    `json:"ssl_bypass_count" redact:"internal"`
	FileBlockExtCount      int    `json:"fileblock_ext_count" redact:"internal"`
	IPFilterMode           string `json:"ip_filter_mode" redact:"internal"`
	IPListCount            int    `json:"ip_list_count" redact:"internal"`
	RateLimitRPM           int    `json:"rate_limit_rpm" redact:"internal"`
	CategoryGroupCount     int    `json:"category_group_count" redact:"internal"`
	DecryptionProfileCount int    `json:"decryption_profile_count" redact:"internal"`
	URLCategoryCount       int    `json:"url_category_count" redact:"internal"`
	ConnLimitEnabled       bool   `json:"conn_limit_enabled" redact:"internal"`
	ConnLimitMaxPerIP      int    `json:"conn_limit_max_per_ip" redact:"internal"`
}

type configCollector struct{}

func (configCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "config", Path: "sections/config.json", Owner: "core", SchemaVersion: 1,
		Description: "Non-secret configuration summary (modes, toggles, counts)", Timeout: 3 * time.Second,
		ByteBudget: 64 << 10, Mandatory: false, MinLevel: support.L1,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (configCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	// captureConfigBackup is side-effect-free and deliberately omits the
	// export-only secret fields (upstream creds, webhook secrets). We further
	// reduce it to counts + non-secret scalars here.
	cb := captureConfigBackup()
	cs := configSection{
		Version:                cb.Version,
		ProxyPort:              cfg.ProxyPort,
		UIPort:                 cfg.UIPort,
		AuthEnabled:            cfg.AuthEnabled(),
		MetricsTokenSet:        metricsToken != "",
		DefaultAction:          cb.DefaultAction,
		BlocklistMode:          cb.BlocklistMode,
		BlocklistCount:         len(cb.Blocklist),
		PolicyRuleCount:        len(cb.PolicyRules),
		RewriteRuleCount:       len(cb.RewriteRules),
		SSLBypassCount:         len(cb.SSLBypass),
		FileBlockExtCount:      len(cb.FileBlockExtensions),
		IPFilterMode:           cb.IPFilterMode,
		IPListCount:            len(cb.IPList),
		RateLimitRPM:           cb.RateLimitRPM,
		CategoryGroupCount:     len(cb.CategoryGroups),
		DecryptionProfileCount: len(cb.DecryptionProfiles),
		URLCategoryCount:       len(cb.URLCategories),
		ConnLimitEnabled:       cb.ConnLimitEnabled,
		ConnLimitMaxPerIP:      cb.ConnLimitMaxPerIP,
	}
	res := in.Redactor.Classify(cs)
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

// ── policy ───────────────────────────────────────────────────────────────────

type policyRuleSummary struct {
	Priority          int    `json:"priority" redact:"public"`
	Name              string `json:"name" redact:"internal"`
	Action            string `json:"action" redact:"public"`
	Enabled           bool   `json:"enabled" redact:"public"`
	HasSchedule       bool   `json:"has_schedule" redact:"public"`
	DestFQDN          string `json:"dest_fqdn,omitempty" redact:"internal"`
	DestCategory      string `json:"dest_category,omitempty" redact:"internal"`
	SourceIP          string `json:"source_ip,omitempty" redact:"internal"`
	SourceIdentity    string `json:"source_identity,omitempty" redact:"sensitive"`
	SourceGroup       string `json:"source_group,omitempty" redact:"internal"`
	SSLAction         string `json:"ssl_action,omitempty" redact:"internal"`
	DecryptionProfile string `json:"decryption_profile,omitempty" redact:"internal"`
	HitCount          int64  `json:"hit_count" redact:"internal"`
}

type policySection struct {
	Version   int64               `json:"version" redact:"public"`
	UpdatedAt string              `json:"updated_at" redact:"public"`
	RuleCount int                 `json:"rule_count" redact:"public"`
	Truncated bool                `json:"truncated" redact:"public"`
	Rules     []policyRuleSummary `json:"rules" redact:"internal"`
}

type policyCollector struct{}

func (policyCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "policy", Path: "sections/policy.json", Owner: "policy", SchemaVersion: 1,
		Description: "Access policy rule set (names + match criteria, no live user data)", Timeout: 3 * time.Second,
		ByteBudget: 256 << 10, Mandatory: false, MinLevel: support.L1,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (policyCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	ver, updated := policyStore.policyVersion()
	rules := listPolicyRules() // access rules only, race-safe deep copy
	sec := policySection{Version: ver, UpdatedAt: updated, RuleCount: len(rules)}
	if len(rules) > supportMaxPolicyRules {
		rules = rules[:supportMaxPolicyRules]
		sec.Truncated = true
	}
	sec.Rules = make([]policyRuleSummary, 0, len(rules))
	for i := range rules {
		r := &rules[i]
		sec.Rules = append(sec.Rules, policyRuleSummary{
			Priority:          r.Priority,
			Name:              r.Name,
			Action:            string(r.Action),
			Enabled:           r.Enabled == nil || *r.Enabled,
			HasSchedule:       r.Schedule != nil,
			DestFQDN:          r.DestFQDN,
			DestCategory:      string(r.DestCategory),
			SourceIP:          r.SourceIP,
			SourceIdentity:    r.SourceIdentity,
			SourceGroup:       r.SourceGroup,
			SSLAction:         string(r.SSLAction),
			DecryptionProfile: r.DecryptionProfile,
			HitCount:          r.HitCount,
		})
	}
	res := in.Redactor.Classify(sec)
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

// ── audit ────────────────────────────────────────────────────────────────────

type auditEntrySummary struct {
	Time   string `json:"time" redact:"public"`
	Actor  string `json:"actor" redact:"sensitive"` // client IP / admin username → masked
	Action string `json:"action" redact:"public"`
	Object string `json:"object,omitempty" redact:"internal"`
	Detail string `json:"detail,omitempty" redact:"sensitive"` // free-form → masked (scrubber is M2)
	// Before/After config diffs are intentionally NOT mapped: they carry arbitrary
	// config values that the centralized free-form scrubber (M2) is designed for.
}

type auditSection struct {
	Count        int                 `json:"count" redact:"public"`
	RingCapacity int                 `json:"ring_capacity" redact:"public"`
	Entries      []auditEntrySummary `json:"entries" redact:"internal"`
}

type auditCollector struct{}

func (auditCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "audit", Path: "sections/audit.json", Owner: "governance", SchemaVersion: 1,
		Description: "Recent admin audit-ring entries (actor + detail masked)", Timeout: 3 * time.Second,
		ByteBudget: 128 << 10, Mandatory: false, MinLevel: support.L1,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (auditCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	entries := auditGet() // newest-first, race-safe copy
	sec := auditSection{Count: len(entries), RingCapacity: maxAuditLogs}
	if len(entries) > supportMaxAuditRows {
		entries = entries[:supportMaxAuditRows]
	}
	sec.Entries = make([]auditEntrySummary, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		sec.Entries = append(sec.Entries, auditEntrySummary{
			Time: e.Time, Actor: e.Actor, Action: e.Action, Object: e.Object, Detail: e.Detail,
		})
	}
	res := in.Redactor.Classify(sec)
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

// ── metrics ──────────────────────────────────────────────────────────────────

// metricsSection is aggregate, non-identifying counters. Top-hosts are
// deliberately omitted — a destination-FQDN histogram is SENSITIVE and masking it
// to tokens would make it useless; it belongs to the M2 masked-request-logs work.
type metricsSection struct {
	Total        int64 `json:"total" redact:"internal"`
	Blocked      int64 `json:"blocked" redact:"internal"`
	AuthFail     int64 `json:"auth_fail" redact:"internal"`
	FileBlocked  int64 `json:"file_blocked" redact:"internal"`
	BytesSent    int64 `json:"bytes_sent" redact:"internal"`
	BytesRecv    int64 `json:"bytes_recv" redact:"internal"`
	AuthExempt   int64 `json:"auth_exempt" redact:"internal"`
	CrashRecords int64 `json:"crash_records" redact:"internal"`
}

type metricsCollector struct{}

func (metricsCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "metrics", Path: "sections/metrics.json", Owner: "observability", SchemaVersion: 1,
		Description: "Aggregate runtime counters (non-identifying)", Timeout: 2 * time.Second,
		ByteBudget: 16 << 10, Mandatory: false, MinLevel: support.L1,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (metricsCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	ms := metricsSection{
		Total:        atomic.LoadInt64(&statTotal),
		Blocked:      atomic.LoadInt64(&statBlocked),
		AuthFail:     atomic.LoadInt64(&statAuthFail),
		FileBlocked:  atomic.LoadInt64(&statFileBlocked),
		BytesSent:    atomic.LoadInt64(&statBytesSent),
		BytesRecv:    atomic.LoadInt64(&statBytesRecv),
		AuthExempt:   atomic.LoadInt64(&statAuthExempt),
		CrashRecords: atomic.LoadInt64(&statCrashRecords),
	}
	res := in.Redactor.Classify(ms)
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

// ── logs ─────────────────────────────────────────────────────────────────────

type logEntrySummary struct {
	Time        string `json:"time" redact:"public"`
	Level       string `json:"level" redact:"public"`
	Method      string `json:"method,omitempty" redact:"public"`
	Status      string `json:"status,omitempty" redact:"internal"`
	IP          string `json:"ip,omitempty" redact:"sensitive"`       // client IP → masked
	Identity    string `json:"identity,omitempty" redact:"sensitive"` // authenticated user → masked
	Host        string `json:"host,omitempty" redact:"sensitive"`     // destination → masked
	URI         string `json:"uri,omitempty" redact:"sensitive"`      // full URL → masked
	RuleMatched string `json:"rule_matched,omitempty" redact:"internal"`
	ActionTaken string `json:"action_taken,omitempty" redact:"internal"`
	BytesSent   int64  `json:"bytes_sent" redact:"internal"`
	BytesRecv   int64  `json:"bytes_recv" redact:"internal"`
	DurationMs  int64  `json:"duration_ms" redact:"internal"`
}

type logsSection struct {
	Count        int               `json:"count" redact:"public"`
	RingCapacity int               `json:"ring_capacity" redact:"public"`
	Entries      []logEntrySummary `json:"entries" redact:"internal"`
}

type logsCollector struct{}

func (logsCollector) Meta() support.CollectorMeta {
	return support.CollectorMeta{
		ID: "logs", Path: "sections/logs.json", Owner: "observability", SchemaVersion: 1,
		Description: "Recent request-log ring (identifiers masked)", Timeout: 3 * time.Second,
		ByteBudget: 256 << 10, Mandatory: false, MinLevel: support.L1,
		MaxClass: redaction.ClassInternal, Sensitivity: redaction.ClassInternal,
	}
}

func (logsCollector) Collect(_ context.Context, in support.CollectInput, sink support.SectionSink) support.Result {
	entries := logGet() // newest-first, race-safe copy
	sec := logsSection{Count: len(entries), RingCapacity: reqlog.MaxRing}
	if len(entries) > supportMaxLogRows {
		entries = entries[:supportMaxLogRows]
	}
	sec.Entries = make([]logEntrySummary, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		sec.Entries = append(sec.Entries, logEntrySummary{
			Time: e.Time, Level: e.Level, Method: e.Method, Status: e.Status,
			IP: e.IP, Identity: e.Identity, Host: e.Host, URI: e.URI,
			RuleMatched: e.RuleMatched, ActionTaken: e.ActionTaken,
			BytesSent: e.BytesSent, BytesRecv: e.BytesRecv, DurationMs: e.DurationMs,
		})
	}
	res := in.Redactor.Classify(sec)
	if err := sink.WriteJSON(res.Value); err != nil {
		return support.Result{Status: support.StatusFailed, Note: "write"}
	}
	return support.Result{Status: support.StatusOK, ClassMax: res.ClassMax}
}

func init() {
	support.Register(configCollector{})
	support.Register(policyCollector{})
	support.Register(auditCollector{})
	support.Register(metricsCollector{})
	support.Register(logsCollector{})
}
