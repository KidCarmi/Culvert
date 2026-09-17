package main

// auth_ldap_provider.go — LDAP / Active Directory as a first-class IdP
// registry provider (ADR-0027).
//
// LDAPIdPProvider adapts the hardened directory engine in auth_ldap.go (two-
// step bind, CHAOS-47 unreachable gating, authoritative-only caching) to the
// IdentityProvider contract: it validates presented Basic credentials and
// produces a full Identity (Sub = user DN, Email/Name/Groups from configurable
// attributes, Provider = profile ID → authSource "ldap:<profile-id>").
//
// Capability posture (load-bearing, pinned by tests): LDAP is CREDENTIAL-
// capable and NEVER interactive — CaptiveLoginURL always returns "" and the
// registry's capability predicates (IdPType.Interactive) exclude it from every
// browser-SSO surface.

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
)

// LDAPProfileConfig holds LDAP/AD-specific settings for an IdP profile.
// Persisted in idp_profiles.json and synced CP→DP on the Sensitive
// IdPProfiles snapshot surface.
type LDAPProfileConfig struct {
	// URL is the canonical directory endpoint: "ldap://host:port" or
	// "ldaps://host:port". The GUI presents Server + Connection security +
	// Port and derives this canonical form.
	URL string `json:"url"`

	// StartTLS upgrades a plain ldap:// connection with STARTTLS. Invalid in
	// combination with ldaps:// (contradictory transport states are rejected
	// at validation rather than silently ignored).
	StartTLS bool `json:"startTls,omitempty"`

	// TLSSkipVerify disables certificate verification (Advanced / unsafe;
	// dev-only, warned at compile time). Never enabled automatically.
	TLSSkipVerify bool `json:"tlsSkipVerify,omitempty"`

	// BindDN is the service-account DN used to locate users. Empty =
	// anonymous bind (not recommended for AD).
	BindDN string `json:"bindDn,omitempty"`

	// BindPassword is the service-account credential. WRITE-ONLY API input:
	// blanked in every read/audit projection (publicIdPProfile), preserved on
	// omitted update, explicitly clearable with an empty-string value when the
	// field is present in the request body. Never logged, never in metrics.
	BindPassword string `json:"bindPassword,omitempty"`

	// BindCredentialConfigured is READ-ONLY response metadata: whether a bind
	// credential is currently stored. Ignored on write.
	BindCredentialConfigured bool `json:"bindCredentialConfigured,omitempty"`

	// BaseDN is the subtree searched for users. Required.
	BaseDN string `json:"baseDn"`

	// UserFilter is the search filter template; the single %s placeholder is
	// replaced with the ldap.EscapeFilter-escaped username.
	// Default: "(sAMAccountName=%s)" (Active Directory).
	UserFilter string `json:"userFilter,omitempty"`

	// EmailAttribute maps to Identity.Email. Default "mail".
	EmailAttribute string `json:"emailAttribute,omitempty"`

	// NameAttribute maps to Identity.Name. Default "displayName" (falls back
	// to cn, then the login username).
	NameAttribute string `json:"nameAttribute,omitempty"`

	// GroupAttribute maps to Identity.Groups. Default "memberOf". Values are
	// kept verbatim (full group DNs — the collision-safe authorization value
	// for Access Rules). Direct membership only; no nested resolution.
	GroupAttribute string `json:"groupAttribute,omitempty"`

	// RequiredGroup is the legacy provider-level access gate: when set, the
	// user must be a DIRECT member of this group DN to authenticate at all.
	// Kept for compatibility; the modern authorization model is Access Rules
	// over Identity.Groups.
	RequiredGroup string `json:"requiredGroup,omitempty"`

	// CacheTTLSeconds bounds how long an authoritative auth result is cached.
	// 0 = default (300s). Bounded to [minLDAPCacheTTL, maxLDAPCacheTTL].
	CacheTTLSeconds int `json:"cacheTtlSeconds,omitempty"`
}

// Validation bounds. Directory DNs can legitimately be long, but every field
// an admin submits is capped so a hostile/buggy client can't persist blobs.
const (
	maxLDAPURLLen       = 256
	maxLDAPDNLen        = 1024
	maxLDAPFilterLen    = 512
	maxLDAPAttrLen      = 64
	maxLDAPBindInputLen = 1024
	minLDAPCacheTTLSecs = 10
	maxLDAPCacheTTLSecs = 86400 // 24h
	defLDAPCacheTTLSecs = 300
)

// validateLDAPProfileConfig is the dedicated LDAP profile validator.
// Deliberately NOT validateExternalURL: enterprise directories live on
// RFC1918/internal DNS by design, so no private-address rejection here — the
// only actuated probe is the Admin-only, audited, bounded test endpoint.
func validateLDAPProfileConfig(cfg *LDAPProfileConfig) error {
	if cfg == nil {
		return fmt.Errorf("config is required")
	}
	if err := validateLDAPURL(cfg.URL); err != nil {
		return fmt.Errorf("url: %w", err)
	}
	if cfg.StartTLS && strings.HasPrefix(strings.ToLower(cfg.URL), "ldaps://") {
		return fmt.Errorf("startTls is contradictory with an ldaps:// URL — LDAPS is already TLS; choose one transport")
	}
	if strings.TrimSpace(cfg.BaseDN) == "" {
		return fmt.Errorf("baseDn is required")
	}
	for _, f := range []struct{ name, v string }{
		{"baseDn", cfg.BaseDN}, {"bindDn", cfg.BindDN}, {"requiredGroup", cfg.RequiredGroup},
	} {
		if err := validateLDAPDN(f.v); err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
	}
	if len(cfg.BindPassword) > maxLDAPBindInputLen {
		return fmt.Errorf("bind credential exceeds %d bytes", maxLDAPBindInputLen)
	}
	if err := validateLDAPUserFilter(cfg.UserFilter); err != nil {
		return fmt.Errorf("userFilter: %w", err)
	}
	for _, f := range []struct{ name, v string }{
		{"emailAttribute", cfg.EmailAttribute}, {"nameAttribute", cfg.NameAttribute}, {"groupAttribute", cfg.GroupAttribute},
	} {
		if err := validateLDAPAttrName(f.v); err != nil {
			return fmt.Errorf("%s: %w", f.name, err)
		}
	}
	if cfg.CacheTTLSeconds != 0 &&
		(cfg.CacheTTLSeconds < minLDAPCacheTTLSecs || cfg.CacheTTLSeconds > maxLDAPCacheTTLSecs) {
		return fmt.Errorf("cacheTtlSeconds must be 0 (default) or between %d and %d", minLDAPCacheTTLSecs, maxLDAPCacheTTLSecs)
	}
	return nil
}

// validateLDAPURL accepts only ldap:// and ldaps:// endpoints with a plain
// host[:port] authority — no credentials, path, query, or fragment (which is
// where hidden schemes and referral tricks would hide).
func validateLDAPURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("is required")
	}
	if len(raw) > maxLDAPURLLen {
		return fmt.Errorf("exceeds %d characters", maxLDAPURLLen)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("is not a valid URL")
	}
	if u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return fmt.Errorf("scheme must be ldap:// or ldaps://")
	}
	if u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("must be scheme://host[:port] only — no credentials, path, or query")
	}
	return validateLDAPHostPort(u)
}

// validateLDAPHostPort checks the authority part of an already scheme- and
// shape-validated directory URL.
func validateLDAPHostPort(u *url.URL) error {
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("host is required")
	}
	if net.ParseIP(host) == nil && !isValidHostname(host) {
		return fmt.Errorf("host %q is not a valid hostname or IP address", host)
	}
	if portStr := u.Port(); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("port must be between 1 and 65535")
		}
	}
	return nil
}

// isValidHostname is a conservative RFC-1123 hostname check.
func isValidHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if !isValidHostLabel(label) {
			return false
		}
	}
	return true
}

// isValidHostLabel checks one dot-separated hostname label.
func isValidHostLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		ok := c == '-' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !ok {
			return false
		}
	}
	return label[0] != '-' && label[len(label)-1] != '-'
}

// validateLDAPDN bounds an (optional) DN-shaped field. Empty is allowed —
// requiredness is the caller's decision. Control characters are rejected so a
// stored DN can never smuggle log-splitting or protocol bytes.
func validateLDAPDN(dn string) error {
	if len(dn) > maxLDAPDNLen {
		return fmt.Errorf("exceeds %d characters", maxLDAPDNLen)
	}
	for _, r := range dn {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("contains control characters")
		}
	}
	return nil
}

// validateLDAPUserFilter enforces exactly-safe placeholder semantics: the
// template must contain exactly one %s verb and no other % verbs, so
// fmt.Sprintf(filter, ldap.EscapeFilter(username)) can never be steered by an
// admin typo into a second substitution or a literal-% corruption, and the
// escaped username remains the only dynamic content (LDAP-injection guard).
func validateLDAPUserFilter(filter string) error {
	if filter == "" {
		return nil // default applied at compile time
	}
	if len(filter) > maxLDAPFilterLen {
		return fmt.Errorf("exceeds %d characters", maxLDAPFilterLen)
	}
	for _, r := range filter {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("contains control characters")
		}
	}
	placeholders := 0
	for i := 0; i < len(filter); i++ {
		if filter[i] != '%' {
			continue
		}
		if i+1 >= len(filter) {
			return fmt.Errorf("ends with a bare %%")
		}
		switch filter[i+1] {
		case 's':
			placeholders++
		case '%':
			// literal percent, fine
		default:
			return fmt.Errorf("only the %%s placeholder is allowed")
		}
		i++
	}
	if placeholders != 1 {
		return fmt.Errorf("must contain exactly one %%s placeholder (found %d)", placeholders)
	}
	if !strings.HasPrefix(filter, "(") || !strings.HasSuffix(filter, ")") {
		return fmt.Errorf("must be a parenthesized LDAP filter, e.g. (sAMAccountName=%%s)")
	}
	return nil
}

// validateLDAPAttrName bounds an (optional) attribute descriptor to the LDAP
// AttributeDescription grammar (letter, then letters/digits/hyphens).
func validateLDAPAttrName(attr string) error {
	if attr == "" {
		return nil // default applied at compile time
	}
	if len(attr) > maxLDAPAttrLen {
		return fmt.Errorf("exceeds %d characters", maxLDAPAttrLen)
	}
	for i := 0; i < len(attr); i++ {
		c := attr[i]
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if i == 0 && !isAlpha {
			return fmt.Errorf("must start with a letter")
		}
		if !isAlpha && (c < '0' || c > '9') && c != '-' {
			return fmt.Errorf("may contain only letters, digits, and hyphens")
		}
	}
	return nil
}

// ─── Legacy YAML authority shadowing + durable cutover (ADR-0027 / P1-2) ─────
//
// AUTHORITY MODEL: there is exactly ONE operational LDAP authenticator.
// Until cutover, the legacy YAML block is the bootstrap authenticator. The
// moment an enabled registry LDAP profile is observed while a legacy YAML
// block exists, the node CUTS OVER: the legacy provider is deactivated and
// the durable, node-local `legacy_ldap_retired` sentinel is recorded in
// admin_settings.json (the AdminDurable sentinel pattern —
// BlocklistFeedsSaved et al.). After cutover the YAML block is bootstrap/
// import SOURCE MATERIAL only — never an operational authenticator again,
// across registry disable/delete, process restarts, and CP/DP restarts.
// Authority is deliberately NOT keyed on HasEnabledLDAP() alone: enable/
// disable is runtime state, not source-of-truth ownership.
//
// Break-glass revert (explicit, offline, documented in
// docs/operator/ldap-identity-provider.md): stop the node, remove
// `legacy_ldap_retired` from admin_settings.json, remove/disable the
// registry LDAP profile, restart. There is intentionally no API for it.

// legacyLDAPRetiredFlag is the in-memory view of the durable sentinel.
var legacyLDAPRetiredFlag atomic.Bool

// legacyLDAPCutoverDurableFlag records whether the RUNTIME cutover is known
// to be on disk (FE-6A.0 correction, Blocker 9): the admin path flips it
// only inside a durable save's applyOnSuccess and the settings load sets it
// from the file; the OBSERVED path (boot reconciliation / CP→DP sync) marks
// the runtime first — safety first — and reports `durable:false` /
// `pending_reconciliation` until a save lands. A best-effort sentinel save
// never silently claims durability.
var legacyLDAPCutoverDurableFlag atomic.Bool

// legacyLDAPCutoverDurable reports whether the active cutover is durable.
func legacyLDAPCutoverDurable() bool { return legacyLDAPCutoverDurableFlag.Load() }

// legacyLDAPCutoverReadModel projects the cutover record + its durability
// truth for the admin read model.
func legacyLDAPCutoverReadModel(rec *LegacyLDAPCutover) map[string]any {
	if rec == nil {
		return nil
	}
	return map[string]any{
		"operationId":      rec.OperationID,
		"profileId":        rec.ProfileID,
		"profileName":      rec.ProfileName,
		"registryRevision": rec.RegistryRevision,
		"actor":            rec.Actor,
		"trigger":          rec.Trigger,
		"at":               rec.At,
		"durable":          legacyLDAPCutoverDurable(),
	}
}

// legacyLDAPCutoverRecordMissing reports the DEGRADED evidence posture
// (round 5, Blocker 1): the durable file carried `legacy_ldap_retired:true`
// WITHOUT its operation record. The sentinel stays in force (fail closed —
// a missing record never re-arms the legacy authenticator), nothing is
// invented, and the read model says so explicitly. Derived, never latched:
// an unreadable boot (observation pending) is a different, KNOWN-unknown
// posture and reports pending_reconciliation as before.
func legacyLDAPCutoverRecordMissing() bool {
	return legacyLDAPRetired() && legacyLDAPCutover() == nil && !legacyLDAPBootReconcilePending()
}

// legacyLDAPCutoverDurability is the bounded posture word for the read model.
func legacyLDAPCutoverDurability() string {
	switch {
	case !legacyLDAPRetired():
		return "not_retired"
	case legacyLDAPCutoverRecordMissing():
		return "record_missing"
	case legacyLDAPCutoverDurable():
		return "durable"
	default:
		return "pending_reconciliation"
	}
}

// legacyLDAPShadowWarnOnce dedupes the cutover warning: one clear line, no
// per-sync log spam (ReplaceAll runs on every CP→DP config poll).
var legacyLDAPShadowWarnOnce sync.Once

// legacyLDAPRetired reports whether this node has durably cut over from the
// legacy YAML LDAP block to the IdP registry. Also consulted by
// cfg.IsConfigured(): a deployment whose only setup anchor was the YAML
// provider stays "configured" across the cutover and every later restart, so
// deactivating the proxy backend can never fail the admin-UI setup gate open.
func legacyLDAPRetired() bool { return legacyLDAPRetiredFlag.Load() }

// legacyLDAPBootObserved records that THIS boot's legacy-provider slice
// observed an enabled registry LDAP profile BEFORE the durable settings were
// loaded (FE-6A.2 correction, Blocker 4). The observation enforces the
// single-authority rule immediately (the legacy provider is never wired)
// but it is NOT a transition until the settings load has reconciled it
// against the durable sentinel: a completed cutover keeps its record
// identity and emits no new retirement audit; only a node whose readable
// settings carry NO sentinel records the observed transition — once.
var legacyLDAPBootObserved atomic.Bool

// observeLegacyLDAPShadowAtBoot is the boot-time observation (the legacy
// slice runs before the settings load): fail-closed single authority now,
// no record, no audit, no save — the settings load decides what it was.
func observeLegacyLDAPShadowAtBoot() {
	legacyLDAPRetiredFlag.Store(true)
	legacyLDAPCutoverDurableFlag.Store(false)
	legacyLDAPBootObserved.Store(true)
}

// reconcileLegacyLDAPBootObservation is called once the durable truth is
// known — by a READABLE settings load, by a MISSING settings file (nothing
// durable exists, so the observed transition may be recorded), and by the
// first successful settings save after an UNREADABLE/CORRUPT load (storage
// recovery). durableRetired reports whether readable settings carry the
// sentinel (its record, if any, was adopted by the caller). Returns true
// when THIS call minted the observed record — PENDING its audit — that the
// caller must now persist; the audit follows the durable save (round 3,
// Blocker 3), never precedes it. Idempotent per boot observation: the latch
// is consumed on the first call, so a pending transition is reconciled
// exactly once.
func reconcileLegacyLDAPBootObservation(durableRetired bool) bool {
	if !legacyLDAPBootObserved.Swap(false) {
		return false
	}
	if durableRetired {
		return false // a completed cutover: same identity, nothing new
	}
	mintPendingLegacyLDAPRetirement()
	return true
}

// legacyLDAPObservedReason is the bounded reason the observed transition
// carries into its audit entry.
const legacyLDAPObservedReason = "enabled LDAP identity provider present in the IdP registry"

// mintPendingLegacyLDAPRetirement records an OBSERVED transition in memory
// with its audit pending: the sentinel is set, the record is minted ONCE,
// and nothing is audited until a save proves the record durable.
func mintPendingLegacyLDAPRetirement() {
	rec := newLegacyLDAPCutover(nil, "", "system", "observed")
	rec.AuditPending = true
	// Record BEFORE sentinel: a reader never observes "retired without a
	// record" (the record_missing posture) for a transition that has one.
	legacyLDAPCutoverRec.Store(&rec)
	legacyLDAPRetiredFlag.Store(true)
}

// legacyLDAPRetirementReason is the bounded reason text of a cutover's
// retirement audit, derived from the DURABLE record (so a completion at a
// later save or boot emits the same line the transition would have).
func legacyLDAPRetirementReason(rec *LegacyLDAPCutover) string {
	if rec.Trigger == "admin_api" {
		return "enabled LDAP identity provider " + rec.ProfileID + " committed through the admin API"
	}
	return legacyLDAPObservedReason
}

// completeLegacyLDAPRetirementAudit emits the success audit of a durable
// transition — observed OR admin-triggered (round 5, Blocker 3) — EXACTLY ONCE through the operation-keyed boundary
// (audit.AppendOperation appends only if the durable record does not
// already hold the entry) and clears the pending flag in memory. Returns
// true when the flag was cleared and the caller must persist it; a failed
// append leaves the audit pending for the next save or boot. Never called
// before the record is durable (or, without a settings file, at all —
// see the unpersisted save path).
func completeLegacyLDAPRetirementAudit() bool {
	rec := legacyLDAPCutover()
	if rec == nil || !rec.AuditPending {
		return false
	}
	if _, err := audit.AppendOperation(audit.Entry{
		TS:          time.Now().UnixMilli(),
		Time:        time.Now().Format("2006-01-02 15:04:05"),
		Actor:       rec.Actor,
		Action:      "idp.legacy_ldap.retired",
		Object:      "legacy-ldap",
		ObjectID:    rec.ProfileID,
		Detail:      "legacy YAML ldap block permanently retired as an operational authenticator (" + legacyLDAPRetirementReason(rec) + "); registry is the sole LDAP authority; operationId=" + rec.OperationID,
		OperationID: rec.OperationID,
	}); err != nil {
		logger.Printf("IdP: legacy-LDAP cutover %s (%s) is durable but its audit could not be recorded yet (%v) — retried at the next save/boot", sanitizeLog(rec.OperationID), sanitizeLog(rec.Trigger), err)
		return false
	}
	rec.AuditPending = false
	legacyLDAPCutoverRec.Store(rec)
	return true
}

// legacyLDAPBootReconcilePending reports whether this boot's observation is
// still awaiting its durable reconciliation (an unreadable/corrupt settings
// load): the sentinel must not be serialised without its record until then.
func legacyLDAPBootReconcilePending() bool { return legacyLDAPBootObserved.Load() }

// LegacyLDAPCutover is the DURABLE, operation-identified record of the
// legacy-YAML → registry LDAP authority cutover (FE-6A.0 R7). It binds the
// once-ever transition to the candidate that carried it (profile id + the
// registry's document revision), the actor, the trigger and the instant;
// it is persisted beside the sentinel in admin_settings.json and surfaced
// read-only on GET /api/idp/legacy-ldap. Node-local, off every config
// surface (same row as the sentinel).
type LegacyLDAPCutover struct {
	OperationID      string `json:"operationId"`
	ProfileID        string `json:"profileId,omitempty"`
	ProfileName      string `json:"profileName,omitempty"`
	RegistryRevision string `json:"registryRevision,omitempty"`
	Actor            string `json:"actor"`
	Trigger          string `json:"trigger"` // admin_api | observed
	At               string `json:"at"`
	// AuditPending (round 3, Blocker 3) marks an OBSERVED transition whose
	// record has been minted (and, once saved, made durable) but whose
	// success audit has not yet been proven durable: the audit is emitted
	// ONLY after the save that carries the record succeeds, through the
	// operation-keyed audit boundary (audit.AppendOperation — idempotent on
	// the record's operationId), and the flag is cleared durably afterwards.
	// A crash between the durable record and the audit therefore completes
	// the SAME identity's audit exactly once on the next boot; a crash after
	// the audit and before the clearing save re-appends nothing.
	AuditPending bool `json:"auditPending,omitempty"`
}

// legacyLDAPCutoverRec is the in-memory view of the durable cutover record.
var legacyLDAPCutoverRec atomic.Pointer[LegacyLDAPCutover]

// legacyLDAPCutover returns a copy of the recorded cutover, or nil.
func legacyLDAPCutover() *LegacyLDAPCutover {
	rec := legacyLDAPCutoverRec.Load()
	if rec == nil {
		return nil
	}
	cp := *rec
	return &cp
}

// newLegacyLDAPCutover mints the record for a cutover triggered now.
func newLegacyLDAPCutover(profile *IdPProfile, registryRevision, actor, trigger string) LegacyLDAPCutover {
	rec := LegacyLDAPCutover{
		OperationID:      mustRandHex(16),
		RegistryRevision: registryRevision,
		Actor:            actor,
		Trigger:          trigger,
		At:               time.Now().UTC().Format(time.RFC3339),
	}
	if profile != nil {
		rec.ProfileID, rec.ProfileName = profile.ID, profile.Name
	}
	return rec
}

// markLegacyLDAPRetired records an OBSERVED cutover (boot reconciliation,
// CP→DP sync): in-memory immediately, durable via the admin-settings
// snapshot (best-effort, like every admin mutation; re-recorded by any later
// save and re-observed from the registry at next boot, so a lost write
// cannot resurrect the legacy authenticator while the registry profile
// exists). Idempotent; audited once. The ADMIN API path does NOT use this:
// it persists the sentinel BEFORE the registry publish and attributes the
// record to the admin (markLegacyLDAPRetiredWith).
func markLegacyLDAPRetired(reason string) {
	if legacyLDAPRetiredFlag.Swap(true) {
		return
	}
	_ = reason // bounded: the audit carries legacyLDAPObservedReason
	// Round 3 (Blocker 3): the record is minted with its audit PENDING and
	// persisted FIRST; the save's success path emits the operation-keyed
	// audit once and clears the flag durably. Synchronous persist: cutover
	// is a once-ever authority transition, so the one bounded disk write on
	// this path is worth durable-before-return semantics. The OUTCOME is
	// recorded, never assumed: a failed save leaves the runtime cutover
	// active (safety first), the record pending its audit, and the read
	// model reporting pending_reconciliation until a later save lands.
	mintPendingLegacyLDAPRetirement()
	legacyLDAPCutoverDurableFlag.Store(false)
	if err := SaveAdminSettings(); err != nil {
		logger.Printf("IdP: observed legacy-LDAP cutover is active at runtime but NOT yet durable — pending reconciliation")
		return
	}
}

// markLegacyLDAPRetiredWith installs the admin-attributed record and flips
// the in-memory sentinel ONCE (record first, so no reader sees a retired
// sentinel without its record). Reports whether this call performed the
// transition (false ⇒ already retired: at-most-once). It emits NO audit
// (round 5, Blocker 3): the record arrives with AuditPending set, the
// caller's save has already made sentinel + record durable, and the save's
// success path completes the operation-keyed audit exactly once
// (completeLegacyLDAPRetirementAudit) and persists the cleared marker; a
// failed append leaves the marker pending for the next save or boot.
func markLegacyLDAPRetiredWith(rec LegacyLDAPCutover) bool {
	if legacyLDAPRetiredFlag.Load() {
		return false
	}
	legacyLDAPCutoverRec.Store(&rec)
	return !legacyLDAPRetiredFlag.Swap(true)
}

// enforceLegacyLDAPShadowing enforces the single-authority rule at every
// registry write ingress that can enable an LDAP profile (admin API create/
// update, CP→DP snapshot sync) and after the durable sentinel loads at boot.
// Unconditional: cfg.IsConfigured() counts the retirement sentinel, so
// deactivating the legacy provider can never reopen first-time setup — there
// is no "keep two authenticators" fallback under any deployment shape.
func enforceLegacyLDAPShadowing() {
	if legacyLDAPYAMLConfig() == nil {
		return // no legacy block on this node — nothing to arbitrate
	}
	if !legacyLDAPRetired() {
		if idpRegistry == nil || !idpRegistry.HasEnabledLDAP() {
			return // pre-cutover: the YAML bootstrap authenticator stays valid
		}
		markLegacyLDAPRetired("enabled LDAP identity provider observed in the IdP registry")
	}
	// Retired (now or previously): the legacy provider must not stay wired.
	if _, isLegacyLDAP := cfg.snapshotAuthBackend().provider.(*LDAPAuth); isLegacyLDAP {
		cfg.SetProvider(nil)
		legacyLDAPShadowWarnOnce.Do(func() {
			logWarnf("Auth: legacy YAML ldap provider DEACTIVATED — the IdP registry is the sole operational LDAP " +
				"authority on this node (durable cutover recorded). The YAML file is untouched; its ldap block is " +
				"bootstrap/import source material only. Remove it at your convenience")
		})
	}
}

// ldapProfileDefault returns v or def when v is empty.
func ldapProfileDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// LDAPIdPProvider is the IdentityProvider adapter for an LDAP IdP profile.
type LDAPIdPProvider struct {
	engine  *LDAPAuth
	profile *IdPProfile // compile-time snapshot; the registry replaces the provider on edit
}

// NewLDAPIdPProvider compiles an LDAP IdP profile into a live provider. Pure
// composition + validation — it performs NO network I/O, so registry
// compile/ReplaceAll stays deterministic and a directory outage can never
// block a config apply (the connection preflight is the admin test surface).
func NewLDAPIdPProvider(p *IdPProfile) (*LDAPIdPProvider, error) {
	cfg := p.LDAP
	if cfg == nil {
		return nil, fmt.Errorf("ldap[%s]: config required", p.ID)
	}
	if err := validateLDAPProfileConfig(cfg); err != nil {
		return nil, fmt.Errorf("ldap[%s]: %w", p.ID, err)
	}
	ttl := time.Duration(cfg.CacheTTLSeconds) * time.Second
	if cfg.CacheTTLSeconds == 0 {
		ttl = defLDAPCacheTTLSecs * time.Second
	}
	engine, err := NewLDAPAuth(LDAPConfig{
		URL:           cfg.URL,
		BindDN:        cfg.BindDN,
		BindPassword:  cfg.BindPassword,
		BaseDN:        cfg.BaseDN,
		UserFilter:    ldapProfileDefault(cfg.UserFilter, "(sAMAccountName=%s)"),
		RequiredGroup: cfg.RequiredGroup,
		StartTLS:      cfg.StartTLS,
		TLSSkipVerify: cfg.TLSSkipVerify,
		CacheTTL:      ttl,
	})
	if err != nil {
		return nil, fmt.Errorf("ldap[%s]: %w", p.ID, err)
	}
	engine.attrs = ldapIdentityAttrs{
		email: ldapProfileDefault(cfg.EmailAttribute, "mail"),
		name:  ldapProfileDefault(cfg.NameAttribute, "displayName"),
		group: ldapProfileDefault(cfg.GroupAttribute, "memberOf"),
	}
	engine.providerID = p.ID
	engine.backendName = "ldap:" + p.ID
	return &LDAPIdPProvider{engine: engine, profile: p}, nil
}

// Name is the machine key used for policy/filtering lookups; the "ldap:"
// scheme joins "oidc:"/"saml:" in splitIdPSource/matchAuthSource.
func (p *LDAPIdPProvider) Name() string { return "ldap:" + p.profile.ID }

// DisplayName returns the admin-configured label, falling back to the machine
// key if unset (same convention as OIDC/SAML providers).
func (p *LDAPIdPProvider) DisplayName() string {
	if p.profile.Name != "" {
		return p.profile.Name
	}
	return p.Name()
}

// Verify validates presented Basic credentials against the directory.
func (p *LDAPIdPProvider) Verify(username, password string) bool {
	return p.engine.Verify(username, password)
}

// ResolveIdentity authenticates and returns the full Identity (Sub = user DN,
// Groups = group-attribute values, Provider = profile ID).
func (p *LDAPIdPProvider) ResolveIdentity(username, password string) (*Identity, bool) {
	return p.engine.resolveIdentity(username, password)
}

// CaptiveLoginURL always returns "": LDAP can NEVER drive a browser SSO flow.
// This is a hard capability guarantee (ADR-0027), not an unimplemented stub —
// the interactive surfaces additionally exclude LDAP structurally via
// IdPType.Interactive, so this is defense-in-depth.
func (p *LDAPIdPProvider) CaptiveLoginURL(string, *http.Request) string { return "" }
