package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/crewjam/saml/samlsp"
)

// ---------------------------------------------------------------------------
// IdP profile types
// ---------------------------------------------------------------------------

// IdPType identifies the protocol used by an identity provider.
type IdPType string

const (
	IdPTypeOIDC IdPType = "oidc"
	IdPTypeSAML IdPType = "saml"
	IdPTypeLDAP IdPType = "ldap"
)

// ─── Provider capability model (ADR-0027) ────────────────────────────────────
//
// Capabilities are a pure function of the IdP type, declared ONCE here and
// consumed by every SSO/credential predicate. Before LDAP joined the registry,
// "enabled registry profile" and "interactive SSO provider" were the same set,
// and several per-request predicates leaned on that coincidence
// (ssoCapable := HasEnabledProviders(), credCapable via HasEnabledOIDC()).
// With a non-interactive, credential-capable type in the registry those
// equations are wrong in both directions, so security decisions must go
// through these capability predicates — never through raw type switches
// scattered across the proxy.

// Interactive reports whether providers of this type can drive a browser SSO
// flow (captive portal / IdP selector / SSORequired). LDAP is deliberately
// NEVER interactive: it must not appear on the SSO selector, mint captive
// login URLs, count toward ssoCapable, or satisfy an SSORequired providerRef.
func (t IdPType) Interactive() bool {
	return t == IdPTypeOIDC || t == IdPTypeSAML
}

// CredentialCapable reports whether providers of this type can validate a
// PRESENTED Basic credential (proxy username/password or token). SAML is
// browser-only and excluded — counting it would re-open the identity-spoofing
// hazard documented at resolveRequestAuth's credCapable predicate.
func (t IdPType) CredentialCapable() bool {
	return t == IdPTypeOIDC || t == IdPTypeLDAP
}

// IdPProfile is the persistent configuration for one identity provider.
// Profiles are stored in a JSON file (idp_profiles.json) and managed
// at runtime via the admin UI without requiring a proxy restart.
type IdPProfile struct {
	ID           string   `json:"id"`           // generated UUID slug
	Name         string   `json:"name"`         // human-readable label
	Type         IdPType  `json:"type"`         // "oidc" | "saml"
	EmailDomains []string `json:"emailDomains"` // routing hints, e.g. ["corp.com"]
	Enabled      bool     `json:"enabled"`
	Priority     int      `json:"priority"` // lower = higher priority; 0 = default

	// KnownGroups is the admin-maintained list of group names available in
	// this IdP.  Used by the policy UI to populate the group dropdown.
	// Not used for authentication decisions — the live token/assertion is
	// the authoritative source.
	KnownGroups []string `json:"knownGroups,omitempty"`

	// Revision is the SERVER-MINTED per-entry fencing token (FE-6A.0 C2):
	// 1 on create, +1 on every replace; a fenced PUT/DELETE must echo it
	// (428 when absent, 409 stale when it moved). Caller-supplied values are
	// ignored on write; persisted so it survives restarts; carried CP→DP.
	Revision int64 `json:"revision,omitempty"`

	// OperationID is the durable PROVENANCE of the write that created this
	// entry (round-3 correction, Blocker 1): the client operationId of the
	// operation-identified create, co-written in the same atomic registry
	// write as the profile. It is what proves a pending intent COMMITTED —
	// never the profile's mere presence. Server-owned: a caller-supplied
	// value is ignored, a replace preserves it, and it is carried CP→DP.
	OperationID string `json:"operationId,omitempty"`

	// Only one of OIDC/SAML/LDAP is populated depending on Type.
	OIDC *OIDCProfileConfig `json:"oidc,omitempty"`
	SAML *SAMLProfileConfig `json:"saml,omitempty"`
	LDAP *LDAPProfileConfig `json:"ldap,omitempty"`
}

// OIDCProfileConfig holds OIDC-specific settings for an IdP profile.
type OIDCProfileConfig struct {
	// Issuer is the only field required from the operator.
	// The proxy will fetch /.well-known/openid-configuration automatically.
	Issuer string `json:"issuer"`

	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret,omitempty"` // never logged; WRITE-ONLY (never on a read model)

	// ClientSecretConfigured is READ-ONLY response metadata (FE-6A.0 R6):
	// whether a client secret is currently stored. Ignored on write.
	ClientSecretConfigured bool `json:"clientSecretConfigured,omitempty"`

	// Scopes to request. Defaults to ["openid","email","profile"].
	// Add "groups" for Okta / Azure AD group support.
	Scopes []string `json:"scopes"`

	// GroupsClaim is the ID-token / userinfo claim that contains the user's
	// groups or roles.  Defaults to "groups".
	GroupsClaim string `json:"groupsClaim"`

	// Optional enforcement filters (empty = no check).
	RequiredScope    string `json:"requiredScope"`
	RequiredAudience string `json:"requiredAudience"`

	// TLSSkipVerify disables upstream TLS verification (dev/test only).
	TLSSkipVerify bool `json:"tlsSkipVerify"`

	// ─── Auto-discovered fields (read-only, populated by the proxy) ───────
	AuthorizationEndpoint string `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string `json:"tokenEndpoint,omitempty"`
	IntrospectionEndpoint string `json:"introspectionEndpoint,omitempty"`
	UserinfoEndpoint      string `json:"userinfoEndpoint,omitempty"`
	JWKsURI               string `json:"jwksUri,omitempty"`
}

// SAMLProfileConfig holds SAML 2.0 SP settings for an IdP profile.
type SAMLProfileConfig struct {
	// Exactly one of MetadataURL or MetadataXML must be provided.
	MetadataURL string `json:"metadataUrl,omitempty"`
	MetadataXML string `json:"metadataXml,omitempty"` // raw XML (admin upload); WRITE-ONLY

	// InlineMetadataConfigured is READ-ONLY response metadata (FE-6A.0 R6):
	// whether inline metadata XML is currently stored. Ignored on write.
	InlineMetadataConfigured bool `json:"inlineMetadataConfigured,omitempty"`

	// NameIDFormat requested in AuthnRequest.
	// Common values: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	//                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	// Defaults to emailAddress if empty.
	NameIDFormat string `json:"nameIdFormat"`

	// GroupsAttribute is the SAML assertion attribute that carries group
	// memberships.  Common values: "groups", "memberOf", "Role".
	GroupsAttribute string `json:"groupsAttribute"`

	// EmailAttribute is the assertion attribute for the user's email
	// (when NameID is not an email address).  Usually "email" or
	// "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".
	EmailAttribute string `json:"emailAttribute"`

	// NameAttribute is the assertion attribute for the display name.
	// Usually "displayName" or "cn".
	NameAttribute string `json:"nameAttribute"`
}

// ---------------------------------------------------------------------------
// IdP registry
// ---------------------------------------------------------------------------

// IdPRegistry stores and manages IdP profiles.  It is the authoritative
// source of truth for all configured identity providers.
//
// LOCKING (FE-6A.0, R1): r.mu guards ONLY the published state (profiles +
// live) and is held for pointer swaps and reads — never across a compile
// (OIDC discovery / SAML metadata fetch are network I/O with 10–15 s
// budgets) and never across a disk write. Every mutation is a transaction
// serialised on idpMutationMu (admin-rate): compile OUTSIDE both locks →
// build the candidate → persist it → run the optional pre-publish step
// (the legacy-LDAP cutover sentinel) → swap under r.mu. A reader on the
// proxy request path (RouteByDomain, EnabledProviders, …) is therefore
// never queued behind a slow identity provider.
type IdPRegistry struct {
	mu       sync.RWMutex
	profiles []*IdPProfile
	path     string // JSON file path (empty = in-memory only)

	// live holds compiled/initialised provider instances keyed by profile ID.
	live map[string]IdentityProvider

	// degraded is non-nil while the on-disk registry was found corrupt at
	// load (quarantined beside the store, R8): the registry runs EMPTY and
	// refuses every admin mutation until the operator acknowledges the
	// quarantine evidence through the fenced repair (or a CP snapshot
	// rebuilds the DP's copy).
	degraded *idpRegistryDegradation

	// ops is the durable operation-intent ring (Blocker 9), a sibling of the
	// registry file; nil until first use on a registry built without Load.
	ops *idpOperationStore
}

// operations returns the registry's intent store (lazily in-memory for a
// registry that was never loaded from a path).
func (r *IdPRegistry) operations() *idpOperationStore {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ops == nil {
		r.ops = newIdPOperationStore(r.path)
	}
	return r.ops
}

// idpRegistryDegradation is the read-only degraded posture (R8).
type idpRegistryDegradation struct {
	Reason         string `json:"reason"`
	QuarantinePath string `json:"quarantinePath,omitempty"`
	Detail         string `json:"detail"`
}

// idpMutationMu serialises every registry mutation transaction (admin API,
// legacy import, CP→DP sync, repair). Readers never take it.
var idpMutationMu sync.Mutex

var idpRegistry = &IdPRegistry{live: make(map[string]IdentityProvider)}

// Sentinel errors of the mutation contract (mapped to typed refusals by
// the handlers; see ui_refusal.go).
var (
	// errIdPPersistFailed marks a registry mutation that failed at the
	// PERSIST step. The transactional model guarantees nothing published
	// changed when this is returned; API handlers map it to 500.
	errIdPPersistFailed = errors.New("idp: persisting the profile registry failed; no change was applied")
	// errIdPOutcomeUnknown marks a split durable outcome: the registry
	// candidate was persisted, the pre-publish step failed, and rolling the
	// registry file back ALSO failed. Nothing was published; the next boot
	// reconciles from disk. NON-terminal (500 outcome_unknown).
	errIdPOutcomeUnknown = errors.New("idp: outcome unknown — registry file persisted, sentinel not durable, rollback failed; nothing published")
	// errIdPVanished: a fenced write named an id that no longer exists.
	errIdPVanished = errors.New("idp: profile vanished")
	// errIdPRegistryDegraded: mutations refused while the store is degraded.
	errIdPRegistryDegraded = errors.New("idp: registry degraded — the profile file was quarantined; repair first")
	// errIdPNotDegraded: repair called on a healthy registry.
	errIdPNotDegraded = errors.New("idp: registry is not degraded")
	// errIdPRepairUnavailable: the corrupt file could not be quarantined, so
	// no acknowledgeable evidence exists — restore the file and restart.
	errIdPRepairUnavailable = errors.New("idp: repair unavailable — the corrupt file could not be moved aside; restore it or a backup and restart")
	// errIdPRepairMismatch: the confirm word did not name the quarantine.
	errIdPRepairMismatch = errors.New("idp: repair confirm does not name the quarantined file")
)

// idpStaleError carries the authoritative revision a stale fenced write
// must reload (409 stale).
type idpStaleError struct{ Current int64 }

func (e *idpStaleError) Error() string {
	return fmt.Sprintf("idp: stale revision (current %d)", e.Current)
}

// idpDocStaleError is the document-level twin (Blocker 4): a CREATE is
// fenced on the registry DOCUMENT revision — the only identity that exists
// before the profile does — and carries the authoritative value.
type idpDocStaleError struct{ Current string }

func (e *idpDocStaleError) Error() string {
	return "idp: stale document revision (current " + e.Current + ")"
}

// idpValidationError is an INTRINSIC write-input defect (400 invalid_input):
// the message is Culvert's own wording about the caller's input and carries
// no dependency detail (Blocker 6).
type idpValidationError struct{ msg string }

func (e *idpValidationError) Error() string { return e.msg }

// idpCompileError is a DEPENDENCY / provider-construction failure (502
// provider_compile_failed): the profile validated, but the live provider
// could not be built — OIDC discovery, SAML metadata fetch/parse, LDAP
// provider construction. Only the bounded reason class crosses the trust
// boundary; the underlying error (which embeds hostnames, TLS and transport
// text) is dropped at this seam and never logged, audited or returned.
type idpCompileError struct{ reason string }

func (e *idpCompileError) Error() string { return "idp: provider compile failed (" + e.reason + ")" }

// idpCompileReason maps a profile type to its bounded compile-failure class.
func idpCompileReason(t IdPType) string {
	switch t {
	case IdPTypeOIDC:
		return "oidc_discovery"
	case IdPTypeSAML:
		return "saml_metadata"
	case IdPTypeLDAP:
		return "ldap_provider"
	default:
		return "unsupported"
	}
}

// Load reads IdP profiles from the JSON file.  Silent no-op when path is
// empty. A CORRUPT file never fails the boot (R8): it is quarantined beside
// the store (CHAOS-05 convention, `<path>.corrupt.<unixnano>`), the registry
// starts EMPTY in the degraded posture, and Load returns nil.
func (r *IdPRegistry) Load(path string) error {
	if path == "" {
		return nil
	}
	r.mu.Lock()
	r.path = path
	r.mu.Unlock()
	noteResidualQuarantine("idp_profiles", path)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		r.mu.Lock()
		r.ops = newIdPOperationStore(path)
		r.mu.Unlock()
		r.reconcileOperations()
		return nil // first run — empty registry
	}
	if err != nil {
		return fmt.Errorf("idp registry: read %s: %w", path, err)
	}
	var profiles []*IdPProfile
	if err := json.Unmarshal(data, &profiles); err != nil {
		qpath := quarantineCorruptStateFile("idp_profiles", path, err)
		d := &idpRegistryDegradation{Reason: "corrupt_quarantined", QuarantinePath: qpath,
			Detail: "the identity-provider registry file was corrupt and has been moved aside; the registry is EMPTY and refuses changes until the quarantine is acknowledged (POST /api/idp/repair) or the file is restored and the node restarted"}
		if qpath == "" {
			d.Reason = "corrupt_not_quarantined"
			d.Detail = "the identity-provider registry file is corrupt and could not be moved aside; the registry is EMPTY and refuses changes — restore the file or a backup and restart"
		}
		r.mu.Lock()
		r.profiles = nil
		r.live = make(map[string]IdentityProvider)
		r.degraded = d
		r.ops = newIdPOperationStore(path)
		r.mu.Unlock()
		logger.Printf("IdP: registry DEGRADED — %s", sanitizeLog(d.Detail))
		return nil
	}
	// Drop profiles whose ID/name collides with the reserved authSource
	// namespace, fail-closed (hand-edited or pre-guard files only — Upsert and
	// ReplaceAll reject them on write). Keeping one would let an IdP authenticate
	// under a reserved authSource and make Stage-2 rules ambiguous. Mirrors the
	// policy store's drop-invalid-on-load behavior; the file is not rewritten here.
	kept := profiles[:0]
	for _, p := range profiles {
		if err := validateReservedIdPNaming(p); err != nil {
			logWarnf("IdP: dropping profile on load — %v", err)
			continue
		}
		if p.Revision <= 0 {
			p.Revision = 1 // pre-revision file: server-minted floor
		}
		kept = append(kept, p)
	}
	profiles = kept
	// Initialise live providers for enabled profiles BEFORE publishing (no
	// network I/O under the lock).
	live := make(map[string]IdentityProvider)
	for _, p := range profiles {
		if p.Enabled {
			prov, err := compileBounded(p)
			if err != nil {
				continue // bounded class already logged at the seam
			}
			live[p.ID] = prov
		}
	}
	r.mu.Lock()
	r.profiles = profiles
	r.live = live
	r.degraded = nil
	r.ops = newIdPOperationStore(path)
	r.mu.Unlock()
	r.reconcileOperations()
	return nil
}

// reconcileOperations settles every non-terminal durable intent against the
// registry content just loaded (Blocker 9: a process that died between the
// intent and the outcome leaves a truth the file can decide).
//
// Round 3: a pending intent is proven COMMITTED only by a profile carrying
// its provenance (never by presence); a committed record whose success
// audit was never emitted is audited here EXACTLY ONCE (the `audited` flag
// is durable, so a replay never audits twice). A degraded ledger settles
// nothing — it is fail-closed until the operator restores it.
func (r *IdPRegistry) reconcileOperations() {
	ops := r.operations()
	if ops.Degraded() != nil {
		return
	}
	settled := 0
	unresolved := ops.Unresolved()
	for i := range unresolved {
		op := &unresolved[i]
		if err := r.settleOperation(ops, *op, r.Get(op.ProfileID), "reconciled"); err != nil {
			logger.Printf("IdP: operation %s could not be settled at reconciliation (%s)", sanitizeLog(op.OperationID), boundedPersistClass(err))
			continue
		}
		settled++
	}
	audited := 0
	unaudited := ops.UnauditedCommits()
	for i := range unaudited {
		op := &unaudited[i]
		if err := ops.emitOperationAudit(*op); err != nil {
			logger.Printf("IdP: operation %s audit could not be marked durable (%s)", sanitizeLog(op.OperationID), boundedPersistClass(err))
			continue
		}
		audited++
	}
	if settled > 0 || audited > 0 {
		logger.Printf("IdP: reconciled %d unsettled operation intent(s) and completed %d pending success audit(s) from the registry file", settled, audited)
	}
}

// boundedPersistClass names a ledger failure by its bounded class only —
// the underlying filesystem error never reaches the log.
func boundedPersistClass(err error) string {
	switch {
	case errors.Is(err, errIdPOperationLedgerDegraded):
		return "ledger_degraded"
	case errors.Is(err, errIdPOperationPersist):
		return "ledger_not_durable"
	case errors.Is(err, errIdPOperationAuditPending):
		return "audit_pending"
	default:
		return "settle_failed"
	}
}

// settleOperation decides one unresolved intent DURABLY from the registry's
// own evidence and completes its audit:
//
//   - target present and carrying the intent's provenance ⇒ committed
//     (the success audit is emitted from the recorded facts, exactly once);
//   - target present WITHOUT that provenance ⇒ aborted (`<why>_unproven`):
//     another writer owns the entry, so this intent never committed;
//   - target absent ⇒ aborted (`<why>_absent`).
//
// The verdict is persisted BEFORE it is reported; a persist failure leaves
// the intent unresolved and is returned to the caller.
func (r *IdPRegistry) settleOperation(ops *idpOperationStore, op idpOperation, target *IdPProfile, why string) error {
	switch {
	case target == nil:
		return ops.Finish(op.OperationID, idpOpAborted, why+"_absent", "", nil, "", nil)
	case target.OperationID != op.OperationID:
		return ops.Finish(op.OperationID, idpOpAborted, why+"_unproven", "", nil, "", nil)
	}
	result := map[string]any{"id": target.ID, "operationId": op.OperationID, "settled": why}
	if err := ops.Finish(op.OperationID, idpOpCommitted, why+"_committed", r.DocumentRevision(), result, op.AuditDetail, auditIdPProfile(target)); err != nil {
		return err
	}
	rec, err := ops.Get(op.OperationID)
	if err != nil || rec == nil {
		return err
	}
	// The verdict is durable; the success audit is completed through the
	// exactly-once boundary. A sink that cannot take it now leaves the
	// operation committed-but-audit-pending (retried by lookup and boot) —
	// never a reason to refuse the writer that settled it (round 4).
	if aerr := ops.emitOperationAudit(*rec); aerr != nil {
		logger.Printf("IdP: operation %s settled committed; success audit pending (%s)", sanitizeLog(op.OperationID), boundedPersistClass(aerr))
	}
	return nil
}

// settleBeforeWrite runs inside every registry transaction, after the
// candidate is built and BEFORE anything is persisted: for every current
// profile the candidate removes or replaces, an outstanding intent on that
// profile (other than the transaction's own, activeOp) is settled durably
// first. If it cannot be settled the transaction is refused with
// errIdPOperationUnsettled and NOTHING is written — historical authorship
// is never inferred from content the writer is about to change.
//
// A DEGRADED ledger cannot say whether an intent is outstanding, so it
// refuses every write that changes or removes an EXISTING profile (a pure
// add touches nothing an intent could target).
func (r *IdPRegistry) settleBeforeWrite(cur, next []*IdPProfile, activeOp string) error {
	ops := r.operations()
	degraded := ops.Degraded() != nil
	pending := ops.Unresolved()
	if !degraded && len(pending) == 0 {
		return nil
	}
	nextByID := make(map[string]*IdPProfile, len(next))
	for _, p := range next {
		nextByID[p.ID] = p
	}
	for _, p := range cur {
		if n, ok := nextByID[p.ID]; ok && n == p {
			continue // untouched entry
		}
		if degraded {
			return fmt.Errorf("%w: %w", errIdPOperationUnsettled, errIdPOperationLedgerDegraded)
		}
		for i := range pending {
			op := &pending[i]
			if op.ProfileID != p.ID || op.OperationID == activeOp {
				continue
			}
			if err := r.settleOperation(ops, *op, p, "settled_before_write"); err != nil {
				return fmt.Errorf("%w: %v", errIdPOperationUnsettled, err)
			}
		}
	}
	return nil
}

// Degraded returns a copy of the degraded posture, or nil when healthy.
func (r *IdPRegistry) Degraded() *idpRegistryDegradation {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.degraded == nil {
		return nil
	}
	cp := *r.degraded
	return &cp
}

// Repair acknowledges the quarantine evidence (confirm = the quarantined
// file's base name, the fenced T2 word) and clears the degraded posture.
// The registry stays EMPTY — the operator has reviewed the moved-aside copy
// and chosen to start over. Nothing is written.
func (r *IdPRegistry) Repair(confirm string) error {
	idpMutationMu.Lock()
	defer idpMutationMu.Unlock()
	d := r.Degraded()
	switch {
	case d == nil:
		return errIdPNotDegraded
	case d.QuarantinePath == "":
		return errIdPRepairUnavailable
	case confirm == "" || confirm != filepath.Base(d.QuarantinePath):
		return errIdPRepairMismatch
	}
	r.mu.Lock()
	r.degraded = nil
	r.mu.Unlock()
	return nil
}

// persist writes the CANDIDATE profile set to the JSON file (called inside
// the mutation transaction, BEFORE the candidate is published). The write is
// atomic (temp file + fsync + rename) so a crash mid-write can never
// truncate or corrupt the on-disk registry.
//
// TRANSACTIONAL MUTATION MODEL (P1-3 + FE-6A.0, shared by every mutation):
//
//	compile next live set (NO lock) → build next candidate profiles
//	    → persist(next) atomically
//	    → optional pre-publish step (legacy-LDAP cutover sentinel), with a
//	      compensating persist(prev) when it fails
//	    → ONLY then: publish profiles+live under r.mu
//
// A persistence failure therefore leaves the old profiles, old live
// providers, and old credentials fully authoritative — the API reports
// failure and nothing (audit success, cluster snapshot) is emitted for a
// state that does not exist. In deliberate in-memory mode (path == "") the
// warning is kept and the publish proceeds — explicit pre-existing behavior.
func (r *IdPRegistry) persist(profiles []*IdPProfile) error {
	r.mu.RLock()
	path := r.path
	r.mu.RUnlock()
	if path == "" {
		logger.Printf("IdP: WARNING — profile change is in-memory only and will be LOST on restart; set -idp-profiles-file (or proxy.idp_profiles_file) to persist")
		return nil
	}
	data, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: %v", errIdPPersistFailed, err)
	}
	if err := atomicWriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("%w: %v", errIdPPersistFailed, err)
	}
	return nil
}

// readPersisted returns the current registry file bytes (hadFile=false when
// absent or in-memory mode).
func (r *IdPRegistry) readPersisted() ([]byte, bool) {
	r.mu.RLock()
	path := r.path
	r.mu.RUnlock()
	if path == "" {
		return nil, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return b, true
}

// restorePersisted is the compensating write of a failed pre-publish step:
// the prior bytes are written back atomically, or the file is removed when
// none existed before.
func (r *IdPRegistry) restorePersisted(prev []byte, hadFile bool) error {
	r.mu.RLock()
	path := r.path
	r.mu.RUnlock()
	if path == "" {
		return nil
	}
	if !hadFile {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return atomicWriteFile(path, prev, 0o600)
}

// Persisted reports whether profile changes are written to disk. False means
// the registry is in-memory only (no -idp-profiles-file / idp_profiles_file
// configured) and all profiles are lost on restart.
func (r *IdPRegistry) Persisted() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.path != ""
}

// idpCandidate is what a mutation's build step returns: the candidate
// profile set and the candidate live map. Both must be FRESH values —
// the published slice/map are never mutated in place.
type idpCandidate struct {
	profiles []*IdPProfile
	live     map[string]IdentityProvider
}

// mutate runs one registry transaction (see persist). build receives the
// CURRENT published profiles (read-only) and a COPY of the live map, and
// returns the candidate. beforePublish, when non-nil, runs after the
// candidate is durable and before it is published; its failure rolls the
// registry file back to cur (a failed rollback is errIdPOutcomeUnknown).
// allowDegraded lets the CP→DP sync rebuild a degraded DP registry.
// activeOp is the transaction's own operationId ("" for an unidentified
// write): an outstanding intent on every OTHER profile the candidate changes
// or removes is settled durably first (settleBeforeWrite, round 3).
func (r *IdPRegistry) mutate(allowDegraded bool, activeOp string, build func(cur []*IdPProfile, live map[string]IdentityProvider) (idpCandidate, error), beforePublish func(next []*IdPProfile) error) error {
	idpMutationMu.Lock()
	defer idpMutationMu.Unlock()

	r.mu.RLock()
	cur := r.profiles
	curLive := make(map[string]IdentityProvider, len(r.live)+1)
	for id, prov := range r.live {
		curLive[id] = prov
	}
	degraded := r.degraded != nil
	r.mu.RUnlock()
	if degraded && !allowDegraded {
		return errIdPRegistryDegraded
	}
	next, err := build(cur, curLive)
	if err != nil {
		return err
	}
	if err := r.settleBeforeWrite(cur, next.profiles, activeOp); err != nil {
		return err
	}
	// Snapshot the prior file BYTES so a compensating rollback restores the
	// exact durable state (including "no file yet"), not a re-serialisation.
	prevBytes, hadFile := r.readPersisted()
	if err := r.persist(next.profiles); err != nil {
		return err // old profiles + old live providers stay authoritative
	}
	if beforePublish != nil {
		if err := beforePublish(next.profiles); err != nil {
			if rbErr := r.restorePersisted(prevBytes, hadFile); rbErr != nil {
				return fmt.Errorf("%w: %v (rollback: %v)", errIdPOutcomeUnknown, err, rbErr)
			}
			return err
		}
	}
	r.mu.Lock()
	r.profiles, r.live = next.profiles, next.live
	if allowDegraded {
		r.degraded = nil
	}
	r.mu.Unlock()
	return nil
}

// compile initialises a live IdentityProvider from a profile.
// Calling under r.mu.Lock is the caller's responsibility.
func (r *IdPRegistry) compile(p *IdPProfile) error {
	prov, err := compileIdPProfile(p)
	if err != nil {
		return err
	}
	r.live[p.ID] = prov
	return nil
}

// validateUpsertProfile validates an admin-supplied profile on the Upsert path.
// Kept separate from validateIdPProfile (the ReplaceAll/Load path) to preserve
// Upsert's exact, slightly-looser semantics (it does not require an OIDC config
// block to be present), while sharing the reserved-name guard so no IdP entry
// point can bypass it.
func validateUpsertProfile(p *IdPProfile) error {
	if p.Name == "" {
		return fmt.Errorf("idp: name is required")
	}
	// Reserved authSource namespace (shared with validateIdPProfile / Load): the
	// admin create/update path runs through Upsert, not validateIdPProfile, so
	// the reserved-name guard must be enforced here too.
	if err := validateReservedIdPNaming(p); err != nil {
		return err
	}
	if p.Type != IdPTypeOIDC && p.Type != IdPTypeSAML && p.Type != IdPTypeLDAP {
		return fmt.Errorf("idp: type must be 'oidc', 'saml', or 'ldap'")
	}
	// Security: validate issuer/metadata URLs before compiling.
	if p.Type == IdPTypeOIDC && p.OIDC != nil {
		if err := validateExternalURL(p.OIDC.Issuer); err != nil {
			return fmt.Errorf("idp oidc issuer: %w", err)
		}
		if p.Enabled && p.OIDC.ClientID == "" {
			// Intrinsic (the constructor would refuse it before any
			// discovery): keep it a 400, never a dependency failure.
			return fmt.Errorf("idp oidc: client_id is required")
		}
	}
	if p.Type == IdPTypeOIDC && p.OIDC == nil && p.Enabled {
		return fmt.Errorf("idp oidc: config is required")
	}
	if p.Type == IdPTypeLDAP && p.LDAP == nil {
		return fmt.Errorf("idp ldap: config is required")
	}
	if p.Type == IdPTypeSAML {
		if err := validateSAMLProfileConfig(p.SAML); err != nil {
			return fmt.Errorf("idp saml: %w", err)
		}
	}
	if p.Type == IdPTypeLDAP {
		if err := validateLDAPProfileConfig(p.LDAP); err != nil {
			return fmt.Errorf("idp ldap: %w", err)
		}
	}
	return nil
}

// normalizeIdPProfileWriteInput strips response-only metadata a client may
// echo back on write (the GET projection is round-trippable by design). The
// stored profile must never carry the derived configured-indicator bits or a
// caller-asserted revision — publicIdPProfile recomputes the indicators from
// the stored secrets on every read and the registry mints every revision.
func normalizeIdPProfileWriteInput(p *IdPProfile) {
	if p == nil {
		return
	}
	p.Revision = 0
	p.OperationID = ""
	if p.LDAP != nil {
		p.LDAP.BindCredentialConfigured = false
	}
	if p.OIDC != nil {
		p.OIDC.ClientSecretConfigured = false
	}
	if p.SAML != nil {
		p.SAML.InlineMetadataConfigured = false
	}
}

// prepareProfile validates the write input and compiles the live provider
// OUTSIDE every registry lock (network I/O). compiled is nil for a disabled
// profile.
func prepareProfile(p *IdPProfile) (IdentityProvider, error) {
	normalizeIdPProfileWriteInput(p)
	if err := validateUpsertProfile(p); err != nil {
		return nil, &idpValidationError{msg: err.Error()}
	}
	if !p.Enabled {
		return nil, nil
	}
	// A SAML profile carrying INLINE metadata XML that does not parse is
	// the caller's own input, not a dependency: report it as validation
	// (bounded wording — the blob is never echoed).
	if p.Type == IdPTypeSAML && p.SAML != nil && p.SAML.MetadataXML != "" {
		if _, perr := samlsp.ParseMetadata([]byte(p.SAML.MetadataXML)); perr != nil {
			return nil, &idpValidationError{msg: "idp saml: metadata_xml is not valid SAML metadata"}
		}
	}
	return compileBounded(p)
}

// compileBounded is THE single classification seam every provider
// compilation crosses (admin write, boot Load, CP→DP ReplaceAll — round 3,
// Blocker 3). The cause embeds the dependency's hostname / TLS / transport
// text; it is dropped HERE and only the bounded class survives — in the
// returned *idpCompileError, in the process log, and therefore in every
// audit, diagnostic and read model downstream.
func compileBounded(p *IdPProfile) (IdentityProvider, error) {
	prov, err := compileIdPProfile(p)
	if err != nil {
		reason := idpCompileReason(p.Type)
		logger.Printf("IdP: provider compile failed id=%q type=%q reason=%s", sanitizeLog(p.ID), sanitizeLog(string(p.Type)), reason)
		return nil, &idpCompileError{reason: reason}
	}
	return prov, nil
}

// Upsert adds or replaces a profile (create-or-replace, UNFENCED — the
// legacy import and internal callers). The admin API's fenced update is
// Update. A created profile gets revision 1; a replaced one advances.
func (r *IdPRegistry) Upsert(p *IdPProfile) error {
	if p.ID == "" {
		p.ID = mintIdPID()
	}
	compiled, err := prepareProfile(p)
	if err != nil {
		return err
	}
	return r.mutate(false, "", func(cur []*IdPProfile, live map[string]IdentityProvider) (idpCandidate, error) {
		return applyProfileCandidate(cur, live, p, compiled), nil
	}, nil)
}

// mintIdPID mints a fresh registry profile id.
func mintIdPID() string {
	b := make([]byte, 6)
	rand.Read(b) //nolint:errcheck // crypto/rand.Read never returns an error on supported platforms
	return hex.EncodeToString(b)
}

// Create adds a NEW profile and runs beforePublish between the durable write
// and the publication (the legacy-LDAP cutover hook of an enabling create).
// p.ID may be PRE-MINTED by the caller (the operation-identified admin path
// records it in the durable intent before this call); empty mints one here.
// expectedDocRev is the registry DOCUMENT revision fence (Blocker 4),
// decided INSIDE the transaction against the current profile set: "" skips
// the fence (internal callers), a mismatch is *idpDocStaleError, and an id
// collision is refused rather than silently replacing.
// operationID, when non-empty, is stamped on the profile as its durable
// PROVENANCE in the same atomic write (round 3).
func (r *IdPRegistry) Create(p *IdPProfile, expectedDocRev, operationID string, beforePublish func(next []*IdPProfile) error) error {
	if p.ID == "" {
		p.ID = mintIdPID()
	}
	compiled, err := prepareProfile(p)
	if err != nil {
		return err
	}
	p.OperationID = operationID
	return r.mutate(false, operationID, func(cur []*IdPProfile, live map[string]IdentityProvider) (idpCandidate, error) {
		if expectedDocRev != "" {
			if cur := idpDocumentRevisionOf(cur); cur != expectedDocRev {
				return idpCandidate{}, &idpDocStaleError{Current: cur}
			}
		}
		if findIdPProfile(cur, p.ID) != nil {
			return idpCandidate{}, &idpValidationError{msg: "idp: profile id already exists"}
		}
		return applyProfileCandidate(cur, live, p, compiled), nil
	}, beforePublish)
}

// Update replaces the profile p.ID under the revision fence: the target must
// exist (errIdPVanished) and expectedRev must equal its current revision
// (*idpStaleError with the authoritative value). The fence is decided INSIDE
// the transaction, never against a value the caller read earlier. The
// candidate carries the next revision.
//
// FE-6A.2: an operation-identified update (operationID != "") stamps its
// identity as the profile's provenance in the SAME atomic write — the
// ledger settles the intent by that provenance exactly as it does for a
// create — and its own intent is excluded from settle-before-write.
func (r *IdPRegistry) Update(p *IdPProfile, expectedRev int64, operationID string, beforePublish func(next []*IdPProfile) error) error {
	compiled, err := prepareProfile(p)
	if err != nil {
		return err
	}
	if operationID != "" {
		p.OperationID = operationID
	}
	return r.mutate(false, operationID, func(cur []*IdPProfile, live map[string]IdentityProvider) (idpCandidate, error) {
		existing := findIdPProfile(cur, p.ID)
		if existing == nil {
			return idpCandidate{}, errIdPVanished
		}
		if expectedRev != idpEntryRevision(existing) {
			return idpCandidate{}, &idpStaleError{Current: idpEntryRevision(existing)}
		}
		return applyProfileCandidate(cur, live, p, compiled), nil
	}, beforePublish)
}

// applyProfileCandidate builds the candidate for a create/replace of p,
// minting its revision from the current entry (1 for a new id).
func applyProfileCandidate(cur []*IdPProfile, live map[string]IdentityProvider, p *IdPProfile, compiled IdentityProvider) idpCandidate {
	nextProfiles := make([]*IdPProfile, len(cur))
	copy(nextProfiles, cur)
	found := false
	for i, existing := range nextProfiles {
		if existing.ID == p.ID {
			p.Revision = idpEntryRevision(existing) + 1
			if p.OperationID == "" {
				p.OperationID = existing.OperationID // provenance survives a replace
			}
			nextProfiles[i] = p
			found = true
			break
		}
	}
	if !found {
		p.Revision = 1
		nextProfiles = append(nextProfiles, p)
	}
	if p.Enabled && compiled != nil {
		live[p.ID] = compiled
	} else {
		delete(live, p.ID)
	}
	return idpCandidate{profiles: nextProfiles, live: live}
}

func findIdPProfile(profiles []*IdPProfile, id string) *IdPProfile {
	for _, p := range profiles {
		if p != nil && p.ID == id {
			return p
		}
	}
	return nil
}

func validateSAMLProfileConfig(cfg *SAMLProfileConfig) error {
	if cfg == nil {
		return fmt.Errorf("config is required")
	}
	if (cfg.MetadataURL == "") == (cfg.MetadataXML == "") {
		return fmt.Errorf("exactly one of metadata_url or metadata_xml is required")
	}
	if err := validateSAMLNameIDFormat(cfg.NameIDFormat); err != nil {
		return fmt.Errorf("name_id_format: %w", err)
	}
	if cfg.MetadataURL != "" {
		if err := validateExternalURL(cfg.MetadataURL); err != nil {
			return fmt.Errorf("metadata_url: %w", err)
		}
	}
	return nil
}

func compileIdPProfile(p *IdPProfile) (IdentityProvider, error) {
	switch p.Type {
	case IdPTypeOIDC:
		if p.OIDC == nil {
			return nil, fmt.Errorf("oidc profile missing oidc config")
		}
		return NewOIDCFlowProvider(p)
	case IdPTypeSAML:
		if p.SAML == nil {
			return nil, fmt.Errorf("saml profile missing saml config")
		}
		return NewSAMLProvider(p)
	case IdPTypeLDAP:
		if p.LDAP == nil {
			return nil, fmt.Errorf("ldap profile missing ldap config")
		}
		return NewLDAPIdPProvider(p)
	default:
		return nil, fmt.Errorf("unknown IdP type %q", p.Type)
	}
}

// Delete removes a profile by ID (UNFENCED — internal callers and tests;
// the admin API uses DeleteFenced). Transactional: persisted before
// published, so a persist failure leaves the profile and its live provider
// active.
func (r *IdPRegistry) Delete(id string) error {
	return r.deleteWhere(id, nil)
}

// DeleteFenced removes a profile under the revision fence (errIdPVanished /
// *idpStaleError), decided inside the transaction.
func (r *IdPRegistry) DeleteFenced(id string, expectedRev int64) error {
	return r.deleteWhere(id, &expectedRev)
}

func (r *IdPRegistry) deleteWhere(id string, expectedRev *int64) error {
	return r.mutate(false, "", func(cur []*IdPProfile, live map[string]IdentityProvider) (idpCandidate, error) {
		for i, p := range cur {
			if p.ID != id {
				continue
			}
			if expectedRev != nil && *expectedRev != idpEntryRevision(p) {
				return idpCandidate{}, &idpStaleError{Current: idpEntryRevision(p)}
			}
			nextProfiles := make([]*IdPProfile, 0, len(cur)-1)
			nextProfiles = append(nextProfiles, cur[:i]...)
			nextProfiles = append(nextProfiles, cur[i+1:]...)
			delete(live, id)
			return idpCandidate{profiles: nextProfiles, live: live}, nil
		}
		if expectedRev != nil {
			return idpCandidate{}, errIdPVanished
		}
		return idpCandidate{}, fmt.Errorf("idp %q not found", id)
	}, nil)
}

// Get returns the profile with the given ID (nil if not found).
func (r *IdPRegistry) Get(id string) *IdPProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.profiles {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// All returns a copy of all profiles. NEVER nil: an empty registry is an
// empty slice, so the CP→DP wire carries an explicit `idp_profiles: []` and
// a DP observes the last delete (R5).
func (r *IdPRegistry) All() []*IdPProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneIdPProfiles(r.profiles)
}

// DocumentRevision is the content-derived revision of the whole registry
// (every id + entry revision, sorted), the fence a list-level consumer
// compares. Identical across restarts for identical content.
func (r *IdPRegistry) DocumentRevision() string {
	r.mu.RLock()
	parts := make([]string, 0, len(r.profiles))
	for _, p := range r.profiles {
		if p != nil {
			parts = append(parts, p.ID+"@"+strconv.FormatInt(idpEntryRevision(p), 10))
		}
	}
	r.mu.RUnlock()
	sort.Strings(parts)
	return contentSecRevision(append([]string{"idp-registry"}, parts...)...)
}

// ReplaceAll atomically swaps the registry to match profiles (the CP→DP
// application path). Enabled providers are compiled BEFORE the transaction
// so callers never observe a half-applied IdP snapshot, and the candidate is
// PERSISTED before it is published (P1-3): a persistence failure rejects the
// whole replacement and the previous set stays live. A degraded DP registry
// is rebuilt (and un-degraded) by a valid snapshot — the CP's set is the
// authoritative repair on a data plane.
func (r *IdPRegistry) ReplaceAll(profiles []*IdPProfile) error {
	nextProfiles := cloneIdPProfiles(profiles)
	if nextProfiles == nil {
		nextProfiles = []*IdPProfile{}
	}
	nextLive := make(map[string]IdentityProvider)
	for _, p := range nextProfiles {
		rev, prov := p.Revision, p.OperationID
		normalizeIdPProfileWriteInput(p)
		p.Revision, p.OperationID = rev, prov
		if p.Revision <= 0 {
			p.Revision = 1
		}
		if err := validateIdPProfile(p); err != nil {
			return err
		}
		if !p.Enabled {
			continue
		}
		live, err := compileBounded(p) // bounded class only (round 3, Blocker 3)
		if err != nil {
			return fmt.Errorf("idp %q: %w", p.ID, err)
		}
		nextLive[p.ID] = live
	}
	return r.mutate(true, "", func([]*IdPProfile, map[string]IdentityProvider) (idpCandidate, error) {
		return idpCandidate{profiles: nextProfiles, live: nextLive}, nil
	}, nil)
}

// validateReservedIdPNaming rejects IdP profile IDs and names that collide with
// the reserved authSource namespace {exempt, unauth, local, system}. Profile IDs
// feed the authSource value seen by Stage-2 policy ("oidc:<ID>"/"saml:<ID>" with
// the prefix stripped during matching, and the bare ID via session identities),
// so a colliding ID/name would make authSource-scoped access rules ambiguous.
// Generated hex IDs never collide; supplied IDs (admin Upsert, cluster ReplaceAll,
// startup Load, import) are the vectors. Shared by every IdP entry point so the
// guard cannot be bypassed (pre-Phase-2 correction).
func validateReservedIdPNaming(p *IdPProfile) error {
	if p == nil {
		return nil
	}
	if isReservedAuthSourceName(p.ID) {
		return fmt.Errorf("idp: id %q collides with the reserved authSource namespace (exempt, unauth, local, system)", p.ID)
	}
	if isReservedAuthSourceName(p.Name) {
		return fmt.Errorf("idp: name %q collides with the reserved authSource namespace (exempt, unauth, local, system)", p.Name)
	}
	return nil
}

func validateIdPProfile(p *IdPProfile) error {
	if p == nil {
		return fmt.Errorf("idp: profile is required")
	}
	if p.ID == "" {
		return fmt.Errorf("idp: id is required")
	}
	if p.Name == "" {
		return fmt.Errorf("idp: name is required")
	}
	if err := validateReservedIdPNaming(p); err != nil {
		return err
	}
	if p.Type != IdPTypeOIDC && p.Type != IdPTypeSAML && p.Type != IdPTypeLDAP {
		return fmt.Errorf("idp: type must be 'oidc', 'saml', or 'ldap'")
	}
	if p.Type == IdPTypeOIDC {
		if p.OIDC == nil {
			return fmt.Errorf("idp: oidc config is required")
		}
		if err := validateExternalURL(p.OIDC.Issuer); err != nil {
			return fmt.Errorf("idp oidc issuer: %w", err)
		}
	}
	if p.Type == IdPTypeSAML {
		if err := validateSAMLProfileConfig(p.SAML); err != nil {
			return fmt.Errorf("idp saml: %w", err)
		}
	}
	if p.Type == IdPTypeLDAP {
		if err := validateLDAPProfileConfig(p.LDAP); err != nil {
			return fmt.Errorf("idp ldap: %w", err)
		}
	}
	return nil
}

func cloneIdPProfiles(profiles []*IdPProfile) []*IdPProfile {
	out := make([]*IdPProfile, 0, len(profiles))
	for _, p := range profiles {
		if p == nil {
			out = append(out, nil)
			continue
		}
		cp := *p
		cp.EmailDomains = append([]string(nil), p.EmailDomains...)
		cp.KnownGroups = append([]string(nil), p.KnownGroups...)
		if p.OIDC != nil {
			oidc := *p.OIDC
			oidc.Scopes = append([]string(nil), p.OIDC.Scopes...)
			cp.OIDC = &oidc
		}
		if p.SAML != nil {
			saml := *p.SAML
			cp.SAML = &saml
		}
		if p.LDAP != nil {
			ldap := *p.LDAP
			cp.LDAP = &ldap
		}
		out = append(out, &cp)
	}
	return out
}

// publicIdPProfile returns a response-safe copy. Client secrets, uploaded
// SAML metadata XML, and the LDAP bind credential are write-only API inputs
// and must not be exposed through viewer/admin read responses.
//
// This is an explicit ALLOWLIST projection, deliberately not a struct copy
// with the secret fields blanked afterwards: a copy still aliases (or is
// derived from) secret-bearing memory, which both taint analysis (CodeQL
// clear-text-logging, which does not strong-update pointer fields) and a
// future refactor can trip over. Rebuilding every sub-config from named
// non-secret fields makes the projection provably secret-free by
// construction. Field-completeness is pinned by
// TestPublicIdPProfile_ProjectionParity — adding a profile field means
// adding it here (or to the declared redaction set) or that test fails.
func publicIdPProfile(p *IdPProfile) *IdPProfile {
	if p == nil {
		return nil
	}
	cp := &IdPProfile{
		ID:           p.ID,
		Name:         p.Name,
		Type:         p.Type,
		EmailDomains: append([]string(nil), p.EmailDomains...),
		Enabled:      p.Enabled,
		Priority:     p.Priority,
		KnownGroups:  append([]string(nil), p.KnownGroups...),
		Revision:     idpEntryRevision(p),
		OperationID:  p.OperationID,
	}
	if p.OIDC != nil {
		cp.OIDC = &OIDCProfileConfig{
			Issuer:   p.OIDC.Issuer,
			ClientID: p.OIDC.ClientID,
			// ClientSecret: write-only input, redacted. Read surfaces expose
			// only the derived ClientSecretConfigured metadata bit.
			ClientSecretConfigured: p.OIDC.ClientSecret != "",
			Scopes:                 append([]string(nil), p.OIDC.Scopes...),
			GroupsClaim:            p.OIDC.GroupsClaim,
			RequiredScope:          p.OIDC.RequiredScope,
			RequiredAudience:       p.OIDC.RequiredAudience,
			TLSSkipVerify:          p.OIDC.TLSSkipVerify,
			AuthorizationEndpoint:  p.OIDC.AuthorizationEndpoint,
			TokenEndpoint:          p.OIDC.TokenEndpoint,
			IntrospectionEndpoint:  p.OIDC.IntrospectionEndpoint,
			UserinfoEndpoint:       p.OIDC.UserinfoEndpoint,
			JWKsURI:                p.OIDC.JWKsURI,
		}
	}
	if p.SAML != nil {
		cp.SAML = &SAMLProfileConfig{
			MetadataURL: p.SAML.MetadataURL,
			// MetadataXML: write-only admin upload, redacted. Read surfaces
			// expose only the derived InlineMetadataConfigured metadata bit
			// (named without the "metadataXml" stem so secret-absence scans
			// for that key never false-positive on the indicator).
			InlineMetadataConfigured: p.SAML.MetadataXML != "",
			NameIDFormat:             p.SAML.NameIDFormat,
			GroupsAttribute:          p.SAML.GroupsAttribute,
			EmailAttribute:           p.SAML.EmailAttribute,
			NameAttribute:            p.SAML.NameAttribute,
		}
	}
	if p.LDAP != nil {
		cp.LDAP = &LDAPProfileConfig{
			URL:           p.LDAP.URL,
			StartTLS:      p.LDAP.StartTLS,
			TLSSkipVerify: p.LDAP.TLSSkipVerify,
			BindDN:        p.LDAP.BindDN,
			// BindPassword: write-only input, redacted. Read surfaces expose
			// only the derived BindCredentialConfigured metadata bit.
			BindCredentialConfigured: p.LDAP.BindPassword != "",
			BaseDN:                   p.LDAP.BaseDN,
			UserFilter:               p.LDAP.UserFilter,
			EmailAttribute:           p.LDAP.EmailAttribute,
			NameAttribute:            p.LDAP.NameAttribute,
			GroupAttribute:           p.LDAP.GroupAttribute,
			RequiredGroup:            p.LDAP.RequiredGroup,
			CacheTTLSeconds:          p.LDAP.CacheTTLSeconds,
		}
	}
	return cp
}

func publicIdPProfiles(profiles []*IdPProfile) []*IdPProfile {
	out := make([]*IdPProfile, len(profiles))
	for i := range profiles {
		out[i] = publicIdPProfile(profiles[i])
	}
	return out
}

// RouteByDomain returns the first enabled live provider whose EmailDomains
// list contains domain (case-insensitive).  Returns nil if none match.
// RouteByDomain returns the enabled provider whose email domain matches.
// When multiple providers match the same domain, the one with the lowest
// Priority value wins (0 is treated as default = max int for sorting).
// Only INTERACTIVE providers are eligible: RouteByDomain exists to pick the
// browser-SSO destination for a captive redirect, and a non-interactive type
// (LDAP) can never fulfil one — matching it would swallow the redirect.
func (r *IdPRegistry) RouteByDomain(domain string) IdentityProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var bestProfile *IdPProfile
	var bestProv IdentityProvider
	for _, p := range r.profiles {
		if !p.Enabled || !p.Type.Interactive() {
			continue
		}
		for _, d := range p.EmailDomains {
			if !stringsEqualFold(d, domain) {
				continue
			}
			prov, ok := r.live[p.ID]
			if !ok {
				continue
			}
			pri := p.effectivePriority()
			if bestProfile == nil || pri < bestProfile.effectivePriority() {
				bestProfile = p
				bestProv = prov
			}
		}
	}
	return bestProv
}

// idpEntryRevision is the fencing token of a stored entry, floored at 1:
// every persisted/minted revision is ≥1, and a directly-seeded in-memory
// profile (tests, pre-revision loads) still exposes an echoable token.
func idpEntryRevision(p *IdPProfile) int64 {
	if p == nil || p.Revision <= 0 {
		return 1
	}
	return p.Revision
}

// effectivePriority returns the priority for sorting (0 → max int).
func (p *IdPProfile) effectivePriority() int {
	if p == nil || p.Priority == 0 {
		return 1<<31 - 1
	}
	return p.Priority
}

// LiveProvider returns the compiled provider for a given profile ID.
func (r *IdPRegistry) LiveProvider(id string) (IdentityProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.live[id]
	return p, ok
}

// EnabledProviders returns all live (enabled+compiled) providers in profile order.
func (r *IdPRegistry) EnabledProviders() []IdentityProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []IdentityProvider
	for _, p := range r.profiles {
		if p.Enabled {
			if prov, ok := r.live[p.ID]; ok {
				out = append(out, prov)
			}
		}
	}
	return out
}

// HasEnabledProviders reports whether at least one enabled profile has a live
// (compiled) provider instance — the exact predicate EnabledProviders applies,
// without building the slice. It exists for the per-request ssoCapable probe
// in resolveRequestAuth (proxy.go), which runs on EVERY proxied request and
// needs only the boolean: going through EnabledProviders allocates a fresh
// slice per call whenever any provider is enabled, which at proxy request
// rates is pure per-request garbage. Callers that use the providers keep
// calling EnabledProviders. Allocation-free (pinned by the benchgate).
func (r *IdPRegistry) HasEnabledProviders() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.profiles {
		if p != nil && p.Enabled {
			if _, ok := r.live[p.ID]; ok {
				return true
			}
		}
	}
	return false
}

// EnabledInteractiveProviders returns the live providers that can drive a
// browser SSO flow (OIDC/SAML), in profile order. This is the ONLY accessor
// interactive surfaces (captive portal, /auth/select) may iterate — a
// non-interactive provider (LDAP) must never be offered a browser flow.
func (r *IdPRegistry) EnabledInteractiveProviders() []IdentityProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []IdentityProvider
	for _, p := range r.profiles {
		if p != nil && p.Enabled && p.Type.Interactive() {
			if prov, ok := r.live[p.ID]; ok {
				out = append(out, prov)
			}
		}
	}
	return out
}

// EnabledCredentialProviders returns the live providers that can validate a
// PRESENTED Basic credential (OIDC introspection, LDAP bind), in profile
// order. The proxy's Basic-auth arm iterates this — not EnabledProviders — so
// browser-only providers are structurally excluded from credential
// validation rather than relying on their ResolveIdentity returning false.
func (r *IdPRegistry) EnabledCredentialProviders() []IdentityProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []IdentityProvider
	for _, p := range r.profiles {
		if p != nil && p.Enabled && p.Type.CredentialCapable() {
			if prov, ok := r.live[p.ID]; ok {
				out = append(out, prov)
			}
		}
	}
	return out
}

// HasEnabledInteractiveProvider is the allocation-free boolean probe behind
// resolveRequestAuth's per-request ssoCapable predicate: at least one enabled
// profile of an INTERACTIVE type (OIDC/SAML) with a live compiled provider.
// Before ADR-0027 this was HasEnabledProviders — correct only while every
// registry type was interactive; an enabled LDAP profile must NOT make the
// proxy advertise an SSO/captive flow it can never fulfil.
// Allocation-free (pinned by the benchgate).
func (r *IdPRegistry) HasEnabledInteractiveProvider() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.profiles {
		if p != nil && p.Enabled && p.Type.Interactive() {
			if _, ok := r.live[p.ID]; ok {
				return true
			}
		}
	}
	return false
}

// HasEnabledCredentialProvider is the allocation-free boolean probe behind
// hasCredentialCapableProvider's registry term (resolveRequestAuth's
// credCapable, per request): at least one enabled profile of a
// CREDENTIAL-CAPABLE type (OIDC/LDAP). Like HasEnabledOIDC before it, this is
// deliberately profile-level and NOT gated on a live compiled instance — a
// compile failure must not silently flip the deployment into the no-backend
// inert path. Allocation-free (pinned by the benchgate).
func (r *IdPRegistry) HasEnabledCredentialProvider() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.profiles {
		if p != nil && p.Enabled && p.Type.CredentialCapable() {
			return true
		}
	}
	return false
}

// HasEnabledLDAP reports whether any profile is enabled with Type LDAP —
// consulted by the legacy-YAML shadowing rule (ADR-0027 §authority): when an
// enabled registry LDAP profile exists, the registry is the sole operational
// LDAP authority and the legacy FileConfig.LDAP provider is not wired /
// deactivated. Profile-level (not live-gated), matching HasEnabledOIDC.
func (r *IdPRegistry) HasEnabledLDAP() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.profiles {
		if p != nil && p.Enabled && p.Type == IdPTypeLDAP {
			return true
		}
	}
	return false
}

// HasEnabledOIDC reports whether any profile is enabled with Type OIDC — the
// credential-capable predicate hasCredentialCapableProvider (diagnostics.go)
// evaluates on EVERY proxied request. It reads the profiles in place: the
// previous implementation went through All(), which deep-clones every profile
// (struct + EmailDomains/KnownGroups/Scopes slices + OIDC/SAML sub-structs)
// per call just to answer a boolean. Same predicate as before — profile-level
// only, deliberately NOT gated on a live compiled instance (a compile failure
// must not silently flip the deployment into the no-backend inert path).
// Allocation-free (pinned by the benchgate).
func (r *IdPRegistry) HasEnabledOIDC() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.profiles {
		if p != nil && p.Enabled && p.Type == IdPTypeOIDC {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// URL validation helper
// ---------------------------------------------------------------------------

// validateExternalURL rejects URLs that target private/internal addresses or
// use non-HTTPS schemes.  This prevents SSRF via admin-configured IdP URLs.
func validateExternalURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("URL is required")
	}
	// isSafeRedirectURL already validates HTTPS + non-private.
	if !isSafeRedirectURL(raw) {
		return fmt.Errorf("URL must be https:// and must not point to a private address")
	}
	return nil
}

// stringsEqualFold is a nil-safe case-insensitive string comparison.
func stringsEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}
