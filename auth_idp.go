package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
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

// ─── Provider capability model (ADR-0025) ────────────────────────────────────
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
	ClientSecret string `json:"clientSecret"` // never logged

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
	MetadataXML string `json:"metadataXml,omitempty"` // raw XML (admin upload)

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
type IdPRegistry struct {
	mu       sync.RWMutex
	profiles []*IdPProfile
	path     string // JSON file path (empty = in-memory only)

	// live holds compiled/initialised provider instances keyed by profile ID.
	live map[string]IdentityProvider
}

var idpRegistry = &IdPRegistry{live: make(map[string]IdentityProvider)}

// Load reads IdP profiles from the JSON file.  Silent no-op when path is empty.
func (r *IdPRegistry) Load(path string) error {
	if path == "" {
		return nil
	}
	r.mu.Lock()
	r.path = path
	r.mu.Unlock()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil // first run — empty registry
	}
	if err != nil {
		return fmt.Errorf("idp registry: read %s: %w", path, err)
	}
	var profiles []*IdPProfile
	if err := json.Unmarshal(data, &profiles); err != nil {
		return fmt.Errorf("idp registry: parse %s: %w", path, err)
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
		kept = append(kept, p)
	}
	profiles = kept
	r.mu.Lock()
	r.profiles = profiles
	r.mu.Unlock()

	// Initialise live providers for enabled profiles.
	for _, p := range profiles {
		if p.Enabled {
			if err := r.compile(p); err != nil {
				logger.Printf("IdP %q compile error: %v", p.ID, err)
			}
		}
	}
	return nil
}

// errIdPPersistFailed marks a registry mutation that failed at the PERSIST
// step. The transactional mutation model (P1-3) guarantees nothing published
// changed when this is returned; API handlers map it to 500 (the request was
// valid — the appliance could not store it) rather than 400.
var errIdPPersistFailed = errors.New("idp: persisting the profile registry failed; no change was applied")

// persist writes the CANDIDATE profile set to the JSON file (called under
// lock, BEFORE the candidate is published — see the mutation model below).
// The write is atomic (temp file + fsync + rename) so a crash mid-write can
// never truncate or corrupt the on-disk registry — Load fails startup on
// corrupt JSON, so a torn write would brick the proxy at next boot.
//
// TRANSACTIONAL MUTATION MODEL (P1-3, shared by Upsert/Delete/ReplaceAll):
//
//	build next candidate profiles → validate → compile next live set
//	    → persist(next) atomically
//	    → ONLY on persist success: publish profiles+live under the lock
//
// A persistence failure therefore leaves the old profiles, old live
// providers, and old credentials fully authoritative — the API reports
// failure and nothing (audit success, cluster snapshot) is emitted for a
// state that does not exist. In deliberate in-memory mode (path == "") the
// warning is kept and the publish proceeds — explicit pre-existing behavior.
func (r *IdPRegistry) persist(profiles []*IdPProfile) error {
	if r.path == "" {
		logger.Printf("IdP: WARNING — profile change is in-memory only and will be LOST on restart; set -idp-profiles-file (or proxy.idp_profiles_file) to persist")
		return nil
	}
	data, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		return fmt.Errorf("%w: %v", errIdPPersistFailed, err)
	}
	if err := atomicWriteFile(r.path, data, 0o600); err != nil {
		return fmt.Errorf("%w: %v", errIdPPersistFailed, err)
	}
	return nil
}

// Persisted reports whether profile changes are written to disk. False means
// the registry is in-memory only (no -idp-profiles-file / idp_profiles_file
// configured) and all profiles are lost on restart.
func (r *IdPRegistry) Persisted() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.path != ""
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

// Upsert adds or replaces a profile and saves to disk.
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
// stored profile must never carry the derived BindCredentialConfigured bit —
// publicIdPProfile recomputes it from the stored credential on every read.
func normalizeIdPProfileWriteInput(p *IdPProfile) {
	if p != nil && p.LDAP != nil {
		p.LDAP.BindCredentialConfigured = false
	}
}

func (r *IdPRegistry) Upsert(p *IdPProfile) error {
	if p.ID == "" {
		b := make([]byte, 6)
		rand.Read(b) //nolint:errcheck // crypto/rand.Read never returns an error on supported platforms
		p.ID = hex.EncodeToString(b)
	}
	normalizeIdPProfileWriteInput(p)
	if err := validateUpsertProfile(p); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	var compiled IdentityProvider
	if p.Enabled {
		prov, err := compileIdPProfile(p)
		if err != nil {
			return fmt.Errorf("idp compile error: %w", err)
		}
		compiled = prov
	}

	// Build the CANDIDATE state on copies — the published slice/map must not
	// be touched until persistence succeeds (P1-3 transactional model).
	nextProfiles := make([]*IdPProfile, len(r.profiles))
	copy(nextProfiles, r.profiles)
	found := false
	for i, existing := range nextProfiles {
		if existing.ID == p.ID {
			nextProfiles[i] = p
			found = true
			break
		}
	}
	if !found {
		nextProfiles = append(nextProfiles, p)
	}
	nextLive := make(map[string]IdentityProvider, len(r.live)+1)
	for id, prov := range r.live {
		nextLive[id] = prov
	}
	if p.Enabled {
		nextLive[p.ID] = compiled
	} else {
		delete(nextLive, p.ID)
	}

	if err := r.persist(nextProfiles); err != nil {
		return err // old profiles + old live providers stay authoritative
	}
	r.profiles, r.live = nextProfiles, nextLive
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

// Delete removes a profile by ID (transactional: persisted before published,
// so a persist failure leaves the profile and its live provider active).
func (r *IdPRegistry) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, p := range r.profiles {
		if p.ID != id {
			continue
		}
		nextProfiles := make([]*IdPProfile, 0, len(r.profiles)-1)
		nextProfiles = append(nextProfiles, r.profiles[:i]...)
		nextProfiles = append(nextProfiles, r.profiles[i+1:]...)
		nextLive := make(map[string]IdentityProvider, len(r.live))
		for lid, prov := range r.live {
			if lid != id {
				nextLive[lid] = prov
			}
		}
		if err := r.persist(nextProfiles); err != nil {
			return err // the profile stays stored AND live
		}
		r.profiles, r.live = nextProfiles, nextLive
		return nil
	}
	return fmt.Errorf("idp %q not found", id)
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

// All returns a copy of all profiles.
func (r *IdPRegistry) All() []*IdPProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneIdPProfiles(r.profiles)
}

// ReplaceAll atomically swaps the registry to match profiles. Enabled
// providers are compiled before the swap so callers never observe a
// half-applied IdP snapshot, and the candidate is PERSISTED before it is
// published (P1-3): a persistence failure rejects the whole replacement and
// the previous set — including on a DP applying a CP snapshot — stays live.
func (r *IdPRegistry) ReplaceAll(profiles []*IdPProfile) error {
	nextProfiles := cloneIdPProfiles(profiles)
	nextLive := make(map[string]IdentityProvider)
	for _, p := range nextProfiles {
		normalizeIdPProfileWriteInput(p)
		if err := validateIdPProfile(p); err != nil {
			return err
		}
		if !p.Enabled {
			continue
		}
		prov, err := compileIdPProfile(p)
		if err != nil {
			return fmt.Errorf("idp %q compile error: %w", p.ID, err)
		}
		nextLive[p.ID] = prov
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.persist(nextProfiles); err != nil {
		return err // the previous profile set + live providers stay authoritative
	}
	r.profiles = nextProfiles
	r.live = nextLive
	return nil
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

// publicIdPProfile returns a response-safe copy. Client secrets and uploaded
// SAML metadata XML are write-only API inputs and must not be exposed through
// viewer/admin read responses.
func publicIdPProfile(p *IdPProfile) *IdPProfile {
	if p == nil {
		return nil
	}
	cp := *p
	cp.EmailDomains = append([]string(nil), p.EmailDomains...)
	cp.KnownGroups = append([]string(nil), p.KnownGroups...)
	if p.OIDC != nil {
		oidc := *p.OIDC
		oidc.Scopes = append([]string(nil), p.OIDC.Scopes...)
		oidc.ClientSecret = ""
		cp.OIDC = &oidc
	}
	if p.SAML != nil {
		saml := *p.SAML
		saml.MetadataXML = ""
		cp.SAML = &saml
	}
	if p.LDAP != nil {
		ldap := *p.LDAP
		// The bind credential is a write-only API input (same containment as
		// the OIDC client secret): blanked in every read/audit projection.
		// Read surfaces expose only the BindCredentialConfigured metadata bit.
		ldap.BindPassword = ""
		ldap.BindCredentialConfigured = p.LDAP.BindPassword != ""
		cp.LDAP = &ldap
	}
	return &cp
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
// Before ADR-0025 this was HasEnabledProviders — correct only while every
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
// consulted by the legacy-YAML shadowing rule (ADR-0025 §authority): when an
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
