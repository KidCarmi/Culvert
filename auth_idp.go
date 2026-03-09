package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
)

// IdPProfile is the persistent configuration for one identity provider.
// Profiles are stored in a JSON file (idp_profiles.json) and managed
// at runtime via the admin UI without requiring a proxy restart.
type IdPProfile struct {
	ID           string   `json:"id"`           // generated UUID slug
	Name         string   `json:"name"`         // human-readable label
	Type         IdPType  `json:"type"`         // "oidc" | "saml"
	EmailDomains []string `json:"emailDomains"` // routing hints, e.g. ["corp.com"]
	Enabled      bool     `json:"enabled"`

	// Only one of OIDC/SAML is populated depending on Type.
	OIDC *OIDCProfileConfig `json:"oidc,omitempty"`
	SAML *SAMLProfileConfig `json:"saml,omitempty"`
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
	r.path = path
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

// save persists current profiles to the JSON file (must be called under lock).
func (r *IdPRegistry) save() error {
	if r.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(r.profiles, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.path, data, 0o600)
}

// compile initialises a live IdentityProvider from a profile.
// Calling under r.mu.Lock is the caller's responsibility.
func (r *IdPRegistry) compile(p *IdPProfile) error {
	switch p.Type {
	case IdPTypeOIDC:
		if p.OIDC == nil {
			return fmt.Errorf("oidc profile missing oidc config")
		}
		prov, err := NewOIDCFlowProvider(p)
		if err != nil {
			return err
		}
		r.live[p.ID] = prov
	case IdPTypeSAML:
		if p.SAML == nil {
			return fmt.Errorf("saml profile missing saml config")
		}
		prov, err := NewSAMLProvider(p)
		if err != nil {
			return err
		}
		r.live[p.ID] = prov
	default:
		return fmt.Errorf("unknown IdP type %q", p.Type)
	}
	return nil
}

// Upsert adds or replaces a profile and saves to disk.
func (r *IdPRegistry) Upsert(p *IdPProfile) error {
	if p.ID == "" {
		b := make([]byte, 6)
		rand.Read(b) //nolint:errcheck
		p.ID = hex.EncodeToString(b)
	}
	// Validate.
	if p.Name == "" {
		return fmt.Errorf("idp: name is required")
	}
	if p.Type != IdPTypeOIDC && p.Type != IdPTypeSAML {
		return fmt.Errorf("idp: type must be 'oidc' or 'saml'")
	}
	// Security: validate issuer/metadata URLs before compiling.
	if p.Type == IdPTypeOIDC && p.OIDC != nil {
		if err := validateExternalURL(p.OIDC.Issuer); err != nil {
			return fmt.Errorf("idp oidc issuer: %w", err)
		}
	}
	if p.Type == IdPTypeSAML && p.SAML != nil && p.SAML.MetadataURL != "" {
		if err := validateExternalURL(p.SAML.MetadataURL); err != nil {
			return fmt.Errorf("idp saml metadata_url: %w", err)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Replace or append.
	found := false
	for i, existing := range r.profiles {
		if existing.ID == p.ID {
			r.profiles[i] = p
			found = true
			break
		}
	}
	if !found {
		r.profiles = append(r.profiles, p)
	}

	// Recompile live provider if enabled.
	if p.Enabled {
		if err := r.compile(p); err != nil {
			return fmt.Errorf("idp compile error: %w", err)
		}
	} else {
		delete(r.live, p.ID)
	}

	return r.save()
}

// Delete removes a profile by ID.
func (r *IdPRegistry) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, p := range r.profiles {
		if p.ID == id {
			r.profiles = append(r.profiles[:i], r.profiles[i+1:]...)
			delete(r.live, id)
			return r.save()
		}
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
	out := make([]*IdPProfile, len(r.profiles))
	copy(out, r.profiles)
	return out
}

// RouteByDomain returns the first enabled live provider whose EmailDomains
// list contains domain (case-insensitive).  Returns nil if none match.
func (r *IdPRegistry) RouteByDomain(domain string) IdentityProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.profiles {
		if !p.Enabled {
			continue
		}
		for _, d := range p.EmailDomains {
			if stringsEqualFold(d, domain) {
				if prov, ok := r.live[p.ID]; ok {
					return prov
				}
			}
		}
	}
	return nil
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
