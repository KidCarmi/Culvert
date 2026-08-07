package runtime

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// wellKnownProtectedResourcePrefix is the RFC 9728 well-known path prefix under
// which a protected resource publishes its own metadata. The resource-specific
// document is served at this prefix followed by the resource's path component.
const wellKnownProtectedResourcePrefix = "/.well-known/oauth-protected-resource"

// ProtectedResourceMetadata is the bounded, PUBLIC OAuth 2.0 Protected Resource
// Metadata (RFC 9728) a capability listener publishes so a Model-A client can
// discover the authorization server(s) and the exact canonical resource it must
// request a token audience for. It carries ONLY public, non-secret configuration
// — never a tenant id, a token, a key, a certificate, or any credential material.
//
// Every value is precomputed by the composition root (package main) from the
// authoritative startup config: the runtime package parses no URL and trusts no
// request Host header when building the document or the challenge, so a
// host-header-confusion attempt can never influence the advertised resource or
// metadata URL.
type ProtectedResourceMetadata struct {
	// Resource is the exact canonical resource identifier a client must request a
	// token audience for (identical to the capability's CapabilityAuthConfig
	// CanonicalResource — the audience validator enforces the same string).
	Resource string
	// AuthorizationServers are the issuer identifiers (URLs) whose tokens this
	// resource accepts.
	AuthorizationServers []string
	// WellKnownPath is the exact request path this listener serves the document at
	// (e.g. "/.well-known/oauth-protected-resource/mcp/gateway").
	WellKnownPath string
	// MetadataURL is the absolute URL of WellKnownPath, advertised verbatim in the
	// WWW-Authenticate challenge's resource_metadata parameter.
	MetadataURL string
	// ResourceName is an optional human-readable label (safe, non-secret).
	ResourceName string
}

// NewProtectedResourceMetadata builds the published metadata from a canonical
// resource identifier (which MUST be an absolute https URL — the exact token
// audience) and the authorization-server issuer URLs. It derives the RFC 9728
// well-known request path and absolute metadata URL from the resource: for a
// resource "https://host/mcp/gateway" the document is served at
// "https://host/.well-known/oauth-protected-resource/mcp/gateway". It parses the
// operator-supplied resource once at construction (never a request Host header),
// and returns an error for a non-absolute or non-https resource so a misconfigured
// audience fails activation closed rather than publishing a confusing document.
func NewProtectedResourceMetadata(canonicalResource string, authServers []string, resourceName string) (*ProtectedResourceMetadata, error) {
	u, err := url.Parse(canonicalResource)
	if err != nil {
		return nil, fmt.Errorf("canonical resource is not a valid URL")
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("canonical resource must be an absolute https URL")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("canonical resource has no host")
	}
	// Normalize the audience to the scheme://host[/path] form the validator expects,
	// dropping any query/fragment (an audience never carries them).
	resPath := strings.TrimRight(u.EscapedPath(), "/")
	resource := u.Scheme + "://" + u.Host + resPath
	wellKnownPath := wellKnownProtectedResourcePrefix + resPath
	metadataURL := u.Scheme + "://" + u.Host + wellKnownPath
	return &ProtectedResourceMetadata{
		Resource:             resource,
		AuthorizationServers: append([]string(nil), authServers...),
		WellKnownPath:        wellKnownPath,
		MetadataURL:          metadataURL,
		ResourceName:         resourceName,
	}, nil
}

// prMetadataDoc is the exact wire shape of the published document (RFC 9728 §2).
type prMetadataDoc struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name,omitempty"`
}

// documentJSON renders the bounded public metadata document. Bearer methods are
// fixed to "header" — a query-string or body credential is a forbidden location
// on this listener (parseCredential rejects it), so it is never advertised.
func (m *ProtectedResourceMetadata) documentJSON() []byte {
	doc := prMetadataDoc{
		Resource:               m.Resource,
		AuthorizationServers:   m.AuthorizationServers,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           m.ResourceName,
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return []byte(`{}`) // fixed-shape struct; marshal cannot realistically fail
	}
	return b
}

// challenge returns the WWW-Authenticate value advertised on a 401. It points a
// client at the metadata document (RFC 9728 §5.1) without leaking any request,
// tenant, or credential data. A nil/empty metadata yields "" (no header emitted).
func (m *ProtectedResourceMetadata) challenge() string {
	if m == nil || m.MetadataURL == "" {
		return ""
	}
	// The URL is operator-configured and controlled; still strip any double-quote
	// so a malformed value can never break the header's quoted-string framing.
	safe := strings.ReplaceAll(m.MetadataURL, `"`, "")
	return `Bearer resource_metadata="` + safe + `"`
}

// servesWellKnown reports whether a GET path targets this listener's protected
// resource metadata document. It matches the exact resource-specific path and the
// bare well-known prefix (a client may probe either).
func (m *ProtectedResourceMetadata) servesWellKnown(path string) bool {
	if m == nil {
		return false
	}
	return path == m.WellKnownPath || path == wellKnownProtectedResourcePrefix
}
