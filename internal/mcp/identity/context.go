package identity

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// ConfirmationMethod is the sender-constraint proof method carried in the context.
type ConfirmationMethod uint8

const (
	// ConfirmNone — no sender constraint (bearer).
	ConfirmNone ConfirmationMethod = iota
	// ConfirmDPoP — DPoP proof-of-possession.
	ConfirmDPoP
	// ConfirmMTLS — mutual-TLS certificate binding.
	ConfirmMTLS
)

// SenderConstraint is the sender-constraint state carried into the context. The
// thumbprint is a sanitized public confirmation value (a DPoP jkt or an
// x5t#S256), never key material.
type SenderConstraint struct {
	Method     ConfirmationMethod
	Thumbprint string
}

// ResolveInput is the already-token-validated material the identity layer resolves
// into an immutable context. The authn layer fills it after validating the token
// (signature, issuer, audience, expiry, scopes); the identity layer validates the
// PRINCIPAL CHAIN, tenant consistency, capability isolation, and Gateway
// server/tool resolution. It carries NO raw token — only a sanitized digest.
type ResolveInput struct {
	Capability        protocol.Capability
	Tenant            Tenant
	Subject           Subject
	Agent             *Agent             // optional; if present its owner must be the subject
	Client            Client             // required
	Server            *registry.ServerID // Gateway only
	Tool              *ToolRef           // Gateway only; optional
	Resource          *ResourceRef       // optional protected-resource reference
	CanonicalResource string             // the validated canonical Culvert resource (audience)
	Issuer            string
	Scopes            []string
	Assurance         AssuranceLevel
	SenderConstraint  SenderConstraint
	Expiry            time.Time
	AuthTime          time.Time
	HasAuthTime       bool
	TokenDigest       string // one-way sanitized correlation digest; never a raw token
}

// ResolvedContext is the immutable, validated resolved identity. Fields are
// unexported and read through accessors (slices are copied out) so a consumer can
// neither mutate it nor extract a raw token — there is deliberately no RawToken /
// ForwardToken / AuthorizationHeader accessor.
type ResolvedContext struct {
	capability        protocol.Capability
	tenant            Tenant
	subject           Subject
	agent             *Agent
	client            Client
	server            *registry.ServerID
	tool              *ToolRef
	toolEligibility   catalog.Eligibility
	hasToolElig       bool
	resource          *ResourceRef
	canonicalResource string
	issuer            string
	scopes            []string
	assurance         AssuranceLevel
	sender            SenderConstraint
	expiry            time.Time
	authTime          time.Time
	hasAuthTime       bool
	tokenDigest       string
	fingerprint       string
}

// Capability returns the surface the identity is scoped to.
func (c *ResolvedContext) Capability() protocol.Capability { return c.capability }

// Tenant returns the tenant.
func (c *ResolvedContext) Tenant() Tenant { return c.tenant }

// TenantID returns the tenant id.
func (c *ResolvedContext) TenantID() TenantID { return c.tenant.ID }

// Subject returns the authenticated subject (Human or Workload) as a deep copy, so
// a consumer can never mutate the context's internal principal (which would
// diverge it from its precomputed fingerprint).
func (c *ResolvedContext) Subject() Subject { return cloneSubject(c.subject) }

// Agent returns the agent principal and whether one is present.
func (c *ResolvedContext) Agent() (Agent, bool) {
	if c.agent == nil {
		return Agent{}, false
	}
	return *c.agent, true
}

// Client returns the OAuth client / application principal.
func (c *ResolvedContext) Client() Client { return c.client }

// Server returns the Gateway server id and whether one is present.
func (c *ResolvedContext) Server() (registry.ServerID, bool) {
	if c.server == nil {
		return "", false
	}
	return *c.server, true
}

// Tool returns the tool reference, its carried catalog eligibility, and presence.
// The eligibility is CARRIED for downstream policy (PR-6); PR-3 never turns a
// quarantined/review state into an allow decision.
func (c *ResolvedContext) Tool() (ToolRef, catalog.Eligibility, bool) {
	if c.tool == nil {
		return ToolRef{}, 0, false
	}
	return *c.tool, c.toolEligibility, true
}

// CanonicalResource returns the validated canonical Culvert resource (audience).
func (c *ResolvedContext) CanonicalResource() string { return c.canonicalResource }

// Issuer returns the token issuer.
func (c *ResolvedContext) Issuer() string { return c.issuer }

// Scopes returns a copy of the granted scopes.
func (c *ResolvedContext) Scopes() []string {
	out := make([]string, len(c.scopes))
	copy(out, c.scopes)
	return out
}

// Assurance returns the subject assurance level.
func (c *ResolvedContext) Assurance() AssuranceLevel { return c.assurance }

// SenderConstraint returns the sender-constraint state.
func (c *ResolvedContext) SenderConstraint() SenderConstraint { return c.sender }

// Expiry returns the token expiry.
func (c *ResolvedContext) Expiry() time.Time { return c.expiry }

// AuthTime returns the authentication time and whether it is present.
func (c *ResolvedContext) AuthTime() (time.Time, bool) { return c.authTime, c.hasAuthTime }

// TokenDigest returns the one-way sanitized token correlation digest.
func (c *ResolvedContext) TokenDigest() string { return c.tokenDigest }

// Fingerprint returns the stable identity fingerprint used for binding equality
// (NOT pointer identity or display names).
func (c *ResolvedContext) Fingerprint() string { return c.fingerprint }

func chainInvalid(detail string) error {
	return mcperr.New(mcperr.ReasonDelegationChainInvalid, "identity.resolve", detail)
}

// Resolve validates a ResolveInput into an immutable ResolvedContext, or returns a
// typed rejection. It makes NO allow/deny policy decision; it only proves the
// principal chain, tenant consistency, capability isolation, and Gateway
// server/tool resolution. reg/cat may be nil for Management (which must not
// reference a server/tool).
func Resolve(in ResolveInput, reg *registry.Registry, cat *catalog.Catalog) (*ResolvedContext, error) {
	if err := validateSubject(in.Subject); err != nil {
		return nil, err
	}
	if err := validateTenant(in); err != nil {
		return nil, err
	}
	if in.Client.Capability != in.Capability {
		return nil, mcperr.New(mcperr.ReasonCapabilityMismatch, "identity.resolve", "client capability does not match context capability")
	}
	if in.Agent != nil {
		if in.Agent.Owner != in.Subject.ref() {
			return nil, chainInvalid("agent owner does not reference the authenticated subject")
		}
	}
	// Deep-copy every caller-owned pointer/slice so the context owns private copies:
	// the caller must not be able to mutate the subject/agent/resource (or server/tool,
	// copied in resolveCapabilityRefs) after resolution and silently diverge the
	// identity from its precomputed fingerprint.
	ctx := &ResolvedContext{
		capability: in.Capability, tenant: in.Tenant, subject: cloneSubject(in.Subject),
		agent: cloneAgent(in.Agent), client: in.Client, resource: cloneResource(in.Resource),
		canonicalResource: in.CanonicalResource, issuer: in.Issuer,
		assurance: in.Assurance, sender: in.SenderConstraint,
		expiry: in.Expiry, authTime: in.AuthTime, hasAuthTime: in.HasAuthTime,
		tokenDigest: in.TokenDigest,
	}
	ctx.scopes = append([]string(nil), in.Scopes...)
	if err := resolveCapabilityRefs(in, reg, cat, ctx); err != nil {
		return nil, err
	}
	ctx.fingerprint = computeFingerprint(ctx)
	return ctx, nil
}

func validateSubject(s Subject) error {
	switch s.Kind {
	case SubjectHuman:
		if s.Human == nil || s.Workload != nil {
			return chainInvalid("human subject requires exactly a Human")
		}
		if s.Human.Subject == "" {
			return chainInvalid("human subject is empty")
		}
	case SubjectWorkload:
		if s.Workload == nil || s.Human != nil {
			return chainInvalid("workload subject requires exactly a Workload")
		}
		if s.Workload.Service == "" {
			return chainInvalid("workload service identity is empty")
		}
	default:
		return chainInvalid("no authenticated subject (neither Human nor Workload)")
	}
	return nil
}

func validateTenant(in ResolveInput) error {
	if in.Tenant.ID == "" {
		return mcperr.New(mcperr.ReasonTenantMismatch, "identity.resolve", "tenant id is empty")
	}
	if in.Subject.tenant() != in.Tenant.ID {
		return mcperr.New(mcperr.ReasonTenantMismatch, "identity.resolve", "subject tenant does not match context tenant")
	}
	if in.Client.Tenant != in.Tenant.ID {
		return mcperr.New(mcperr.ReasonTenantMismatch, "identity.resolve", "client tenant does not match context tenant")
	}
	if in.Resource != nil && in.Resource.Tenant != in.Tenant.ID {
		return mcperr.New(mcperr.ReasonTenantMismatch, "identity.resolve", "resource tenant does not match context tenant (cross-tenant reference)")
	}
	return nil
}

// resolveCapabilityRefs enforces the Gateway/Management server-tool split and
// resolves the Gateway server/tool against the live registry/catalog.
func resolveCapabilityRefs(in ResolveInput, reg *registry.Registry, cat *catalog.Catalog, ctx *ResolvedContext) error {
	if in.Capability == protocol.Management {
		if in.Server != nil || in.Tool != nil {
			return chainInvalid("Management context must not carry Gateway server/tool authority")
		}
		return nil
	}
	// Gateway.
	if in.Server == nil {
		return chainInvalid("Gateway context requires a registered server")
	}
	if reg == nil {
		return mcperr.New(mcperr.ReasonRegistryServerUnavailable, "identity.resolve", "no registry available for Gateway resolution")
	}
	srv, ok := reg.Current().Get(*in.Server)
	if !ok || !srv.Usable() {
		return mcperr.New(mcperr.ReasonRegistryServerUnavailable, "identity.resolve", "Gateway server is not registered or not enabled")
	}
	serverCopy := *in.Server
	ctx.server = &serverCopy
	if in.Tool == nil {
		return nil
	}
	if in.Tool.Server != *in.Server {
		return chainInvalid("tool reference does not belong to the selected server")
	}
	if cat == nil {
		return chainInvalid("no catalog available to resolve the tool reference")
	}
	rec, ok := cat.Current().Get(catalog.ToolKey{Server: in.Tool.Server, Name: in.Tool.Name})
	if !ok {
		return chainInvalid("tool reference does not resolve under the selected server")
	}
	// Carry the catalog eligibility (quarantined/review) — never turn it into an
	// allow decision here (PR-6 owns that).
	toolCopy := *in.Tool
	ctx.tool = &toolCopy
	ctx.toolEligibility = rec.Eligibility
	ctx.hasToolElig = true
	return nil
}

// computeFingerprint builds the stable binding fingerprint over the identity-
// defining fields (never pointers or display-only text). Length-prefixed segments
// prevent field-boundary collisions.
func computeFingerprint(c *ResolvedContext) string {
	h := sha256.New()
	seg := func(b string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write([]byte(b))
	}
	seg("cap:" + c.capability.String())
	seg(string(c.tenant.ID))
	h.Write([]byte{byte(c.subject.Kind)})
	seg(c.subject.ref().ID)
	seg(c.client.ClientID)
	if c.agent != nil {
		seg("a:" + c.agent.AgentID)
	} else {
		seg("a:")
	}
	seg(c.canonicalResource)
	if c.server != nil {
		seg("s:" + string(*c.server))
	} else {
		seg("s:")
	}
	if c.tool != nil {
		seg("t:" + string(c.tool.Server) + "/" + c.tool.Name)
	} else {
		seg("t:")
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)
}
