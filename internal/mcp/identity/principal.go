// Package identity is the listener-independent MCP principal + resolved-identity
// model for both capabilities (Management and Gateway). It represents the DISTINCT
// principal types, the explicit delegation chain, the immutable resolved identity
// context, and the one-identity-per-protocol-session binding.
//
// It is a pure data engine: it binds no socket, performs no network I/O, and makes
// no allow/deny policy decision (that is PR-6). It receives already-validated
// authentication material (from internal/mcp/authn and internal/mcp/senderconstraint)
// and returns either a validated immutable context or a typed rejection. It never
// holds a raw token — only a one-way sanitized correlation digest.
//
// Deliberately NOT the SWG/browser identity model: there is no browser session
// identity, no client_id-as-audience, no flat human-only principal, no SWG role as
// MCP authorization. The principal types are separate structs, never one generic
// map with optional fields.
package identity

import (
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// TenantID is a stable tenant identifier. Tenant isolation is enforced by exact
// equality across every reference in a resolved context.
type TenantID string

// AssuranceLevel is the subject's authentication-assurance level.
//
// CAUTION (OVN-05). The labels below describe NIST-AAL-style HUMAN authentication
// strength. Culvert cannot currently determine that: no `amr`/`acr` claim is
// parsed anywhere, so no AAL fact exists in the product. What is actually derived
// is the strength of the VERIFIED SENDER BINDING — a DPoP proof shows the
// presenter controls the token's key, not that a person completed MFA.
//
// Express a sender-constraint requirement with the policy fields
// `principal.sender_binding` / `principal.sender_bound`, not with this value, and
// do not "upgrade" the derivation to claim an AAL it cannot observe — see
// docs/design/mcp/OPEN-DECISION-assurance-model.md.
//
// Higher is stronger; the capability config sets the minimum accepted.
type AssuranceLevel uint8

const (
	// AssuranceUnknown — no assurance asserted (rejected where a minimum is required).
	AssuranceUnknown AssuranceLevel = iota
	// AssuranceLow — single-factor / basic.
	AssuranceLow
	// AssuranceMedium — multi-factor.
	AssuranceMedium
	// AssuranceHigh — hardware-backed / phishing-resistant.
	AssuranceHigh
)

// ManagedState is whether an agent runs under managed control.
type ManagedState uint8

const (
	// ManagedUnknown — not asserted.
	ManagedUnknown ManagedState = iota
	// Managed — the agent is centrally managed.
	Managed
	// Unmanaged — the agent is not centrally managed.
	Unmanaged
)

// TrustClass is a supplied risk/trust classification. It is carried, never
// synthesized, and is not itself a policy decision.
type TrustClass uint8

const (
	// TrustUnknown — no classification supplied.
	TrustUnknown TrustClass = iota
	// TrustUntrusted — explicitly untrusted.
	TrustUntrusted
	// TrustLow — low trust.
	TrustLow
	// TrustHigh — high trust.
	TrustHigh
)

// PrincipalKind is the type tag of a principal, used by typed cross-references
// (e.g. an Agent's owner) so a reference can never be mistaken for another type.
type PrincipalKind uint8

const (
	// KindNone — the zero value: no principal.
	KindNone PrincipalKind = iota
	// KindHuman — a human subject.
	KindHuman
	// KindWorkload — a non-human workload/service subject.
	KindWorkload
	// KindAgent — an agent principal.
	KindAgent
	// KindClient — an OAuth client / application.
	KindClient
	// KindTenant — a tenant.
	KindTenant
	// KindServer — a registered MCP server.
	KindServer
	// KindTool — a catalog tool.
	KindTool
	// KindResource — a protected resource.
	KindResource
)

// PrincipalRef is a stable, typed reference to another principal (never a display
// name). An Agent's owner, for example, is a PrincipalRef the chain validates
// against the authenticated subject.
type PrincipalRef struct {
	Kind PrincipalKind
	ID   string
}

// Human is a human subject principal.
type Human struct {
	Subject    string // stable subject identifier (sub)
	Tenant     TenantID
	Groups     []string
	Assurance  AssuranceLevel
	Issuer     string
	SessionRef string // session / delegation reference (never a raw token)
}

// Workload is a non-human workload/service subject principal.
type Workload struct {
	Service     string // stable service identity
	Tenant      TenantID
	Namespace   string
	Environment string
	Attestation string // attestation reference
	Issuer      string
}

// Agent is an agent principal that acts on behalf of a subject.
type Agent struct {
	AgentID string
	Owner   PrincipalRef // MUST reference the authenticated subject
	Version string
	Managed ManagedState
	Trust   TrustClass
}

// Client is an OAuth client / application principal.
type Client struct {
	ClientID   string // OAuth client_id
	AppID      string // application / deployment id
	Tenant     TenantID
	Capability protocol.Capability // MUST match the resolved context capability
	Trust      TrustClass
}

// Tenant is a tenant principal / isolation boundary.
type Tenant struct {
	ID        TenantID
	Isolation string // isolation-boundary identifier
	Residency string // optional residency classification
}

// ResourceRef is a protected-resource principal reference.
type ResourceRef struct {
	Type   string // stable resource type
	ID     string // stable resource identifier
	Tenant TenantID
	Scope  string // bounded scope representation
}

// ToolRef references a catalog tool by its PR-2 key (server + name). Authorization
// by name alone is forbidden; the key binds the tool to a specific server.
type ToolRef struct {
	Server registry.ServerID
	Name   string
}

// cloneSubject returns a deep copy of a Subject: the Human/Workload pointer and the
// Human.Groups slice are copied so the returned value shares no mutable state with
// the input. Used to isolate the resolved context from caller-owned pointers (both
// when resolving and when handing a subject back through an accessor).
func cloneSubject(s Subject) Subject {
	out := Subject{Kind: s.Kind}
	if s.Human != nil {
		h := *s.Human
		if s.Human.Groups != nil {
			h.Groups = append([]string(nil), s.Human.Groups...)
		}
		out.Human = &h
	}
	if s.Workload != nil {
		w := *s.Workload
		out.Workload = &w
	}
	return out
}

// cloneAgent returns a deep copy of an Agent pointer (nil-safe). Agent has only
// value fields, so a shallow struct copy behind a fresh pointer fully isolates it.
func cloneAgent(a *Agent) *Agent {
	if a == nil {
		return nil
	}
	c := *a
	return &c
}

// cloneResource returns a deep copy of a ResourceRef pointer (nil-safe).
func cloneResource(r *ResourceRef) *ResourceRef {
	if r == nil {
		return nil
	}
	c := *r
	return &c
}

// SubjectKind selects which subject a Subject carries.
type SubjectKind uint8

const (
	// SubjectNone — no subject (invalid).
	SubjectNone SubjectKind = iota
	// SubjectHuman — the subject is a Human.
	SubjectHuman
	// SubjectWorkload — the subject is a Workload.
	SubjectWorkload
)

// Subject is the single authenticated subject: exactly one of Human or Workload.
// Modeling it as a tagged union (not two optional fields) makes "both set" and
// "neither set" representable-but-rejected at validation, never silently ignored.
type Subject struct {
	Kind     SubjectKind
	Human    *Human
	Workload *Workload
}

// tenant returns the subject's tenant and issuer.
func (s Subject) tenant() TenantID {
	switch s.Kind {
	case SubjectHuman:
		return s.Human.Tenant
	case SubjectWorkload:
		return s.Workload.Tenant
	default:
		return ""
	}
}

// ref returns the typed reference identifying the subject (for owner-chain checks).
func (s Subject) ref() PrincipalRef {
	switch s.Kind {
	case SubjectHuman:
		return PrincipalRef{Kind: KindHuman, ID: s.Human.Subject}
	case SubjectWorkload:
		return PrincipalRef{Kind: KindWorkload, ID: s.Workload.Service}
	default:
		return PrincipalRef{}
	}
}

// String returns the principal-kind label.
func (k PrincipalKind) String() string {
	switch k {
	case KindHuman:
		return "human"
	case KindWorkload:
		return "workload"
	case KindAgent:
		return "agent"
	case KindClient:
		return "client"
	case KindTenant:
		return "tenant"
	case KindServer:
		return "server"
	case KindTool:
		return "tool"
	case KindResource:
		return "resource"
	default:
		return "none"
	}
}
