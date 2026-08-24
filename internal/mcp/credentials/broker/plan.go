package broker

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// PlanInput is the trusted, typed input to Plan (phase 1). It carries the PR-3
// resolved identity, the policy-selected profile reference, the operation class,
// and the specific request bindings. It contains NO secret and NO raw client token.
type PlanInput struct {
	Identity     *identity.ResolvedContext // PR-3 immutable resolved identity
	Profile      profile.ID                // policy-selected profile reference (opaque id)
	BaseRevision uint64                    // expected PROFILE revision (Profile.Revision(); 0 ⇒ skip). Compared to the selected profile's own revision, NOT the store snapshot revision, so an unrelated profile change never spuriously rejects.
	Environment  profile.Environment       // deployment environment (must match the profile)
	Operation    profile.OperationClass
	Tool         *profile.ToolBinding // optional tool binding (catalog-resolved)
	Resources    []string             // requested resource selectors (⊆ profile scope)
}

// CredentialPlan is the immutable output of Plan. It contains only non-secret
// planning metadata: it never holds a secret, never triggers a provider call, and
// never decrypts a cache entry.
type CredentialPlan struct {
	planID       string
	profileID    profile.ID
	providerID   profile.ProviderID
	tenant       identity.TenantID
	environment  profile.Environment
	server       registry.ServerID
	tool         *profile.ToolBinding
	toolElig     catalog.Eligibility
	hasToolElig  bool
	resources    profile.ResourceScope
	operation    profile.OperationClass
	risk         profile.RiskClass
	kind         profile.CredentialKind
	powerCeiling profile.CredentialPower
	profileRev   uint64
	deadline     time.Time
	tokenDigest  string // PR-3 one-way correlation digest ONLY
	// principalID / principalKind are the AUTHENTICATED subject's stable id and
	// type, carried so a durable credential event can attribute the materialization
	// to the principal that caused it instead of substituting the plan id. They are
	// non-secret identifiers, never credential material.
	principalID   string
	principalKind string
}

// Accessors (all non-secret).

// PlanID returns the plan field (non-secret).
func (p CredentialPlan) PlanID() string { return p.planID }

// PrincipalID returns the AUTHENTICATED subject's stable id (non-secret). It is
// the plan's attribution anchor: a durable credential event must name the
// principal that caused a materialization, not the plan that describes it.
func (p CredentialPlan) PrincipalID() string { return p.principalID }

// PrincipalKind returns the authenticated subject's type ("human"/"workload"), or
// "" when the identity asserted none. It is never inferred.
func (p CredentialPlan) PrincipalKind() string { return p.principalKind }

// ProfileID returns the plan field (non-secret).
func (p CredentialPlan) ProfileID() profile.ID { return p.profileID }

// ProviderID returns the plan field (non-secret).
func (p CredentialPlan) ProviderID() profile.ProviderID { return p.providerID }

// Tenant returns the plan field (non-secret).
func (p CredentialPlan) Tenant() identity.TenantID { return p.tenant }

// Environment returns the plan field (non-secret).
func (p CredentialPlan) Environment() profile.Environment { return p.environment }

// Server returns the plan field (non-secret).
func (p CredentialPlan) Server() registry.ServerID { return p.server }

// Operation returns the plan field (non-secret).
func (p CredentialPlan) Operation() profile.OperationClass { return p.operation }

// Risk returns the plan field (non-secret).
func (p CredentialPlan) Risk() profile.RiskClass { return p.risk }

// Kind returns the plan field (non-secret).
func (p CredentialPlan) Kind() profile.CredentialKind { return p.kind }

// PowerCeiling returns the plan field (non-secret).
func (p CredentialPlan) PowerCeiling() profile.CredentialPower { return p.powerCeiling }

// ProfileRevision returns the plan field (non-secret).
func (p CredentialPlan) ProfileRevision() uint64 { return p.profileRev }

// Deadline returns the plan field (non-secret).
func (p CredentialPlan) Deadline() time.Time { return p.deadline }

// TokenDigest returns the plan field (non-secret).
func (p CredentialPlan) TokenDigest() string { return p.tokenDigest }

// ToolEligibility returns the carried catalog eligibility and whether a tool is
// bound. PR-4 CARRIES the eligibility (e.g. Quarantined) but never turns it into an
// allow decision — a quarantined tool is not silently made usable.
func (p CredentialPlan) ToolEligibility() (catalog.Eligibility, bool) {
	return p.toolElig, p.hasToolElig
}

// Resources returns a copy of the plan's resource bindings.
func (p CredentialPlan) Resources() profile.ResourceScope { return p.resources }

// scopeBound builds the plan-side bound used to validate provider-returned scope.
func (p CredentialPlan) scopeBound(requireProof bool) profile.ScopeBound {
	var tools []string
	if p.tool != nil {
		tools = []string{p.tool.Name}
	}
	return profile.ScopeBound{
		Tenant: p.tenant, Environment: p.environment, Server: p.server,
		Tools: tools, Resources: p.resources,
		PowerFloor: p.operation.CeilingPower(), PowerCeiling: p.powerCeiling,
		RequireProof: requireProof,
	}
}

func planErr(reason mcperr.Reason, detail string) error {
	return mcperr.New(reason, "credentials.broker.plan", detail)
}

// plan validates a PlanInput against the profile snapshot, the live registry and
// catalog, and the PR-3 identity, returning an immutable CredentialPlan. It is PURE
// with respect to secret material: no provider call, no cache decrypt, no plaintext.
func (b *Broker) plan(in PlanInput, planID string) (CredentialPlan, error) {
	id := in.Identity
	if id == nil {
		return CredentialPlan{}, planErr(mcperr.ReasonDelegationChainInvalid, "nil resolved identity")
	}
	// Capability boundary: the Gateway broker rejects a Management identity context.
	if id.Capability() != protocol.Gateway {
		return CredentialPlan{}, planErr(mcperr.ReasonCapabilityMismatch, "credential broker serves the Gateway capability only")
	}
	if !in.Operation.Valid() {
		return CredentialPlan{}, planErr(mcperr.ReasonCredentialScopeMismatch, "invalid operation class")
	}
	prof, ok := b.profiles.Current().Get(in.Profile)
	if !ok {
		return CredentialPlan{}, planErr(mcperr.ReasonCredentialProfileMissing, "no such profile")
	}
	if !prof.Enabled() {
		return CredentialPlan{}, planErr(mcperr.ReasonCredentialProfileDisabled, "profile is disabled")
	}
	if in.BaseRevision != 0 && in.BaseRevision != prof.Revision() {
		return CredentialPlan{}, planErr(mcperr.ReasonCredentialVersionStale, "plan base revision is stale")
	}
	if _, err := b.checkPlanConsistency(in, prof, id); err != nil {
		return CredentialPlan{}, err
	}
	// Resource binding must be within the profile scope.
	reqScope, err := requestScope(in.Resources, prof.Resources())
	if err != nil {
		return CredentialPlan{}, err
	}
	// Tool binding: must resolve under the server, be within profile tools, and (if
	// the profile pins a fingerprint) match it. The eligibility is CARRIED, never
	// turned into an allow decision.
	plan := CredentialPlan{
		planID: planID, profileID: prof.ID(), providerID: prof.Provider(),
		tenant: prof.Tenant(), environment: prof.Environment(), server: prof.Server(),
		resources: reqScope, operation: in.Operation, risk: in.Operation.Risk(),
		kind: prof.Kind(), powerCeiling: planPowerCeiling(prof, in.Operation),
		profileRev: prof.Revision(), deadline: b.clock().Add(prof.MaxTTL()),
		tokenDigest: id.TokenDigest(),
		principalID: subjectRefID(id), principalKind: subjectKindLabel(id),
	}
	if in.Tool != nil {
		elig, err := b.resolveToolBinding(prof, in.Tool)
		if err != nil {
			return CredentialPlan{}, err
		}
		tb := *in.Tool
		plan.tool = &tb
		plan.toolElig = elig
		plan.hasToolElig = true
	}
	return plan, nil
}

// checkPlanConsistency enforces identity↔profile consistency (tenant, server,
// environment, permitted operation) and that the server is still live. It returns
// the resolved server id.
func (b *Broker) checkPlanConsistency(in PlanInput, prof profile.Profile, id *identity.ResolvedContext) (registry.ServerID, error) {
	if string(id.TenantID()) != string(prof.Tenant()) {
		return "", planErr(mcperr.ReasonTenantMismatch, "identity tenant does not match the profile tenant")
	}
	srv, hasSrv := id.Server()
	if !hasSrv || srv != prof.Server() {
		return "", planErr(mcperr.ReasonCredentialScopeMismatch, "identity server does not match the profile server")
	}
	if in.Environment != prof.Environment() {
		return "", planErr(mcperr.ReasonCredentialScopeMismatch, "request environment does not match the profile environment")
	}
	if !prof.Permits(in.Operation) {
		return "", planErr(mcperr.ReasonCredentialScopeMismatch, "profile does not permit this operation class")
	}
	rec, okReg := b.registry().Get(srv)
	if !okReg || !rec.Usable() {
		return "", planErr(mcperr.ReasonRegistryServerUnavailable, "profile server is not usable")
	}
	return srv, nil
}

// planPowerCeiling is the least-privilege power ceiling for the plan: the lower of
// the profile ceiling and the operation's inherent ceiling. A read plan therefore
// rejects any write-or-higher credential.
func planPowerCeiling(prof profile.Profile, op profile.OperationClass) profile.CredentialPower {
	return profile.MinPower(prof.Power(), op.CeilingPower())
}

// requestScope validates that every requested resource selector is within the
// profile's resource scope and returns an immutable ResourceScope for the request.
func requestScope(requested []string, profScope profile.ResourceScope) (profile.ResourceScope, error) {
	if len(requested) == 0 {
		// Default to the whole profile scope when the request pins none.
		return profScope, nil
	}
	rs, err := profile.NewResourceScope(requested)
	if err != nil {
		return profile.ResourceScope{}, planErr(mcperr.ReasonCredentialScopeMismatch, "malformed requested resource scope")
	}
	if !profile.ScopeSubset(rs, profScope) {
		return profile.ResourceScope{}, planErr(mcperr.ReasonCredentialScopeMismatch, "requested resource is outside the profile scope")
	}
	return rs, nil
}

// resolveToolBinding checks the tool resolves under the server in the catalog and,
// when the profile pins tools or a fingerprint, that it matches. It returns the
// carried eligibility. It never approves a quarantined tool.
func (b *Broker) resolveToolBinding(prof profile.Profile, tb *profile.ToolBinding) (catalog.Eligibility, error) {
	if tb.Server != prof.Server() {
		return 0, planErr(mcperr.ReasonCredentialScopeMismatch, "tool binding names a different server")
	}
	if tools := prof.Tools(); len(tools) > 0 {
		found := false
		for _, t := range tools {
			if t == tb.Name {
				found = true
				break
			}
		}
		if !found {
			return 0, planErr(mcperr.ReasonCredentialScopeMismatch, "tool is not within the profile tool scope")
		}
	}
	if b.catalog() == nil {
		return 0, planErr(mcperr.ReasonCredentialScopeMismatch, "no catalog to resolve the tool binding")
	}
	rec, ok := b.catalog().Get(catalog.ToolKey{Server: tb.Server, Name: tb.Name})
	if !ok {
		return 0, planErr(mcperr.ReasonCredentialScopeMismatch, "tool does not resolve under the server")
	}
	if fp, pinned := prof.Fingerprint(); pinned && rec.Fingerprint != fp {
		return 0, planErr(mcperr.ReasonCredentialScopeMismatch, "tool fingerprint does not match the profile binding")
	}
	return rec.Eligibility, nil
}

// subjectRefID extracts the resolved subject's stable id. It never returns a token
// or any credential material.
func subjectRefID(id *identity.ResolvedContext) string {
	if id == nil {
		return ""
	}
	sub := id.Subject()
	switch sub.Kind {
	case identity.SubjectHuman:
		if sub.Human != nil {
			return sub.Human.Subject
		}
	case identity.SubjectWorkload:
		if sub.Workload != nil {
			return sub.Workload.Service
		}
	}
	return ""
}

// subjectKindLabel maps the resolved subject to its event-model type label. An
// unset kind yields "" — an event must not invent a principal type.
func subjectKindLabel(id *identity.ResolvedContext) string {
	if id == nil {
		return ""
	}
	switch id.Subject().Kind {
	case identity.SubjectHuman:
		return "human"
	case identity.SubjectWorkload:
		return "workload"
	default:
		return ""
	}
}
