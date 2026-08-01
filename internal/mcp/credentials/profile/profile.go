package profile

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

func policyErr(detail string) error {
	return mcperr.New(mcperr.ReasonCredentialProfileMissing, "credentials.profile", detail)
}

// Profile is one immutable credential profile. All fields are unexported and read
// through accessors; slices/maps are copied out so no caller alias can mutate live
// state. A Profile NEVER contains credential plaintext.
type Profile struct {
	id          ID
	provider    ProviderID
	tenant      identity.TenantID
	environment Environment
	server      registry.ServerID
	tools       []string             // exact permitted tool names (empty ⇒ any tool under the server)
	fingerprint *catalog.Fingerprint // optional exact catalog fingerprint binding
	resources   ResourceScope
	operations  map[OperationClass]struct{}
	kind        CredentialKind
	power       CredentialPower // the profile's power ceiling
	maxTTL      time.Duration
	cache       CachePolicy
	rotation    RotationPolicy
	failure     FailurePolicy
	enabled     bool
	revision    uint64
}

// Input is the caller-supplied trusted configuration for a profile.
type Input struct {
	ID          ID
	Provider    ProviderID
	Tenant      identity.TenantID
	Environment Environment
	Server      registry.ServerID
	Tools       []string
	Fingerprint *catalog.Fingerprint
	Resources   ResourceScope
	Operations  []OperationClass
	Kind        CredentialKind
	Power       CredentialPower
	MaxTTL      time.Duration
	Cache       CachePolicy
	Rotation    RotationPolicy
	Failure     FailurePolicy
	Enabled     bool
}

// NewProfile validates in against the live registry snapshot and the credential
// limits, returning an immutable Profile at the given revision or a stable
// sanitized rejection. reg must be the CURRENT registry snapshot: the bound server
// must exist, be Gateway capability (never Management), be usable (enabled +
// verified), and — when it carries an owner scope — be owned by the profile's
// tenant (no cross-tenant server ownership).
func NewProfile(in Input, reg *registry.Snapshot, lim limits.CredentialLimits, revision uint64) (Profile, error) {
	if err := validateProfileScalars(in, lim); err != nil {
		return Profile{}, err
	}
	ops, err := validateOperations(in.Operations, in.Power)
	if err != nil {
		return Profile{}, err
	}
	if err := validateTools(in.Tools); err != nil {
		return Profile{}, err
	}
	if err := validatePolicies(in.Cache, in.Rotation, in.Failure, in.MaxTTL, lim.RotationGrace(), lim.MaxCacheFreshness()); err != nil {
		return Profile{}, err
	}
	if err := validateServerBinding(in, reg); err != nil {
		return Profile{}, err
	}
	if in.Fingerprint != nil && in.Fingerprint.Server != in.Server {
		return Profile{}, scopeErr("catalog fingerprint binding names a different server")
	}

	p := Profile{
		id: in.ID, provider: in.Provider, tenant: in.Tenant, environment: in.Environment,
		server: in.Server, tools: append([]string(nil), in.Tools...),
		resources: in.Resources.clone(), operations: ops, kind: in.Kind, power: in.Power,
		maxTTL: in.MaxTTL, cache: in.Cache, rotation: in.Rotation, failure: in.Failure,
		enabled: in.Enabled, revision: revision,
	}
	if in.Fingerprint != nil {
		fp := *in.Fingerprint
		p.fingerprint = &fp
	}
	return p, nil
}

// validateProfileScalars checks the scalar/identifier fields and TTL bound.
func validateProfileScalars(in Input, lim limits.CredentialLimits) error {
	if err := validID("profile id", string(in.ID)); err != nil {
		return err
	}
	if err := validID("provider id", string(in.Provider)); err != nil {
		return err
	}
	if in.Tenant == "" {
		return mcperr.New(mcperr.ReasonTenantMismatch, "credentials.profile", "profile tenant is empty")
	}
	if in.Environment == "" {
		return policyErr("profile environment is empty")
	}
	if in.Server == "" {
		return mcperr.New(mcperr.ReasonRegistryServerUnavailable, "credentials.profile", "profile server is empty")
	}
	if !in.Kind.Valid() {
		return mcperr.New(mcperr.ReasonCredentialKindUnsupported, "credentials.profile", "credential kind is unset/invalid")
	}
	if !in.Power.Valid() {
		return policyErr("credential power ceiling is unset/invalid")
	}
	if in.Resources.Len() == 0 {
		return scopeErr("profile resource scope is empty")
	}
	if len(in.Operations) == 0 {
		return policyErr("profile permits no operation class")
	}
	if in.MaxTTL <= 0 {
		return policyErr("profile max lease TTL must be positive")
	}
	if in.MaxTTL > lim.MaxCredentialTTL() {
		return policyErr("profile max lease TTL exceeds the configured maximum")
	}
	return nil
}

// validateServerBinding enforces the registry-owned server constraints.
func validateServerBinding(in Input, reg *registry.Snapshot) error {
	if reg == nil {
		return mcperr.New(mcperr.ReasonRegistryServerUnavailable, "credentials.profile", "no registry snapshot for server validation")
	}
	rec, ok := reg.Get(in.Server)
	if !ok {
		return mcperr.New(mcperr.ReasonRegistryServerUnavailable, "credentials.profile", "profile server is not registered")
	}
	if rec.Capability != protocol.Gateway {
		return mcperr.New(mcperr.ReasonCapabilityMismatch, "credentials.profile", "profile server is not a Gateway-capability server (Management not permitted)")
	}
	if !rec.Usable() {
		return mcperr.New(mcperr.ReasonRegistryServerUnavailable, "credentials.profile", "profile server is disabled or not verified")
	}
	// Cross-tenant server ownership: a server that declares an owner scope must be
	// owned by the profile's tenant.
	if rec.OwnerScope != "" && string(rec.OwnerScope) != string(in.Tenant) {
		return mcperr.New(mcperr.ReasonTenantMismatch, "credentials.profile", "profile server is owned by a different tenant")
	}
	return nil
}

// validateOperations de-duplicates the operation set and rejects an operation
// whose least-privilege power ceiling exceeds the profile's declared power ceiling
// (a profile must be able to satisfy every operation it permits).
func validateOperations(ops []OperationClass, ceiling CredentialPower) (map[OperationClass]struct{}, error) {
	set := make(map[OperationClass]struct{}, len(ops))
	for _, o := range ops {
		if !o.Valid() {
			return nil, policyErr("profile permits an unset/invalid operation class")
		}
		if o.CeilingPower() > ceiling {
			return nil, mcperr.New(mcperr.ReasonCredentialPowerExceeded, "credentials.profile", "profile permits an operation requiring more power than its ceiling")
		}
		set[o] = struct{}{}
	}
	return set, nil
}

// validateTools rejects unsafe wildcard / malformed tool selectors. An empty tool
// set is allowed (the profile is scoped to the whole server).
func validateTools(tools []string) error {
	for _, t := range tools {
		if hasUnsafeWildcard(t) {
			return scopeErr("tool selector is empty, wildcard or malformed")
		}
		if len(t) > maxIDBytes {
			return scopeErr("tool selector exceeds the maximum length")
		}
	}
	return nil
}

// ── Accessors (immutable; slices/maps copied out) ──────────────────────────

// ID returns the profile field.
func (p Profile) ID() ID { return p.id }

// Provider returns the profile field.
func (p Profile) Provider() ProviderID { return p.provider }

// Tenant returns the profile field.
func (p Profile) Tenant() identity.TenantID { return p.tenant }

// Environment returns the profile field.
func (p Profile) Environment() Environment { return p.environment }

// Server returns the profile field.
func (p Profile) Server() registry.ServerID { return p.server }

// Kind returns the profile field.
func (p Profile) Kind() CredentialKind { return p.kind }

// Power returns the profile field.
func (p Profile) Power() CredentialPower { return p.power }

// MaxTTL returns the profile field.
func (p Profile) MaxTTL() time.Duration { return p.maxTTL }

// Cache returns the profile field.
func (p Profile) Cache() CachePolicy { return p.cache }

// Rotation returns the profile field.
func (p Profile) Rotation() RotationPolicy { return p.rotation }

// Failure returns the profile field.
func (p Profile) Failure() FailurePolicy { return p.failure }

// Enabled returns the profile field.
func (p Profile) Enabled() bool { return p.enabled }

// Revision returns the profile field.
func (p Profile) Revision() uint64 { return p.revision }

// Resources returns the profile field.
func (p Profile) Resources() ResourceScope { return p.resources.clone() }

// Tools returns a copy of the permitted tool names (empty ⇒ whole-server scope).
func (p Profile) Tools() []string { return append([]string(nil), p.tools...) }

// Fingerprint returns a copy of the optional catalog fingerprint binding.
func (p Profile) Fingerprint() (catalog.Fingerprint, bool) {
	if p.fingerprint == nil {
		return catalog.Fingerprint{}, false
	}
	return *p.fingerprint, true
}

// Permits reports whether the profile permits the operation class.
func (p Profile) Permits(op OperationClass) bool {
	_, ok := p.operations[op]
	return ok
}

// Operations returns a copy of the permitted operation classes.
func (p Profile) Operations() []OperationClass {
	out := make([]OperationClass, 0, len(p.operations))
	for o := range p.operations {
		out = append(out, o)
	}
	return out
}

// withRevision returns a copy of the profile stamped at a new revision (used by the
// store on publication). Enabled state may also be toggled via withEnabled.
func (p Profile) withRevision(rev uint64) Profile { p.revision = rev; return p }

// withEnabled returns the profile field.
func (p Profile) withEnabled(enabled bool) Profile { p.enabled = enabled; return p }
