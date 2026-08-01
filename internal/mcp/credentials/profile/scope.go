package profile

import (
	"sort"

	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// ResourceScope is the resource dimension of a profile's grant: a set of EXACT
// resource selectors (no wildcards). It is deliberately narrow — server, tool,
// tenant and environment are separate scalar dimensions on the profile itself.
type ResourceScope struct {
	selectors []string // sorted, de-duplicated, exact (validated: no wildcards)
}

// NewResourceScope validates and normalizes exact resource selectors into an
// immutable ResourceScope. It rejects an empty set and any unsafe wildcard.
func NewResourceScope(selectors []string) (ResourceScope, error) {
	if len(selectors) == 0 {
		return ResourceScope{}, scopeErr("resource scope is empty")
	}
	seen := make(map[string]struct{}, len(selectors))
	out := make([]string, 0, len(selectors))
	for _, s := range selectors {
		if hasUnsafeWildcard(s) {
			return ResourceScope{}, scopeErr("resource selector is empty, wildcard or malformed")
		}
		if len(s) > maxIDBytes {
			return ResourceScope{}, scopeErr("resource selector exceeds the maximum length")
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return ResourceScope{selectors: out}, nil
}

// Selectors returns a copy of the exact resource selectors.
func (r ResourceScope) Selectors() []string {
	return append([]string(nil), r.selectors...)
}

// Len returns the selector count.
func (r ResourceScope) Len() int { return len(r.selectors) }

// clone deep-copies the scope so no caller alias can mutate stored state.
func (r ResourceScope) clone() ResourceScope {
	return ResourceScope{selectors: append([]string(nil), r.selectors...)}
}

// contains reports whether sel is an exact permitted selector.
func (r ResourceScope) contains(sel string) bool {
	// selectors is sorted; binary search.
	i := sort.SearchStrings(r.selectors, sel)
	return i < len(r.selectors) && r.selectors[i] == sel
}

// subsetOf reports whether every selector in r is permitted by other (r ⊆ other).
func (r ResourceScope) subsetOf(other ResourceScope) bool {
	for _, s := range r.selectors {
		if !other.contains(s) {
			return false
		}
	}
	return true
}

func scopeErr(detail string) error {
	return mcperr.New(mcperr.ReasonCredentialScopeMismatch, "credentials.profile", detail)
}

// ScopeSubset reports whether every selector in a is permitted by b (a ⊆ b). It is
// the exported form of the subset check used by the broker when validating a
// requested resource scope against the profile scope.
func ScopeSubset(a, b ResourceScope) bool { return a.subsetOf(b) }

// ToolBinding references a catalog tool by its PR-2 key (server + name). A binding
// is authorized only via this exact key, never by name alone.
type ToolBinding struct {
	Server registry.ServerID
	Name   string
}

// EffectiveScope is the scope + power a PROVIDER reports for the material it
// returned. The broker validates it against the plan (never broadening): tenant,
// environment, server, tools and resources must all be within the plan, and the
// power must not exceed the plan's power ceiling.
type EffectiveScope struct {
	Tenant      identity.TenantID
	Environment Environment
	Server      registry.ServerID
	Tools       []string // tool names the credential is scoped to (subset of the plan's)
	Resources   ResourceScope
	Power       CredentialPower
	// HasScopeProof reports whether the provider supplied effective-scope metadata.
	// A profile that requires proof rejects material lacking it.
	HasScopeProof bool
}

// ScopeBound is the plan-side bound the effective scope is checked against. The
// broker builds it from the immutable plan (never from the provider). The credential
// power must be exactly within [PowerFloor, PowerCeiling]: at least the floor (a
// read-only credential is NOT suitable for a write operation) and at most the ceiling
// (a credential must not be more powerful than the operation needs).
type ScopeBound struct {
	Tenant       identity.TenantID
	Environment  Environment
	Server       registry.ServerID
	Tools        []string // permitted tool names ("" ⇒ any tool under the plan's server is allowed)
	Resources    ResourceScope
	PowerFloor   CredentialPower // least power required by the operation
	PowerCeiling CredentialPower // most power the operation permits
	RequireProof bool
}

// ValidateEffectiveScope verifies that eff does not exceed bound. It returns a
// stable sanitized reason on any broadening. It NEVER makes a policy decision;
// it only proves the provider's material is within the already-selected plan.
func ValidateEffectiveScope(eff EffectiveScope, bound ScopeBound) error {
	if bound.RequireProof && !eff.HasScopeProof {
		return scopeErr("provider returned no effective-scope proof but the profile requires it")
	}
	if eff.Tenant != bound.Tenant {
		return scopeErr("credential tenant scope does not match the plan tenant")
	}
	if eff.Environment != bound.Environment {
		return scopeErr("credential environment scope does not match the plan environment")
	}
	if eff.Server != bound.Server {
		return scopeErr("credential server scope does not match the plan server")
	}
	// Power window: the credential must be at least the floor (a read-only credential
	// is not suitable for a write/admin/destructive operation) and at most the ceiling
	// (not more powerful than the operation needs).
	if !eff.Power.Valid() {
		return scopeErr("credential effective power is unset/invalid")
	}
	if bound.PowerFloor != PowerUnset && eff.Power < bound.PowerFloor {
		return scopeErr("credential effective power is insufficient for the operation")
	}
	if eff.Power > bound.PowerCeiling {
		return mcperr.New(mcperr.ReasonCredentialPowerExceeded, "credentials.profile", "credential effective power exceeds the plan ceiling")
	}
	// Tools: when the plan pins specific tools, the credential's tools must be a
	// subset. When the plan pins none, any tool under the plan's server is allowed,
	// but the credential must still not name a tool outside an explicit plan set.
	if len(bound.Tools) > 0 {
		permitted := make(map[string]struct{}, len(bound.Tools))
		for _, t := range bound.Tools {
			permitted[t] = struct{}{}
		}
		for _, t := range eff.Tools {
			if _, ok := permitted[t]; !ok {
				return scopeErr("credential tool scope is broader than the plan")
			}
		}
	}
	// Resources: effective resources must be a subset of the plan's.
	if !eff.Resources.subsetOf(bound.Resources) {
		return scopeErr("credential resource scope is broader than the plan")
	}
	return nil
}
