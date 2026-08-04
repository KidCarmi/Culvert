package main

import (
	"net/http"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// PR-UX-5 rollout-scope read model + candidate-scope validation preview.
//
// The scope summary answers "what exact scope is configured?" and "is it
// enumerable / high-risk / percentage-based / exclusion-based?" from the REAL
// rollout.ScopeSpec on the capability's current signed config (never a guess). The
// candidate validator answers "what would a candidate scope change?" by compiling
// the candidate through the SAME pure rollout.Compile the DP would use - it changes
// no state, publishes nothing, and requires no admin role (read-only preview).

// mcpScopeSummary builds the safe, structured summary of a rollout scope spec. It
// compiles the spec (pure) to derive enumerable / matches-nothing / content hash;
// a spec that fails to compile is reported with valid=false and a classified code
// (the current active scope always compiles, so that path is for candidates).
func mcpScopeSummary(spec rollout.ScopeSpec, lim rollout.Limits) map[string]any {
	ops := make([]string, 0, len(spec.Operations))
	for _, o := range spec.Operations {
		ops = append(ops, o.String())
	}
	kind := "enumerated"
	compiled, cerr := rollout.Compile(spec, 0, lim)
	enumerable, matchesNothing, hash, valid := false, true, "", cerr == nil
	if cerr == nil {
		enumerable = compiled.Enumerable()
		matchesNothing = compiled.MatchesNothing()
		hash = compiled.Hash()
	}
	switch {
	case matchesNothing:
		kind = "matches-nothing"
	case spec.Percent > 0 && !enumerable:
		kind = "percentage"
	case spec.Percent > 0 && enumerable:
		kind = "enumerated+percentage"
	case !enumerable:
		kind = "percentage"
	}
	exclusionBased := len(spec.ExcludeTenants)+len(spec.ExcludeServers)+len(spec.ExcludeTools)+len(spec.ExcludePrincipals) > 0
	return map[string]any{
		"valid":           valid,
		"error_code":      scopeErrCode(cerr),
		"hash":            hash,
		"kind":            kind,
		"enumerable":      enumerable,
		"matches_nothing": matchesNothing,
		"high_risk":       spec.HighRisk,
		"exclusion_based": exclusionBased,
		"percent":         spec.Percent,
		"operations":      ops,
		"selector_counts": map[string]int{
			"tenants": len(spec.Tenants), "servers": len(spec.Servers),
			"tool_fingerprints": len(spec.ToolFingerprints), "tools": len(spec.Tools),
			"principals": len(spec.Principals), "agents": len(spec.Agents),
			"clients": len(spec.Clients), "groups": len(spec.Groups),
			"environments": len(spec.Environments),
		},
		"exclusion_counts": map[string]int{
			"tenants": len(spec.ExcludeTenants), "servers": len(spec.ExcludeServers),
			"tools": len(spec.ExcludeTools), "principals": len(spec.ExcludePrincipals),
		},
		// The exact serializable scope selectors (bounded by Compile limits; no secret,
		// token, or raw request/response - only reviewed config identifiers).
		"spec": spec,
	}
}

func scopeErrCode(err error) string {
	if err == nil {
		return ""
	}
	return mcperr.ReasonOf(err).Code()
}

// strSetDelta returns how many entries are added / removed going from -> to.
func strSetDelta(from, to []string) (added, removed int) {
	f := make(map[string]struct{}, len(from))
	for _, v := range from {
		f[v] = struct{}{}
	}
	t := make(map[string]struct{}, len(to))
	for _, v := range to {
		t[v] = struct{}{}
	}
	for v := range t {
		if _, ok := f[v]; !ok {
			added++
		}
	}
	for v := range f {
		if _, ok := t[v]; !ok {
			removed++
		}
	}
	return added, removed
}

func toolSetDelta(from, to []rollout.ToolSel) (added, removed int) {
	f := make(map[rollout.ToolSel]struct{}, len(from))
	for _, v := range from {
		f[v] = struct{}{}
	}
	t := make(map[rollout.ToolSel]struct{}, len(to))
	for _, v := range to {
		t[v] = struct{}{}
	}
	for v := range t {
		if _, ok := f[v]; !ok {
			added++
		}
	}
	for v := range f {
		if _, ok := t[v]; !ok {
			removed++
		}
	}
	return added, removed
}

// mcpScopeDiff summarizes what a candidate scope would change vs the current one:
// per-dimension add/remove counts, percentage, high-risk, enumerable and hash
// transitions. It is pure and read-only.
func mcpScopeDiff(from, to rollout.ScopeSpec, lim rollout.Limits) map[string]any {
	dims := map[string]map[string]int{}
	addDim := func(name string, a, r int) {
		if a != 0 || r != 0 {
			dims[name] = map[string]int{"added": a, "removed": r}
		}
	}
	for _, d := range []struct {
		name     string
		from, to []string
	}{
		{"tenants", from.Tenants, to.Tenants},
		{"servers", from.Servers, to.Servers},
		{"tool_fingerprints", from.ToolFingerprints, to.ToolFingerprints},
		{"principals", from.Principals, to.Principals},
		{"agents", from.Agents, to.Agents},
		{"clients", from.Clients, to.Clients},
		{"groups", from.Groups, to.Groups},
		{"environments", from.Environments, to.Environments},
		{"exclude_tenants", from.ExcludeTenants, to.ExcludeTenants},
		{"exclude_servers", from.ExcludeServers, to.ExcludeServers},
		{"exclude_principals", from.ExcludePrincipals, to.ExcludePrincipals},
	} {
		a, r := strSetDelta(d.from, d.to)
		addDim(d.name, a, r)
	}
	if a, r := toolSetDelta(from.Tools, to.Tools); a != 0 || r != 0 {
		addDim("tools", a, r)
	}
	if a, r := toolSetDelta(from.ExcludeTools, to.ExcludeTools); a != 0 || r != 0 {
		addDim("exclude_tools", a, r)
	}
	fromC, _ := rollout.Compile(from, 0, lim)
	toC, _ := rollout.Compile(to, 0, lim)
	return map[string]any{
		"hash_from":            fromC.Hash(),
		"hash_to":              toC.Hash(),
		"hash_changed":         fromC.Hash() != toC.Hash(),
		"percent_from":         from.Percent,
		"percent_to":           to.Percent,
		"high_risk_from":       from.HighRisk,
		"high_risk_to":         to.HighRisk,
		"enumerable_from":      fromC.Enumerable(),
		"enumerable_to":        toC.Enumerable(),
		"matches_nothing_from": fromC.MatchesNothing(),
		"matches_nothing_to":   toC.MatchesNothing(),
		"dimensions":           dims,
	}
}

// apiMCPRolloutScopeValidate (PR-UX-5) validates a CANDIDATE scope and previews its
// diff against the capability's current active scope. It is a read-only preview:
// viewer-readable, non-mutating, no publication, no audit - it compiles the
// candidate through the SAME pure rollout.Compile the DP uses and returns a
// classified error code when invalid. It NEVER applies the candidate.
func apiMCPRolloutScopeValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		mcpMethodNotAllowed(w)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	capab := mcpRolloutCapability(r)
	var req struct {
		Scope rollout.ScopeSpec `json:"scope"`
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	// Bind the candidate capability to the requested capability (isolation): a
	// candidate can never be validated as, or diffed across, the other capability.
	req.Scope.Capability = capab
	lim := rollout.DefaultLimits()
	st := getMCPRollout().stateFor(capab)
	cur := st.CurrentConfig().Scope
	cur.Capability = capab
	_, cerr := rollout.Compile(req.Scope, st.CurrentConfig().ScopeRevision+1, lim)
	resp := map[string]any{
		"capability": capab.String(),
		"valid":      cerr == nil,
		"error_code": scopeErrCode(cerr),
		"current":    mcpScopeSummary(cur, lim),
		"candidate":  mcpScopeSummary(req.Scope, lim),
	}
	if cerr == nil {
		resp["diff"] = mcpScopeDiff(cur, req.Scope, lim)
	}
	jsonOK(w, resp)
}
