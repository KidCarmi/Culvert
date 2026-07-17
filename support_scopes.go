package main

import "sort"

// Incident scopes (M3): a named catalog mapping an incident type to the focused
// set of collectors worth running for it, so an operator can collect for THIS
// incident instead of the full standard bundle. Every scope implicitly includes
// the baseline context collectors so a focused bundle stays interpretable. The
// special scope "standard" applies no filter (every collector runs).
//
// The catalog lives here (package main, where collectors are defined) — the
// engine stays generic and only takes an include-set of collector IDs.

// supportScopeBaseline is always included in any incident scope. It carries
// level-gated collectors too (e.g. the L2 "runtime" host snapshot): the runner
// applies the scope gate before the level gate, so a level-gated collector must be
// a scope candidate here or it can never run in a scoped bundle regardless of the
// requested level — it is still level-gated out below its MinLevel.
var supportScopeBaseline = []string{"product", "health", "readiness", "diagnostics", "crash", "runtime"}

// supportIncidentScopes maps a scope name to its incident-specific collector IDs
// (baseline is unioned in by resolveSupportScope). IDs must exist in the
// collector registry — pinned by TestSupportScopes_ReferenceRealCollectors.
var supportIncidentScopes = map[string][]string{
	"tls":      {"tls", "scan", "logs", "config", "policy"},
	"upstream": {"upstream", "logs", "config", "metrics"},
	"policy":   {"policy", "config", "audit", "logs", "config_versions"},
	"storage":  {"metrics", "config_versions", "governance"},
	"dns":      {"upstream", "logs", "config"},
	"cluster":  {"governance", "config", "config_versions", "cdr"},
	"scan":     {"scan", "cdr", "logs", "config"},
}

// supportScopeNames returns the selectable scope names — "standard" first, then
// the incident scopes sorted — for the status endpoint / panel dropdown.
func supportScopeNames() []string {
	names := make([]string, 0, len(supportIncidentScopes))
	for n := range supportIncidentScopes {
		names = append(names, n)
	}
	sort.Strings(names)
	return append([]string{"standard"}, names...)
}

// resolveSupportScope maps a scope name to the include-set of collector IDs, or
// nil for "standard"/empty (no filter = every collector). ok is false for an
// unknown scope name (the caller rejects it).
func resolveSupportScope(name string) (include map[string]bool, ok bool) {
	if name == "" || name == "standard" {
		return nil, true
	}
	ids, found := supportIncidentScopes[name]
	if !found {
		return nil, false
	}
	include = make(map[string]bool, len(ids)+len(supportScopeBaseline))
	for _, id := range supportScopeBaseline {
		include[id] = true
	}
	for _, id := range ids {
		include[id] = true
	}
	return include, true
}
