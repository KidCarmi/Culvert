//go:build policy_conformance

// Package policyref is an INDEPENDENT reference model of Culvert's Stage-2 access
// policy decision, used only by the shadow differential test
// (policy_reference_conformance_test.go at the module root). It is not a production
// package: every file carries the build tag `policy_conformance`, nothing in the product
// imports it, and a plain `go build ./...` / `go test ./...` never compiles it.
//
// Independence: it imports the standard library only — never the product, never
// internal/hostutil, internal/urlcat or internal/catgroup — and is written from the
// clauses below, not by transcribing policy.go. TestIndependence enforces the import
// rule. Where a clause's source does not settle a case, the model says so
// (Specified=false) instead of guessing; the differential test reports what the product
// does there as an OPEN contract question and never asserts it.
//
// Scope (v1): access rules only; source IP/CIDR, identity, group, auth source;
// destination FQDN, category and category group; enable flag; rule type; priority;
// default action at startup. NOT modelled: schedules (time), destination country
// (geo cache), IDNA/punycode beyond ASCII case and trailing dot, the community
// category DB and the signed-feed view, SSL/file/redirect side fields.
//
// Specification clauses (source in brackets):
//
//	R1  Rules are considered in ascending Priority; the first rule whose every
//	    configured condition holds decides. [POL-001; ADR-0026]
//	R2  Two enabled rules with the same Priority: order UNSPECIFIED. [POL-001 says
//	    "priority order"; nothing orders ties]
//	R3  A rule with Enabled unset or true is active; Enabled=false is skipped. [rule
//	    schema: absent field keeps pre-existing rules active]
//	R4  Only access rules decide: type "" or "access". Any other type ("auth") is
//	    inert in this stage. [ADR-0026; two-stage policy design]
//	R5  An empty condition field means "any"; configured conditions are ANDed.
//	R6  SourceIP: a CIDR matches a client address inside it; a single address matches
//	    the same address in any spelling (IPv4-mapped IPv6 equals its IPv4 form). An
//	    unparseable or zoned client address matches no source-scoped rule. A rule
//	    SourceIP that is neither a CIDR nor an address: UNSPECIFIED (writes validate it).
//	R7  SourceIdentity: case-insensitive equality.
//	R8  SourceGroup: case-insensitive equality with ANY of the request's groups, both
//	    sides trimmed of surrounding space.
//	R9  AuthSource: case-insensitive equality; additionally a bare provider name and
//	    the same name with an "oidc:"/"saml:"/"ldap:" scheme refer to one provider,
//	    but two DIFFERENT explicit schemes never alias. [cross-IdP confusion guard]
//	R10 Host canonical form: ASCII lower case, one trailing dot removed; an IP literal
//	    (optionally bracketed) is compared by address, IPv4-mapped folded to IPv4.
//	R11 DestFQDN, after the same canonicalisation: "*" matches every host; "*.d"
//	    matches d and every subdomain of d; a bare "d" ALSO matches d and every
//	    subdomain (label boundary required: "d" never matches "xd"). No other
//	    wildcard. [admin docs: Palo Alto-style domain match]
//	R12 DestCategory: empty or the wire sentinel "Any" (the value the admin UI writes)
//	    means unset; otherwise the host must be a MEMBER of the category
//	    (case-insensitive name): some pattern p of the category equals the host or is
//	    a parent domain of it. Another casing of the sentinel ("any", "ANY"):
//	    UNSPECIFIED -- is it "unset" or a category nobody belongs to?
//	R13 DestCategoryGroup: the host must be a member of ANY category of the group; a
//	    group that does not exist matches nothing (fail closed). [owner decision in
//	    categorygroup_membership_test.go: membership, same as R12]
//	R14 No rule decides -> the default action.
//	R15 Startup default action: an explicit "allow" or "deny" wins. Empty: "allow"
//	    when no rules are configured, "deny" otherwise. [POL-002; errata] Any other
//	    explicit spelling ("Allow", "block"): UNSPECIFIED.
package policyref

import (
	"net/netip"
	"sort"
	"strings"
)

// Rule is the modelled subset of a policy rule.
type Rule struct {
	Name           string
	Priority       int
	Enabled        *bool
	Type           string
	Action         string
	SourceIP       string
	SourceIdentity string
	SourceGroup    string
	AuthSource     string
	DestFQDN       string
	DestCategory   string
	DestGroupID    string
}

// Env is the category environment: category name -> host patterns, group id ->
// category names.
type Env struct {
	Categories map[string][]string
	Groups     map[string][]string
}

// Request is one access decision input.
type Request struct {
	ClientIP   string
	Identity   string
	AuthSource string
	Host       string
	Groups     []string
}

// Outcome is the model's answer. Rule is the deciding rule's Name, or "" for the default.
// Specified=false means the clauses do not settle this input; Why names the clause.
type Outcome struct {
	Rule      string
	Specified bool
	Why       string
}

// Evaluate applies R1-R14 and returns the deciding rule, or "" when the default decides.
func Evaluate(rules []Rule, env Env, req Request) Outcome {
	active := make([]Rule, 0, len(rules))
	for i := range rules {
		if (rules[i].Enabled == nil || *rules[i].Enabled) && (rules[i].Type == "" || rules[i].Type == "access") {
			active = append(active, rules[i]) // R3, R4
		}
	}
	sort.SliceStable(active, func(i, j int) bool { return active[i].Priority < active[j].Priority })
	host := canonicalHost(req.Host)
	for i := range active {
		r := &active[i]
		ok, why := matches(r, env, req, host)
		if why != "" {
			return Outcome{Specified: false, Why: why + " (" + r.Name + ")"}
		}
		if !ok {
			continue
		}
		// R2: a tie with a later active rule that would ALSO match makes the winner unspecified.
		for j := i + 1; j < len(active) && active[j].Priority == r.Priority; j++ {
			if ok2, _ := matches(&active[j], env, req, host); ok2 {
				return Outcome{Specified: false, Why: "R2: tied priority between matching rules " + r.Name + " and " + active[j].Name}
			}
		}
		return Outcome{Rule: r.Name, Specified: true}
	}
	return Outcome{Specified: true} // R14
}

// matches reports whether every configured condition of r holds (R5). A non-empty why
// names the clause that leaves this rule's verdict unspecified for this request.
// Conditions are checked in clause order and an unspecified one is reported only if no
// earlier condition already excluded the rule.
func matches(r *Rule, env Env, req Request, host string) (ok bool, why string) {
	if ok, why = sourceMatches(r, req); !ok || why != "" {
		return ok, why
	}
	return destMatches(r, env, host)
}

// sourceMatches applies R6-R9.
func sourceMatches(r *Rule, req Request) (ok bool, why string) {
	if r.SourceIP != "" {
		hit, spec := sourceIPMatches(r.SourceIP, req.ClientIP)
		if !spec {
			return false, "R6: rule SourceIP is neither a CIDR nor an address"
		}
		if !hit {
			return false, ""
		}
	}
	return (r.SourceIdentity == "" || strings.EqualFold(r.SourceIdentity, req.Identity)) && // R7
		(r.SourceGroup == "" || inGroups(r.SourceGroup, req.Groups)) && // R8
		(r.AuthSource == "" || sameProvider(r.AuthSource, req.AuthSource)), "" // R9
}

// destMatches applies R11-R13.
func destMatches(r *Rule, env Env, host string) (ok bool, why string) {
	if r.DestFQDN != "" && !fqdnMatches(canonicalHost(r.DestFQDN), host) { // R11
		return false, ""
	}
	if c := r.DestCategory; c != "" && c != "Any" { // R12
		if strings.EqualFold(c, "any") {
			return false, "R12: category sentinel spelled " + c
		}
		if !memberOf(env, c, host) {
			return false, ""
		}
	}
	if r.DestGroupID != "" && !groupMatches(env, r.DestGroupID, host) { // R13
		return false, ""
	}
	return true, ""
}

// clientAddr parses a client address per R6: unzoned, IPv4-mapped folded.
func clientAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// sourceIPMatches applies R6. specified=false for a rule value R6 does not settle.
func sourceIPMatches(rule, client string) (hit, specified bool) {
	if strings.Contains(rule, "/") {
		return cidrMatches(rule, client)
	}
	ra, err := netip.ParseAddr(rule)
	if err != nil || ra.Zone() != "" {
		return false, false
	}
	a, ok := clientAddr(client)
	return ok && a == ra.Unmap(), true
}

func cidrMatches(rule, client string) (hit, specified bool) {
	p, err := netip.ParsePrefix(rule)
	if err != nil {
		return false, false
	}
	if pa := p.Addr(); pa.Is4In6() { // a mapped prefix names IPv4 space
		if p.Bits() < 96 {
			return false, false
		}
		p = netip.PrefixFrom(pa.Unmap(), p.Bits()-96)
	}
	a, ok := clientAddr(client)
	return ok && p.Masked().Contains(a), true
}

func inGroups(want string, groups []string) bool {
	want = strings.TrimSpace(want)
	for _, g := range groups {
		if strings.EqualFold(strings.TrimSpace(g), want) {
			return true
		}
	}
	return false
}

func splitScheme(s string) (scheme, name string) {
	for _, p := range []string{"oidc", "saml", "ldap"} {
		if rest, ok := strings.CutPrefix(s, p+":"); ok && rest != "" {
			return p, rest
		}
	}
	return "", s
}

func sameProvider(rule, actual string) bool {
	if strings.EqualFold(rule, actual) {
		return true
	}
	rs, rn := splitScheme(rule)
	as, an := splitScheme(actual)
	return strings.EqualFold(rn, an) && (rs == "" || as == "" || rs == as)
}

// canonicalHost applies R10.
func canonicalHost(h string) string {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	bare := h
	if len(bare) >= 2 && bare[0] == '[' && bare[len(bare)-1] == ']' {
		bare = bare[1 : len(bare)-1]
	}
	if a, err := netip.ParseAddr(bare); err == nil && a.Zone() == "" {
		return a.Unmap().String()
	}
	return h
}

// underDomain reports whether host is d or a subdomain of d (label boundary).
func underDomain(host, d string) bool {
	return host == d || strings.HasSuffix(host, "."+d)
}

func fqdnMatches(pattern, host string) bool {
	switch {
	case pattern == "*":
		return true
	case strings.HasPrefix(pattern, "*."):
		return underDomain(host, pattern[2:])
	}
	return underDomain(host, pattern)
}

func memberOf(env Env, category, host string) bool {
	for name, patterns := range env.Categories {
		if !strings.EqualFold(name, category) {
			continue
		}
		for _, p := range patterns {
			if underDomain(host, canonicalHost(p)) {
				return true
			}
		}
	}
	return false
}

func groupMatches(env Env, id, host string) bool {
	cats, ok := env.Groups[id]
	if !ok {
		return false // R13: unknown group fails closed
	}
	for _, c := range cats {
		if memberOf(env, c, host) {
			return true
		}
	}
	return false
}

// StartupDefault applies R15. specified=false for an explicit value R15 does not settle.
func StartupDefault(explicit string, rulesConfigured int) (action string, specified bool) {
	switch explicit {
	case "allow", "deny":
		return explicit, true
	case "":
		if rulesConfigured == 0 {
			return "allow", true
		}
		return "deny", true
	}
	return "", false
}
