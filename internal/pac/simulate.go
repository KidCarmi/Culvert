package pac

// simulate.go — the PAC steering simulator (initiative PR 3). It answers
// "what would profile P return for URL U / host H?" by evaluating the SAME
// normalized rule model the compiler emits — NOT a second rule engine. The
// compiler turns each rule into a JS condition; Simulate turns the same rule
// into the equivalent Go predicate, so the two cannot drift on rule
// semantics. A parity test compiles a profile, runs a battery of inputs
// through both this evaluator and a golden expectation, and asserts they
// agree.
//
// DNS: the simulator performs NO live resolution (it runs on a viewer-
// reachable API). The caller may supply an already-resolved IP; without one,
// DNS-dependent rules (cidr4, the private-network bypass) report
// OutcomeUndeterminedDNS rather than guessing.

import (
	"net"
	"strings"
)

// Simulate outcomes for the matched decision.
const (
	// OutcomeMatched: a rule (or the terminal) decided the directive.
	OutcomeMatched = "matched"
	// OutcomeUndeterminedDNS: the deciding rule needs the host's IP and no
	// resolved IP was supplied — the real answer depends on client DNS.
	OutcomeUndeterminedDNS = "undetermined_dns"
)

// SimInput is one simulation query.
type SimInput struct {
	// URL is the full request URL (scheme + authority; path is advisory —
	// clients strip it for https). Optional if Host is set.
	URL string `json:"url"`
	// Host is the destination hostname or IP literal. Derived from URL when
	// empty.
	Host string `json:"host"`
	// Scheme overrides the scheme parsed from URL (http/https).
	Scheme string `json:"scheme"`
	// Port is the destination port as it would appear in the URL authority
	// (0 = none/default; default ports are unmatchable, as for real clients).
	Port int `json:"port"`
	// ResolvedIP optionally supplies the host's resolved IPv4 address so
	// cidr4 / private-network rules can be evaluated deterministically. When
	// empty, those rules yield OutcomeUndeterminedDNS.
	ResolvedIP string `json:"resolvedIp"`
}

// SimMatchedRule identifies which rule fired (index into the profile's rule
// list, or a synthetic marker for built-ins/terminal).
type SimMatchedRule struct {
	// Index is the 0-based rule index, or -1 for a non-rule decision.
	Index int `json:"index"`
	// Kind is the rule kind, or a synthetic label: "plain-host",
	// "private-network", "terminal".
	Kind string `json:"kind"`
	// Pattern is the rule pattern (empty for synthetic decisions).
	Pattern string `json:"pattern,omitempty"`
	// Action is the rule action or the synthetic decision's effect.
	Action string `json:"action"`
}

// SimResult is the explainable simulation outcome.
type SimResult struct {
	// Directive is the PAC return string (e.g. "PROXY a:8080; DIRECT").
	Directive string `json:"directive"`
	// Outcome is OutcomeMatched or OutcomeUndeterminedDNS.
	Outcome string `json:"outcome"`
	// MatchedRule describes the deciding rule/branch.
	MatchedRule SimMatchedRule `json:"matchedRule"`
	// Reason is a human-readable explanation of the decision.
	Reason string `json:"reason"`
	// PoolID is the pool whose chain was selected (empty for DIRECT).
	PoolID string `json:"poolId,omitempty"`
	// Chain is the ordered failover directive list.
	Chain []string `json:"chain"`
	// DirectPossible reports whether this decision can yield DIRECT (either
	// the directive is/contains DIRECT, or availability mode appends it).
	DirectPossible bool `json:"directPossible"`
	// Warnings carries evaluation notes (e.g. undetermined DNS).
	Warnings []string `json:"warnings,omitempty"`
	// CompilerVersion and Revision pin the semantics used.
	CompilerVersion string `json:"compilerVersion"`
	Revision        int64  `json:"revision"`
}

// Simulate evaluates in for profile p against its pools, mirroring the
// compiler's emission order exactly: host hygiene → plain-host (non-IPv6) →
// private-network bypass (privateNetworks=direct, non-secure) → ordered
// rules → terminal.
func Simulate(p Profile, pools map[string]Pool, in SimInput) SimResult {
	host := simHost(in)
	terminal, chain := profileTerminal(p, pools, func(_, _, _ string) {})
	res := SimResult{
		Directive: terminal, Outcome: OutcomeMatched, Chain: chain,
		CompilerVersion: CompilerVersion, Revision: p.Revision,
	}

	// 1. plain (dotless) intranet names — but NOT IPv6 literals (they are
	// dotless yet must follow the rules; mirrors the compiler guard).
	if host != "" && !strings.Contains(host, ".") && !strings.Contains(host, ":") {
		return simDirect(&res, SimMatchedRule{Index: -1, Kind: "plain-host", Action: "direct"},
			"plain (dotless) hostname bypasses the proxy")
	}

	// 2. private-network bypass (privateNetworks=direct, non-secure mode).
	if p.PrivateNetworks == PrivateDirect && p.AvailabilityMode != ModeSecure {
		if hit, undetermined := simPrivateNetwork(in); undetermined {
			res.Outcome = OutcomeUndeterminedDNS
			res.Warnings = append(res.Warnings, "private-network rule depends on DNS resolution; supply resolvedIp for a definite answer")
		} else if hit {
			return simDirect(&res, SimMatchedRule{Index: -1, Kind: "private-network", Action: "direct"},
				"destination IP is in a private (RFC-1918/loopback) range")
		}
	}

	// 3. ordered rules (first match wins).
	for i := range p.Rules {
		matched, undetermined := simRuleMatches(&p.Rules[i], in, host)
		if undetermined {
			res.Outcome = OutcomeUndeterminedDNS
			res.Warnings = append(res.Warnings, "rule "+p.Rules[i].Kind+" depends on DNS resolution; supply resolvedIp for a definite answer")
			continue
		}
		if matched {
			return simRuleDecision(&res, p, pools, &p.Rules[i], i, terminal)
		}
	}

	// 4. terminal.
	res.MatchedRule = SimMatchedRule{Index: -1, Kind: "terminal", Action: "use_pool"}
	res.PoolID = p.PoolID
	res.Reason = "no rule matched; profile terminal (" + p.AvailabilityMode + " mode)"
	res.DirectPossible = strings.Contains(terminal, "DIRECT")
	return res
}

func simDirect(res *SimResult, mr SimMatchedRule, reason string) SimResult {
	res.Directive = "DIRECT"
	res.Chain = []string{"DIRECT"}
	res.MatchedRule = mr
	res.Reason = reason
	res.DirectPossible = true
	res.PoolID = ""
	return *res
}

func simRuleDecision(res *SimResult, p Profile, pools map[string]Pool, r *Rule, idx int, terminal string) SimResult {
	res.MatchedRule = SimMatchedRule{Index: idx, Kind: r.Kind, Pattern: r.Pattern, Action: r.Action}
	// Secure mode neutralizes DIRECT rules to the terminal (compiler parity).
	if r.Action == ActionDirect && p.AvailabilityMode != ModeSecure {
		return simDirect(res, res.MatchedRule, "rule "+itoa(idx+1)+" ("+r.Kind+" "+r.Pattern+") → DIRECT")
	}
	// Honor ruleDirective's ok bool exactly as writeProfileRule does: a
	// use_pool rule whose pool override is missing/empty degrades to the
	// profile terminal (not an empty directive), matching the compiled JS.
	directive, ok := ruleDirective(r, p, pools, terminal)
	if !ok {
		directive = terminal
	}
	res.Directive = directive
	res.Chain = strings.Split(directive, "; ")
	res.DirectPossible = strings.Contains(directive, "DIRECT")
	if r.PoolID != "" {
		res.PoolID = r.PoolID
	} else {
		res.PoolID = p.PoolID
	}
	if r.Action == ActionDirect { // secure-mode degradation
		res.Reason = "rule " + itoa(idx+1) + " is DIRECT but secure mode degrades it to the pool terminal"
	} else {
		res.Reason = "rule " + itoa(idx+1) + " (" + r.Kind + " " + r.Pattern + ") → pool " + res.PoolID
	}
	return *res
}

// simHost derives the destination host: explicit Host wins, else parse it
// from the URL authority.
func simHost(in SimInput) string {
	if in.Host != "" {
		return normalizeSimHost(in.Host)
	}
	return normalizeSimHost(hostFromURLAuthority(in.URL))
}

func normalizeSimHost(h string) string {
	h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	return strings.Trim(h, "[]")
}

// hostFromURLAuthority extracts the host (no port) from a full URL string
// using the same authority logic the compiler emits.
func hostFromURLAuthority(u string) string {
	if i := strings.Index(u, "//"); i != -1 {
		u = u[i+2:]
	}
	if i := strings.IndexAny(u, "/?#"); i != -1 {
		u = u[:i]
	}
	if i := strings.LastIndex(u, "@"); i != -1 {
		u = u[i+1:]
	}
	// Strip a trailing :port (but keep IPv6 colons inside brackets).
	if strings.HasPrefix(u, "[") {
		if j := strings.Index(u, "]"); j != -1 {
			return u[:j+1]
		}
	}
	if i := strings.LastIndex(u, ":"); i != -1 && !strings.Contains(u, "]") {
		u = u[:i]
	}
	return u
}

// simRuleMatches reports whether r matches in/host. The second return is true
// when the rule needs DNS and no resolved IP was supplied.
func simRuleMatches(r *Rule, in SimInput, host string) (matched, undetermined bool) {
	if !simGuardsMatch(r, in) {
		return false, false
	}
	pattern := strings.TrimSpace(r.Pattern)
	switch r.Kind {
	case RuleKindDomain:
		return simMatchDomain(pattern, host), false
	case RuleKindSuffix:
		return simMatchSuffix(pattern, host), false
	case RuleKindWildcard:
		return simMatchWildcard(pattern, host), false
	case RuleKindCIDR4:
		return simMatchCIDR(pattern, in)
	default:
		return false, false
	}
}

// simMatch* mirror the compiler's ruleCondition acceptance per kind: a rule
// whose pattern doesn't normalize to the kind's expected form is DROPPED
// (never emitted), so the simulator must not honor it either.
func simMatchDomain(pattern, host string) bool {
	e, _, reject := normalizeExclusion(pattern)
	if reject != nil || (e.Kind != KindDomain && e.Kind != KindHostLiteral) {
		return false
	}
	if e.Kind == KindHostLiteral {
		return host == e.Host
	}
	return host == e.Host || strings.HasSuffix(host, "."+e.Host)
}

func simMatchSuffix(pattern, host string) bool {
	e, _, reject := normalizeExclusion(pattern)
	if reject != nil || e.Kind != KindDomain {
		return false
	}
	return strings.HasSuffix(host, "."+e.Host)
}

func simMatchWildcard(pattern, host string) bool {
	if hasControlOrSpace(pattern) || strings.ContainsAny(pattern, `"\`) {
		return false
	}
	return globMatch(strings.ToLower(pattern), host)
}

func simMatchCIDR(pattern string, in SimInput) (matched, undetermined bool) {
	e, _, reject := normalizeCIDR(pattern)
	if reject != nil {
		return false, false
	}
	if in.ResolvedIP == "" {
		return false, true // needs DNS
	}
	return ipInCIDR(in.ResolvedIP, e.CIDRIP, e.CIDRPrefix), false
}

// simGuardsMatch evaluates the optional scheme/port guards.
func simGuardsMatch(r *Rule, in SimInput) bool {
	if r.Scheme != "" {
		scheme := in.Scheme
		if scheme == "" {
			scheme = schemeFromURL(in.URL)
		}
		if scheme != r.Scheme {
			return false
		}
	}
	if r.Port != 0 {
		port := in.Port
		if port == 0 {
			port = portFromURL(in.URL)
		}
		if port != r.Port {
			return false
		}
	}
	return true
}

// simPrivateNetwork reports whether the resolved IP is loopback/RFC-1918. The
// second return is true when no IP was supplied (undetermined).
func simPrivateNetwork(in SimInput) (hit, undetermined bool) {
	if in.ResolvedIP == "" {
		return false, true
	}
	ip := net.ParseIP(in.ResolvedIP)
	if ip == nil || ip.To4() == nil {
		return false, false
	}
	return ip.IsLoopback() || ip.IsPrivate(), false
}

func ipInCIDR(ipStr, network string, prefix int) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return false
	}
	_, ipnet, err := net.ParseCIDR(network + "/" + itoa(prefix))
	if err != nil {
		return false
	}
	return ipnet.Contains(ip)
}

// globMatch implements shExpMatch semantics (`*` = any run, `?` = one char)
// on already-lowercased inputs — the same glob the compiler emits. It uses a
// linear two-pointer scan with single-star backtracking (O(len(p)·len(s))
// worst case) rather than per-star recursion, so an admin- OR viewer-supplied
// pattern like "*a*a*…*b" against "aaaa…" cannot trigger catastrophic
// exponential backtracking (a management-plane DoS via the simulator/analyzer).
func globMatch(pattern, s string) bool {
	var pi, si int
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi // remember the star and the position it started matching
			mark = si
			pi++
		case star != -1:
			pi = star + 1 // backtrack: let the last star consume one more char
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

func schemeFromURL(u string) string {
	if i := strings.Index(u, "://"); i != -1 {
		return strings.ToLower(u[:i])
	}
	return ""
}

func portFromURL(u string) int {
	auth := hostFromURLAuthorityWithPort(u)
	if i := strings.LastIndex(auth, ":"); i != -1 && !strings.HasSuffix(auth, "]") {
		return atoiSafe(auth[i+1:])
	}
	return 0
}

func hostFromURLAuthorityWithPort(u string) string {
	if i := strings.Index(u, "//"); i != -1 {
		u = u[i+2:]
	}
	if i := strings.IndexAny(u, "/?#"); i != -1 {
		u = u[:i]
	}
	if i := strings.LastIndex(u, "@"); i != -1 {
		u = u[i+1:]
	}
	return u
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func atoiSafe(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}
