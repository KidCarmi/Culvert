package pac

// compile_profiles.go — the profile compiler (initiative PR 2). Same
// determinism and ES3/ASCII portability contract as compile.go. Rules are
// emitted in admin-authored order (order-sensitive: actions differ), so no
// DNS-hoisting reorder happens here; DNS is resolved at most ONCE via a
// nested helper. With privateNetworks=proxy the resolution is fully lazy
// (rule chains that answer before any cidr4 rule never pay for a lookup);
// with privateNetworks=direct the private-network bypass must precede the
// rules to keep its guarantee, so every evaluation resolves once up front —
// the same cost profile as the legacy generator.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// PoolDirectives renders a pool's ordered failover chain, e.g.
// "PROXY a:8080; PROXY b:8080". Empty pool renders "" (caller handles).
func PoolDirectives(pool Pool) string {
	parts := make([]string, 0, len(pool.Endpoints))
	for _, ep := range pool.Endpoints {
		parts = append(parts, fmt.Sprintf("PROXY %s:%d", ep.Host, ep.Port))
	}
	return strings.Join(parts, "; ")
}

// CompileProfile compiles one custom profile against its pools. The
// returned artifact is deterministic for identical inputs. Unresolvable
// pieces (unknown pool refs, junk patterns) are DROPPED with warnings —
// tolerant, mirroring NormalizeLenient — so replayed/synced configs always
// compile; strict validation guards the API boundary instead.
func CompileProfile(p Profile, pools map[string]Pool) Artifact {
	var warnings []ValidationIssue
	warn := func(code, entry, msg string) {
		warnings = append(warnings, ValidationIssue{Field: "profiles", Entry: entry, Code: code, Message: msg})
	}

	terminal, chain := profileTerminal(p, pools, warn)
	js := compileProfileJS(p, pools, terminal, warn)
	sum := sha256.Sum256([]byte(js))
	return Artifact{
		JS:              js,
		Digest:          hex.EncodeToString(sum[:]),
		Fingerprint:     profileFingerprint(p, pools),
		CompilerVersion: CompilerVersion,
		GeneratedAt:     time.Now(),
		Warnings:        warnings,
		ProxyChain:      chain,
		HostFallback:    false,
	}
}

// profileTerminal resolves the profile's terminal directive string and the
// structured chain. Secure/balanced: pool chain only (fail closed);
// availability: pool chain + DIRECT.
func profileTerminal(p Profile, pools map[string]Pool, warn func(code, entry, msg string)) (terminal string, chainOut []string) {
	pool, ok := pools[p.PoolID]
	var chain []string
	if !ok || len(pool.Endpoints) == 0 {
		warn(IssueUnknownPool, "profile "+p.ID,
			fmt.Sprintf("pool %q is missing or empty; terminal keeps the pool reference unresolved", p.PoolID))
	} else {
		for _, ep := range pool.Endpoints {
			chain = append(chain, fmt.Sprintf("PROXY %s:%d", ep.Host, ep.Port))
		}
	}
	if p.AvailabilityMode == ModeAvailability {
		chain = append(chain, "DIRECT")
	}
	if len(chain) == 0 {
		// Degenerate: no resolvable proxy and no DIRECT permitted. Secure
		// semantics forbid inventing a DIRECT fallback — emit an
		// unresolvable PROXY target so traffic fails closed, with a warning
		// naming the branch (reviewed F10 decision).
		warn(IssueSecureModeConflict, "profile "+p.ID,
			"no resolvable proxy endpoint and mode forbids DIRECT; PAC fails closed via an unresolvable placeholder")
		chain = []string{"PROXY unresolvable.invalid:9"}
	}
	return strings.Join(chain, "; "), chain
}

// profileFingerprint hashes the canonical profile+resolved-pool material.
func profileFingerprint(p Profile, pools map[string]Pool) string {
	canon := struct {
		Profile Profile `json:"profile"`
		Pool    Pool    `json:"pool"`
		Over    []Pool  `json:"overridePools,omitempty"`
	}{Profile: p, Pool: pools[p.PoolID]}
	for i := range p.Rules {
		if id := p.Rules[i].PoolID; id != "" {
			canon.Over = append(canon.Over, pools[id])
		}
	}
	data, _ := json.Marshal(canon) //nolint:errcheck // fixed shape cannot fail
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// compileProfileJS emits the FindProxyForURL body for a profile.
func compileProfileJS(p Profile, pools map[string]Pool, terminal string, warn func(code, entry, msg string)) string {
	var sb strings.Builder
	sb.WriteString("// Culvert proxy auto-config (PAC). Generated file - do not edit.\n")
	fmt.Fprintf(&sb, "// compiler: v%s\n", CompilerVersion)
	fmt.Fprintf(&sb, "// profile: %s revision %d\n", p.ID, p.Revision)
	fmt.Fprintf(&sb, "// fingerprint: %s\n", profileFingerprint(p, pools))
	sb.WriteString("function FindProxyForURL(url, host) {\n")
	sb.WriteString("  // Normalize: clients differ on casing and trailing dots.\n")
	sb.WriteString("  host = host.toLowerCase();\n")
	sb.WriteString("  if (host.charAt(host.length - 1) === \".\") {\n")
	sb.WriteString("    host = host.substring(0, host.length - 1);\n")
	sb.WriteString("  }\n")
	sb.WriteString("  // Plain (dotless) names never traverse the proxy.\n")
	sb.WriteString("  if (isPlainHostName(host)) return \"DIRECT\";\n")
	sb.WriteString("  // Lazy single DNS resolution shared by all IP-based rules.\n")
	sb.WriteString("  var ipDone = false;\n")
	sb.WriteString("  var ipVal = null;\n")
	sb.WriteString("  function resolveOnce() {\n")
	sb.WriteString("    if (!ipDone) { ipDone = true; ipVal = dnsResolve(host); }\n")
	sb.WriteString("    return ipVal;\n")
	sb.WriteString("  }\n")

	if profileUsesPortGuards(&p) {
		// Extract the URL authority ("host:port") once so port guards
		// compare against the authority tail, never the path/query. All
		// string ops are ES3 (String.prototype.indexOf/substring are ES3;
		// only the Array variants are ES5+).
		sb.WriteString("  // URL authority for explicit-port rule guards.\n")
		sb.WriteString("  var auth = url;\n")
		sb.WriteString("  var ai = auth.indexOf(\"//\");\n")
		sb.WriteString("  if (ai !== -1) { auth = auth.substring(ai + 2); }\n")
		sb.WriteString("  var as = auth.indexOf(\"/\");\n")
		sb.WriteString("  if (as !== -1) { auth = auth.substring(0, as); }\n")
		sb.WriteString("  var aat = auth.lastIndexOf(\"@\");\n")
		sb.WriteString("  if (aat !== -1) { auth = auth.substring(aat + 1); }\n")
	}

	if p.PrivateNetworks == PrivateDirect {
		sb.WriteString("  // Private networks: DIRECT (profile setting).\n")
		sb.WriteString("  var pip = resolveOnce();\n")
		sb.WriteString("  if (pip) {\n")
		sb.WriteString("    if (isInNet(pip, \"127.0.0.0\", \"255.0.0.0\")) return \"DIRECT\";\n")
		sb.WriteString("    if (isInNet(pip, \"10.0.0.0\", \"255.0.0.0\")) return \"DIRECT\";\n")
		sb.WriteString("    if (isInNet(pip, \"172.16.0.0\", \"255.240.0.0\")) return \"DIRECT\";\n")
		sb.WriteString("    if (isInNet(pip, \"192.168.0.0\", \"255.255.0.0\")) return \"DIRECT\";\n")
		sb.WriteString("  }\n")
	}

	for i := range p.Rules {
		writeProfileRule(&sb, &p.Rules[i], i, p, pools, terminal, warn)
	}

	sb.WriteString("\n  // Terminal: profile availability mode decides the chain.\n")
	fmt.Fprintf(&sb, "  return %q;\n", terminal)
	sb.WriteString("}\n")
	return sb.String()
}

// writeProfileRule emits one ordered rule. Junk patterns and unknown pool
// overrides are dropped with warnings (tolerant compile).
func writeProfileRule(sb *strings.Builder, r *Rule, idx int, p Profile, pools map[string]Pool, terminal string, warn func(code, entry, msg string)) {
	entry := fmt.Sprintf("profile %s rule %d", p.ID, idx+1)
	directive, ok := ruleDirective(r, p, pools, terminal)
	if !ok {
		warn(IssueInvalidRule, entry, "rule references an unknown or empty pool; dropped from generated PAC")
		return
	}
	cond, ok := ruleCondition(r)
	if !ok {
		warn(IssueInvalidRule, entry, fmt.Sprintf("pattern %q could not be compiled; rule dropped from generated PAC", r.Pattern))
		return
	}
	guards := ruleGuards(r)
	fmt.Fprintf(sb, "  if (%s%s) return %q;\n", guards, cond, directive)
}

// ruleDirective resolves the rule's return value.
func ruleDirective(r *Rule, p Profile, pools map[string]Pool, terminal string) (string, bool) {
	if r.Action == ActionDirect {
		return "DIRECT", true
	}
	if r.PoolID == "" {
		return terminal, true
	}
	pool, ok := pools[r.PoolID]
	if !ok || len(pool.Endpoints) == 0 {
		return "", false
	}
	d := PoolDirectives(pool)
	if p.AvailabilityMode == ModeAvailability {
		d += "; DIRECT"
	}
	return d, true
}

// profileUsesPortGuards reports whether any rule needs the URL-authority
// preamble.
func profileUsesPortGuards(p *Profile) bool {
	for i := range p.Rules {
		if p.Rules[i].Port != 0 {
			return true
		}
	}
	return false
}

// ruleGuards renders optional scheme/port guards. The port guard compares
// the AUTHORITY tail ("...:8443"), never a substring of the full URL — a
// ":80" rule must not fire on ":8080" or on path text. Clients omit default
// ports from the URL, so default ports cannot be matched (documented
// limitation).
func ruleGuards(r *Rule) string {
	var g strings.Builder
	if r.Scheme != "" {
		fmt.Fprintf(&g, "url.substring(0, %d) === %q && ", len(r.Scheme)+1, r.Scheme+":")
	}
	if r.Port != 0 {
		suffix := fmt.Sprintf(":%d", r.Port)
		fmt.Fprintf(&g, "auth.substring(auth.length - %d) === %q && ", len(suffix), suffix)
	}
	return g.String()
}

// ruleCondition renders the kind-specific host condition.
func ruleCondition(r *Rule) (string, bool) {
	pattern := strings.TrimSpace(r.Pattern)
	switch r.Kind {
	case RuleKindDomain:
		e, _, reject := normalizeExclusion(pattern)
		if reject != nil || (e.Kind != KindDomain && e.Kind != KindHostLiteral) {
			return "", false
		}
		if e.Kind == KindHostLiteral {
			return fmt.Sprintf("host === %q", e.Host), true
		}
		return fmt.Sprintf("(host === %q || dnsDomainIs(host, %q))", e.Host, "."+e.Host), true
	case RuleKindSuffix:
		e, _, reject := normalizeExclusion(pattern)
		if reject != nil || e.Kind != KindDomain {
			return "", false
		}
		return fmt.Sprintf("dnsDomainIs(host, %q)", "."+e.Host), true
	case RuleKindWildcard:
		if hasControlOrSpace(pattern) || strings.ContainsAny(pattern, `"\`) {
			return "", false
		}
		return fmt.Sprintf("shExpMatch(host, %q)", strings.ToLower(pattern)), true
	case RuleKindCIDR4:
		e, _, reject := normalizeCIDR(pattern)
		if reject != nil {
			return "", false
		}
		return fmt.Sprintf("(resolveOnce() && isInNet(resolveOnce(), %q, %q))", e.CIDRIP, e.CIDRMask), true
	default:
		return "", false
	}
}
