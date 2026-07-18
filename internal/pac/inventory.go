package pac

// inventory.go — PAC Exception Intelligence P0: the config-derived DIRECT
// inventory. It enumerates every path by which a PAC profile can return
// DIRECT — a FULL security-path bypass (traffic skips TLS inspection, DLP,
// CDR, URL filtering, threat inspection, auth, policy, and ALL proxy logging;
// it never reaches Culvert), which is distinct from a TLS-decryption bypass.
//
// This is an OBSERVABLE read-model: it reports what the configuration makes
// reachable, never that a bypass was USED. Culvert cannot observe DIRECT
// traffic (it never reaches the proxy), so usage is out of scope here and is
// deferred to a future endpoint-agent evidence source. Pure + deterministic.

import "strings"

// DirectBypassKind identifies WHY a profile can emit DIRECT.
type DirectBypassKind = string

// DIRECT-bypass sources (stable API strings).
const (
	// BypassRule is an explicit ActionDirect routing rule.
	BypassRule DirectBypassKind = "direct_rule"
	// BypassAvailability is availability mode appending DIRECT to the terminal
	// chain (fail-open when all proxies are unreachable).
	BypassAvailability DirectBypassKind = "availability_mode"
	// BypassPrivate is private-networks=direct sending all RFC-1918/loopback
	// destinations DIRECT.
	BypassPrivate DirectBypassKind = "private_networks"
	// BypassPlainHost is the unconditional dotless-intranet-hostname DIRECT
	// guard the compiler emits in EVERY profile (including secure mode). Every
	// PAC profile therefore bypasses for plain single-label hostnames. (The
	// profile compiler additionally excludes IPv6 literals; the legacy default
	// compiler does not — so the detail text does not promise IPv6 exclusion.)
	BypassPlainHost DirectBypassKind = "plain_host"
	// BypassFailOpen is the legacy default PAC failing OPEN to DIRECT for ALL
	// traffic when no proxy host is configured (and the fetching client
	// supplies no resolvable Host). It applies only to the synthesized legacy
	// default profile and is injected by the root inventory builder, since the
	// static profile model cannot otherwise express the request-dependent
	// terminal of the legacy compiler.
	BypassFailOpen DirectBypassKind = "fail_open"
)

// DirectEntry is one config-derived path by which a profile fully bypasses
// Culvert. EvidenceClass is always config-Observable.
type DirectEntry struct {
	Kind      DirectBypassKind `json:"kind"`
	Detail    string           `json:"detail"`
	RuleIndex int              `json:"ruleIndex,omitempty"` // 1-based, for BypassRule
	// RuleKind is the routing-rule kind (domain/suffix/wildcard/cidr4) for a
	// BypassRule entry — distinct from Kind (always "direct_rule" for rules).
	// Carried structurally so the change-diff can tell a same-pattern kind flip
	// (e.g. suffix→domain, which broadens subdomains-only to apex+subdomains)
	// apart, which Kind alone cannot.
	RuleKind string `json:"ruleKind,omitempty"`
	Pattern  string `json:"pattern,omitempty"`
	Scheme   string `json:"scheme,omitempty"`
	Port     int    `json:"port,omitempty"`
	// Broad flags a wide-reaching bypass (wildcard, broad IPv4 CIDR, or an
	// all-destinations mode/private bypass) — a config-only heuristic, not an
	// observation of scope.
	Broad bool `json:"broad,omitempty"`
}

// ProfileDirectInventory summarizes one profile's DIRECT footprint.
type ProfileDirectInventory struct {
	ProfileID string `json:"profileId"`
	Name      string `json:"name"`
	// Serving is true when the profile is enabled and therefore served at
	// /pac/<id>.pac (a disabled profile 404s and reaches no client).
	Serving          bool          `json:"serving"`
	AvailabilityMode string        `json:"availabilityMode"`
	DirectCapable    bool          `json:"directCapable"`
	DirectPaths      []DirectEntry `json:"directPaths,omitempty"`
}

// DirectInventory is the fleet-wide, config-derived inventory of every PAC
// full-security-path bypass. Counts describe configuration, not traffic.
type DirectInventory struct {
	// EvidenceClass is always "config" — this is Observable configuration
	// state, never observed DIRECT usage (which the proxy cannot see).
	EvidenceClass         string                   `json:"evidenceClass"`
	Profiles              []ProfileDirectInventory `json:"profiles"`
	TotalProfiles         int                      `json:"totalProfiles"`
	DirectCapableProfiles int                      `json:"directCapableProfiles"`
	// ServingDirectProfiles counts enabled profiles that can emit DIRECT —
	// the ones whose bypass is reachable by clients right now.
	ServingDirectProfiles int `json:"servingDirectProfiles"`
	TotalDirectPaths      int `json:"totalDirectPaths"`
	// BroadDirectPaths counts wide-reaching DIRECT paths (wildcards, broad
	// CIDRs, all-destination bypasses) — the "high-risk wildcard/broad CIDR"
	// signal, computed from config.
	BroadDirectPaths int `json:"broadDirectPaths"`
}

// broadCIDRMaxPrefix — an IPv4 CIDR at or below this prefix length covers a
// large address span and is flagged broad (e.g. /8, /16). /24 and narrower
// are not flagged.
const broadCIDRMaxPrefix = 16

// BuildDirectInventory enumerates the DIRECT footprint of every profile in
// cfg. Secure-mode profiles are reported not-DIRECT-capable: the compiler
// neutralizes DIRECT (rules, private bypass, and terminal) in secure mode, so
// no bypass is reachable regardless of what the spec lists.
func BuildDirectInventory(cfg ProfilesConfig) DirectInventory {
	inv := DirectInventory{EvidenceClass: "config"}
	for i := range cfg.Profiles {
		p := &cfg.Profiles[i]
		pinv := ProfileDirectInventory{
			ProfileID:        p.ID,
			Name:             p.Name,
			Serving:          p.Enabled,
			AvailabilityMode: p.AvailabilityMode,
		}
		pinv.DirectPaths = directEntriesFor(p)
		pinv.DirectCapable = len(pinv.DirectPaths) > 0

		inv.Profiles = append(inv.Profiles, pinv)
		inv.TotalProfiles++
		if pinv.DirectCapable {
			inv.DirectCapableProfiles++
			if pinv.Serving {
				inv.ServingDirectProfiles++
			}
		}
		for j := range pinv.DirectPaths {
			inv.TotalDirectPaths++
			if pinv.DirectPaths[j].Broad {
				inv.BroadDirectPaths++
			}
		}
	}
	return inv
}

// directEntriesFor enumerates the DIRECT paths of a single profile. EVERY
// profile — including secure mode — carries the unconditional plain-host
// bypass the compiler emits (compile_profiles.go); secure mode neutralizes
// only the rule/private/availability DIRECT sources, not the plain-host guard.
func directEntriesFor(p *Profile) []DirectEntry {
	// Always present: the compiler unconditionally sends plain (dotless)
	// intranet hostnames DIRECT (IPv6 literals excluded), in every mode.
	out := []DirectEntry{{
		Kind:   BypassPlainHost,
		Detail: "plain (dotless) intranet hostnames are sent DIRECT (unconditional, every mode)",
	}}
	if p.AvailabilityMode == ModeSecure {
		// Secure mode neutralizes DIRECT rules, the private-network bypass, and
		// the terminal chain — only the plain-host guard above remains.
		return out
	}
	if p.AvailabilityMode == ModeAvailability {
		out = append(out, DirectEntry{
			Kind:   BypassAvailability,
			Detail: "availability mode appends DIRECT to the terminal chain (fail-open when all proxies are unreachable)",
			Broad:  true,
		})
	}
	if p.PrivateNetworks == PrivateDirect {
		out = append(out, DirectEntry{
			Kind:   BypassPrivate,
			Detail: "private-networks=direct sends all RFC-1918/loopback destinations DIRECT",
			Broad:  true,
		})
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Action != ActionDirect {
			continue
		}
		// Only inventory a rule the compiler would actually emit. An invalid
		// pattern (bad glob/CIDR/domain, unknown kind) is dropped by
		// ruleCondition, so no DIRECT is produced — reporting it anyway would
		// over-count the DIRECT footprint (and mis-flag broad).
		if _, ok := ruleCondition(r); !ok {
			continue
		}
		out = append(out, DirectEntry{
			Kind:      BypassRule,
			Detail:    "rule " + itoa(i+1) + " (" + r.Kind + " " + r.Pattern + ") → DIRECT",
			RuleIndex: i + 1,
			RuleKind:  r.Kind,
			Pattern:   r.Pattern,
			Scheme:    r.Scheme,
			Port:      r.Port,
			Broad:     ruleIsBroad(r),
		})
	}
	return out
}

// ruleIsBroad flags a DIRECT rule that covers a wide destination span: a
// wildcard glob, or an IPv4 CIDR at or below broadCIDRMaxPrefix. Config-only
// heuristic — it does not observe how much traffic the rule actually carries.
func ruleIsBroad(r *Rule) bool {
	switch r.Kind {
	case RuleKindWildcard:
		return true
	case RuleKindCIDR4:
		if slash := strings.LastIndexByte(r.Pattern, '/'); slash >= 0 {
			if prefix, ok := atoiPrefix(r.Pattern[slash+1:]); ok {
				return prefix <= broadCIDRMaxPrefix
			}
		}
	}
	return false
}

// atoiPrefix parses a small non-negative CIDR prefix (0-32). Returns false on
// any non-digit or out-of-range value rather than importing strconv for one
// tiny parse on a validated field.
func atoiPrefix(s string) (int, bool) {
	if s == "" || len(s) > 2 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if n > 32 {
		return 0, false
	}
	return n, true
}
