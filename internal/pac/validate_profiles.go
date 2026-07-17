package pac

// validate_profiles.go — strict validation for profiles/pools (initiative
// PR 2). Same boundary contract as validate.go: strict ONLY at the admin
// API / import boundary; ProfileStore.Set and every replay path stay
// tolerant (the compiler skips what it cannot resolve).

import (
	"fmt"
	"net"
	"strings"
)

// Profile/pool validation issue codes (stable API strings).
const (
	IssueInvalidID          = "invalid_id"
	IssueDuplicateID        = "duplicate_id"
	IssueReservedID         = "reserved_id"
	IssueUnknownPool        = "unknown_pool"
	IssueInvalidEndpoint    = "invalid_endpoint"
	IssueTooManyEndpoints   = "too_many_endpoints"
	IssueNoEndpoints        = "no_endpoints"
	IssueInvalidRule        = "invalid_rule"
	IssueInvalidMode        = "invalid_mode"
	IssueTooManyProfiles    = "too_many_profiles"
	IssueTooManyPools       = "too_many_pools"
	IssueTooManyRules       = "too_many_rules"
	IssueSecureModeConflict = "secure_mode_conflict"
)

// ValidateProfilesConfig strictly validates a full profiles+pools config.
// Empty config is valid. Issues are actionable and name the offending
// object in Entry ("profile <id>" / "pool <id>" / "rule N of <id>").
func ValidateProfilesConfig(cfg ProfilesConfig) []ValidationIssue {
	var issues []ValidationIssue
	issues = append(issues, validatePoolsSection(cfg.Pools)...)
	issues = append(issues, validateProfilesSection(cfg)...)
	return issues
}

func validatePoolsSection(pools []Pool) []ValidationIssue {
	var issues []ValidationIssue
	if len(pools) > MaxPools {
		issues = append(issues, ValidationIssue{Field: "pools", Code: IssueTooManyPools,
			Message: fmt.Sprintf("%d pools exceed the maximum of %d", len(pools), MaxPools)})
	}
	seen := map[string]bool{}
	for i := range pools {
		p := &pools[i]
		entry := "pool " + p.ID
		if !ValidIdentifier(p.ID) {
			issues = append(issues, ValidationIssue{Field: "pools", Entry: entry, Code: IssueInvalidID,
				Message: fmt.Sprintf("pool ID %q must match [a-z0-9][a-z0-9-]{0,63}", p.ID)})
			continue
		}
		if seen[p.ID] {
			issues = append(issues, ValidationIssue{Field: "pools", Entry: entry, Code: IssueDuplicateID,
				Message: fmt.Sprintf("duplicate pool ID %q", p.ID)})
			continue
		}
		seen[p.ID] = true
		issues = append(issues, validatePoolEndpoints(p, entry)...)
	}
	return issues
}

func validatePoolEndpoints(p *Pool, entry string) []ValidationIssue {
	var issues []ValidationIssue
	if len(p.Endpoints) == 0 {
		issues = append(issues, ValidationIssue{Field: "pools", Entry: entry, Code: IssueNoEndpoints,
			Message: fmt.Sprintf("pool %q needs at least one proxy endpoint", p.ID)})
	}
	if len(p.Endpoints) > MaxPoolEndpoints {
		issues = append(issues, ValidationIssue{Field: "pools", Entry: entry, Code: IssueTooManyEndpoints,
			Message: fmt.Sprintf("pool %q has %d endpoints; maximum is %d (primary/secondary/tertiary)", p.ID, len(p.Endpoints), MaxPoolEndpoints)})
	}
	for _, ep := range p.Endpoints {
		if is := validateEndpoint(ep, entry); is != nil {
			issues = append(issues, *is)
		}
	}
	return issues
}

func validateEndpoint(ep PoolEndpoint, entry string) *ValidationIssue {
	bad := func(msg string) *ValidationIssue {
		return &ValidationIssue{Field: "pools", Entry: entry, Code: IssueInvalidEndpoint, Message: msg}
	}
	if ep.Port < 1 || ep.Port > 65535 {
		return bad(fmt.Sprintf("endpoint port %d is outside 1-65535", ep.Port))
	}
	if hostIssue := validateProxyHost(ep.Host); ep.Host == "" || hostIssue != nil {
		return bad(fmt.Sprintf("endpoint host %q is not a valid hostname or IP", ep.Host))
	}
	return nil
}

func validateProfilesSection(cfg ProfilesConfig) []ValidationIssue {
	var issues []ValidationIssue
	if len(cfg.Profiles) > MaxProfiles {
		issues = append(issues, ValidationIssue{Field: "profiles", Code: IssueTooManyProfiles,
			Message: fmt.Sprintf("%d profiles exceed the maximum of %d", len(cfg.Profiles), MaxProfiles)})
	}
	pools := map[string]bool{}
	for i := range cfg.Pools {
		pools[cfg.Pools[i].ID] = true
	}
	seen := map[string]bool{}
	for i := range cfg.Profiles {
		issues = append(issues, validateProfile(&cfg.Profiles[i], pools, seen)...)
	}
	return issues
}

func validateProfile(p *Profile, pools map[string]bool, seen map[string]bool) []ValidationIssue {
	var issues []ValidationIssue
	entry := "profile " + p.ID
	add := func(code, msg string) {
		issues = append(issues, ValidationIssue{Field: "profiles", Entry: entry, Code: code, Message: msg})
	}
	switch {
	case p.ID == DefaultProfileID:
		add(IssueReservedID, `"default" is the legacy-backed profile; manage it via /api/pac-config`)
	case !ValidIdentifier(p.ID):
		add(IssueInvalidID, fmt.Sprintf("profile ID %q must match [a-z0-9][a-z0-9-]{0,63}", p.ID))
	case seen[p.ID]:
		add(IssueDuplicateID, fmt.Sprintf("duplicate profile ID %q", p.ID))
	default:
		seen[p.ID] = true
	}
	if p.Name == "" {
		add(IssueInvalidRule, "profile name must not be empty")
	}
	if !pools[p.PoolID] {
		add(IssueUnknownPool, fmt.Sprintf("profile references unknown pool %q", p.PoolID))
	}
	validateProfileModes(p, add)
	if len(p.Rules) > MaxRulesPerProfile {
		add(IssueTooManyRules, fmt.Sprintf("%d rules exceed the maximum of %d", len(p.Rules), MaxRulesPerProfile))
	}
	for ri := range p.Rules {
		if is := validateRule(&p.Rules[ri], ri, entry, pools); is != nil {
			issues = append(issues, *is)
		}
	}
	return issues
}

// validateProfileModes checks the availability/private-network enums and the
// secure-mode contract: "no DIRECT ever" — explicit DIRECT rules (or a
// direct private-network bypass) contradict it. Balanced is the mode for
// chain-terminal-without-fallback plus explicit DIRECT carve-outs.
func validateProfileModes(p *Profile, add func(code, msg string)) {
	switch p.AvailabilityMode {
	case ModeSecure, ModeBalanced, ModeAvailability:
	default:
		add(IssueInvalidMode, fmt.Sprintf("availabilityMode %q must be secure, balanced, or availability", p.AvailabilityMode))
	}
	switch p.PrivateNetworks {
	case PrivateDirect, PrivateProxy:
	default:
		add(IssueInvalidMode, fmt.Sprintf("privateNetworks %q must be direct or proxy", p.PrivateNetworks))
	}
	if p.AvailabilityMode != ModeSecure {
		return
	}
	if p.PrivateNetworks == PrivateDirect {
		add(IssueSecureModeConflict, "secure mode cannot combine with privateNetworks=direct (use balanced for explicit DIRECT carve-outs)")
	}
	for ri := range p.Rules {
		if p.Rules[ri].Action == ActionDirect {
			add(IssueSecureModeConflict, fmt.Sprintf("secure mode forbids DIRECT rules (rule %d); use balanced", ri+1))
			return
		}
	}
}

func validateRule(r *Rule, idx int, entry string, pools map[string]bool) *ValidationIssue {
	bad := func(msg string) *ValidationIssue {
		return &ValidationIssue{Field: "profiles", Entry: fmt.Sprintf("%s rule %d", entry, idx+1),
			Code: IssueInvalidRule, Message: msg}
	}
	switch r.Action {
	case ActionDirect:
		if r.PoolID != "" {
			return bad("a DIRECT rule must not reference a pool")
		}
	case ActionUsePool:
		if r.PoolID != "" && !pools[r.PoolID] {
			return bad(fmt.Sprintf("rule references unknown pool %q", r.PoolID))
		}
	default:
		return bad(fmt.Sprintf("action %q must be use_pool or direct", r.Action))
	}
	if r.Scheme != "" && r.Scheme != "http" && r.Scheme != "https" {
		return bad(fmt.Sprintf("scheme %q must be empty, http, or https", r.Scheme))
	}
	if r.Port < 0 || r.Port > 65535 {
		return bad(fmt.Sprintf("port %d is outside 0-65535 (0 = any)", r.Port))
	}
	return validateRulePattern(r, bad)
}

func validateRulePattern(r *Rule, bad func(string) *ValidationIssue) *ValidationIssue {
	pattern := strings.TrimSpace(r.Pattern)
	if pattern == "" || len(pattern) > MaxEntryLen || hasControlOrSpace(pattern) {
		return bad(fmt.Sprintf("pattern %q must be 1-%d printable characters", r.Pattern, MaxEntryLen))
	}
	switch r.Kind {
	case RuleKindDomain, RuleKindSuffix:
		entryNorm, _, reject := normalizeExclusion(pattern)
		if reject != nil || (entryNorm.Kind != KindDomain && entryNorm.Kind != KindHostLiteral) {
			return bad(fmt.Sprintf("pattern %q is not a valid domain or IP", pattern))
		}
		if r.Kind == RuleKindSuffix && net.ParseIP(pattern) != nil {
			return bad("suffix rules cannot use an IP literal")
		}
		return nil
	case RuleKindWildcard:
		if !validGlobPattern(pattern) {
			return bad(fmt.Sprintf("wildcard pattern %q may contain only [a-zA-Z0-9.-_*]", pattern))
		}
		return nil
	case RuleKindCIDR4:
		if _, _, reject := normalizeCIDR(pattern); reject != nil {
			return bad(fmt.Sprintf("pattern %q is not a valid IPv4 CIDR", pattern))
		}
		return nil
	default:
		return bad(fmt.Sprintf("kind %q must be domain, suffix, wildcard, or cidr4", r.Kind))
	}
}

// validGlobPattern pins the shExpMatch glob alphabet:
// letters/digits/dots/hyphens/underscores/stars only (question marks
// excluded: WinINET's translation is inconsistent).
func validGlobPattern(pattern string) bool {
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') &&
			c != '.' && c != '-' && c != '_' && c != '*' {
			return false
		}
	}
	return true
}
