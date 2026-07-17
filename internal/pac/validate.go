package pac

// validate.go — typed validation + normalization for the PAC configuration.
//
// Two entry points share one per-entry core:
//
//   - ValidateConfig (STRICT): every malformed entry is a hard error with an
//     actionable message. Used ONLY at the admin API boundary
//     (POST /api/pac-config) and the config-import pre-validation pass.
//   - NormalizeLenient (TOLERANT): malformed entries are dropped and surfaced
//     as warnings. Used by every replay path — Store load, PAC compilation,
//     config-version rollback, and cluster snapshot apply — so historically
//     persisted junk can never wedge a rollback or DP sync.
//
// The strict/tolerant split is a reviewed design decision: strictness must
// never live in Store.Set, whose callers (configversion.go, cluster apply)
// discard errors.

import (
	"fmt"
	"net"
	"strings"

	"github.com/KidCarmi/Culvert/internal/hostutil"
)

// Validation limits. MaxExclusionEntries mirrors the cluster snapshot cap
// (maxSnapPACExclusions in controlplane_snapshot.go) so a config that
// validates here can always ride a ConfigSnapshot.
const (
	MaxExclusionEntries = 10000
	// MaxEntryLen matches the DNS name length bound (RFC 1035).
	MaxEntryLen = 253
	// MaxArtifactBytes is the hard compiled-output budget. Chromium rejects
	// PAC scripts over 1 MiB at fetch time, so a config that compiles past
	// that is undeliverable and must be rejected, not served.
	MaxArtifactBytes = 1 << 20
	// WarnArtifactBytes is the advisory compiled-output budget.
	WarnArtifactBytes = 512 << 10
)

// ValidationIssue codes. Stable strings — they are part of the admin API
// response shape.
const (
	IssueEmptyEntry       = "empty_entry"
	IssueControlChars     = "control_chars"
	IssueEntryTooLong     = "entry_too_long"
	IssueTooManyEntries   = "too_many_exclusions"
	IssueInvalidCIDR      = "invalid_cidr"
	IssueInvalidWildcard  = "invalid_wildcard"
	IssueInvalidHost      = "invalid_host"
	IssueInvalidPort      = "invalid_port"
	IssueInvalidProxyHost = "invalid_proxy_host"
	IssueDuplicateEntry   = "duplicate_entry"
	IssueHostFallback     = "proxy_host_fallback"
	IssueCIDRNormalized   = "cidr_normalized"
	IssueOutputTooLarge   = "output_too_large"
	IssueOutputLarge      = "output_large"
)

// ValidationIssue is one actionable validation error or warning.
type ValidationIssue struct {
	// Field names the config field: "proxyHost", "proxyPort", "exclusions".
	Field string `json:"field"`
	// Entry is the offending exclusion entry, when applicable.
	Entry string `json:"entry,omitempty"`
	// Code is a stable machine-readable issue code (Issue* constants).
	Code string `json:"code"`
	// Message is the human-readable explanation.
	Message string `json:"message"`
}

// ExclusionKind classifies a normalized exclusion entry.
type ExclusionKind int

// Exclusion kinds, in compiler emission group order.
const (
	// KindDomain matches the exact host and all subdomains (legacy bare-domain
	// semantics: host === "x" || dnsDomainIs(host, ".x")).
	KindDomain ExclusionKind = iota
	// KindWildcard matches subdomains only ("*.x" → dnsDomainIs(host, ".x")).
	KindWildcard
	// KindHostLiteral matches one IP literal exactly (host === "x").
	KindHostLiteral
	// KindCIDR matches when the resolved IP falls in an IPv4 network.
	KindCIDR
)

// NormalizedExclusion is one exclusion entry in canonical form.
type NormalizedExclusion struct {
	Kind ExclusionKind
	// Host is the lowercased, IDNA-punycoded, trailing-dot-stripped hostname
	// (KindDomain/KindWildcard, without the "*." prefix) or the IP literal
	// text (KindHostLiteral).
	Host string
	// CIDRIP/CIDRMask/CIDRPrefix carry the parsed IPv4 network (KindCIDR).
	// CIDRIP is the masked network base address.
	CIDRIP     string
	CIDRMask   string
	CIDRPrefix int
	// Raw is the entry as configured (trimmed), for error reporting.
	Raw string
}

// Canonical returns the canonical config-file text for the entry — the form
// persisted after a strictly validated mutation.
func (e NormalizedExclusion) Canonical() string {
	switch e.Kind {
	case KindWildcard:
		return "*." + e.Host
	case KindCIDR:
		return fmt.Sprintf("%s/%d", e.CIDRIP, e.CIDRPrefix)
	default:
		return e.Host
	}
}

// dedupeKey is the identity used for duplicate detection.
func (e NormalizedExclusion) dedupeKey() string {
	return fmt.Sprintf("%d|%s", e.Kind, e.Canonical())
}

// Normalized is the canonical, validated form of a Config. It is the single
// input shape the compiler consumes.
type Normalized struct {
	// ProxyHost is the validated proxy hostname/IP, or "" when the request
	// Host header fallback is in effect.
	ProxyHost string
	// ProxyPort is the configured port (0 = auto: startup default, then 8080).
	ProxyPort int
	// Exclusions preserves configured order with duplicates removed.
	Exclusions []NormalizedExclusion
	// Warnings collects non-fatal normalization notes (dropped entries in
	// lenient mode, dedupes, host-fallback advisory).
	Warnings []ValidationIssue
}

// ValidateConfig strictly validates and normalizes c. The returned issue list
// is non-empty exactly when the config must be rejected; warnings that do not
// reject (dedupe, host-fallback advisory) are on the returned Normalized.
func ValidateConfig(c Config) (Normalized, []ValidationIssue) {
	return normalizeConfig(c, true)
}

// NormalizeLenient normalizes c tolerantly: malformed entries are dropped and
// recorded as warnings, never errors. Replay-path safe.
func NormalizeLenient(c Config) Normalized {
	n, _ := normalizeConfig(c, false)
	return n
}

// normalizeConfig is the shared core. In strict mode entry problems become
// hard issues; in lenient mode they become warnings and the entry is dropped.
func normalizeConfig(c Config, strict bool) (Normalized, []ValidationIssue) {
	var n Normalized
	var issues []ValidationIssue

	fail := func(is ValidationIssue) {
		if strict {
			issues = append(issues, is)
		} else {
			n.Warnings = append(n.Warnings, is)
		}
	}

	normalizeScalars(c, &n, strict, fail)

	if len(c.Exclusions) > MaxExclusionEntries {
		fail(ValidationIssue{
			Field: "exclusions", Code: IssueTooManyEntries,
			Message: fmt.Sprintf("%d exclusions exceed the maximum of %d", len(c.Exclusions), MaxExclusionEntries),
		})
		if !strict {
			c.Exclusions = c.Exclusions[:MaxExclusionEntries]
		}
	}
	normalizeExclusions(c.Exclusions, &n, strict, fail)

	issues = appendSizeBudgetIssues(&n, strict, issues)
	return n, issues
}

// normalizeScalars applies host/port validation into n.
func normalizeScalars(c Config, n *Normalized, strict bool, fail func(ValidationIssue)) {
	n.ProxyHost, n.ProxyPort = c.ProxyHost, c.ProxyPort
	if hostIssue := validateProxyHost(c.ProxyHost); hostIssue != nil {
		fail(*hostIssue)
		if !strict {
			n.ProxyHost = ""
		}
	}
	if c.ProxyHost == "" {
		n.Warnings = append(n.Warnings, ValidationIssue{
			Field: "proxyHost", Code: IssueHostFallback,
			Message: "proxyHost is empty: /proxy.pac derives the proxy hostname from each request's Host header",
		})
	}
	if c.ProxyPort < 0 || c.ProxyPort > 65535 {
		fail(ValidationIssue{
			Field: "proxyPort", Code: IssueInvalidPort,
			Message: fmt.Sprintf("proxyPort %d is outside 0-65535 (0 = auto-detect)", c.ProxyPort),
		})
		if !strict {
			n.ProxyPort = 0
		}
	}
}

// normalizeExclusions parses, dedupes, and appends entries into n.
func normalizeExclusions(exclusions []string, n *Normalized, strict bool, fail func(ValidationIssue)) {
	seen := make(map[string]bool, len(exclusions))
	for _, raw := range exclusions {
		entry, warn, errIssue := normalizeExclusion(raw)
		if errIssue != nil {
			// Lenient mode: blank entries were always silently skipped by the
			// legacy generator — keep them warning-free to avoid noise.
			if !strict && strings.TrimSpace(raw) == "" {
				continue
			}
			fail(*errIssue)
			continue
		}
		if warn != nil {
			n.Warnings = append(n.Warnings, *warn)
		}
		key := entry.dedupeKey()
		if seen[key] {
			n.Warnings = append(n.Warnings, ValidationIssue{
				Field: "exclusions", Entry: entry.Raw, Code: IssueDuplicateEntry,
				Message: fmt.Sprintf("duplicate exclusion %q removed (same as an earlier entry)", entry.Raw),
			})
			continue
		}
		seen[key] = true
		n.Exclusions = append(n.Exclusions, entry)
	}
}

// appendSizeBudgetIssues enforces the compiled-output byte budget (strict
// mode only): Chromium rejects PAC scripts over 1 MiB at fetch time, so an
// oversized config is undeliverable and must be rejected at the API
// boundary. The tolerant replay path never rejects — an oversized legacy
// config keeps serving.
func appendSizeBudgetIssues(n *Normalized, strict bool, issues []ValidationIssue) []ValidationIssue {
	if !strict || len(issues) > 0 {
		return issues
	}
	size := len(compilePAC(*n, "PROXY size-probe.invalid:8080"))
	switch {
	case size > MaxArtifactBytes:
		issues = append(issues, ValidationIssue{
			Field: "exclusions", Code: IssueOutputTooLarge,
			Message: fmt.Sprintf("compiled PAC would be %d bytes; clients reject scripts over %d bytes — remove exclusions", size, MaxArtifactBytes),
		})
	case size > WarnArtifactBytes:
		n.Warnings = append(n.Warnings, ValidationIssue{
			Field: "exclusions", Code: IssueOutputLarge,
			Message: fmt.Sprintf("compiled PAC is %d bytes; large scripts slow PAC evaluation on some clients", size),
		})
	}
	return issues
}

// validateProxyHost checks the configured proxy host (empty = fallback mode,
// valid). Accepts a hostname or IP literal; rejects ports, schemes, control
// characters, and anything IDNA cannot canonicalize.
func validateProxyHost(host string) *ValidationIssue {
	if host == "" {
		return nil
	}
	bad := func(msg string) *ValidationIssue {
		return &ValidationIssue{Field: "proxyHost", Entry: host, Code: IssueInvalidProxyHost, Message: msg}
	}
	if len(host) > MaxEntryLen {
		return bad(fmt.Sprintf("proxy host exceeds %d characters", MaxEntryLen))
	}
	if hasControlOrSpace(host) {
		return bad("proxy host contains whitespace or control characters")
	}
	if strings.Contains(host, "/") || strings.Contains(host, "@") {
		return bad("proxy host must be a bare hostname or IP (no scheme, path, or credentials)")
	}
	trimmed := strings.Trim(host, "[]")
	if net.ParseIP(trimmed) != nil {
		return nil
	}
	if strings.Contains(host, ":") {
		return bad("proxy host must not include a port (set proxyPort instead)")
	}
	if _, ok := hostutil.NormalizeHostStrict(host); !ok {
		return bad("proxy host is not a valid hostname (IDNA normalization failed)")
	}
	return nil
}

// normalizeExclusion parses one raw exclusion entry into canonical form.
// warn is advisory (e.g. CIDR host-bits cleared); reject is the rejection
// issue (nil when the entry is valid).
func normalizeExclusion(raw string) (entry NormalizedExclusion, warn, reject *ValidationIssue) {
	trimmed := strings.TrimSpace(raw)
	bad := func(code, msg string) (NormalizedExclusion, *ValidationIssue, *ValidationIssue) {
		return NormalizedExclusion{}, nil, &ValidationIssue{Field: "exclusions", Entry: trimmed, Code: code, Message: msg}
	}
	switch {
	case trimmed == "":
		return bad(IssueEmptyEntry, "empty exclusion entry (remove blank lines)")
	case len(trimmed) > MaxEntryLen:
		return bad(IssueEntryTooLong, fmt.Sprintf("exclusion exceeds %d characters", MaxEntryLen))
	case hasControlOrSpace(trimmed):
		return bad(IssueControlChars, "exclusion contains whitespace or control characters")
	case strings.Contains(trimmed, "/"):
		return normalizeCIDR(trimmed)
	case strings.HasPrefix(trimmed, "*."):
		rest := trimmed[2:]
		if rest == "" || strings.Contains(rest, "*") {
			return bad(IssueInvalidWildcard, "wildcard exclusions must look like *.example.com")
		}
		norm, ok := hostutil.NormalizeHostStrict(rest)
		if !ok || norm == "" {
			return bad(IssueInvalidHost, fmt.Sprintf("%q is not a valid domain", rest))
		}
		return NormalizedExclusion{Kind: KindWildcard, Host: norm, Raw: trimmed}, nil, nil
	case strings.Contains(trimmed, "*"):
		return bad(IssueInvalidWildcard, "wildcard '*' is only allowed as a leading '*.' prefix")
	default:
		if ip := net.ParseIP(strings.Trim(trimmed, "[]")); ip != nil {
			return NormalizedExclusion{Kind: KindHostLiteral, Host: strings.ToLower(strings.Trim(trimmed, "[]")), Raw: trimmed}, nil, nil
		}
		norm, ok := hostutil.NormalizeHostStrict(trimmed)
		if !ok || norm == "" {
			return bad(IssueInvalidHost, fmt.Sprintf("%q is not a valid domain, IP, or CIDR", trimmed))
		}
		return NormalizedExclusion{Kind: KindDomain, Host: norm, Raw: trimmed}, nil, nil
	}
}

// normalizeCIDR parses an IPv4 CIDR entry, clearing host bits (with an
// advisory warning when they were set).
func normalizeCIDR(trimmed string) (entry NormalizedExclusion, warn, reject *ValidationIssue) {
	ip, ipnet, err := net.ParseCIDR(trimmed)
	if err != nil {
		return NormalizedExclusion{}, nil, &ValidationIssue{Field: "exclusions", Entry: trimmed, Code: IssueInvalidCIDR,
			Message: fmt.Sprintf("%q is not a valid CIDR (expected e.g. 192.168.0.0/16)", trimmed)}
	}
	if ipnet.IP.To4() == nil {
		return NormalizedExclusion{}, nil, &ValidationIssue{Field: "exclusions", Entry: trimmed, Code: IssueInvalidCIDR,
			Message: "only IPv4 CIDR exclusions are supported (PAC isInNet is IPv4-only)"}
	}
	prefix, _ := ipnet.Mask.Size()
	entry = NormalizedExclusion{
		Kind:       KindCIDR,
		CIDRIP:     ipnet.IP.String(),
		CIDRMask:   net.IP(ipnet.Mask).String(),
		CIDRPrefix: prefix,
		Raw:        trimmed,
	}
	if !ip.Mask(ipnet.Mask).Equal(ipnet.IP) || ip.String() != ipnet.IP.String() {
		warn = &ValidationIssue{Field: "exclusions", Entry: trimmed, Code: IssueCIDRNormalized,
			Message: fmt.Sprintf("CIDR %q normalized to network address %s/%d", trimmed, entry.CIDRIP, prefix)}
	}
	return entry, warn, nil
}

// hasControlOrSpace reports whether s contains ASCII control characters,
// spaces, or DEL — none of which appear in a valid host, CIDR, or wildcard.
func hasControlOrSpace(s string) bool {
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
