package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3 Slice 5 — SSORequired + auth-rule shadow/overlap diagnostics.
//
// All functions here are REPORT-ONLY: they never mutate rules, never touch the
// request path, and only build OperatorContractCheck rows (warn/fail). They are
// pure over the supplied ruleset plus the two environmental facts they read
// (UnauthMode and the live IdP registry via eligibleSSOProviders / idpRegistry).
// ─────────────────────────────────────────────────────────────────────────────

// authSSORequiredDiagnostics reports operator risks for SSORequired (SSO) Stage-1
// rules. It mirrors authCredentialRequiredDiagnostics. Returns nil when no SSO
// rules exist. Codes/severities:
//   - auth_sso_no_idp                  FAIL — SSO rules but zero enabled interactive IdPs.
//   - auth_sso_rule_no_eligible_provider FAIL — a rule's providerRefs resolve to none.
//   - auth_sso_providerref_unavailable WARN — some (not all) refs disabled/deleted.
//   - auth_sso_dead_under_unauth_mode  WARN — SSO rules dead under UnauthMode.
//   - auth_sso_may_match_non_browser   WARN — protocol "" / connect can match non-browsers.
//   - auth_sso_ambiguous_idp           WARN — multiple IdPs + empty providerRefs.
func authSSORequiredDiagnostics(rules []PolicyRule, unauthMode bool) []OperatorContractCheck {
	var ssoRules []*PolicyRule
	for i := range rules {
		r := &rules[i]
		if ruleTypeOf(r) != ruleTypeAuth || r.Auth == nil || r.Auth.Outcome != OutcomeSSORequired {
			continue
		}
		// Disabled or already-expired rules cannot fire (authRuleMatches checks
		// ruleIsEnabled + authRuleNotExpired), so they must not produce findings —
		// otherwise an inert rule could falsely FAIL the operator contract.
		if !ruleIsEnabled(r) || !authRuleNotExpired(r.Auth) {
			continue
		}
		ssoRules = append(ssoRules, r)
	}
	if len(ssoRules) == 0 {
		return nil
	}

	var checks []OperatorContractCheck
	allEligible := eligibleSSOProviders(nil) // all enabled interactive IdPs

	if len(allEligible) == 0 {
		checks = append(checks, OperatorContractCheck{
			Code:           "auth_sso_no_idp",
			Status:         diagFail,
			Message:        "SSORequired rules exist but no enabled interactive (OIDC/SAML) IdP is configured — every covered browser redirects into nothing and every non-browser is failed closed (403): " + ruleNameList(ssoRules),
			OperatorAction: "Enable at least one OIDC or SAML identity provider, or remove the SSORequired rules.",
		})
	}
	if unauthMode {
		checks = append(checks, OperatorContractCheck{
			Code:           "auth_sso_dead_under_unauth_mode",
			Status:         diagWarn,
			Message:        "SSORequired rules cannot fire while the proxy is in UnauthMode (the auth gate is skipped): " + ruleNameList(ssoRules),
			OperatorAction: "Disable UnauthMode under Settings if these rules should enforce SSO, or remove the rules.",
		})
	}
	checks = append(checks, ssoProviderRefChecks(ssoRules, len(allEligible))...)
	return checks
}

// ssoRefBuckets collects the per-rule providerRef / scope risk categories.
type ssoRefBuckets struct {
	deadRules, unavailable, nonBrowser []string
	ambiguous                          bool
}

// classifySSORefRisks buckets each SSO rule by its providerRef availability and
// non-browser scope. Pure; never mutates the rules. Split out of
// ssoProviderRefChecks to keep cognitive complexity low.
func classifySSORefRisks(ssoRules []*PolicyRule, eligibleCount int) ssoRefBuckets {
	var b ssoRefBuckets
	for _, r := range ssoRules {
		refs := r.Auth.ProviderRefs
		switch bad := unavailableSSORefs(refs); {
		case len(refs) == 0:
			if eligibleCount > 1 {
				b.ambiguous = true
			}
		case len(bad) == len(refs):
			b.deadRules = append(b.deadRules, ruleLabel(r)+" [dead refs: "+strings.Join(bad, ", ")+"]")
		case len(bad) > 0:
			b.unavailable = append(b.unavailable, ruleLabel(r)+" [unavailable: "+strings.Join(bad, ", ")+"]")
		}
		if p := r.Auth.Protocol; p == "" || p == "connect" {
			b.nonBrowser = append(b.nonBrowser, ruleLabel(r))
		}
	}
	return b
}

// ssoProviderRefChecks emits the per-rule providerRef / non-browser / ambiguity
// rows from the classified buckets.
func ssoProviderRefChecks(ssoRules []*PolicyRule, eligibleCount int) []OperatorContractCheck {
	b := classifySSORefRisks(ssoRules, eligibleCount)
	deadRules, unavailable, nonBrowser, ambiguous := b.deadRules, b.unavailable, b.nonBrowser, b.ambiguous

	var checks []OperatorContractCheck
	if len(deadRules) > 0 {
		checks = append(checks, OperatorContractCheck{
			Code:           "auth_sso_rule_no_eligible_provider",
			Status:         diagFail,
			Message:        "SSORequired rules name providerRefs that resolve to NO enabled interactive IdP — these rules always fail closed (403) for every matched client: " + strings.Join(deadRules, "; "),
			OperatorAction: "Fix the providerRefs to name enabled OIDC/SAML profiles, clear providerRefs to use all compatible IdPs, or remove the rules.",
		})
	}
	if len(unavailable) > 0 {
		checks = append(checks, OperatorContractCheck{
			Code:           "auth_sso_providerref_unavailable",
			Status:         diagWarn,
			Message:        "SSORequired rules reference disabled/deleted IdP profiles (other eligible providers remain, so the rules still function): " + strings.Join(unavailable, "; "),
			OperatorAction: "Re-enable the referenced IdP, update providerRefs, or accept the narrowed provider set.",
		})
	}
	if len(nonBrowser) > 0 {
		checks = append(checks, OperatorContractCheck{
			Code:           "auth_sso_may_match_non_browser",
			Status:         diagWarn,
			Message:        `SSORequired rules with protocol "" (any) or "connect" can match non-browser/CONNECT traffic, which is failed closed (403) — those clients cannot complete an interactive SSO flow: ` + strings.Join(nonBrowser, ", "),
			OperatorAction: "Scope these rules to browser sources / protocol http, or pair them with a CredentialRequired rule for service clients.",
		})
	}
	if ambiguous {
		checks = append(checks, OperatorContractCheck{
			Code:           "auth_sso_ambiguous_idp",
			Status:         diagWarn,
			Message:        "Multiple interactive IdPs are enabled and one or more SSORequired rules have empty providerRefs — matched browsers see the provider selection page rather than a direct redirect (low severity).",
			OperatorAction: "Set providerRefs to a single IdP for a direct redirect, or accept the selection page.",
		})
	}
	return checks
}

// unavailableSSORefs returns the refs that do NOT resolve to an enabled
// interactive (OIDC/SAML) IdP profile (disabled, deleted, or wrong type).
func unavailableSSORefs(refs []string) []string {
	var out []string
	for _, ref := range refs {
		id := strings.TrimSpace(ref)
		if idpRegistry == nil {
			out = append(out, id)
			continue
		}
		p := idpRegistry.Get(id)
		if p == nil || !p.Enabled || (p.Type != IdPTypeOIDC && p.Type != IdPTypeSAML) {
			out = append(out, id)
		}
	}
	return out
}

// maxShadowFindings caps shadow rows so a pathological ruleset can't flood the
// operator contract.
const maxShadowFindings = 25

// authRuleShadowDiagnostics reports auth rules that are conservatively shadowed
// by an earlier (higher-priority) matching auth rule. One finding per shadowed
// rule (the highest-priority shadower). REPORT-ONLY; never mutates rules.
//
// CONSERVATIVE / BEST-EFFORT — documented limits:
//   - Only ENABLED, non-expired auth rules are considered.
//   - Containment is computed only on dimensions we can cheaply prove:
//     source CIDRs (containment + intersection), destination (exact FQDN, simple
//     "*.x" wildcard suffix, or SAME category / category-group name), and
//     protocol/method. A rule whose shadower carries a Schedule or ExpiresAt is
//     downgraded full→partial (the shadower is not always active).
//   - It does NOT resolve category/group MEMBERSHIP, CIDR overlaps that are not
//     containment, wildcard-vs-FQDN beyond a simple suffix, or schedule-window
//     overlap. It favors precision (few false positives); it will MISS some real
//     shadows (false negatives). Absence of a warning is NOT a guarantee of no
//     shadow.
func authRuleShadowDiagnostics(rules []PolicyRule) []OperatorContractCheck {
	var auth []*PolicyRule
	for i := range rules {
		r := &rules[i]
		if ruleTypeOf(r) != ruleTypeAuth || r.Auth == nil || !ruleIsEnabled(r) {
			continue
		}
		if !authRuleNotExpired(r.Auth) { // skip already-expired rules
			continue
		}
		auth = append(auth, r)
	}
	sort.SliceStable(auth, func(i, j int) bool { return auth[i].Priority < auth[j].Priority })

	var checks []OperatorContractCheck
	for bi := 1; bi < len(auth) && len(checks) < maxShadowFindings; bi++ {
		for ai := 0; ai < bi; ai++ {
			covered, full := authRuleCovers(auth[ai], auth[bi])
			if !covered {
				continue
			}
			checks = append(checks, OperatorContractCheck{
				Code:           "auth_rule_shadowed",
				Status:         diagWarn,
				Message:        shadowMessage(auth[ai], auth[bi], full),
				OperatorAction: "Reorder or scope the rules so the intended outcome wins (priority is the only tie-breaker), or remove the redundant rule.",
			})
			break // one finding per shadowed rule
		}
	}
	return checks
}

// scheduleEffectivelyAlwaysActive reports whether a schedule is always active:
// nil (no schedule field) or an all-zero struct (e.g. JSON {"schedule":{}}) with
// a parseable (or absent) timezone. It mirrors the two runtime gates that would
// prevent a rule from ever firing:
//   - authScheduleParseable: an invalid IANA timezone causes authRuleMatches to
//     fail closed, so that rule never shadows anything regardless of days/times.
//   - matchSchedule: non-empty Days or TimeStart+TimeEnd constrain firing windows.
func scheduleEffectivelyAlwaysActive(s *PolicySchedule) bool {
	if s == nil {
		return true
	}
	// An unparseable timezone fails closed at runtime (authRuleMatches →
	// authScheduleParseable). Such a rule never fires, so it is not a full shadower.
	if !authScheduleParseable(s) {
		return false
	}
	return len(s.Days) == 0 && s.TimeStart == "" && s.TimeEnd == ""
}

// authRuleCovers reports whether higher-priority rule a conservatively shadows
// lower-priority rule b, and whether the shadow is full (b can never fire).
func authRuleCovers(a, b *PolicyRule) (covered, full bool) {
	if !protoMethodCovers(a.Auth, b.Auth) || !destCovers(a, b) {
		return false, false
	}
	fullSubject := subjectFullyContained(a.SubjectMatch, b.SubjectMatch)
	if !fullSubject && !subjectsOverlap(a.SubjectMatch, b.SubjectMatch) {
		return false, false
	}
	// A full shadow needs full subject containment AND an always-active shadower.
	if fullSubject && scheduleEffectivelyAlwaysActive(a.Schedule) && a.Auth.ExpiresAt == "" {
		return true, true
	}
	return true, false
}

// protoMethodCovers reports whether a's protocol/method scope is a superset of
// b's. Empty ("any") covers anything; otherwise an exact match is required.
func protoMethodCovers(a, b *AuthRuleSpec) bool {
	if a.Protocol != "" && !strings.EqualFold(a.Protocol, b.Protocol) {
		return false
	}
	// Method is meaningless for connect; only compare for non-connect scopes.
	if a.Method != "" && a.Protocol != "connect" && !strings.EqualFold(a.Method, b.Method) {
		return false
	}
	return true
}

// destCovers reports whether a's destination selector covers b's, using only
// cheap/provable forms (see the function-doc limits).
func destCovers(a, b *PolicyRule) bool {
	if a.DestFQDN != "" {
		if b.DestFQDN == "" {
			return false
		}
		if a.DestFQDN == b.DestFQDN {
			return true
		}
		if strings.HasPrefix(a.DestFQDN, "*.") {
			suffix := a.DestFQDN[1:] // ".example.com"
			return b.DestFQDN == a.DestFQDN[2:] || strings.HasSuffix(b.DestFQDN, suffix)
		}
		return false
	}
	if a.DestCategory != "" && a.DestCategory != CategoryAny {
		return a.DestCategory == b.DestCategory
	}
	if a.DestCategoryGroup != "" {
		return a.DestCategoryGroup == b.DestCategoryGroup
	}
	return false
}

// subjectFullyContained reports whether every CIDR in b is contained within some
// CIDR in a (a's source scope is a superset of b's).
func subjectFullyContained(a, b *SubjectMatch) bool {
	bcidrs := subjectCIDRs(b)
	acidrs := subjectCIDRs(a)
	if len(bcidrs) == 0 || len(acidrs) == 0 {
		return false
	}
	for _, bc := range bcidrs {
		covered := false
		for _, ac := range acidrs {
			if cidrContains(ac, bc) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// subjectsOverlap reports whether any CIDR in a intersects any CIDR in b.
func subjectsOverlap(a, b *SubjectMatch) bool {
	for _, ac := range subjectCIDRs(a) {
		for _, bc := range subjectCIDRs(b) {
			if cidrsIntersect(ac, bc) {
				return true
			}
		}
	}
	return false
}

func subjectCIDRs(sm *SubjectMatch) []string {
	if sm == nil {
		return nil
	}
	var out []string
	for i := range sm.All {
		if sm.All[i].Type == subjectPredicateCIDR {
			out = append(out, sm.All[i].Values...)
		}
	}
	return out
}

// cidrContains reports whether the outer CIDR/IP fully contains the inner one.
func cidrContains(outer, inner string) bool {
	on, in := toIPNet(outer), toIPNet(inner)
	if on == nil || in == nil {
		return false
	}
	oOnes, oBits := on.Mask.Size()
	iOnes, iBits := in.Mask.Size()
	if oBits != iBits || oOnes > iOnes {
		return false // different family, or outer is narrower than inner
	}
	return on.Contains(in.IP)
}

// cidrsIntersect reports whether two CIDRs/IPs overlap at all.
func cidrsIntersect(x, y string) bool {
	xn, yn := toIPNet(x), toIPNet(y)
	if xn == nil || yn == nil {
		return false
	}
	return xn.Contains(yn.IP) || yn.Contains(xn.IP)
}

// toIPNet parses a CIDR or bare IP into a normalized *net.IPNet (host routes for
// bare IPs), or nil on parse failure.
func toIPNet(s string) *net.IPNet {
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil
		}
		if ip4 := ip.To4(); ip4 != nil {
			return &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil
	}
	return n
}

// ── message helpers ──────────────────────────────────────────────────────────

func shadowMessage(a, b *PolicyRule, full bool) string {
	verb := "partially shadows"
	if full {
		verb = "fully shadows (the lower-priority rule can never fire)"
	}
	msg := fmt.Sprintf("auth rule %s %s lower-priority %s", ruleRef(a), verb, ruleRef(b))
	if b.Auth.Outcome == OutcomeExempt &&
		(a.Auth.Outcome == OutcomeSSORequired || a.Auth.Outcome == OutcomeCredentialRequired) {
		msg += " — traffic the Exempt rule would waive is instead " + challengeOutcomeVerb(a.Auth.Outcome) +
			"; non-auth-capable devices relying on the exemption may break"
	}
	return msg
}

func challengeOutcomeVerb(o AuthOutcome) string {
	if o == OutcomeSSORequired {
		return "redirected to SSO (browsers) or failed closed (403, non-browsers)"
	}
	return "challenged for credentials (407)"
}

func ruleRef(r *PolicyRule) string {
	return fmt.Sprintf("%q (id=%s priority=%d outcome=%s)", r.Name, r.ID, r.Priority, r.Auth.Outcome)
}

// ruleLabel is a compact name#priority label for list messages.
func ruleLabel(r *PolicyRule) string {
	return fmt.Sprintf("%s#%d", r.Name, r.Priority)
}

// ruleNameList renders the rule names for an aggregate message.
func ruleNameList(rules []*PolicyRule) string {
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		names = append(names, r.Name)
	}
	return strings.Join(names, ", ")
}
