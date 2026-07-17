package pac

// impact.go — change diff + bounded impact analysis for safe publishing
// (initiative PR 3). DiffProfiles explains what a publish would change;
// ImpactReport replays sampled destinations through the active vs candidate
// revisions and categorizes the movement. Both are pure and reuse the
// Simulate evaluator, so impact classification cannot drift from what the
// compiler emits.

// ProfileDiff is the structured change set between two profile revisions.
type ProfileDiff struct {
	RulesAdded         []string `json:"rulesAdded,omitempty"`
	RulesRemoved       []string `json:"rulesRemoved,omitempty"`
	RulesReordered     bool     `json:"rulesReordered"`
	PoolChanged        bool     `json:"poolChanged"`
	OldPool            string   `json:"oldPool,omitempty"`
	NewPool            string   `json:"newPool,omitempty"`
	AvailabilityChange string   `json:"availabilityChange,omitempty"` // "old→new"
	PrivateNetChange   string   `json:"privateNetChange,omitempty"`
	NewDirectPaths     []string `json:"newDirectPaths,omitempty"`
	RemovedDirectPaths []string `json:"removedDirectPaths,omitempty"`
	// SecuritySensitive is true when the change widens DIRECT exposure,
	// weakens availability toward fail-open, or flips private-network to
	// direct — the changes a reviewer must look at first.
	SecuritySensitive bool `json:"securitySensitive"`
}

// DiffProfiles computes the change set from old to new. hasOld=false treats
// new as an initial publish (everything is "added").
func DiffProfiles(old Profile, hasOld bool, next Profile) ProfileDiff {
	var d ProfileDiff
	if !hasOld {
		for i := range next.Rules {
			d.RulesAdded = append(d.RulesAdded, ruleDesc(&next.Rules[i], i))
		}
		d.NewPool = next.PoolID
		d.PoolChanged = true
		d.AvailabilityChange = "(new) → " + next.AvailabilityMode
		d.PrivateNetChange = "(new) → " + next.PrivateNetworks
		d.NewDirectPaths = newDirectPaths(next, Profile{}, false)
		d.SecuritySensitive = len(d.NewDirectPaths) > 0 || next.AvailabilityMode == ModeAvailability
		return d
	}

	// Added/removed use the SPEC-identity key (match tuple + action + pool
	// override) so an in-place action or pool-override change surfaces as a
	// removal of the old spec and an addition of the new one. Reorder and
	// shadow detection below deliberately stay on the match-only ruleKey — a
	// same-match rule with a different action still shadows a later rule and is
	// still the "same slot" for ordering.
	oldKeys := ruleSpecKeySet(old.Rules)
	newKeys := ruleSpecKeySet(next.Rules)
	for i := range next.Rules {
		if !oldKeys[ruleSpecKey(&next.Rules[i])] {
			d.RulesAdded = append(d.RulesAdded, ruleDesc(&next.Rules[i], i))
		}
	}
	for i := range old.Rules {
		if !newKeys[ruleSpecKey(&old.Rules[i])] {
			d.RulesRemoved = append(d.RulesRemoved, ruleDesc(&old.Rules[i], i))
		}
	}
	d.RulesReordered = rulesReordered(old.Rules, next.Rules)
	if old.PoolID != next.PoolID {
		d.PoolChanged = true
		d.OldPool, d.NewPool = old.PoolID, next.PoolID
	}
	if old.AvailabilityMode != next.AvailabilityMode {
		d.AvailabilityChange = old.AvailabilityMode + " → " + next.AvailabilityMode
	}
	if old.PrivateNetworks != next.PrivateNetworks {
		d.PrivateNetChange = old.PrivateNetworks + " → " + next.PrivateNetworks
	}
	d.NewDirectPaths = newDirectPaths(next, old, true)
	d.RemovedDirectPaths = newDirectPaths(old, next, true) // symmetric: DIRECT present in old, gone in new
	d.SecuritySensitive = len(d.NewDirectPaths) > 0 ||
		(old.AvailabilityMode != ModeAvailability && next.AvailabilityMode == ModeAvailability) ||
		(old.PrivateNetworks != PrivateDirect && next.PrivateNetworks == PrivateDirect)
	return d
}

func ruleKeySet(rules []Rule) map[string]bool {
	m := make(map[string]bool, len(rules))
	for i := range rules {
		m[ruleKey(&rules[i])] = true
	}
	return m
}

// ruleSpecKey extends the match-only ruleKey with the routing spec (action +
// pool override) so the added/removed diff distinguishes an in-place action or
// pool-override change (same match tuple) that ruleKey alone would report as
// "unchanged".
func ruleSpecKey(r *Rule) string {
	return ruleKey(r) + "|" + r.Action + "|" + r.PoolID
}

func ruleSpecKeySet(rules []Rule) map[string]bool {
	m := make(map[string]bool, len(rules))
	for i := range rules {
		m[ruleSpecKey(&rules[i])] = true
	}
	return m
}

func ruleDesc(r *Rule, idx int) string {
	s := "rule " + itoa(idx+1) + " (" + r.Kind + " " + r.Pattern
	if r.Scheme != "" {
		s += " scheme=" + r.Scheme
	}
	if r.Port != 0 {
		s += " port=" + itoa(r.Port)
	}
	return s + " → " + r.Action + ")"
}

// rulesReordered reports whether the shared rules appear in a different
// relative order (ignoring pure additions/removals).
func rulesReordered(a, b []Rule) bool {
	var aq, bq []string
	bSet := ruleKeySet(b)
	for i := range a {
		if bSet[ruleKey(&a[i])] {
			aq = append(aq, ruleKey(&a[i]))
		}
	}
	aSet := ruleKeySet(a)
	for i := range b {
		if aSet[ruleKey(&b[i])] {
			bq = append(bq, ruleKey(&b[i]))
		}
	}
	if len(aq) != len(bq) {
		return false // membership already differs; not a reorder
	}
	for i := range aq {
		if aq[i] != bq[i] {
			return true
		}
	}
	return false
}

// ImpactCategory classifies how one destination moves between revisions.
type ImpactCategory = string

// Impact categories.
const (
	ImpactUnchanged      = "unchanged"
	ImpactPoolChanged    = "pool_changed"
	ImpactBecameDirect   = "became_direct"
	ImpactNoLongerDirect = "no_longer_direct"
	ImpactLostProxy      = "lost_proxy_path"
	ImpactUndetermined   = "undetermined_dns"
)

// DestinationImpact is one sampled destination's movement.
type DestinationImpact struct {
	Host         string         `json:"host"`
	Category     ImpactCategory `json:"category"`
	OldDirective string         `json:"oldDirective"`
	NewDirective string         `json:"newDirective"`
}

// ImpactReport summarizes a candidate publish against the active revision
// over a sample of destinations.
type ImpactReport struct {
	// Source names where the sample came from ("observed" | "test_vectors").
	Source string `json:"source"`
	// Sampled is how many destinations were evaluated.
	Sampled int `json:"sampled"`
	// Counts is the per-category tally.
	Counts map[string]int `json:"counts"`
	// Movements lists the destinations that changed (unchanged omitted).
	Movements []DestinationImpact `json:"movements"`
	// UnreachableRules/ShadowedRules/DuplicateRules are static analysis of
	// the candidate's rule list, independent of the sample.
	UnreachableRules []string `json:"unreachableRules,omitempty"`
	ShadowedRules    []string `json:"shadowedRules,omitempty"`
	DuplicateRules   []string `json:"duplicateRules,omitempty"`
	// Notes carries caveats (e.g. CIDR outcomes undetermined without IPs).
	Notes []string `json:"notes,omitempty"`
}

// AnalyzeImpact replays sample hosts through active vs candidate and
// categorizes movement. pools is the current pool map. sampleSource labels
// the origin. Hosts are plain hostnames (no resolved IPs), so cidr4/private
// outcomes are reported as undetermined rather than guessed.
func AnalyzeImpact(active Profile, hasActive bool, candidate Profile, pools map[string]Pool, sample []string, sampleSource string) ImpactReport {
	rep := ImpactReport{Source: sampleSource, Counts: map[string]int{}}
	rep.ShadowedRules, rep.DuplicateRules = analyzeRuleList(candidate.Rules)
	if hasCIDRRule(candidate.Rules) || candidate.PrivateNetworks == PrivateDirect {
		rep.Notes = append(rep.Notes, "cidr4 and private-network outcomes are undetermined for hostname-only samples (no resolved IPs)")
	}
	seen := map[string]bool{}
	for _, h := range sample {
		host := normalizeSimHost(h)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		rep.Sampled++
		in := SimInput{Host: host}
		var oldRes SimResult
		if hasActive {
			oldRes = Simulate(active, pools, in)
		}
		newRes := Simulate(candidate, pools, in)
		cat := classifyMovement(oldRes, hasActive, newRes)
		rep.Counts[cat]++
		if cat != ImpactUnchanged {
			rep.Movements = append(rep.Movements, DestinationImpact{
				Host: host, Category: cat,
				OldDirective: oldRes.Directive, NewDirective: newRes.Directive,
			})
		}
	}
	return rep
}

func classifyMovement(oldRes SimResult, hasActive bool, newRes SimResult) ImpactCategory {
	if newRes.Outcome == OutcomeUndeterminedDNS || (hasActive && oldRes.Outcome == OutcomeUndeterminedDNS) {
		return ImpactUndetermined
	}
	if !hasActive {
		if isDirect(newRes.Directive) {
			return ImpactBecameDirect
		}
		return ImpactPoolChanged
	}
	oldDirect, newDirect := isDirect(oldRes.Directive), isDirect(newRes.Directive)
	switch {
	case oldRes.Directive == newRes.Directive:
		return ImpactUnchanged
	case hasProxyPath(oldRes.Directive) && !hasProxyPath(newRes.Directive) && !newDirect:
		// Was proxied, now has neither a proxy path nor DIRECT — a
		// fail-closed dead end (e.g. secure mode with an unresolvable pool).
		return ImpactLostProxy
	case !oldDirect && newDirect:
		return ImpactBecameDirect
	case oldDirect && !newDirect:
		return ImpactNoLongerDirect
	default:
		return ImpactPoolChanged
	}
}

// isDirect reports whether a directive is a bare DIRECT (no proxy path at
// all). A chain ending in "; DIRECT" still has a proxy path first.
func isDirect(directive string) bool {
	return directive == "DIRECT"
}

// hasProxyPath reports whether a directive routes through at least one proxy
// (any "PROXY " entry). The secure-mode unresolvable placeholder is a
// PROXY directive but resolves nowhere — treat it as no usable path.
func hasProxyPath(directive string) bool {
	return containsSub(directive, "PROXY ") && !containsSub(directive, "unresolvable.invalid")
}

// analyzeRuleList finds shadowed (covered by an earlier broader rule) and
// exact-duplicate rules — static, sample-independent.
func analyzeRuleList(rules []Rule) (shadowed, duplicate []string) {
	seen := map[string]int{}
	for i := range rules {
		k := ruleKey(&rules[i])
		if first, ok := seen[k]; ok {
			duplicate = append(duplicate, ruleDesc(&rules[i], i)+" duplicates rule "+itoa(first+1))
			continue
		}
		seen[k] = i
	}
	// Shadowing: a later rule whose match set is a subset of an earlier
	// same-guard rule of the SAME action can never fire. Detect the common
	// cases: an earlier suffix/domain that covers a later domain/suffix.
	for j := range rules {
		for i := 0; i < j; i++ {
			if ruleShadows(&rules[i], &rules[j]) {
				shadowed = append(shadowed, ruleDesc(&rules[j], j)+" is shadowed by rule "+itoa(i+1))
				break
			}
		}
	}
	return shadowed, duplicate
}

// ruleShadows reports whether earlier rule a makes later rule b unreachable.
// Conservative: only flags clear suffix/domain coverage with matching
// scheme/port guards.
func ruleShadows(a, b *Rule) bool {
	if a.Scheme != b.Scheme || a.Port != b.Port {
		return false
	}
	ae, _, ar := normalizeExclusion(a.Pattern)
	be, _, br := normalizeExclusion(b.Pattern)
	if ar != nil || br != nil {
		return false
	}
	// An earlier suffix ".x" shadows any later domain/suffix ending in ".x".
	if a.Kind == RuleKindSuffix && (b.Kind == RuleKindSuffix || b.Kind == RuleKindDomain) {
		return be.Host == ae.Host || hasDotSuffix(be.Host, ae.Host)
	}
	// An earlier domain "x" (exact+subdomains) shadows a later suffix/domain of x.
	if a.Kind == RuleKindDomain && (b.Kind == RuleKindDomain || b.Kind == RuleKindSuffix) {
		return be.Host == ae.Host || hasDotSuffix(be.Host, ae.Host)
	}
	return false
}

func hasDotSuffix(host, suffix string) bool {
	return len(host) > len(suffix)+1 && host[len(host)-len(suffix)-1] == '.' &&
		host[len(host)-len(suffix):] == suffix
}

func hasCIDRRule(rules []Rule) bool {
	for i := range rules {
		if rules[i].Kind == RuleKindCIDR4 {
			return true
		}
	}
	return false
}
