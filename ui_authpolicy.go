package main

import (
	"fmt"
	"net/http"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// Auth Policy admin API — Phase 1 Slice 8.
//
// CRUD + reorder for Stage-1 auth/exempt rules, kept on a DEDICATED endpoint:
// /api/policy rejects ruleType="auth" payloads, and this endpoint refuses to
// touch access rules. Writes are ADMIN-only (stricter than the operator-level
// access-policy API — an authentication waiver is a security-sensitive change);
// reads are viewer. No runtime behavior is added here: rules flow through the
// same validatePolicyRule → PolicyStore path the rest of the system uses, and
// the Stage-1 resolver wiring from Slice 7 is untouched.
// ─────────────────────────────────────────────────────────────────────────────

// authRuleView is a PolicyRule enriched with the non-fatal validation warnings
// (broad source, no destination ack, expired, …) so the UI can render risk
// badges without re-implementing validation client-side.
type authRuleView struct {
	PolicyRule
	Warnings []string `json:"warnings,omitempty"`
}

// listAuthRules returns the auth (Stage-1) subset of the policy store, each
// enriched with validateAuthRule warnings. Read-only.
func listAuthRules() []authRuleView {
	rules := policyStore.List()
	out := make([]authRuleView, 0, 4)
	for i := range rules {
		if ruleTypeOf(&rules[i]) != ruleTypeAuth {
			continue
		}
		warnings, _ := validateAuthRule(rules[i]) // stored rules already validated; surface warnings only
		out = append(out, authRuleView{PolicyRule: rules[i], Warnings: warnings})
	}
	return out
}

// findRuleByPriority returns a copy of the rule at the given priority, or nil.
func findRuleByPriority(priority int) *PolicyRule {
	rules := policyStore.List()
	for i := range rules { // index-based: PolicyRule is large (avoids rangeValCopy)
		if rules[i].Priority == priority {
			r := rules[i]
			return &r
		}
	}
	return nil
}

// normalizeIncomingAuthRule defaults an empty RuleType to "auth" and rejects
// anything else: this endpoint manages Stage-1 rules only.
func normalizeIncomingAuthRule(rule *PolicyRule) error {
	if rule.RuleType == "" {
		rule.RuleType = ruleTypeAuth
	}
	if rule.RuleType != ruleTypeAuth {
		return fmt.Errorf(`this endpoint manages ruleType "auth" rules only (use /api/policy for access rules)`)
	}
	return nil
}

// GET/POST/PUT/DELETE /api/authpolicy — manage Stage-1 auth/exempt rules.
func apiAuthPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		rules := listAuthRules()
		jsonOK(w, map[string]any{
			"rules":         rules,
			"count":         len(rules),
			"defaultAction": defaultPolicyAction(),
			"note":          authExemptNote,
		})

	case http.MethodPost:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		apiAuthPolicyCreate(w, r)

	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		apiAuthPolicyUpdate(w, r)

	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		apiAuthPolicyDelete(w, r)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// authExemptNote is the operator-facing contract statement rendered by the UI
// panel and the simulator: an exemption is NOT an allow.
const authExemptNote = "Exempt skips end-user authentication only — it never allows traffic. " +
	"It applies only when the client presents no credentials; Stage-2 policy still decides access and default-deny still applies."

func apiAuthPolicyCreate(w http.ResponseWriter, r *http.Request) {
	var rule PolicyRule
	if err := decodeJSON(r, &rule); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if rule.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if err := normalizeIncomingAuthRule(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validatePolicyRule(rule, policyStore.List(), -1); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Referential providerRefs check (SSORequired) — registry-aware, write-door
	// only. Bulk persistence paths stay shape-only so registry drift never drops
	// stored rules (DR-4). Phase 3 Slice 2.
	if rule.Auth != nil {
		if err := validateSSOProviderRefsLive(rule.Auth); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	added := policyStore.Add(rule)
	policyStore.Save()
	logger.Printf("UI: auth rule added priority=%s name=%q owner=%q",
		strings.ReplaceAll(fmt.Sprintf("%d", added.Priority), "\n", "_"), sanitizeLog(added.Name), sanitizeLog(added.Auth.Owner))
	auditEventDiff(r, "authpolicy.add", added.Name,
		fmt.Sprintf("priority=%d outcome=%s owner=%s", added.Priority, added.Auth.Outcome, added.Auth.Owner), nil, added)
	saveConfigVersion(sessionAdmin(r), "authpolicy.add")
	warnings, _ := validateAuthRule(added)
	jsonOK(w, authRuleView{PolicyRule: added, Warnings: warnings})
}

func apiAuthPolicyUpdate(w http.ResponseWriter, r *http.Request) {
	priority, ok := parsePriorityParam(w, r)
	if !ok {
		return
	}
	before := findRuleByPriority(priority)
	if before == nil {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	if ruleTypeOf(before) != ruleTypeAuth {
		http.Error(w, "rule at this priority is an access rule (use /api/policy)", http.StatusBadRequest)
		return
	}
	var rule PolicyRule
	if err := decodeJSON(r, &rule); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := normalizeIncomingAuthRule(&rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validatePolicyRule(rule, policyStore.List(), priority); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Referential providerRefs check (SSORequired) — write-door only (DR-4).
	if rule.Auth != nil {
		if err := validateSSOProviderRefsLive(rule.Auth); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if !policyStore.Update(priority, rule) {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	policyStore.Save()
	logger.Printf("UI: auth rule updated priority=%s name=%q",
		strings.ReplaceAll(fmt.Sprintf("%d", priority), "\n", "_"), sanitizeLog(rule.Name))
	auditEventDiff(r, "authpolicy.update", rule.Name,
		fmt.Sprintf("priority=%d outcome=%s", priority, rule.Auth.Outcome), before, rule)
	saveConfigVersion(sessionAdmin(r), "authpolicy.update")
	jsonOK(w, map[string]any{"ok": true})
}

func apiAuthPolicyDelete(w http.ResponseWriter, r *http.Request) {
	priority, ok := parsePriorityParam(w, r)
	if !ok {
		return
	}
	before := findRuleByPriority(priority)
	if before == nil {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	if ruleTypeOf(before) != ruleTypeAuth {
		http.Error(w, "rule at this priority is an access rule (use /api/policy)", http.StatusBadRequest)
		return
	}
	if !policyStore.Delete(priority) {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	policyStore.Save()
	logger.Printf("UI: auth rule deleted priority=%s",
		strings.ReplaceAll(fmt.Sprintf("%d", priority), "\n", "_"))
	auditEventDiff(r, "authpolicy.delete", before.Name, "", before, nil)
	saveConfigVersion(sessionAdmin(r), "authpolicy.delete")
	w.WriteHeader(http.StatusNoContent)
}

// parsePriorityParam extracts and validates the ?priority= query parameter,
// writing a 400 on failure.
func parsePriorityParam(w http.ResponseWriter, r *http.Request) (int, bool) {
	priorityStr := strings.TrimSpace(r.URL.Query().Get("priority"))
	var priority int
	if _, err := fmt.Sscanf(priorityStr, "%d", &priority); err != nil {
		http.Error(w, "missing or invalid priority param", http.StatusBadRequest)
		return 0, false
	}
	return priority, true
}

// POST /api/authpolicy/reorder — reorder auth rules among themselves.
// Body: {"priorities":[...]} — ALL auth-rule priorities in the desired order.
// The same priority values are redistributed across the auth rules, so access
// rule ordering is never disturbed.
func apiAuthPolicyReorder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var body struct {
		Priorities []int `json:"priorities"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	// The list must be exactly the current auth-rule priority set: rejecting
	// partial or stale lists keeps the permutation well-defined and guarantees
	// no access-rule priority can ever appear in it.
	authPris := make(map[int]bool)
	rules := policyStore.List()
	for i := range rules {
		if ruleTypeOf(&rules[i]) == ruleTypeAuth {
			authPris[rules[i].Priority] = true
		}
	}
	if len(body.Priorities) != len(authPris) {
		http.Error(w, "priorities must list every auth rule exactly once", http.StatusBadRequest)
		return
	}
	for _, p := range body.Priorities {
		if !authPris[p] {
			http.Error(w, fmt.Sprintf("priority %d is not an auth rule", p), http.StatusBadRequest)
			return
		}
	}
	if !policyStore.PermutePriorities(body.Priorities) {
		http.Error(w, "reorder failed (duplicate or stale priority list)", http.StatusBadRequest)
		return
	}
	policyStore.Save()
	logger.Printf("UI: auth rules reordered (%d rule(s))", len(body.Priorities))
	auditEvent(r, "authpolicy.reorder", fmt.Sprintf("%d rule(s)", len(body.Priorities)), "")
	saveConfigVersion(sessionAdmin(r), "authpolicy.reorder")
	jsonOK(w, map[string]any{"ok": true})
}

// isAuthRulePriority reports whether the rule at the given priority is a
// Stage-1 auth rule. Used by /api/policy to refuse mutating auth rules.
func isAuthRulePriority(priority int) bool {
	r := findRuleByPriority(priority)
	return r != nil && ruleTypeOf(r) == ruleTypeAuth
}

// simulateAuthOutcome runs the Stage-1 resolver for the policy simulator and
// builds the response block. Pure dry-run: resolveAuthOutcomeFrom touches no
// counters or hit-counts, and the exempt metric is NOT incremented. The kill
// switch is consulted (the simulator reflects real runtime behavior).
//
// Credentials win, exactly as at runtime: resolveNoCredAuthOutcome only runs
// for requests with no Proxy-Authorization, so a simulated request that carries
// an identity or an authenticated authSource is NEVER exempt — the resolver is
// skipped and the outcome is Default.
//
// stage2AuthSource mirrors Slice 7's runtime wiring: when the simulated request
// presents no credentials and an exempt rule matches, Stage-2 evaluates with
// authSource="exempt".
func simulateAuthOutcome(rules []PolicyRule, sourceIP, host, protocol, method, identity, rawAuthSource string) (stage2AuthSource string, block map[string]any) {
	if protocol == "" {
		protocol = "http"
	}
	hasCreds := identity != "" || (rawAuthSource != "" && rawAuthSource != "unauth")
	d := AuthDecision{Outcome: OutcomeDefault}
	note := authExemptNote
	if hasCreds {
		note = "Credentials presented — at runtime, valid credentials and sessions always win and exemptions are " +
			"never evaluated; failed credentials get 407 and are never exempted. Stage-1 outcome is Default."
	} else {
		ctx := RequestContext{ClientIP: sourceIP, Host: host, Protocol: protocol, Method: method}
		d = resolveAuthOutcomeFrom(rules, ctx) // priority-ordered resolver (matches the live gate)
		if d.Outcome == OutcomeCredentialRequired {
			// CredentialRequired is a CHALLENGE class, not an access decision. It
			// is NOT Allow or Block: the client must authenticate first, then the
			// Stage-2 decision below applies. (Wired onto the runtime no-credentials
			// path in Phase 2 Slice 3.)
			note = "CredentialRequired — a non-interactive credential challenge (407) would be required before this " +
				"request proceeds. This is NOT Allow or Block; the Stage-2 decision below applies only after the client authenticates."
		}
		if d.Outcome == OutcomeSSORequired {
			// SSORequired is a CHALLENGE class enforced at runtime (Phase 3 Slice 4):
			// a browser client is redirected (302) to the IdP / scoped selection page;
			// a non-browser or CONNECT client, or a request with no eligible IdP after
			// providerRefs filtering, is failed closed (403) — never a 407. It is NOT
			// Allow or Block, and Stage-2 runs only after the client completes SSO and
			// a session exists.
			note = "SSORequired — an interactive browser SSO redirect (302) would be required before this request " +
				"proceeds; non-browser and CONNECT clients are failed closed (403). This is NOT Allow or Block; the " +
				"Stage-2 decision below applies only after the client completes SSO and a session is established."
		}
	}
	stage2AuthSource = rawAuthSource
	if stage2AuthSource == "" {
		stage2AuthSource = "unauth"
	}
	// Stage-2 sees authSource=exempt only when the resolved outcome is Exempt
	// (mirrors Slice 7 runtime wiring). A CR/SSORequired/Default decision keeps the
	// unauthenticated source — those outcomes do not authenticate the request here.
	if d.Outcome == OutcomeExempt {
		stage2AuthSource = authSourceExempt
	}
	block = map[string]any{
		"outcome":              string(d.Outcome),
		"runtimeOutcome":       string(d.Outcome), // runtime now resolves the same outcome the simulator shows
		"killSwitch":           authExemptKillSwitchEngaged(),
		"credentialsPresented": hasCreds,
		"stage2AuthSource":     stage2AuthSource,
		"note":                 note,
	}
	if d.Rule != nil {
		block["rule"] = map[string]any{
			"id":    d.Rule.ID,
			"name":  d.Rule.Name,
			"owner": d.Rule.Auth.Owner,
		}
	}
	return stage2AuthSource, block
}

// authPrioritiesWouldChange reports whether applying PolicyStore.Reorder with
// orderedPriorities would assign any Stage-1 auth rule a different priority
// (Reorder assigns newPriority = index+1). Used by the operator-level
// /api/policy/reorder and /api/policy/move handlers: pure access-rule
// reorders that leave every auth rule at its current priority stay operator-
// level, while any repositioning of an auth rule is an admin-only mutation
// (consistent with /api/authpolicy).
func authPrioritiesWouldChange(orderedPriorities []int) bool {
	rules := policyStore.List()
	authPri := make(map[int]bool)
	for i := range rules {
		if ruleTypeOf(&rules[i]) == ruleTypeAuth {
			authPri[rules[i].Priority] = true
		}
	}
	if len(authPri) == 0 {
		return false
	}
	for idx, p := range orderedPriorities {
		if authPri[p] && idx+1 != p {
			return true
		}
	}
	return false
}
