package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// Auth Policy admin API — Phase 1 Slice 8; hardened in Batch-2 slice 2C.0.
//
// CRUD + reorder for Stage-1 auth/exempt rules, kept on a DEDICATED endpoint:
// /api/policy rejects ruleType="auth" payloads, and this endpoint refuses to
// touch access rules. Writes are ADMIN-only (stricter than the operator-level
// access-policy API — an authentication waiver is a security-sensitive change);
// reads are viewer. No runtime behavior is added here: rules flow through the
// same validatePolicyRule → PolicyStore path the rest of the system uses, and
// the Stage-1 resolver wiring from Slice 7 is untouched.
//
// 2C.0 write contract (mirrors the 2B Stage-2 hardening, transposed to the
// RUNNING domain):
//
//   - Addressing: ?id=<ULID> (stable-ID, reorder-safe, preferred) alongside
//     the legacy ?priority= path. The id path is strict — malformed 400,
//     unknown 404, access-rule 400 — and never falls through to priority.
//   - Version contract: GET serves version/updatedAt from the RUNNING
//     PolicyStore generation (never a draft candidate's), and every mutation
//     accepts an optional ?ifVersion= assertion.
//   - Atomicity: mutations run through fencedRunningMutate
//     (policy_mutation.go) — the fence comparison, the mutation, and the
//     durable persist share ONE coordinator critical section, ALWAYS against
//     the running store. Auth rules take effect immediately; Require Commit
//     never stages them, and a successful auth mutation deliberately stales
//     an active Access-Policy Draft's base generation (its commit fails
//     closed; GET /api/policy/draft surfaces baseStale).
//   - Durability: durable-or-nothing — a pre-replacement persist failure
//     rolls the mutation back and fails the request; a 2xx means the change
//     is on disk (or the recorded ErrReplacedNotSynced degradation).
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
	return authRuleViews(policyStore.List())
}

// authRuleViews filters the auth (Stage-1) subset out of an already-captured
// rule list — a PURE projection, so a fenced reader can derive the views from
// the same snapshot its version fence came from (§7).
func authRuleViews(rules []PolicyRule) []authRuleView {
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
		// ONE running-store snapshot supplies both the rules and the version
		// fence (§7 fenced-read correction): listAuthRules() then
		// policyVersion() as two reads let a concurrent auth mutation land in
		// between, handing a client generation-P rules with a generation-P+1
		// token — its stale later edit would pass the ?ifVersion= fence. The
		// fence stays the RUNNING PolicyStore generation — deliberately NOT
		// effectivePolicyVersion: auth rules live in the running domain even
		// while a Stage-2 draft is engaged, so the candidate's generation must
		// never leak here (2C.0a).
		snap := policyStore.SnapshotWithVersion()
		rules := authRuleViews(snap.Rules)
		jsonOK(w, map[string]any{
			"rules":         rules,
			"count":         len(rules),
			"defaultAction": defaultPolicyAction(),
			"note":          authExemptNote,
			"version":       snap.Version,
			"updatedAt":     snap.UpdatedAt,
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

// authRuleTarget is the resolved addressing of one EXISTING auth rule: the
// stable-ID path (?id=<ULID>, preferred — reorder-safe) or the legacy
// ?priority= path, kept for the deprecation window.
type authRuleTarget struct {
	id       string      // non-empty on the id path
	priority int         // the target's priority (resolved on both paths)
	before   *PolicyRule // detached pre-mutation copy (never nil when ok)
}

// resolveAuthRuleTarget resolves ?id= (preferred) or legacy ?priority= to an
// existing Stage-1 auth rule, writing the 4xx and returning ok=false
// otherwise. The id path is STRICT: a malformed id is 400, an unknown id is
// 404, and an access-rule id is 400 — it never falls through to a priority
// guess (2C.0a).
// authRuleAddress is the STRUCTURAL half of a target: the id or priority the
// client addressed, parsed and grammar-checked before the fence. Existence
// and rule-type are decided INSIDE the fence (resolveAuthRuleTargetIn).
type authRuleAddress struct {
	id       string // non-empty on the id path
	priority int    // legacy priority path
}

// parseAuthRuleAddress parses ?id= (preferred) or legacy ?priority=, writing
// the 400 for malformed input. The id path is STRICT and never falls through
// to a priority guess (2C.0a).
func parseAuthRuleAddress(w http.ResponseWriter, r *http.Request) (authRuleAddress, bool) {
	if id := strings.TrimSpace(r.URL.Query().Get("id")); id != "" {
		if !validRuleID(id) {
			http.Error(w, "invalid id param (must be a rule ULID)", http.StatusBadRequest)
			return authRuleAddress{}, false
		}
		return authRuleAddress{id: id}, true
	}
	priority, ok := parsePriorityParam(w, r)
	if !ok {
		return authRuleAddress{}, false
	}
	return authRuleAddress{priority: priority}, true
}

// resolveAuthRuleTargetIn resolves an address against the FENCED store: an
// unknown id/priority is not-found (404); an access rule at the address is a
// current-state conflict (this endpoint manages Stage-1 rules only). Decided
// inside the coordinator fence, so a concurrent reorder or delete between a
// client's load and its write yields the truthful 404/409, never a guess.
func resolveAuthRuleTargetIn(ps *PolicyStore, addr authRuleAddress) (authRuleTarget, *fencedRefusal) {
	if addr.id != "" {
		before := ps.findByIDCopy(addr.id)
		if before == nil {
			return authRuleTarget{}, &fencedRefusal{notFound: true}
		}
		if ruleTypeOf(before) != ruleTypeAuth {
			// An id never changes rule type: wrong on its own terms.
			return authRuleTarget{}, &fencedRefusal{reason: "rule with this id is an access rule (use /api/policy)", invariant: true}
		}
		return authRuleTarget{id: addr.id, priority: before.Priority, before: before}, nil
	}
	before := findByPriorityIn(ps, addr.priority)
	if before == nil {
		return authRuleTarget{}, &fencedRefusal{notFound: true}
	}
	if ruleTypeOf(before) != ruleTypeAuth {
		return authRuleTarget{}, &fencedRefusal{reason: "rule at this priority is an access rule (use /api/policy)"}
	}
	return authRuleTarget{priority: addr.priority, before: before}, nil
}

// runningPolicyVersionConflict is the handler-level fast-path for the RUNNING
// fence: it 400s a malformed ?ifVersion= and 409s an already-stale assertion
// against the RUNNING generation before any body work. fencedRunningMutate
// re-verifies the same assertion inside its critical section — this early
// check exists only for cheap rejection and the canonical 400, exactly like
// the Stage-2 handlers' policyVersionConflict fast-path.
func runningPolicyVersionConflict(w http.ResponseWriter, r *http.Request) bool {
	cur, _ := policyStore.policyVersion()
	return policyVersionConflictAgainst(w, r, cur)
}

func apiAuthPolicyCreate(w http.ResponseWriter, r *http.Request) {
	// Blocker B (shared side): an auth rule can reference shared objects
	// (destination category/group) — acquired before the policy writeGate
	// (gate → writeGate, the documented lock order).
	refWriteLock()
	defer refWriteUnlock()
	if runningPolicyVersionConflict(w, r) {
		return
	}
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
	// Structural validation (state-independent) stays a pre-fence 400; the
	// name/priority uniqueness checks run INSIDE the fence below.
	if err := validateRuleShape(rule); err != nil {
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
	// SERVER CANONICALIZATION FIRST (ID-trust correction): stamp metadata and
	// re-derive object IDs from NAMES (client-supplied IDs are discarded),
	// then validate the FINAL canonical rule — reference validation must
	// never trust a client ID, and no restamp may follow it.
	stampRuleMetadataForWrite(&rule, nil, sessionAdmin(r))
	// Blocker B delete-first order: validate destination object references
	// under the shared gate before committing (auth rules may carry
	// destination category/group/profile scopes).
	if refuseDanglingRuleRefs(w, &rule) {
		return
	}
	policyWriteStateDecision(r, "resolved")
	policyWriteStateDecision(r, "fence")
	// Serialize with commit/revert exactly like the Stage-2 handlers.
	beginPolicyWrite()
	defer endPolicyWrite()
	// Atomic RUNNING-domain fence + uniqueness validation + mutation + durable
	// persist (2C.0a; 2E-C concurrency-status correction) — an auth rule is
	// live the moment this succeeds, draft or no draft.
	var (
		added  PolicyRule
		ref    fencedRefusal
		curVer int64
	)
	res := policyDraft.fencedRunningMutate(parseIfVersion(r), func(ps *PolicyStore) bool {
		curVer, _ = ps.policyVersion()
		if err := validateRuleUniqueness(rule, ps.List(), -1); err != nil {
			ref = fencedRefusal{reason: err.Error()}
			return false
		}
		added = ps.Add(rule)
		return true
	})
	if res.conflict != nil {
		writePolicyVersionConflictError(w, res.conflict)
		return
	}
	if res.err != nil {
		writePolicyPersistFailure(w, res.err)
		return
	}
	if !res.ok {
		writeFencedRefusal(w, r, ref, curVer)
		return
	}
	logger.Printf("UI: auth rule added priority=%s name=%q owner=%q",
		strings.ReplaceAll(fmt.Sprintf("%d", added.Priority), "\n", "_"), sanitizeLog(added.Name), sanitizeLog(added.Auth.Owner))
	auditEventDiff(r, "authpolicy.add", added.Name,
		fmt.Sprintf("priority=%d outcome=%s owner=%s", added.Priority, added.Auth.Outcome, added.Auth.Owner), nil, added)
	finalizeFencedPolicyWrite(r, "authpolicy.add", res)
	warnings, _ := validateAuthRule(added)
	jsonOK(w, authRuleView{PolicyRule: added, Warnings: warnings})
}

func apiAuthPolicyUpdate(w http.ResponseWriter, r *http.Request) {
	// Blocker B (shared side): an edited auth rule can change its shared-
	// object references.
	refWriteLock()
	defer refWriteUnlock()
	if runningPolicyVersionConflict(w, r) {
		return
	}
	addr, ok := parseAuthRuleAddress(w, r)
	if !ok {
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
	if err := validateRuleShape(rule); err != nil {
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
	// SERVER CANONICALIZATION FIRST (ID-trust correction): stamp metadata and
	// re-derive object IDs from NAMES (client-supplied IDs are discarded),
	// then validate the FINAL canonical rule — reference validation must
	// never trust a client ID, and no restamp may follow it. CreatedAt is
	// carried from the target resolved INSIDE the fence.
	stampRuleMetadataForWrite(&rule, nil, sessionAdmin(r))
	// Blocker B delete-first order: validate destination object references
	// under the shared gate before committing the edit.
	if refuseDanglingRuleRefs(w, &rule) {
		return
	}
	policyWriteStateDecision(r, "resolved")
	policyWriteStateDecision(r, "fence")
	beginPolicyWrite()
	defer endPolicyWrite()
	// Target existence, rule type, and name/priority uniqueness are decided
	// against the FENCED snapshot (2E-C concurrency-status correction): a
	// reorder that lands between the client's load and this write can only
	// produce the structured 409, never a stale-slot "name already exists".
	var (
		target authRuleTarget
		ref    fencedRefusal
		curVer int64
	)
	res := policyDraft.fencedRunningMutate(parseIfVersion(r), func(ps *PolicyStore) bool {
		curVer, _ = ps.policyVersion()
		t, rf := resolveAuthRuleTargetIn(ps, addr)
		if rf != nil {
			ref = *rf
			return false
		}
		target = t
		if err := validateRuleUniqueness(rule, ps.List(), target.priority); err != nil {
			ref = fencedRefusal{reason: err.Error()}
			return false
		}
		rule.CreatedAt = target.before.CreatedAt
		if target.id != "" {
			return ps.UpdateByID(target.id, rule)
		}
		return ps.Update(target.priority, rule)
	})
	if res.conflict != nil {
		writePolicyVersionConflictError(w, res.conflict)
		return
	}
	if res.err != nil {
		writePolicyPersistFailure(w, res.err)
		return
	}
	if !res.ok {
		writeFencedRefusal(w, r, ref, curVer)
		return
	}
	logger.Printf("UI: auth rule updated priority=%s name=%q",
		strings.ReplaceAll(fmt.Sprintf("%d", target.priority), "\n", "_"), sanitizeLog(rule.Name))
	auditEventDiffID(r, "authpolicy.update", rule.Name, ruleAuditID(target.before),
		fmt.Sprintf("priority=%d outcome=%s", target.priority, rule.Auth.Outcome), target.before, rule)
	finalizeFencedPolicyWrite(r, "authpolicy.update", res)
	jsonOK(w, map[string]any{"ok": true})
}

func apiAuthPolicyDelete(w http.ResponseWriter, r *http.Request) {
	if runningPolicyVersionConflict(w, r) {
		return
	}
	addr, ok := parseAuthRuleAddress(w, r)
	if !ok {
		return
	}
	policyWriteStateDecision(r, "resolved")
	policyWriteStateDecision(r, "fence")
	beginPolicyWrite()
	defer endPolicyWrite()
	// The target is resolved INSIDE the fence, so the audit names the rule
	// that actually vanished (2E-C concurrency-status correction).
	var (
		target authRuleTarget
		ref    fencedRefusal
		curVer int64
	)
	res := policyDraft.fencedRunningMutate(parseIfVersion(r), func(ps *PolicyStore) bool {
		curVer, _ = ps.policyVersion()
		t, rf := resolveAuthRuleTargetIn(ps, addr)
		if rf != nil {
			ref = *rf
			return false
		}
		target = t
		if target.id != "" {
			return ps.DeleteByID(target.id)
		}
		return ps.Delete(target.priority)
	})
	if res.conflict != nil {
		writePolicyVersionConflictError(w, res.conflict)
		return
	}
	if res.err != nil {
		writePolicyPersistFailure(w, res.err)
		return
	}
	if !res.ok {
		writeFencedRefusal(w, r, ref, curVer)
		return
	}
	logger.Printf("UI: auth rule deleted priority=%s",
		strings.ReplaceAll(fmt.Sprintf("%d", target.priority), "\n", "_"))
	auditEventDiffID(r, "authpolicy.remove", target.before.Name, ruleAuditID(target.before), "", target.before, nil)
	finalizeFencedPolicyWrite(r, "authpolicy.remove", res)
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
// Body: {"ids":[<ULID>,...]} (preferred, stable-ID — reorder-safe against a
// concurrent priority shift) or the legacy {"priorities":[...]} — either way,
// ALL auth rules exactly once in the desired order. The same priority VALUES
// are redistributed across the auth rules, so access-rule ordering is never
// disturbed. Optional ?ifVersion= fence; the requested order is resolved into
// a priority permutation against ONE running snapshot INSIDE the fenced
// critical section (2C.0b), and the permutation is persisted
// durable-or-nothing.
func apiAuthPolicyReorder(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	if runningPolicyVersionConflict(w, r) {
		return
	}
	var body struct {
		IDs        []string `json:"ids"`
		Priorities []int    `json:"priorities"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	switch {
	case len(body.IDs) > 0 && len(body.Priorities) > 0:
		http.Error(w, "provide ids or priorities, not both", http.StatusBadRequest)
		return
	case len(body.IDs) == 0 && len(body.Priorities) == 0:
		http.Error(w, "ids (or legacy priorities) must list every auth rule exactly once", http.StatusBadRequest)
		return
	}
	// Shape-check ids before the critical section so every id echoed into a
	// later error message is ULID-charset-bounded.
	seenID := make(map[string]bool, len(body.IDs))
	for _, id := range body.IDs {
		if !validRuleID(id) {
			http.Error(w, "ids entries must be rule ULIDs", http.StatusBadRequest)
			return
		}
		// A duplicate inside the client's own list is malformed on its own
		// terms (state-independent) — a pre-fence 400, like the grammar check.
		if seenID[id] {
			http.Error(w, "ids contains a duplicate entry "+strconv.Quote(id), http.StatusBadRequest)
			return
		}
		seenID[id] = true
	}
	policyWriteStateDecision(r, "resolved")
	policyWriteStateDecision(r, "fence")
	beginPolicyWrite()
	defer endPolicyWrite()
	var (
		ref    fencedRefusal
		curVer int64
		count  int
	)
	res := policyDraft.fencedRunningMutate(parseIfVersion(r), func(ps *PolicyStore) bool {
		curVer, _ = ps.policyVersion()
		perm, rf := authReorderPermutation(ps, body.IDs, body.Priorities)
		if rf != nil {
			ref = *rf
			return false
		}
		count = len(perm)
		if !ps.PermutePriorities(perm) {
			ref = fencedRefusal{reason: "reorder failed (duplicate or stale priority list)"}
			return false
		}
		return true
	})
	if res.conflict != nil {
		writePolicyVersionConflictError(w, res.conflict)
		return
	}
	if res.err != nil {
		writePolicyPersistFailure(w, res.err)
		return
	}
	if !res.ok {
		// Decided inside the fence against the authoritative set: an order
		// list that no longer covers the auth rules is a state conflict
		// (409 without an assertion, 400 against an asserted generation);
		// an access-rule id is wrong on its own terms (400).
		writeFencedRefusal(w, r, ref, curVer)
		return
	}
	logger.Printf("UI: auth rules reordered (%d rule(s))", count)
	auditEvent(r, "authpolicy.reorder", fmt.Sprintf("%d rule(s)", count), "")
	finalizeFencedPolicyWrite(r, "authpolicy.reorder", res)
	jsonOK(w, map[string]any{"ok": true})
}

// authReorderPermutation resolves the requested order — stable IDs (preferred)
// or the legacy priority list — into a priority permutation against ONE
// snapshot of ps. It runs INSIDE the fenced critical section, so the set it
// validates against is exactly the set the permutation applies to. The list
// must cover every auth rule exactly once: partial, duplicate, unknown, and
// access-rule entries are all rejected, which guarantees no access-rule
// priority can ever enter the permutation.
func authReorderPermutation(ps *PolicyStore, ids []string, priorities []int) ([]int, *fencedRefusal) {
	rules := ps.List()
	authByID := make(map[string]int) // stable ID → current priority
	authPris := make(map[int]bool)
	accessIDs := make(map[string]bool)
	for i := range rules {
		if ruleTypeOf(&rules[i]) == ruleTypeAuth {
			authByID[rules[i].ID] = rules[i].Priority
			authPris[rules[i].Priority] = true
		} else {
			accessIDs[rules[i].ID] = true
		}
	}
	if len(ids) > 0 {
		if len(ids) != len(authByID) {
			return nil, &fencedRefusal{reason: fmt.Sprintf("ids must list every auth rule exactly once (%d listed, %d auth rules)", len(ids), len(authByID))}
		}
		perm := make([]int, 0, len(ids))
		for _, id := range ids {
			pri, ok := authByID[id]
			if !ok {
				if accessIDs[id] {
					// An id never changes rule type: wrong on its own terms.
					return nil, &fencedRefusal{reason: fmt.Sprintf("id %q is not an auth rule", id), invariant: true}
				}
				// Unknown at the authoritative moment — it may have been
				// deleted since the client loaded the list.
				return nil, &fencedRefusal{reason: fmt.Sprintf("id %q is not a current auth rule", id)}
			}
			perm = append(perm, pri)
		}
		return perm, nil
	}
	if len(priorities) != len(authPris) {
		return nil, &fencedRefusal{reason: "priorities must list every auth rule exactly once"}
	}
	for _, p := range priorities {
		if !authPris[p] {
			return nil, &fencedRefusal{reason: fmt.Sprintf("priority %d is not an auth rule", p)}
		}
	}
	return priorities, nil
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
		// Slice 4 parity: when no scoped rule matches, apply the global
		// defaultAuthOutcome exactly as the runtime resolveNoCredAuthOutcome does
		// (kill switch forces Default). Rule stays nil so default-Exempt is
		// distinguishable from a scoped Exempt rule (authSource unauth vs exempt).
		if d.Outcome == OutcomeDefault && d.Rule == nil {
			eff := cfg.DefaultAuthOutcome()
			if authExemptKillSwitchEngaged() {
				eff = OutcomeDefault
			}
			d.Outcome = eff
			if eff == OutcomeExempt {
				note = "Open unmatched traffic (defaultAuthOutcome=Exempt) — no scoped auth rule matched, so this request " +
					"is admitted without authentication. This is NOT Allow: Stage-2 policy still decides access and default-deny " +
					"still applies. Stage-2 sees authSource=\"unauth\" (no identity)."
			}
		}
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
	// Stage-2 sees authSource=exempt ONLY for an explicit scoped Exempt rule
	// (Rule != nil). Default-Exempt (no rule) and CR/SSORequired/Default keep the
	// unauthenticated source — those outcomes do not authenticate the request.
	if d.Outcome == OutcomeExempt && d.Rule != nil {
		stage2AuthSource = authSourceExempt
	}
	// fromDefault: the outcome came from the global default, not a scoped rule.
	fromDefault := !hasCreds && d.Rule == nil
	// stage2Reached: whether Stage-2 is evaluated at runtime for this Stage-1
	// outcome. Exempt (scoped or default) and presented credentials proceed to
	// Stage-2; CR/SSO return a challenge first (Stage-2 not reached); a Default
	// (auth-required) outcome issues a 407/redirect first UNLESS no auth backend
	// is configured — surfaced via stage2Note rather than a misleading bool.
	stage2Reached := hasCreds || d.Outcome == OutcomeExempt
	stage2Note := ""
	switch {
	case d.Outcome == OutcomeCredentialRequired || d.Outcome == OutcomeSSORequired:
		stage2Note = "Stage-2 is NOT reached at runtime until the client authenticates; the decision below is for reference only."
	case d.Outcome == OutcomeDefault && !hasCreds:
		stage2Note = "Default (Require authentication): at runtime a 407/redirect is issued first, so Stage-2 is reached only when no auth backend is configured. The decision below is for reference."
	}
	block = map[string]any{
		"outcome":              string(d.Outcome),
		"runtimeOutcome":       string(d.Outcome), // runtime resolves the same outcome the simulator shows
		"defaultAuthOutcome":   string(cfg.DefaultAuthOutcome()),
		"fromDefault":          fromDefault,
		"killSwitch":           authExemptKillSwitchEngaged(),
		"credentialsPresented": hasCreds,
		"stage2AuthSource":     stage2AuthSource,
		"stage2Reached":        stage2Reached,
		"stage2Note":           stage2Note,
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
