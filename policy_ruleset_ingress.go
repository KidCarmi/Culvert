package main

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// Ingress validation of policy rules: the checks a rule gets when an OPERATOR
// SUBMITS it, as one rule or as a set.
//
// There is one per-rule core, checkRuleIngress (ui_helpers.go), and one
// state-dependent check, validateRuleUniqueness. Every operator-facing door is
// a composition of those two and nothing else; no door has rules of its own.
//
// The core separates two findings (ruleCheck). A rule that is INVALID, or that
// this node cannot ENFORCE as written (a schedule timezone it cannot load), is
// refused at every one of these doors. A rule this node merely CANNOT VERIFY
// right now (errRuleUnverifiable) is the door's decision. That class holds
// only findings whose enforcement is fail-closed at the point of use, which
// today is one: a Redirect host whose DNS lookup failed (ui_helpers.go states
// the principle). The whole door policy:
//
//   - a SINGLE-RULE door refuses it (validateRuleIngress / validateIngressRule,
//     the strict reading). The operator is present, is writing something new,
//     and can retry: POST/PUT /api/policy and /api/authpolicy, policy-learning
//     acceptance;
//   - a RULESET IMPORT installs it and says so, one warning per rule in the
//     response, on the dry run as on the commit. Import is the restore path,
//     used exactly when DNS may be down, and a backup of a healthy policy must
//     not be lost to the resolver of the node it is restored on. This is safe
//     because an unverified Redirect answers 403 at serve time until its host
//     resolves to a public address (checkRedirectURL).
//
// How a set is composed:
//
//   - config import, merge mode: each rule against the rules it will stand
//     beside (the store as the rules merged before it left it). An INVALID
//     rule is skipped and reported; the rest apply (mergeImportedRules);
//   - config import, replace mode: the set replaces the policy, so uniqueness
//     is judged WITHIN it. One INVALID rule refuses the whole import before any
//     section applies (validateIngressRuleset).
//
// The per-rule checks of an import are computed ONCE, at the door, before any
// lock is taken and under a time budget (checkImportRules); the apply and the
// preview read those verdicts and add only the uniqueness check, which reads
// memory.
//
// Stored and wire doors are a different thing and are NOT wired to this file
// (policy file load, config-version rollback, control-plane snapshots, a
// pending draft on disk): see storedRulesetError and
// docs/engineering/security-reviews/2026-11-24-ruleset-refusal-supersedes-per-rule-drop.md.
// A draft COMMIT re-validates its candidate with validatePolicyRule, which is
// this validation without the source literal check, because the candidate
// holds rules inherited from the running policy (stored data) beside rules
// that already passed validateRuleIngress when they were edited.

// validateIngressRule validates one submitted rule against the rules it will
// stand beside, strictly. editPriority is the slot of the rule it replaces, or
// -1 for a new rule (validateRuleUniqueness).
func validateIngressRule(rule PolicyRule, beside []PolicyRule, editPriority int) error {
	if err := validateRuleUniqueness(rule, beside, editPriority); err != nil {
		return err
	}
	return validateRuleIngress(rule)
}

// importRuleChecks holds the state-independent verdict of each rule of one
// import, index-aligned with the rule set it was computed for.
type importRuleChecks struct {
	verdicts []ruleCheck
	first    *PolicyRule // identity of the rule set: its backing array and length
}

// importVerifyBudget bounds, per import request, the time spent on checks that
// wait on the network. When it runs out the remaining lookups are not made and
// their rules are reported as unverified. A var so tests can shrink it.
var importVerifyBudget = 10 * time.Second

// checkImportRules runs the per-rule core over an import's rules within
// importVerifyBudget of ctx. It takes no lock and changes nothing.
func checkImportRules(ctx context.Context, rules []PolicyRule) importRuleChecks {
	ctx, cancel := context.WithTimeout(ctx, importVerifyBudget)
	defer cancel()
	out := importRuleChecks{verdicts: make([]ruleCheck, len(rules)), first: firstRule(rules)}
	for i := range rules {
		out.verdicts[i] = checkRuleIngress(ctx, rules[i])
	}
	return out
}

// firstRule is the address of a rule set's first element (nil when empty).
func firstRule(rules []PolicyRule) *PolicyRule {
	if len(rules) == 0 {
		return nil
	}
	return &rules[0]
}

// forRules returns the verdicts for rules. Verdicts are reused only for the
// very rule set they were computed for (same backing array, same length);
// asked about any other set — a caller that did not come through the import
// door, or a set that was rebuilt since — it validates again rather than hand
// one set's verdicts to another.
func (c importRuleChecks) forRules(rules []PolicyRule) []ruleCheck {
	if len(c.verdicts) == len(rules) && c.first == firstRule(rules) {
		return c.verdicts
	}
	return checkImportRules(context.Background(), rules).verdicts
}

// ingressReasonLimit bounds a validator's message where it is repeated to the
// caller: it can quote a submitted value in full.
const ingressReasonLimit = 256

// importRuleWarning is the one format of a per-rule import warning. The name
// and the reason are operator-supplied: sanitized and bounded.
func importRuleWarning(name, outcome string, reason error) string {
	return fmt.Sprintf("policy rule %q %s: %s", sanitizeLog(boundedRuleName(name)), outcome,
		sanitizeLog(boundedText(reason.Error(), ingressReasonLimit)))
}

// unverifiedRuleWarnings appends one warning per finding this node could not
// verify about a rule that is being installed.
func unverifiedRuleWarnings(warnings []string, name string, c ruleCheck) []string {
	for _, u := range c.unverifiable {
		warnings = append(warnings, importRuleWarning(name, "imported but NOT verified", u))
	}
	return warnings
}

// rulesetIngressError identifies the first rule of a submitted set that fails
// ingress validation.
type rulesetIngressError struct {
	Index int // zero-based position in the submitted set
	Total int
	Name  string
	Err   error
}

func (e *rulesetIngressError) Error() string {
	return fmt.Sprintf("rule %d of %d (%q) is not valid: %s", e.Index+1, e.Total,
		sanitizeLog(boundedRuleName(e.Name)), sanitizeLog(boundedText(e.Err.Error(), ingressReasonLimit)))
}

func (e *rulesetIngressError) Unwrap() error { return e.Err }

// validateIngressRuleset validates a submitted set that will REPLACE the
// policy. Each rule is judged as if the set had been created one rule at a
// time through the policy API, in order: its name and explicit priority
// against the rules before it, then its own verdict from checks. It reads no
// store and changes nothing. A nil error means every rule may be installed;
// warnings name the ones this node could not verify.
func validateIngressRuleset(rules []PolicyRule, verdicts importRuleChecks) (warnings []string, err error) {
	checks := verdicts.forRules(rules)
	for i := range rules {
		err := validateRuleUniqueness(rules[i], rules[:i], -1)
		if err == nil {
			err = checks[i].err
		}
		if err != nil {
			return nil, &rulesetIngressError{Index: i, Total: len(rules), Name: rules[i].Name, Err: err}
		}
		warnings = unverifiedRuleWarnings(warnings, rules[i].Name, checks[i])
	}
	return warnings, nil
}

// policyMergeOutcome is what a merge-mode import of a rule set does, or would
// do: the same function produces it for the apply and for the preview.
type policyMergeOutcome struct {
	warnings               []string
	updates, adds, skipped int
}

// mergeImportedRules UPSERTS rules into target by identity — stable ULID first
// (idempotent re-import), then a one-time name fallback for pre-ID /
// hand-authored backups, else create fresh — so a re-import does not
// accumulate duplicates (POLICY-ARCHITECTURE-FUTURE §1). An invalid rule is
// skipped with a warning. target is the running store for an import, or a
// scratch copy of it for a preview (previewMergeImport): both walk the same
// code, so the preview cannot promise what the apply will skip.
func mergeImportedRules(target *PolicyStore, rules []PolicyRule, verdicts importRuleChecks) (out policyMergeOutcome) {
	checks := verdicts.forRules(rules)
	// Index-based range: PolicyRule is a large struct (CLAUDE.md rangeValCopy).
	for i := range rules {
		rule := rules[i]
		stampObjectRefIDs(&rule)
		existing := target.matchForImport(rule)
		editPriority := -1
		if existing != nil {
			// UpdateByID keeps the live rule's position and DISCARDS the payload
			// priority — so validate against the priority it will actually apply,
			// not the backup's. Otherwise a re-import after the rulebase was
			// reordered (payload priority now owned by a different live rule)
			// would spuriously fail the priority-uniqueness check and silently
			// drop the content update, defeating idempotency.
			rule.Priority = existing.Priority
			editPriority = existing.Priority
		}
		err := validateRuleUniqueness(rule, target.List(), editPriority)
		if err == nil {
			err = checks[i].err
		}
		if err != nil {
			out.skipped++
			out.warnings = append(out.warnings, importRuleWarning(rule.Name, "skipped", err))
			continue
		}
		out.warnings = unverifiedRuleWarnings(out.warnings, rule.Name, checks[i])
		if existing == nil {
			target.Add(rule)
			out.adds++
			continue
		}
		out.updates++
		rule.ID = existing.ID // carry identity for the name-match upsert path
		if !target.UpdateByID(existing.ID, rule) {
			// The matched rule vanished between match and update (concurrent
			// delete / import of the same rule). Don't silently drop the
			// incoming content — add it fresh rather than lose it.
			target.Add(rule)
		}
	}
	return out
}

// previewMergeImport reports what a merge-mode import of rules would do, by
// running mergeImportedRules against a scratch copy of the running policy.
func previewMergeImport(rules []PolicyRule, checks importRuleChecks) policyMergeOutcome {
	// staging: enforces nothing, persists nothing. silent: writes no log line
	// and no Diagnostics row for a policy nobody will run.
	scratch := &PolicyStore{staging: true, silent: true}
	scratch.ReplaceAll(policyStore.List())
	return mergeImportedRules(scratch, rules, checks)
}

// importPolicyPreview is the policy-rule part of an import preview: the merge
// effect line ("" in replace mode, which uses the generic one) and the
// per-rule warnings the commit would return. Computed once per preview.
type importPolicyPreview struct {
	effect   string
	warnings []string
}

func previewImportPolicy(b *configBackup, checks importRuleChecks, replaceMode bool) (p importPolicyPreview) {
	if replaceMode || len(b.PolicyRules) == 0 {
		p.warnings, _ = validateIngressRuleset(b.PolicyRules, checks) // refused at the door if invalid
		return p
	}
	out := previewMergeImport(b.PolicyRules, checks)
	p.effect = fmt.Sprintf("upsert %d: %d update, %d add", len(b.PolicyRules), out.updates, out.adds)
	if out.skipped > 0 {
		p.effect += fmt.Sprintf(", %d skipped as invalid (see warnings)", out.skipped)
	}
	p.warnings = out.warnings
	return p
}

// importReplaceRequested reports whether a config import asked for replace
// mode. Anything else is merge.
func importReplaceRequested(r *http.Request) bool {
	return r.URL.Query().Get("mode") == "replace"
}

// importIngressRefusal is the last step of the import door: the backup version
// check, then the per-rule checks of the rule set (stored in checks for the
// preview and the apply), then — replace mode only — the refusal of a set
// holding an invalid rule. It returns the 400 message, or "" to proceed. Merge
// mode judges each rule while applying, against the store as the rules before
// it left it.
func importIngressRefusal(r *http.Request, b *configBackup, checks *importRuleChecks) string {
	if b.Version < 1 || b.Version > configBackupVersion {
		return "unsupported backup version"
	}
	*checks = checkImportRules(r.Context(), b.PolicyRules)
	// The client is gone (or the server is shutting the request down): nothing
	// has been applied yet and nothing will be. A cancelled request must never
	// go on to mutate, least of all on verdicts its own cancellation cut short.
	if r.Context().Err() != nil {
		return "import aborted: the request was cancelled before the rules were verified; nothing was changed"
	}
	if !importReplaceRequested(r) {
		return ""
	}
	if _, err := validateIngressRuleset(b.PolicyRules, *checks); err != nil {
		return "import refused: policy " + err.Error() +
			"; nothing was changed. The policy API refuses the same rule: correct it in the file and import again"
	}
	return ""
}
