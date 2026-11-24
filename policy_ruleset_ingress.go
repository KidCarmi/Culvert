package main

import (
	"fmt"
	"net/http"
)

// Ingress validation of policy rules: the checks a rule gets when an OPERATOR
// SUBMITS it, as one rule or as a set.
//
// There is one per-rule core, validateRuleIngress (ui_helpers.go), and one
// state-dependent check, validateRuleUniqueness. Every operator-facing door is
// a composition of those two and nothing else:
//
//   - POST/PUT /api/policy and /api/authpolicy: validateRuleIngress before the
//     coordinator fence, validateRuleUniqueness inside it;
//   - config import, merge mode: validateIngressRule per rule, against the
//     rules it will stand beside (the live store, as it is after the rules
//     merged before it). A rule that fails is skipped and reported;
//   - config import, replace mode: validateIngressRuleset over the incoming
//     set. The set replaces the policy, so uniqueness is judged WITHIN it. One
//     failing rule refuses the whole import before any section applies;
//   - policy-learning acceptance: validateIngressRule against the effective
//     policy.
//
// No door has rules of its own. Replace-mode import used to run only the
// POL-005 gate, so it installed what the policy API refuses: a Drop rule whose
// sourceIP the matcher cannot match (inert, so the traffic it restricted fell
// through to the default action), duplicate names and priorities, a Redirect
// with no location, a named rule with no action.
//
// Stored and wire doors are a different thing and are NOT wired to this file
// (policy file load, config-version rollback, control-plane snapshots, a
// pending draft on disk). Their data has no caller to tell, part of this
// validation depends on the environment (a Redirect host is resolved in DNS, a
// schedule timezone is looked up in the host's tzdata), and it refuses shapes
// a store legitimately holds. Those doors keep the pure gate: see
// storedRulesetError and
// docs/engineering/security-reviews/2026-11-24-ruleset-refusal-supersedes-per-rule-drop.md.

// validateIngressRule validates one submitted rule against the rules it will
// stand beside. editPriority is the slot of the rule it replaces, or -1 for a
// new rule (validateRuleUniqueness).
func validateIngressRule(rule PolicyRule, beside []PolicyRule, editPriority int) error {
	if err := validateRuleUniqueness(rule, beside, editPriority); err != nil {
		return err
	}
	return validateRuleIngress(rule)
}

// rulesetIngressError identifies the first rule of a submitted set that fails
// ingress validation.
type rulesetIngressError struct {
	Index int // zero-based position in the submitted set
	Total int
	Name  string
	Err   error
}

// ingressReasonLimit bounds a validator's message where it is repeated to the
// caller: it can quote a submitted value in full.
const ingressReasonLimit = 256

func (e *rulesetIngressError) Error() string {
	return fmt.Sprintf("rule %d of %d (%q) is not valid: %s", e.Index+1, e.Total,
		sanitizeLog(boundedRuleName(e.Name)), sanitizeLog(boundedText(e.Err.Error(), ingressReasonLimit)))
}

func (e *rulesetIngressError) Unwrap() error { return e.Err }

// validateIngressRuleset validates a submitted set that will REPLACE the
// policy. Each rule is validated exactly as if the set had been created one
// rule at a time through the policy API, in order: its shape and source
// literal on its own, its name and explicit priority against the rules before
// it. It reads no store and changes nothing; nil means every rule may be
// installed.
func validateIngressRuleset(rules []PolicyRule) error {
	for i := range rules {
		if err := validateIngressRule(rules[i], rules[:i], -1); err != nil {
			return &rulesetIngressError{Index: i, Total: len(rules), Name: rules[i].Name, Err: err}
		}
	}
	return nil
}

// importReplaceRequested reports whether a config import asked for replace
// mode. Anything else is merge.
func importReplaceRequested(r *http.Request) bool {
	return r.URL.Query().Get("mode") == "replace"
}

// importIngressRefusal is the ingress validation of a replace-mode import's
// rule set. It returns the 400 message, or "" to proceed. Merge mode validates
// rule by rule while applying (importPolicyRules), because each rule is judged
// against the store as the rules before it left it.
func importIngressRefusal(r *http.Request, b *configBackup) string {
	if !importReplaceRequested(r) {
		return ""
	}
	if err := validateIngressRuleset(b.PolicyRules); err != nil {
		return "import refused: policy " + err.Error() +
			"; nothing was changed. The policy API refuses the same rule: correct it in the file and import again"
	}
	return ""
}
