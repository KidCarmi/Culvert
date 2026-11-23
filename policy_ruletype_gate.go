package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Unknown ruleType gate.
//
// A PolicyRule's RuleType selects the stage that evaluates it: "" or "access"
// is a Stage-2 access rule, "auth" a Stage-1 authentication rule. Any other
// value is one this build has no stage for. Stage-2 skips every non-access rule
// and Stage-1 skips every non-auth rule, so such a rule used to be installed
// and then matched NOTHING: with default_action=allow, or a lower-priority
// Allow, the traffic it was written to restrict was forwarded, with no warning.
//
// Unlike an unknown ACTION (POL-004: kept, and a match blocks), an unknown TYPE
// cannot be enforced conservatively by keeping the rule — this build does not
// know which stage it belongs to or what its other fields mean. Dropping it is
// the same fail-open, one step earlier. So a ruleset that contains one is
// refused WHOLE, at every door, and the running policy stays as it was:
//
//   - new writes (API create/update, import merge, draft commit): validateRuleShape;
//   - import, both modes (and its dry-run preview), and config-version rollback:
//     refused before any section applies, in the HANDLERS, with a 400;
//   - a pending policy draft on disk: not reloaded (initPolicyDraft), so it can
//     never come back as an active draft with an empty candidate;
//   - control-plane snapshots: validateConfigSnapshot, on publish and on apply,
//     before any mutation — the node keeps its last applied snapshot;
//   - PolicyStore.Load: returns an error. On reload the previous rules stand AND
//     the reloaded default action is not applied over them (hotReloadPolicyFile);
//     at startup initPolicy treats it as fatal, exactly like a malformed file,
//     so the proxy never serves a policy it could only partly understand;
//   - PolicyStore.ReplaceAll: refuses atomically. Defense in depth — every
//     production caller is gated above.

// knownRuleType reports whether this build has a stage for the rule type.
func knownRuleType(t string) bool {
	return t == "" || t == ruleTypeAccess || t == ruleTypeAuth
}

// unknownRuleTypeError identifies the first rule that carries an unrecognized
// ruleType and how many rules in the set do.
type unknownRuleTypeError struct {
	Name     string
	RuleType string
	Count    int
}

func (e *unknownRuleTypeError) Error() string {
	more := ""
	if e.Count > 1 {
		more = fmt.Sprintf(" (and %d more rule(s))", e.Count-1)
	}
	return fmt.Sprintf("rule %q has ruleType %q, which this version does not recognise%s; the whole ruleset is refused and the running policy is unchanged",
		sanitizeLog(e.Name), sanitizeLog(e.RuleType), more)
}

// unknownRuleTypeIn returns a non-nil *unknownRuleTypeError when any of the n
// rules yielded by at carries an unrecognized ruleType. A nil rule is ignored:
// the persistability gate already refuses it.
func unknownRuleTypeIn(n int, at func(int) *PolicyRule) error {
	var first *unknownRuleTypeError
	for i := 0; i < n; i++ {
		r := at(i)
		if r == nil || knownRuleType(r.RuleType) {
			continue
		}
		if first == nil {
			first = &unknownRuleTypeError{Name: r.Name, RuleType: r.RuleType}
		}
		first.Count++
	}
	if first == nil {
		return nil
	}
	return first
}

// policyRulesRuleTypeError is unknownRuleTypeIn over a value slice (snapshots,
// backups, bulk replace).
func policyRulesRuleTypeError(rules []PolicyRule) error {
	return unknownRuleTypeIn(len(rules), func(i int) *PolicyRule { return &rules[i] })
}

// policyRulesetRefusal is the record of the most recent ruleset this store
// refused for an unrecognized ruleType. Diagnostic state only.
type policyRulesetRefusal struct {
	At     time.Time
	Door   string // "policy file", "bulk replace", "control-plane snapshot"
	Reason string // already sanitized (unknownRuleTypeError.Error)
}

// noteRulesetRefused logs a refusal and records it for Diagnostics. The record
// stays until this store next ACCEPTS a ruleset through Load or ReplaceAll, so
// an operator who was not watching the log still sees that the node is running
// an older policy than the one it was handed.
func (ps *PolicyStore) noteRulesetRefused(door string, err error) {
	logWarnf("Policy: %s REFUSED — %s", sanitizeLog(door), sanitizeLog(err.Error()))
	ps.rulesetRefused.Store(&policyRulesetRefusal{At: time.Now().UTC(), Door: door, Reason: err.Error()})
}

// decodePolicyFile parses a policy file for Load and applies the ruleType gate
// to it, recording a refusal. One step so that Load has a single "this file is
// not loadable" exit.
func (ps *PolicyStore) decodePolicyFile(data []byte) ([]*PolicyRule, error) {
	var rules []*PolicyRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	if err := unknownRuleTypeIn(len(rules), func(i int) *PolicyRule { return rules[i] }); err != nil {
		ps.noteRulesetRefused("policy file", err)
		return nil, err
	}
	// Accepted. Load installs these rules next; retire any earlier refusal.
	ps.rulesetRefused.Store(nil)
	return rules, nil
}

// decodeImportBackup reads a config import body and applies the ruleType gate
// to it. It returns the 400 message, or "" to proceed. The gate runs here, at
// the door, so it precedes every section's apply AND the dry-run preview: a
// preview never promises an import the commit would refuse.
func decodeImportBackup(r *http.Request, b *configBackup) (refusal string) {
	if err := decodeJSON(r, b); err != nil {
		return "invalid JSON: " + err.Error()
	}
	if err := policyRulesRuleTypeError(b.PolicyRules); err != nil {
		return "import refused, unrecognised ruleType: " + err.Error()
	}
	return ""
}

// rollbackTargetRefusal is the shape checks a stored version must pass before
// rollbackConfigVersion applies anything: unique rewrite identities, and no
// rule type this build has no stage for. An error from applyConfigBackup is
// read by the handler as "applied but not durable", so the refusal has to be
// decided here, where it is a truthful 400.
func rollbackTargetRefusal(target *configBackup) error {
	if err := validateRewriteStableIDs(target.RewriteRules); err != nil {
		return err
	}
	return policyRulesRuleTypeError(target.PolicyRules)
}

// clearRulesetRefusal drops the refusal record if it came through door. Used
// where a door accepts a ruleset without calling Load or ReplaceAll: a snapshot
// applied with no policy section must still retire a "snapshot refused" row.
func (ps *PolicyStore) clearRulesetRefusal(door string) {
	if ref := ps.rulesetRefused.Load(); ref != nil && ref.Door == door {
		ps.rulesetRefused.CompareAndSwap(ref, nil)
	}
}

// hotReloadPolicyFile is applyHotReload's policy step. It reports whether the
// reloaded configuration's DEFAULT ACTION may be applied: not when the policy
// file was refused. The rules and the default action are one policy; applying
// a new default over the rules of the previous configuration would enforce a
// combination nobody wrote (old Allow rules under a new default allow, say).
func hotReloadPolicyFile(path string) (applyDefaultAction bool) {
	if path == "" {
		return true
	}
	if err := policyStore.Load(path); err != nil {
		logger.Printf("Reload: policy error: %v — keeping the running rules AND the running default action", err)
		return false
	}
	logger.Printf("Reload: policy %d rules", len(policyStore.List()))
	return true
}

// noteSnapshotPolicyRefusal records a control-plane snapshot refused for an
// unrecognized ruleType against the running store. Any other rejection reason
// is not this gate's to record.
func noteSnapshotPolicyRefusal(err error) {
	var rt *unknownRuleTypeError
	if errors.As(err, &rt) {
		policyStore.noteRulesetRefused("control-plane snapshot", rt)
	}
}

// checkPolicyRulesetRefused surfaces the refusal record. Contributes nothing
// when the last ruleset this store was handed through a bulk door was accepted.
func checkPolicyRulesetRefused(ps *PolicyStore) []OperatorContractCheck {
	ref := ps.rulesetRefused.Load()
	if ref == nil {
		return nil
	}
	return []OperatorContractCheck{{
		Code:   "policy_ruleset_refused_unknown_ruletype",
		Status: diagWarn,
		Message: fmt.Sprintf("A %s was refused at %s and NOT applied: %s. This node is still enforcing the policy it had before.",
			ref.Door, ref.At.Format(time.RFC3339), ref.Reason),
		OperatorAction: "The ruleset was written by a version that knows a rule type this one does not (or was edited by hand). Upgrade this node to that version, or remove or correct the named rule at its source (the policy file, or the control plane that publishes the snapshot) and reload. Nothing is applied until the whole ruleset is understood.",
	}}
}
