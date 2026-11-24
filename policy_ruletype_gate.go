package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// The ruleset gate (POL-005): unknown ruleType, and any rule this build cannot
// enforce as written (unenforceableRuleError, below).
//
// Governing invariant: no policy replacement, normalization, migration or
// compatibility conversion may silently remove an enforcement rule and thereby
// expand access. A ruleset the build cannot fully enforce is refused WHOLE, the
// running and persisted policy stay as they were, and the operator is told.
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
//   - new writes (API create/update, import in both modes, draft commit):
//     validateRuleShape, through the ingress validation an operator-submitted
//     rule gets at every such door (policy_ruleset_ingress.go);
//   - import, both modes (and its dry-run preview), and config-version rollback:
//     refused before any section applies, in the HANDLERS, with a 400. A
//     rollback that passes restores EVERY stored rule, as stored: it used to
//     skip any rule the write-time validator disliked (storedRulesetError);
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
		sanitizeLog(boundedRuleName(e.Name)), sanitizeLog(boundedRuleName(e.RuleType)), more)
}

// boundedRuleName caps an operator- or peer-supplied string that is repeated in
// an error, a log line and a viewer-readable Diagnostics row.
func boundedRuleName(s string) string {
	return boundedText(s, 128)
}

// boundedText caps s at about limit bytes on a rune boundary.
func boundedText(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := 0
	for i := range s {
		if i > limit {
			break
		}
		cut = i
	}
	return s[:cut] + "…"
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

// unenforceableRuleError identifies the first rule of a KNOWN type that this
// build cannot enforce as written, and how many there are. These are the shapes
// policyRulePersistable refuses: an access rule carrying a subjectMatch (the
// evaluator does not consult it), an access rule carrying an auth spec, an auth
// rule that fails validation, a null entry, and an empty entry (ruleEnforceable).
//
// Load and ReplaceAll used to DROP such a rule and install the rest
// (SEC-POLICYDROP-1). That is safe for a scoped Allow and fail-open for
// anything that restricts: measured over a real socket, a Block rule carrying a
// subjectMatch was dropped by a bulk replace and, under default allow, the
// request it was written to stop was forwarded. No replacement may remove an
// enforcement rule and so widen access, so the ruleset is refused whole, by the
// same gate and at the same doors as an unknown ruleType.
type unenforceableRuleError struct {
	Name   string
	Reason string
	Count  int
}

func (e *unenforceableRuleError) Error() string {
	more := ""
	name := boundedRuleName(e.Name)
	if e.Count > 1 {
		more = fmt.Sprintf(" (and %d more rule(s))", e.Count-1)
	}
	return fmt.Sprintf("rule %q cannot be enforced by this version: %s%s; the whole ruleset is refused and the running policy is unchanged",
		sanitizeLog(name), sanitizeLog(e.Reason), more)
}

// rulesetGateError is the whole POL-005 gate over the n rules yielded by at: an
// unknown ruleType first (the more specific finding), then any rule the build
// cannot enforce. A nil result means every rule can be installed as written.
func rulesetGateError(n int, at func(int) *PolicyRule) error {
	if err := unknownRuleTypeIn(n, at); err != nil {
		return err
	}
	var first *unenforceableRuleError
	for i := 0; i < n; i++ {
		r := at(i)
		ok, reason := ruleEnforceable(r)
		if ok {
			continue
		}
		if first == nil {
			first = &unenforceableRuleError{Reason: reason}
			if r != nil {
				first.Name = r.Name
			}
		}
		first.Count++
	}
	if first == nil {
		return nil
	}
	return first
}

// ruleEnforceable is policyRulePersistable plus the EMPTY entry. A JSON null (or
// {}) in a rule array decodes, at every door that reads into []PolicyRule, to
// a rule with no name, no type and no action. Nothing validates it there, it
// has no selectors so it matches every request, and an empty action resolves
// to Allow: one null in an imported backup or a snapshot is an allow-everything
// rule at the top of the policy. Only the policy-file door, which decodes
// pointers, could see the null. The gate refuses the empty entry at all of
// them. A NAMED rule with an empty action is not this case and is untouched
// (POL-901 remains an open question).
func ruleEnforceable(r *PolicyRule) (ok bool, reason string) {
	if r != nil && r.Name == "" && r.Action == "" && r.RuleType == "" {
		return false, "empty entry (a null or {} in the rule list)"
	}
	return policyRulePersistable(r)
}

// policyRulesetError is rulesetGateError over a value slice. It is the check
// every bulk door runs (snapshots, backups, imports, drafts, bulk replace).
func policyRulesetError(rules []PolicyRule) error {
	return rulesetGateError(len(rules), func(i int) *PolicyRule { return &rules[i] })
}

// rulesetRefusalCode maps a gate error to its Diagnostics code.
func rulesetRefusalCode(err error) string {
	var rt *unknownRuleTypeError
	if errors.As(err, &rt) {
		return "policy_ruleset_refused_unknown_ruletype"
	}
	return "policy_ruleset_refused_unenforceable_rule"
}

// isRulesetGateError reports whether err came from the POL-005 gate.
func isRulesetGateError(err error) bool {
	var rt *unknownRuleTypeError
	var ue *unenforceableRuleError
	return errors.As(err, &rt) || errors.As(err, &ue)
}

// policyRulesetRefusal is the record of the most recent ruleset this store
// refused for an unrecognized ruleType. Diagnostic state only.
type policyRulesetRefusal struct {
	At     time.Time // most recent refusal
	First  time.Time // first refusal of this same ruleset through this door
	Logged time.Time // when it was last written to the log
	Count  int       // refusals of this same ruleset through this door
	Door   string    // "policy file", "bulk replace", "control-plane snapshot", "pending policy draft"
	Code   string    // Diagnostics code (rulesetRefusalCode)
	Reason string    // already sanitized and bounded (the gate error's text)
}

// rulesetRefusalRelogEvery bounds how often an UNCHANGED refusal is written to
// the log. A data plane facing a control plane it cannot follow refuses the
// same snapshot on every poll; logging each one buries everything else, while
// logging it once lets it scroll away. The first refusal is always logged, and
// any change of door or reason is logged at once. Diagnostics shows the running
// count and both timestamps throughout.
const rulesetRefusalRelogEvery = 15 * time.Minute

// noteRulesetRefused records a refusal for Diagnostics and logs it: always the
// first time, at once when the door or the reason changes, and otherwise at
// most once per rulesetRefusalRelogEvery. The record stays until this store
// next ACCEPTS a ruleset, so an operator who was not watching the log still
// sees that the node is running an older policy than the one it was handed.
func (ps *PolicyStore) noteRulesetRefused(door string, err error) {
	now := time.Now().UTC()
	next := &policyRulesetRefusal{At: now, First: now, Logged: now, Count: 1, Door: door, Code: rulesetRefusalCode(err), Reason: err.Error()}
	if prev := ps.rulesetRefused.Load(); prev != nil && prev.Door == next.Door && prev.Reason == next.Reason {
		next.First, next.Count, next.Logged = prev.First, prev.Count+1, prev.Logged
		if now.Sub(prev.Logged) < rulesetRefusalRelogEvery {
			ps.rulesetRefused.Store(next)
			return
		}
		next.Logged = now
	}
	ps.rulesetRefused.Store(next)
	logWarnf("Policy: %s REFUSED (%d time(s) since %s) — %s",
		sanitizeLog(door), next.Count, next.First.Format(time.RFC3339), sanitizeLog(err.Error()))
}

// decodePolicyFile parses a policy file for Load and applies the ruleType gate
// to it, recording a refusal. One step so that Load has a single "this file is
// not loadable" exit.
func (ps *PolicyStore) decodePolicyFile(data []byte) ([]*PolicyRule, error) {
	var rules []*PolicyRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	if err := rulesetGateError(len(rules), func(i int) *PolicyRule { return rules[i] }); err != nil {
		ps.noteRulesetRefused("policy file", err)
		return nil, err
	}
	// Accepted. Load installs these rules next; retire any earlier refusal.
	ps.rulesetRefused.Store(nil)
	return rules, nil
}

// decodeImportBackup reads a config import body and applies the ruleType gate
// to it, then the ingress validation of a replace-mode ruleset
// (importIngressRefusal). It returns the 400 message, or "" to proceed. Both
// run here, at the door, so they precede every section's apply AND the dry-run
// preview: a preview never promises an import the commit would refuse.
func decodeImportBackup(r *http.Request, b *configBackup) (refusal string) {
	if err := decodeJSON(r, b); err != nil {
		return "invalid JSON: " + err.Error()
	}
	if err := policyRulesetError(b.PolicyRules); err != nil {
		var rt *unknownRuleTypeError
		if errors.As(err, &rt) {
			return "import refused, unrecognised ruleType: " + err.Error()
		}
		return "import refused, a rule cannot be enforced: " + err.Error()
	}
	return importIngressRefusal(r, b)
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
	return storedRulesetError(target.PolicyRules)
}

// storedRulesetError is the gate for a STORED ruleset that is about to replace
// the running one (a config version being restored). It is the POL-005 gate and
// nothing more, on purpose.
//
// The restore used to run every stored rule through the write-time validator
// and SKIP the ones that failed, applying the rest. Both halves were wrong for
// stored data. Skipping removes a rule by the act of restoring. And the
// write-time validator is not a function of the rule alone: it resolves a
// Redirect rule's host in DNS and reads the host's timezone database, and it
// refuses shapes the store legitimately holds and enforces (an action in the
// spelling the policy-file door folds, a rule with no name, an empty action).
// A version captured from the running system must restore to exactly what was
// running, so a version is restored whole, as stored, or — if it holds a rule
// the gate refuses — not at all.
func storedRulesetError(rules []PolicyRule) error {
	return policyRulesetError(rules)
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

// logSnapshotRejection reports one rejected control-plane snapshot (or delta
// remainder). A rejection by the POL-005 gate goes through noteRulesetRefused,
// which records it for Diagnostics and DEDUPLICATES the log line: a data plane
// refuses the same snapshot on every poll, because validation runs before the
// version ratchet moves. Any other rejection reason is logged as it always was.
func logSnapshotRejection(what string, version int64, err error) {
	if isRulesetGateError(err) {
		policyStore.noteRulesetRefused("control-plane snapshot", err)
		return
	}
	logger.Printf("DataPlane: rejecting %s v%d: %v", what, version, err)
}

// checkPolicyRulesetRefused surfaces the refusal record. Contributes nothing
// when the last ruleset this store was handed through a bulk door was accepted.
func checkPolicyRulesetRefused(ps *PolicyStore) []OperatorContractCheck {
	ref := ps.rulesetRefused.Load()
	if ref == nil {
		return nil
	}
	seen := ""
	if ref.Count > 1 {
		seen = fmt.Sprintf(" (refused %d times since %s)", ref.Count, ref.First.Format(time.RFC3339))
	}
	return []OperatorContractCheck{{
		Code:   ref.Code,
		Status: diagWarn,
		Message: fmt.Sprintf("A %s was refused at %s and NOT applied%s: %s. This node is still enforcing the policy it had before.",
			ref.Door, ref.At.Format(time.RFC3339), seen, ref.Reason),
		OperatorAction: "The ruleset holds a rule this version cannot enforce: it was written by a newer version, or edited by hand. Upgrade this node to that version, or remove or correct the named rule at its source (the policy file, or the control plane that publishes the snapshot) and reload. `culvert policy-check <file>` lists every such rule in a file. Nothing is applied until the whole ruleset is understood.",
	}}
}
