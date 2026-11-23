package main

// default_action_noncanonical.go — owner decision D (policy semantics): a
// stored default policy action that is not exactly "allow" or "deny" keeps
// its fail-closed deny enforcement, but is no longer silent.
//
// Every door that ingests a stored default action validates it with ONE
// validator, parseDefaultAction, and decides on failure:
//
//   - admin_settings.json at boot: enforce deny, log a sanitized warning,
//     raise culvert_default_action_noncanonical{source="admin_settings"} and
//     a diagnostics row, and keep the raw stored value on disk across
//     unrelated settings saves until an operator sets the action explicitly
//     (no silent normalisation of a deployed file).
//   - config-version rollback: enforce deny for "", "block" and every other
//     non-canonical value (unchanged), and say so in the real response's
//     warnings and in the config.rollback audit detail.
//   - config import: ignore the value (unchanged: the current action is
//     kept) and say so in the import response and the dry-run preview.
//   - CP→DP snapshot apply: enforce deny, warn and count; the snapshot is
//     NOT rejected (forward compatibility with a newer CP).
//
// Enforcement never changes here: setDefaultPolicyAction already treats every
// string but exactly "allow" as deny, and a value is never reinterpreted as
// allow ("Allow" would turn a fail-closed deployment into allow-all). YAML
// stays strictly validated at load (config.go validateEnums) and is not
// routed through this file. Startup derivation of an EMPTY action
// (rewrite_default_action_startup.go, POL-002) and how a derived allow
// persists (POL-900, open) are untouched.

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// Sources of a non-canonical default action. They are metric label values,
// so they are fixed strings, never derived from the stored value.
const (
	defaultActionSourceAdminSettings = "admin_settings"
	defaultActionSourceRollback      = "config_rollback"
	defaultActionSourceSnapshot      = "cluster_snapshot"
)

// defaultActionNoncanonicalSources is the fixed emission order of the
// per-source series.
var defaultActionNoncanonicalSources = [...]string{
	defaultActionSourceAdminSettings,
	defaultActionSourceRollback,
	defaultActionSourceSnapshot,
}

// parseDefaultAction is the single validator for a stored or submitted
// default policy action. Only the exact strings "allow" and "deny" are
// canonical; case variants, surrounding whitespace, the legacy "block" and ""
// are not. Callers decide what a failure means for their door; none of them
// may enforce anything but deny for a value this rejects.
func parseDefaultAction(s string) (string, bool) {
	switch s {
	case "allow", "deny":
		return s, true
	}
	return "", false
}

// noncanonicalDefaultAction records that the CURRENT default action is the
// fail-closed deny applied for a non-canonical stored value. word is the
// defaultPolicyActionState word that apply published: any later set (an
// explicit API set, an import, a rollback, a snapshot, a SIGHUP reload)
// strictly increases the word and so retires the record without anyone
// having to clear it.
type noncanonicalDefaultAction struct {
	source string
	raw    string
	word   uint64
}

var noncanonicalDefaultActionState atomic.Pointer[noncanonicalDefaultAction]

// noncanonicalDefaultActionApplied counts, per source, how many times a
// non-canonical value was enforced as deny since startup.
var noncanonicalDefaultActionApplied [len(defaultActionNoncanonicalSources)]atomic.Int64

func noncanonicalDefaultActionSourceIndex(source string) int {
	for i, s := range defaultActionNoncanonicalSources {
		if s == source {
			return i
		}
	}
	return -1
}

// applyNoncanonicalDefaultAction enforces deny for a non-canonical stored
// value and records the episode for the metrics, the diagnostics row and the
// admin-settings raw-value preservation.
func applyNoncanonicalDefaultAction(source, raw string) {
	word := publishDefaultPolicyAction("deny")
	rec := &noncanonicalDefaultAction{source: source, raw: raw, word: word}
	for {
		old := noncanonicalDefaultActionState.Load()
		if old != nil && old.word > word {
			break // a newer non-canonical apply already recorded itself
		}
		if noncanonicalDefaultActionState.CompareAndSwap(old, rec) {
			break
		}
	}
	if i := noncanonicalDefaultActionSourceIndex(source); i >= 0 {
		noncanonicalDefaultActionApplied[i].Add(1)
	}
}

// activeNoncanonicalDefaultAction returns the record while the enforced
// default action is still the deny it applied.
func activeNoncanonicalDefaultAction() (noncanonicalDefaultAction, bool) {
	p := noncanonicalDefaultActionState.Load()
	if p == nil || p.word != defaultPolicyActionState.Load() {
		return noncanonicalDefaultAction{}, false
	}
	return *p, true
}

// applyAdminDefaultAction applies admin_settings.json's default_action at
// boot. Empty means the file does not own the setting (unchanged).
func applyAdminDefaultAction(raw string) {
	if raw == "" {
		return
	}
	if action, ok := parseDefaultAction(raw); ok {
		setDefaultPolicyAction(action)
		return
	}
	applyNoncanonicalDefaultAction(defaultActionSourceAdminSettings, raw)
	logger.Printf("AdminSettings: default_action %q is not \"allow\" or \"deny\"; enforcing deny (fail-closed). Set it explicitly via Policy → Default action.", sanitizeLog(raw))
}

// persistedAdminDefaultAction is the default_action an admin-settings save
// writes. While the enforced deny still stems from a non-canonical value read
// from admin_settings.json, the RAW value is written back verbatim: an
// unrelated settings save must not silently normalise the operator's file.
// It reloads as the same fail-closed deny, and the first explicit set retires
// the record (word fence), after which the canonical live value is written.
func persistedAdminDefaultAction() string {
	if nc, ok := activeNoncanonicalDefaultAction(); ok && nc.source == defaultActionSourceAdminSettings {
		return nc.raw
	}
	return defaultPolicyAction()
}

// applyRollbackDefaultAction applies a config version's default_action. The
// enforcement is unchanged: anything but exactly "allow" is deny, including
// "" (versions captured before the field existed) and the legacy "block".
// It returns the warning for the response and the audit detail, or "".
func applyRollbackDefaultAction(raw string) string {
	if action, ok := parseDefaultAction(raw); ok {
		setDefaultPolicyAction(action)
		return ""
	}
	applyNoncanonicalDefaultAction(defaultActionSourceRollback, raw)
	return rollbackDefaultActionWarning(raw, false)
}

// rollbackDefaultActionWarning is the operator-facing note for a stored
// version whose default_action is not canonical; "" when it is.
func rollbackDefaultActionWarning(raw string, dryRun bool) string {
	if _, ok := parseDefaultAction(raw); ok {
		return ""
	}
	if dryRun {
		return fmt.Sprintf("default_action will be applied as deny (stored %q)", sanitizeLog(raw))
	}
	return fmt.Sprintf("default_action applied as deny (stored %q)", sanitizeLog(raw))
}

// rollbackWarnings is the rollback response's warnings: the pre-flight
// validation (validateConfigBackup, which also feeds the diagnostics rollback
// row and is unchanged) plus the default-action note. valid reflects the
// pre-flight validation only, so a version captured before default_action
// existed ("") or carrying the legacy "block" is not newly reported invalid.
func rollbackWarnings(b *configBackup, dryRun bool) (warnings []string, valid bool) {
	warnings = validateConfigBackup(b)
	valid = len(warnings) == 0
	if note := rollbackDefaultActionWarning(b.DefaultAction, dryRun); note != "" {
		warnings = append(warnings, note)
	}
	return warnings, valid
}

// rollbackDefaultActionAuditSuffix is appended to the config.rollback audit
// detail; "" when the stored value was canonical.
func rollbackDefaultActionAuditSuffix(raw string) string {
	if _, ok := parseDefaultAction(raw); ok {
		return ""
	}
	return fmt.Sprintf("; default_action applied as deny (stored %q)", sanitizeLog(raw))
}

// importDefaultActionWarnings reports an import's default action that will be
// ignored. "" means the export carries no default action (a section export):
// nothing to apply, nothing to report.
func importDefaultActionWarnings(raw string) []string {
	if raw == "" {
		return nil
	}
	if _, ok := parseDefaultAction(raw); ok {
		return nil
	}
	return []string{fmt.Sprintf("defaultAction %q ignored: must be \"allow\" or \"deny\"", sanitizeLog(raw))}
}

// applyImportDefaultAction applies an import's default action when it is
// canonical and otherwise keeps the current one (unchanged behaviour), now
// returning the warning instead of ignoring it silently.
func applyImportDefaultAction(raw string) []string {
	if action, ok := parseDefaultAction(raw); ok {
		setDefaultPolicyAction(action)
		return nil
	}
	return importDefaultActionWarnings(raw)
}

// applySnapshotDefaultAction applies a CP-pushed default action on a DP.
// Empty means the field is absent (unchanged: keep the current action). A
// non-canonical value is enforced as deny (unchanged), warned once per
// episode and counted; the snapshot itself is never rejected for it.
func applySnapshotDefaultAction(raw string) {
	if raw == "" {
		return
	}
	if action, ok := parseDefaultAction(raw); ok {
		setDefaultPolicyAction(action)
		return
	}
	prev, wasActive := activeNoncanonicalDefaultAction()
	applyNoncanonicalDefaultAction(defaultActionSourceSnapshot, raw)
	if wasActive && prev.source == defaultActionSourceSnapshot && prev.raw == raw {
		return // same value re-pushed; already reported
	}
	logger.Printf("DataPlane: config snapshot default_action %q is not \"allow\" or \"deny\"; enforcing deny (fail-closed). The rest of the snapshot is applied.", sanitizeLog(raw))
}

// defaultActionDiagMaxValue bounds the stored value echoed on the
// diagnostics row.
const defaultActionDiagMaxValue = 64

// checkDefaultActionStoredValue is the operator-contract row for a default
// action enforced as deny because its stored value was not canonical. Keyed
// on the CURRENT state, so an explicit set clears it without a restart.
func checkDefaultActionStoredValue() OperatorContractCheck {
	nc, ok := activeNoncanonicalDefaultAction()
	if !ok {
		return OperatorContractCheck{
			Code:    "default_action_stored_value",
			Status:  diagOK,
			Message: fmt.Sprintf("default policy action is %q; no non-canonical stored value is in effect", defaultPolicyAction()),
		}
	}
	raw := nc.raw
	if len(raw) > defaultActionDiagMaxValue {
		raw = raw[:defaultActionDiagMaxValue] + "…"
	}
	return OperatorContractCheck{
		Code:   "default_action_stored_value",
		Status: diagWarn,
		Message: fmt.Sprintf("the default policy action is enforced as deny (fail-closed) because the value from %s is %q, which is not \"allow\" or \"deny\"",
			strings.ReplaceAll(nc.source, "_", " "), sanitizeLog(raw)),
		OperatorAction: "Open Policy > Default action and set Allow or Deny explicitly. Until then the stored value is kept as is and every request that matches no rule is denied.",
	}
}

// defaultActionWritePrometheus emits the non-canonical default-action series
// (called from handleMetrics). Labels are the fixed source names only; the
// stored value never reaches /metrics.
func defaultActionWritePrometheus(w *strings.Builder) {
	nc, active := activeNoncanonicalDefaultAction()
	w.WriteString("\n# HELP culvert_default_action_noncanonical 1 while the default policy action is enforced as deny because the value stored in this source is not \"allow\" or \"deny\"\n")
	w.WriteString("# TYPE culvert_default_action_noncanonical gauge\n")
	for _, src := range defaultActionNoncanonicalSources {
		fmt.Fprintf(w, "culvert_default_action_noncanonical{source=%q} %d\n", src, boolMetric(active && nc.source == src))
	}
	w.WriteString("# HELP culvert_default_action_noncanonical_applied_total Non-canonical stored default policy actions enforced as deny since startup\n")
	w.WriteString("# TYPE culvert_default_action_noncanonical_applied_total counter\n")
	for i, src := range defaultActionNoncanonicalSources {
		fmt.Fprintf(w, "culvert_default_action_noncanonical_applied_total{source=%q} %d\n", src, noncanonicalDefaultActionApplied[i].Load())
	}
}
