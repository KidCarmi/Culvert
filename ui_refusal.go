package main

// ui_refusal.go — the FE-6A.0 typed-refusal dialect shared by the Identity
// Providers and Administrators admin surfaces (FRONTEND-MIGRATION-PLAN.md
// FE-6-0 C1/C2; the 2F-A PAC fence shape reused verbatim).
//
// Every refusal on these surfaces is application/json {error, code[, current]}
// with a BOUNDED code, so a client renders typed facts and never server prose:
//
//	400 invalid_input          — malformed body / invalid field
//	403 forbidden              — role below the route's floor
//	403 invalid_credentials    — the caller's own current password is wrong
//	404 not_found | vanished   — identity absent (vanished: a fenced write's target)
//	409 stale | last_admin | user_exists | referenced | confirm_mismatch | not_degraded
//	428 precondition_required  — fenced write carried no `revision`
//	500 persist_failed         — durable write failed; nothing changed
//	500 outcome_unknown        — split durable state; NON-terminal (see detail)
//	503 registry_degraded      — the store is quarantined; repair first
//
// A refusal mutates nothing, audits no success, publishes no cluster snapshot
// and advances no config version.

import (
	"encoding/json"
	"net/http"
	"strconv"
)

const (
	refusalInvalidInput         = "invalid_input"
	refusalForbidden            = "forbidden"
	refusalWrongCurrent         = "invalid_credentials"
	refusalNotFound             = "not_found"
	refusalVanished             = "vanished"
	refusalStale                = "stale"
	refusalPreconditionRequired = "precondition_required"
	// refusalPersistenceNotConfigured: the store has no persistence path, so an
	// administrative mutation is refused before any runtime state changes
	// (FE-6A.0 correction, Blocker 7).
	refusalPersistenceNotConfigured = "persistence_not_configured"
	// FE-6A.0 correction, Blocker 6/9 (IdP):
	refusalProviderCompileFailed = "provider_compile_failed" // 502: dependency / provider construction (bounded reason)
	refusalOperationIDRequired   = "operation_id_required"   // 428: a cutover-bearing write needs a client operationId
	// FE-6A.2: a cutover-bearing write (POST or PUT) must also echo the legacy
	// block's server-published cutoverConfirmValue in ?cutoverConfirm= — the
	// T2 ceremony is bound to the authenticator being retired by a SERVER fact.
	refusalCutoverConfirmRequired = "cutover_confirm_required"  // 428: ?cutoverConfirm= absent on a cutover-bearing write
	refusalOperationMismatch      = "operation_mismatch"        // 409: operationId reused for a different candidate
	refusalOperationInProgress    = "operation_in_progress"     // 409: the same operation is still being decided
	refusalOperationAborted       = "operation_aborted"         // 409: replay of an operation that aborted
	refusalOperationUnknown       = "operation_outcome_unknown" // 409: replay of a split outcome awaiting reconciliation
	// Round-3 correction (Blockers 1–2): the operation ledger is fail-closed.
	refusalOperationLedgerDegraded = "operation_ledger_degraded" // 503: corrupt/unreadable ledger, evidence preserved
	refusalOperationLedgerFull     = "operation_ledger_full"     // 503: every slot holds an unresolved intent
	refusalOperationUnsettled      = "operation_unsettled"       // 503: an outstanding intent on the target could not be settled durably
	refusalPersistFailed           = "persist_failed"
	refusalOutcomeUnknown          = "outcome_unknown"
	refusalLastAdmin               = "last_admin"
	refusalUserExists              = "user_exists"
	refusalReferenced              = "referenced"
	refusalConfirmMismatch         = "confirm_mismatch"
	refusalNotDegraded             = "not_degraded"
	refusalRepairUnavailable       = "repair_unavailable"
	refusalRegistryDegraded        = "registry_degraded"
	refusalUpstreamError           = "upstream_error"
	refusalMethodNotAllowed        = "method_not_allowed"
)

// writeRefusal renders one typed refusal. current carries the authoritative
// facts the caller needs to retry (the fence token, the referencing rules,
// …); nil omits the key.
func writeRefusal(w http.ResponseWriter, status int, code, msg string, current map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := map[string]any{"error": msg, "code": code}
	if current != nil {
		body["current"] = current
	}
	_ = json.NewEncoder(w).Encode(body) //nolint:errcheck // best-effort refusal body
}

// requireRoleJSON is requireRole with the typed JSON 403 (same C4
// divergence hook, same defense-in-depth contract — invariant #6). The C1.5
// AST scanner recognises it beside requireRole.
func requireRoleJSON(w http.ResponseWriter, r *http.Request, minRole UIRole) bool {
	if uiRole(r).HasRole(minRole) {
		return true
	}
	recordRoleDivergence(r, minRole)
	writeRefusal(w, http.StatusForbidden, refusalForbidden, "forbidden: insufficient role", nil)
	return false
}

// revisionFence returns the caller's `revision` precondition: the query
// parameter wins when present (malformed reads as 0 ⇒ 428), else the body
// value.
func revisionFence(r *http.Request, body int64) int64 {
	if q := r.URL.Query().Get("revision"); q != "" {
		v, err := strconv.ParseInt(q, 10, 64)
		if err != nil {
			return 0
		}
		return v
	}
	return body
}

// checkRevisionFence applies the fence contract against the authoritative
// current value: absent/zero ⇒ 428, mismatch ⇒ 409 stale (both carrying
// current.revision). Returns false after writing the refusal.
func checkRevisionFence(w http.ResponseWriter, token, current int64) bool {
	if token == 0 {
		writeRefusal(w, http.StatusPreconditionRequired, refusalPreconditionRequired,
			"precondition required: echo the current revision you loaded",
			map[string]any{"revision": current})
		return false
	}
	if token != current {
		writeRefusal(w, http.StatusConflict, refusalStale,
			"stale revision: the object changed since you loaded it — reload and retry",
			map[string]any{"revision": current})
		return false
	}
	return true
}
