package main

// access_cidr_diag.go — Diagnostics row for rejected admin-access network
// lists. A malformed UI allowlist or trusted-proxy entry at startup/settings
// load is only logged, and the previous (usually empty) set stays in force:
// an empty UI allowlist admits every client and an empty trusted-proxy set
// ignores X-Forwarded-For. This surfaces what the node already knew; it
// changes no parsing, enforcement or fallback behavior.

import (
	"fmt"
	"sync"
)

const (
	accessCIDRUIAllow      = "ui_allow_ips"
	accessCIDRTrustedProxy = "trusted_proxy_cidrs"
)

var (
	accessCIDRRejectMu sync.Mutex
	accessCIDRRejects  = map[string]string{}
)

// noteAccessCIDRResult records (err != nil) or clears (err == nil) the
// rejection state for one list. Only the error text is kept; it carries the
// offending entry, never a credential.
func noteAccessCIDRResult(list string, err error) {
	accessCIDRRejectMu.Lock()
	defer accessCIDRRejectMu.Unlock()
	if err == nil {
		delete(accessCIDRRejects, list)
		return
	}
	accessCIDRRejects[list] = err.Error()
}

const accessCIDRListsCode = "access_cidr_lists"

// accessCIDRUIAllowRedacted replaces the UI-allowlist clause below RoleAdmin
// (SEC-DIAG-ACCESSCIDR-1). The clause it stands in for carries the rejected
// entry verbatim and says whether the allowlist IN FORCE is empty — i.e.
// whether admin-UI IP restriction is active at all. Both facts are RoleAdmin
// elsewhere: GET /api/ui-allow-ips requires admin in both methods, and the
// list has no other reader. Serving them on the viewer-readable operator
// contract answered "would a stolen admin credential work from off-network?"
// to the lowest authenticated role.
//
// The trusted-proxy clause is deliberately NOT redacted: GET
// /api/settings/network already returns trusted_proxy_cidrs (and
// trust_forwarded_headers) at RoleViewer, so withholding it here would cost an
// operator actionable remediation detail without concealing anything.
const accessCIDRUIAllowRedacted = "The admin UI IP allowlist was rejected; " +
	"its detail is shown to administrators only. "

// accessCIDRListsRows renders the access-list row twice from ONE read of the
// rejection state: the admin row that goes into the contract, and the
// non-admin rendering redactContractForRole swaps in.
//
// Both come from the same read for the same reason the roster row does: two
// reads could straddle a settings save and report a rejection to one role and
// not the other, which is a disclosure oracle of its own.
func accessCIDRListsRows() (admin, viewer OperatorContractCheck) {
	accessCIDRRejectMu.Lock()
	ui, uiBad := accessCIDRRejects[accessCIDRUIAllow]
	tp, tpBad := accessCIDRRejects[accessCIDRTrustedProxy]
	accessCIDRRejectMu.Unlock()
	if !uiBad && !tpBad {
		// An ok row names neither list, so there is nothing to withhold and
		// both roles get it verbatim — redacting a healthy row would report a
		// condition that does not exist (the admin_username_length precedent).
		ok := OperatorContractCheck{
			Code:    accessCIDRListsCode,
			Status:  diagOK,
			Message: "Admin UI allowlist and trusted-proxy lists loaded without rejected entries",
		}
		return ok, ok
	}
	// A rejected update never mutates the live set (both setters validate the
	// whole list before swapping), so the consequence is described from the
	// list actually in force, not assumed from the rejection.
	msg, viewerMsg := "", ""
	if uiBad {
		msg += "Admin UI IP allowlist was rejected (" + ui + "); the previous list stays in force"
		if n := len(ListUIAllowedCIDRs()); n == 0 {
			msg += ", which is empty, so the admin UI accepts every client IP. "
		} else {
			msg += " (" + accessCIDREntries(n) + "). "
		}
		viewerMsg += accessCIDRUIAllowRedacted
	}
	if tpBad {
		tpClause := "Trusted-proxy list was rejected (" + tp + "); the previous list stays in force"
		if n := len(ListTrustedProxyCIDRs()); n == 0 {
			tpClause += ", which is empty, so X-Forwarded-For is not trusted and lockouts, rate limits and audit entries key on the reverse proxy's address. "
		} else {
			tpClause += " (" + accessCIDREntries(n) + "), so X-Forwarded-For is still trusted only from those proxies. "
		}
		msg += tpClause
		viewerMsg += tpClause
	}
	admin = OperatorContractCheck{
		Code:           accessCIDRListsCode,
		Status:         diagWarn,
		Message:        msg,
		OperatorAction: "Correct the entry under Settings (Admin UI allowed IPs / Trusted proxies) or in config.yaml; a valid save clears this warning.",
	}
	// The STATUS stays warn below admin: a non-admin must still see that a
	// network list is misconfigured and escalate. Only the admin-only detail
	// goes. When the trusted-proxy half is also rejected the viewer keeps its
	// remediation; otherwise the only remaining action is to ask an admin.
	viewer = OperatorContractCheck{
		Code:           accessCIDRListsCode,
		Status:         diagWarn,
		Message:        viewerMsg,
		OperatorAction: diagnosticsRedactedAction,
	}
	if tpBad {
		viewer.OperatorAction = "Correct the trusted-proxy entry under Settings or in config.yaml; a valid save clears that half of this warning. " +
			diagnosticsRedactedAction
	}
	return admin, viewer
}

// checkAccessCIDRLists is the ADMIN rendering — the row that goes into
// OperatorContract.Checks. redactContractForRole replaces it below admin with
// the viewer rendering built alongside it (accessCIDRListsRows).
func checkAccessCIDRLists() OperatorContractCheck {
	admin, _ := accessCIDRListsRows()
	return admin
}

func accessCIDREntries(n int) string {
	if n == 1 {
		return "1 entry"
	}
	return fmt.Sprintf("%d entries", n)
}
