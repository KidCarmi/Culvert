package main

// access_cidr_diag.go — Diagnostics row for rejected admin-access network
// lists. A malformed trusted-proxy entry at startup/settings load is only
// logged, and the previous (usually empty) set stays in force: an empty
// trusted-proxy set ignores X-Forwarded-For. A malformed UI allowlist REFUSES
// the admin UI (fail closed, ui_access_policy.go); the row says so. This surfaces what the node already knew; it
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

func checkAccessCIDRLists() OperatorContractCheck {
	accessCIDRRejectMu.Lock()
	ui, uiBad := accessCIDRRejects[accessCIDRUIAllow]
	tp, tpBad := accessCIDRRejects[accessCIDRTrustedProxy]
	accessCIDRRejectMu.Unlock()
	if !uiBad && !tpBad {
		return OperatorContractCheck{
			Code:    "access_cidr_lists",
			Status:  diagOK,
			Message: "Admin UI allowlist and trusted-proxy lists loaded without rejected entries",
		}
	}
	// A rejected update never mutates the live set (both setters validate the
	// whole list before swapping), so the consequence is described from the
	// list actually in force, not assumed from the rejection.
	msg := ""
	if uiBad && uiAccessPolicyRefused() {
		// The appliance line fails CLOSED on a rejected UI allowlist
		// (refuseLoadedUIAccessPolicy): no previous list is in force, the
		// admin UI is refused to everyone. Describing the stale list here
		// would tell the operator the UI is open when it is locked.
		msg += "Admin UI IP allowlist was rejected (" + ui + "); the admin UI is refused to every client until a valid list is saved or local recovery is performed. "
	} else if uiBad {
		msg += "Admin UI IP allowlist was rejected (" + ui + "); the previous list stays in force"
		if n := len(ListUIAllowedCIDRs()); n == 0 {
			msg += ", which is empty, so the admin UI accepts every client IP. "
		} else {
			msg += " (" + accessCIDREntries(n) + "). "
		}
	}
	if tpBad {
		msg += "Trusted-proxy list was rejected (" + tp + "); the previous list stays in force"
		if n := len(ListTrustedProxyCIDRs()); n == 0 {
			msg += ", which is empty, so X-Forwarded-For is not trusted and lockouts, rate limits and audit entries key on the reverse proxy's address. "
		} else {
			msg += " (" + accessCIDREntries(n) + "), so X-Forwarded-For is still trusted only from those proxies. "
		}
	}
	return OperatorContractCheck{
		Code:           "access_cidr_lists",
		Status:         diagWarn,
		Message:        msg,
		OperatorAction: "Correct the entry under Settings (Admin UI allowed IPs / Trusted proxies) or in config.yaml; a valid save clears this warning.",
	}
}

func accessCIDREntries(n int) string {
	if n == 1 {
		return "1 entry"
	}
	return fmt.Sprintf("%d entries", n)
}
