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
	if uiBad {
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
