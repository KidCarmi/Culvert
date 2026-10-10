package main

// access_cidr_diag.go — Diagnostics row for rejected admin-access network
// lists. A malformed UI allowlist or trusted-proxy entry at startup/settings
// load is only logged, and the previous (usually empty) set stays in force:
// an empty UI allowlist admits every client and an empty trusted-proxy set
// ignores X-Forwarded-For. This surfaces what the node already knew; it
// changes no parsing, enforcement or fallback behavior.

import (
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
	msg := ""
	if uiBad {
		msg += "Admin UI IP allowlist was rejected (" + ui + "); the previous list stays in force, so if none was set the admin UI accepts every client IP. "
	}
	if tpBad {
		msg += "Trusted-proxy list was rejected (" + tp + "); X-Forwarded-For is not trusted, so lockouts, rate limits and audit entries key on the reverse proxy's address. "
	}
	return OperatorContractCheck{
		Code:           "access_cidr_lists",
		Status:         diagWarn,
		Message:        msg,
		OperatorAction: "Correct the entry under Settings (Admin UI allowed IPs / Trusted proxies) or in config.yaml; a valid save clears this warning.",
	}
}
