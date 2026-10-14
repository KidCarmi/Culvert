package main

import (
	"fmt"
	"sync/atomic"
)

// file_profile_health.go — operator-contract row for dangling file profiles.
//
// A policy rule that references a file profile by ID fails CLOSED when the
// profile no longer resolves (policy.go fileProfileBlockedByID): file-bearing
// transactions on that rule are blocked. The only signals today are a WARN log
// line (rate-limited to once per 5 minutes) and a /metrics counter. An
// administrator whose users report "downloads are blocked" has to SSH in and
// grep logs, or scrape /metrics, to learn why. This surfaces the counter the
// process already holds as one row on /api/diagnostics. It reads an atomic and
// changes no enforcement, policy decision, or logging.
func checkFileProfileResolution() OperatorContractCheck {
	n := atomic.LoadInt64(&statFileProfileUnresolvedBlocked)
	if n == 0 {
		return OperatorContractCheck{
			Code:    "file_profile_resolution",
			Status:  diagOK,
			Message: "no file transaction has been blocked by an unresolved file profile since boot",
		}
	}
	return OperatorContractCheck{
		Code:           "file_profile_resolution",
		Status:         diagWarn,
		Message:        fmt.Sprintf("%d file transaction(s) blocked since boot because a policy rule references a file profile that no longer exists (fail-closed)", n),
		OperatorAction: "Open Policy > File Profiles and restore the missing profile (or re-point the affected rule to an existing profile). The rule blocks file downloads/uploads until then.",
	}
}
