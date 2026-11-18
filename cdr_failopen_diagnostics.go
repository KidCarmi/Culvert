package main

import (
	"fmt"
	"sync/atomic"
	"time"
)

// cdrUnsanitizedDeliveryCode is the operator-contract code of the row below.
const cdrUnsanitizedDeliveryCode = "cdr_unsanitized_delivery"

// cdrFailOpenRecentWindow is how long after the most recent fail-open
// passthrough the row keeps warning. Bounded so the row clears on its own once
// the engine has stopped erroring, instead of staying amber until a restart.
const cdrFailOpenRecentWindow = 24 * time.Hour

// cdrFailOpenLastUnixNano is the wall-clock time of the most recent document
// delivered UNSANITIZED because the CDR engine errored and fail_mode is open
// (cdrErrorOutcome's fail-open branch). Observability only: nothing on the
// request path reads it.
var cdrFailOpenLastUnixNano int64

// noteCDRFailOpenPassthrough records the time of a fail-open passthrough.
func noteCDRFailOpenPassthrough() {
	atomic.StoreInt64(&cdrFailOpenLastUnixNano, time.Now().UnixNano())
}

// checkCDRFailOpenPassthrough makes a realized fail-open visible on the
// operator contract. The "cdr" row reports pool availability, so a pool whose
// instances are all reachable reads enabled-healthy even while individual
// Sanitize calls error (engine ERROR, timeout, transport fault) and, under
// fail_mode open, the original document is delivered without sanitization.
// That was visible only as culvert_cdr_fail_open_total on /metrics and as
// per-request CDR_ERROR rows; the CDR page shows the fail-open POSTURE, not
// that it has been exercised. Report-only: reads the existing counter and the
// timestamp above, changes neither the fail mode nor any outcome. Contributes
// NO row unless CDR is enabled, fail_mode is open, and a passthrough happened
// within cdrFailOpenRecentWindow.
func checkCDRFailOpenPassthrough() []OperatorContractCheck {
	return cdrFailOpenPassthroughRows(cdrActiveConfig(), atomic.LoadInt64(&statCDRFailOpen),
		atomic.LoadInt64(&cdrFailOpenLastUnixNano), time.Now())
}

func cdrFailOpenPassthroughRows(cfg CDRConfig, total, lastNano int64, now time.Time) []OperatorContractCheck {
	if !cfg.Enabled || !cfg.CDRFailOpen() || total <= 0 || lastNano == 0 {
		return nil
	}
	ago := now.Sub(time.Unix(0, lastNano))
	if ago < 0 {
		ago = 0 // backward clock step: treat as just now rather than hide it
	}
	if ago > cdrFailOpenRecentWindow {
		return nil
	}
	return []OperatorContractCheck{{
		Code:   cdrUnsanitizedDeliveryCode,
		Status: diagWarn,
		Message: fmt.Sprintf("%d document(s) were delivered UNSANITIZED since startup because the CDR engine returned an "+
			"error and fail_mode is open; the most recent was %s ago", total, ago.Truncate(time.Second)),
		OperatorAction: "Filter the request log for CDR_ERROR to see the affected destinations and the engine's reason, then " +
			"check the Sluice instances under CDR → Instances. Fail-open is a deliberate availability choice; set cdr.fail_mode " +
			"to closed if unsanitized delivery is not acceptable. This row clears 24h after the last passthrough.",
	}}
}
