package main

import (
	"fmt"
	"sync/atomic"
	"time"
)

// cdrFailOpenRecentCode is the operator-contract code of the row below.
const cdrFailOpenRecentCode = "cdr_fail_open_recent"

// cdrFailOpenRecentWindow is how long after the most recent fail-open
// passthrough the row keeps warning. Bounded so the row clears on its own once
// the engine has stopped erroring, instead of staying amber until a restart.
const cdrFailOpenRecentWindow = 24 * time.Hour

// cdrFailOpenLastMono is the monoNanos stamp of the most recent fail-open
// passthrough: the CDR engine errored, fail_mode is open, and the ORIGINAL
// document went on down the response pipeline unsanitized (cdrErrorOutcome's
// fail-open branch). It records that DECISION, not a delivery: the downstream
// stages (DPI, ClamAV/YARA) still run and may block the document. 0 means
// "never". Monotonic (CHAOS-83) so a wall-clock step cannot hide or age the
// row; process-local and never persisted. Observability only: nothing on the
// request path reads it.
var cdrFailOpenLastMono int64

// noteCDRFailOpenPassthrough records the time of a fail-open passthrough.
func noteCDRFailOpenPassthrough() {
	atomic.StoreInt64(&cdrFailOpenLastMono, monoNanos())
}

// checkCDRFailOpenPassthrough makes a realized fail-open visible on the
// operator contract. The "cdr" row reports pool availability, so a pool whose
// instances are all reachable reads enabled-healthy even while individual
// Sanitize calls error (engine ERROR, timeout, transport fault) and, under
// fail_mode open, the original document continues unsanitized (to DPI and
// AV, which may still block it).
// That was visible only as culvert_cdr_fail_open_total on /metrics and as
// per-request CDR_ERROR rows; the CDR page shows the fail-open POSTURE, not
// that it has been exercised. Report-only: reads the existing counter and the
// timestamp above, changes neither the fail mode nor any outcome. Contributes
// NO row unless CDR is enabled, fail_mode is open, and a passthrough happened
// within cdrFailOpenRecentWindow.
func checkCDRFailOpenPassthrough() []OperatorContractCheck {
	last := atomic.LoadInt64(&cdrFailOpenLastMono)
	if last == 0 {
		return nil
	}
	return cdrFailOpenPassthroughRows(cdrActiveConfig(), atomic.LoadInt64(&statCDRFailOpen), monoSince(last))
}

// cdrFailOpenPassthroughRows builds the row from the count and the running
// time elapsed since the latest passthrough.
func cdrFailOpenPassthroughRows(cfg CDRConfig, total int64, ago time.Duration) []OperatorContractCheck {
	if !cfg.Enabled || !cfg.CDRFailOpen() || total <= 0 || ago > cdrFailOpenRecentWindow {
		return nil
	}
	return []OperatorContractCheck{{
		Code:   cdrFailOpenRecentCode,
		Status: diagWarn,
		Message: fmt.Sprintf("%d document(s) passed CDR UNSANITIZED since startup because the CDR engine returned an "+
			"error and fail_mode is open; the most recent was %s ago. Each continued to DPI and antivirus scanning, "+
			"which may still have blocked it", total, ago.Truncate(time.Second)),
		OperatorAction: "Filter the request log for CDR_ERROR to see the affected destinations and the engine's reason, then " +
			"check the Sluice instances under CDR → Instances. Fail-open is a deliberate availability choice; set cdr.fail_mode " +
			"to closed if passing documents on unsanitized is not acceptable. This row clears 24h after the last passthrough.",
	}}
}
