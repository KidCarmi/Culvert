package main

// ca_expiry.go — CHAOS-30: expiry surveillance for the SSL-inspection Root CA.
//
// Culvert already watches the DP↔CP *node* certificate slide toward expiry
// (CHAOS-12, dp_enrollment.go): a latched escalation alert plus a /ready row.
// The inspection Root CA — whose expiry is a far larger blast radius, since
// every inspected HTTPS session on the node stops working at once — had no
// equivalent. Its only producer was RotationObserver, which fires *after* a
// rotation succeeds; there was no signal at all for the case that matters,
// which is rotation NOT happening.
//
// This mirrors the CHAOS-12 model deliberately, down to the latch semantics:
//
//   - Three escalation levels (renewal window ≤30d · final week ≤7d · expired)
//     so the 24h rotation ticker cannot re-fire the same alert daily.
//   - The latch RESETS when the CA returns to healthy (a successful rotation
//     pushes expiry years out), so recovery is reported on evidence and the
//     next real escalation is not swallowed.
//   - A restart re-fires once at the current level. Documented, same posture
//     as the DP cert latch and the release-catalog latches (RT-H2).
//
// Evaluation order is load-bearing: the rotation loop attempts rotation FIRST
// and evaluates expiry AFTER. On a healthy appliance auto-rotation resolves
// the condition before it can alert, so a fired alert means what an operator
// needs it to mean — "the CA is expiring and rotation did not fix it."

import (
	"fmt"
	"sync"
	"time"
)

const (
	// caExpiryWarnDays matches the rotation window (ca.caRotationOverlap): once
	// inside it, a healthy node has already rotated, so still being here is the
	// signal.
	caExpiryWarnDays = 30
	// caExpiryCriticalDays is the final week — operator action (redistributing
	// a new root to endpoints) takes days, not minutes.
	caExpiryCriticalDays = 7
)

// caExpiryAlert latches the highest escalation level already reported.
var caExpiryAlert struct {
	mu    sync.Mutex
	level int // 0 healthy · 1 ≤30d · 2 ≤7d · 3 expired
}

// caExpiryAlertLevel maps days-until-expiry to an escalation level.
func caExpiryAlertLevel(days int) int {
	switch {
	case days < 0:
		return 3
	case days <= caExpiryCriticalDays:
		return 2
	case days <= caExpiryWarnDays:
		return 1
	default:
		return 0
	}
}

// caExpiryState reports days-until-expiry for the inspection Root CA and
// whether a CA is loaded at all. It is the single source of truth for the
// expiry clock: it reads certMgr.CAExpiry() (the real NotAfter) rather than
// re-parsing the date-truncated string CACertInfo renders for display.
//
// The two facts are returned separately on purpose. The pre-existing
// caExpiryDaysRemaining() folds "no CA" into -1, which collides with "expired
// yesterday" — the two states an operator most needs to tell apart. Callers
// that must distinguish them use this.
func caExpiryState() (days int, ready bool) {
	expiry := certMgr.CAExpiry()
	if expiry.IsZero() {
		return 0, false
	}
	return int(time.Until(expiry).Hours() / 24), true
}

// checkCAExpiry evaluates the Root CA's expiry clock and fires a latched
// cert_expiry alert on each new escalation. Called immediately at startup and
// after every rotation attempt. No-op when no CA is loaded: a node with SSL
// inspection switched off must not be told its CA is expiring (checkRootCA
// already carries the "not initialised" posture row).
func checkCAExpiry() {
	days, ready := caExpiryState()
	if !ready {
		return
	}
	level := caExpiryAlertLevel(days)

	caExpiryAlert.mu.Lock()
	if level == 0 {
		// Healthy again (rotation succeeded, or a new CA was imported): clear
		// the latch so the next real escalation is reported.
		caExpiryAlert.level = 0
		caExpiryAlert.mu.Unlock()
		return
	}
	latched := level <= caExpiryAlert.level
	if !latched {
		caExpiryAlert.level = level
	}
	caExpiryAlert.mu.Unlock()
	if latched {
		return
	}

	var detail string
	if days < 0 {
		detail = fmt.Sprintf("SSL-inspection Root CA EXPIRED %d day(s) ago — leaf signing is refused (fail-closed) and every inspected HTTPS session on this node fails until a valid CA is installed and distributed to endpoint trust stores", -days)
	} else {
		detail = fmt.Sprintf("SSL-inspection Root CA expires in %d day(s) and auto-rotation has not replaced it — at expiry every inspected HTTPS session on this node fails; note that a rotated Root CA must also be distributed to endpoint trust stores before it can be used", days)
	}
	// deferStartupAlert: the immediate startup check runs before
	// loadPersistentAdminState has populated the webhook store.
	deferStartupAlert("cert_expiry", AlertPayload{
		Host:   "culvert-ca",
		Detail: detail,
		Source: "ca",
	})
}
