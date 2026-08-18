package main

// cluster_ca_validity.go — cluster-CA usability gate + health plane
// (CHAOS-50, register row CA-13).
//
// CHAOS-28 hardened the INSPECTION CA against its own lifecycle: an expired
// root can still sign, because neither x509.CreateCertificate nor the ECDSA
// primitive checks the parent's NotBefore/NotAfter, so the appliance kept
// minting well-formed leaves that every client rejected — a fleet-wide outage
// with every health surface green. That review closed by naming the surviving
// half: the CLUSTER CA — the one that signs Data-Plane node certificates — has
// none of it. This file is that half.
//
// The failure shape is identical and the blast radius is arguably worse. A DP
// node certificate is the credential for the mTLS channel that carries every
// ConfigSnapshot. When it cannot be validated, the Data Plane does not fall
// back to anything: it keeps serving traffic under whatever policy it last
// received, forever, while the Control Plane believes it is publishing. That
// is a silent CONFIGURATION freeze across the fleet — a policy change an
// operator makes to stop an incident never arrives, and nothing says so.
//
// Three properties are enforced here, each mirroring a CHAOS-28 rule:
//
//   1. Usable() is deliberately DISTINCT from Ready(). Ready() answers "is a
//      cluster CA installed", which is what the enrollment surfaces have always
//      used to decide whether to OFFER enrollment; Usable() answers "can it
//      issue a certificate that will actually authenticate". Folding validity
//      into Ready() would report "cluster CA not initialized" for a CA that is
//      very much initialized, sending the operator to the wrong runbook.
//   2. The sign path REFUSES rather than issuing a certificate that cannot
//      work. This costs no availability that signing would have preserved — a
//      leaf chained to an expired issuer fails path validation in every TLS
//      stack, so the enrollment was already dead — but it converts N opaque
//      handshake failures on N nodes into one counted, named, alerted event on
//      the node that can actually fix it.
//   3. Node certificates are CLAMPED to the issuer's window, so a leaf can
//      never outlive the CA that signed it. Unclamped, this produced the
//      hardest-to-diagnose state in the system: a DP whose own expiry check
//      (certNeedsRenewal, dp_enrollment.go) reads "365 days left" and therefore
//      never renews, while every handshake it makes has been failing since the
//      day its issuer expired.
//
// Rotation recovery is reported on EVIDENCE — an observed successful rotation —
// never on elapsed time, matching storage_health.go and ca_health.go. Usability
// deliberately needs no such tracking; see the note on clusterCAHealthRecord.

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"
)

// clusterCAClockSkewTolerance is how far the cluster CA's NotBefore may sit in
// the future before the CA is treated as unusable. It matches the inspection
// CA's tolerance (internal/ca.caClockSkewTolerance) because the hazard is the
// same one: a node that boots with a bad RTC, or NTP stepping backwards, must
// not take cluster enrollment down over a few seconds of disagreement. The
// cluster CA is minted with NotBefore = now-1h, so this is tolerance on top of
// an already generous backdate.
const clusterCAClockSkewTolerance = 5 * time.Minute

// clusterCAUnusableAlertInterval rate-limits the log line and the alert for an
// unusable cluster CA. A reconnect storm (every DP node retrying enrollment
// after a CP restart) would otherwise emit one line and one webhook per
// attempt, flooding out the alerts the operator actually needs. The counters
// carry the magnitude; one signal per interval carries the page.
const clusterCAUnusableAlertInterval = 5 * time.Minute

// ErrClusterCAUnusable is the sentinel returned by Usable and by SignCSR when
// the cluster CA cannot issue a certificate any peer would accept. Callers
// match it with errors.Is; the wrapped text carries the operator-actionable
// detail (which bound was violated, and when) and contains no key material.
var ErrClusterCAUnusable = errors.New("cluster CA unusable")

// Usable reports whether the cluster CA can currently sign a node certificate
// that will authenticate. nil means yes.
//
// Kept separate from Ready() — see the file header, rule 1.
func (ca *clusterCA) Usable() error {
	ca.mu.RLock()
	cert := ca.cert
	key := ca.key
	ca.mu.RUnlock()
	if key == nil {
		return fmt.Errorf("%w: no cluster CA private key loaded", ErrClusterCAUnusable)
	}
	return clusterCAUsable(cert, time.Now())
}

// clusterCAUsable is the pure validity predicate, split out so tests can drive
// it with an explicit clock instead of waiting for a ten-year CA to expire.
func clusterCAUsable(cert *x509.Certificate, now time.Time) error {
	if cert == nil {
		return fmt.Errorf("%w: no cluster CA loaded", ErrClusterCAUnusable)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("%w: expired at %s (%s ago)", ErrClusterCAUnusable,
			cert.NotAfter.UTC().Format(time.RFC3339),
			now.Sub(cert.NotAfter).Round(time.Second))
	}
	if now.Add(clusterCAClockSkewTolerance).Before(cert.NotBefore) {
		return fmt.Errorf("%w: not valid until %s (system clock may have rolled back)",
			ErrClusterCAUnusable, cert.NotBefore.UTC().Format(time.RFC3339))
	}
	return nil
}

// clampNodeCertValidity narrows a proposed node-certificate window so the leaf
// can never outlive — or predate — the cluster CA that signs it.
//
// RFC 5280 path validation evaluates every certificate in the chain at the time
// of use, so an issuer-outliving leaf is never more useful than a clamped one.
// It is only harder to diagnose, and here it is actively harmful: the DP's
// renewal trigger reads the leaf's own NotAfter, so an unclamped leaf teaches
// the node to sit still through the exact window in which it needed to renew.
func clampNodeCertValidity(notBefore, notAfter time.Time, issuer *x509.Certificate) (leafNotBefore, leafNotAfter time.Time) {
	if issuer == nil {
		return notBefore, notAfter
	}
	if notBefore.Before(issuer.NotBefore) {
		notBefore = issuer.NotBefore
	}
	if notAfter.After(issuer.NotAfter) {
		notAfter = issuer.NotAfter
	}
	return notBefore, notAfter
}

// clusterCAExpiry returns the active cluster CA's NotAfter, or the zero time
// when no CA is loaded. Used by the scrape-time metric, which omits the series
// entirely rather than reporting 0 on a node that has no cluster CA at all.
func (ca *clusterCA) Expiry() time.Time {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	if ca.cert == nil {
		return time.Time{}
	}
	return ca.cert.NotAfter
}

// ─── Health plane ────────────────────────────────────────────────────────────

// clusterCAHealthRecord is the process-wide record of cluster-CA faults. It
// follows caUsabilityHealth's (ca_health.go) contract — count every event,
// rate-limit the log and the alert on independent gates, never lose magnitude to
// rate limiting — because the failure has the same shape: an external condition
// that fires from arbitrary goroutines at arbitrary rates, for as long as the
// condition lasts. It is not a field-for-field copy; see the note below on why
// usability needs no sticky recovery timestamp here.
type clusterCAHealthRecord struct {
	mu sync.Mutex

	// signRefusals is every node-certificate issuance the CA refused because it
	// was outside its own validity window. Every refusal is a node that could
	// not enroll or could not renew, so this is a direct measure of customer
	// impact, not just of the guard firing.
	signRefusals int64

	last       time.Time // most recent observed usability fault
	lastReason string    // sanitised, key-material-free detail

	// There is deliberately NO lastOK counterpart for usability, unlike
	// ca_health.go. The two faults need different machinery because they leave
	// different traces. A failed ROTATION leaves none — nothing about the CA
	// tells you it was supposed to be replaced and wasn't — so it needs the
	// sticky lastRotFail/lastRotOK pair below to answer "is this still broken?".
	// Usability leaves the clearest trace there is: the CA's own validity
	// window, which Usable() reads live and exactly, every time anyone asks. A
	// sticky "recovered" timestamp for it would be state nothing can consume
	// that the live predicate does not already answer better.
	//
	// last/lastReason are kept because they answer a different question the live
	// predicate cannot — WHY issuance was refused, after a rotation has since
	// made the CA usable again — and are surfaced on /api/cluster/ca.

	// rotationFailures is CUMULATIVE — the right shape for a Prometheus counter
	// and the wrong shape for a status row, so the CURRENT state is tracked
	// separately (lastRotFail vs lastRotOK). An operator who fixes the volume
	// and rotates has fixed the problem; a warning keyed on the cumulative
	// counter would keep contradicting them until process restart.
	rotationFailures int64
	lastRotErr       string
	lastRotFail      time.Time
	lastRotOK        time.Time

	logAt   time.Time
	alertAt time.Time
}

var clusterCAHealth clusterCAHealthRecord

// fireClusterCAAlert delivers the cert_expiry alert for a cluster-CA fault.
// Package-level seam so tests observe the transition synchronously instead of
// racing the process-global alerts sink (the -count/-shuffle determinism class
// the CI gate catches).
//
// The event name is the EXISTING cert_expiry rather than a new one: an operator
// who already subscribed a webhook to certificate-lifecycle events must not
// have to discover and add a second name to keep hearing about the CA whose
// expiry takes the whole cluster down. Host distinguishes the two CAs.
var fireClusterCAAlert = func(detail string) {
	// Nobody subscribed → do nothing at all, and in particular do not spawn a
	// goroutine (the per-request alert-producer contract in CLAUDE.md; the
	// enrollment path is not the proxy hot path, but a reconnect storm drives
	// it at comparable rates).
	if !globalAlertStore.HasSubscriber("cert_expiry") {
		return
	}
	go fireAlert("cert_expiry", AlertPayload{
		Host:   "culvert-cluster-ca",
		Detail: detail,
		Source: "cluster-ca",
	})
}

// noteClusterCAUnusable records a refused node-certificate issuance. It runs
// synchronously on the enrolling node's RPC goroutine, so it does memory-only
// work and hands the alert off.
func noteClusterCAUnusable(reason string) {
	safe := sanitizeLog(reason)
	now := time.Now()

	clusterCAHealth.mu.Lock()
	clusterCAHealth.signRefusals++
	clusterCAHealth.last = now
	clusterCAHealth.lastReason = safe
	refusals := clusterCAHealth.signRefusals
	doLog := clusterCAHealth.logAt.IsZero() || now.Sub(clusterCAHealth.logAt) >= clusterCAUnusableAlertInterval
	if doLog {
		clusterCAHealth.logAt = now
	}
	doAlert := clusterCAHealth.alertAt.IsZero() || now.Sub(clusterCAHealth.alertAt) >= clusterCAUnusableAlertInterval
	if doAlert {
		clusterCAHealth.alertAt = now
	}
	clusterCAHealth.mu.Unlock()

	// The recorder can be reached before setupLogger in some startup orders.
	if doLog && logger != nil {
		logger.Printf("ClusterCA: node enrollment/renewal is DOWN — the cluster CA cannot issue a usable "+
			"certificate: %q (%d issuances refused since boot). Data-Plane nodes cannot enroll or renew, and "+
			"nodes whose certificates lapse will stop receiving configuration. Rotate the cluster CA.",
			safe, refusals)
	}
	if doAlert {
		fireClusterCAAlert(fmt.Sprintf(
			"Cluster CA cannot issue node certificates: %s (%d issuances refused since boot) — "+
				"Data-Plane nodes cannot enroll or renew and will stop receiving configuration at their own expiry",
			safe, refusals))
	}
}

// noteClusterCARotationFailure records an auto-rotation round that could not
// install a replacement CA (register row CA-13). Always logged and always
// alerted: it fires at most once per rotation attempt (a 24h cadence), so it is
// bounded by construction and needs no gate.
//
// Before this, the ONLY record of a failed cluster-CA rotation was a string in
// the /api/cluster/ca JSON body. Nothing counted it, nothing alerted on it, and
// no probe moved — so the first symptom of a rotation that had been failing
// every day for a month was the cluster-wide enrollment outage at expiry.
func noteClusterCARotationFailure(reason string) {
	safe := sanitizeLog(reason)
	now := time.Now()
	clusterCAHealth.mu.Lock()
	clusterCAHealth.rotationFailures++
	clusterCAHealth.lastRotErr = safe
	clusterCAHealth.lastRotFail = now
	n := clusterCAHealth.rotationFailures
	clusterCAHealth.mu.Unlock()

	if logger != nil {
		logger.Printf("ClusterCA: auto-rotation FAILED (%d since boot): %q — the cluster CA is still the "+
			"expiring one; at expiry no Data-Plane node can enroll or renew", n, safe)
	}
	fireClusterCAAlert(fmt.Sprintf(
		"Cluster CA auto-rotation FAILED (%d failures since boot): %s — the expiring CA is still in use; "+
			"at expiry no Data-Plane node can enroll or renew", n, safe))
}

// noteClusterCARotated records an OBSERVED successful rotation/import. It is
// what clears the rotation warning — see clusterCARotationDegraded. The
// cumulative counter is deliberately NOT decremented: it feeds a Prometheus
// counter, which must never go backwards.
func noteClusterCARotated() {
	now := time.Now()
	clusterCAHealth.mu.Lock()
	clusterCAHealth.lastRotOK = now
	clusterCAHealth.mu.Unlock()
}

// clusterCARotationDegraded reports whether a cluster-CA rotation has failed
// with no successful one observed since. This is what the status surfaces key
// on — not the cumulative counter, which would latch the warning for the life
// of the process even after the operator fixed it.
func clusterCARotationDegraded() bool {
	clusterCAHealth.mu.Lock()
	defer clusterCAHealth.mu.Unlock()
	if clusterCAHealth.lastRotFail.IsZero() {
		return false
	}
	return !clusterCAHealth.lastRotOK.After(clusterCAHealth.lastRotFail)
}

// clusterCAHealthSnapshot is a consistent read of the fault record.
// RotationFailures is CUMULATIVE (the counter); RotationDegraded is the CURRENT
// state (the status row) — the two must not be conflated.
type clusterCAHealthSnapshot struct {
	SignRefusals     int64
	Last             time.Time
	Reason           string
	RotationFailures int64
	RotationErr      string
	RotationDegraded bool
}

func clusterCAHealthFailures() clusterCAHealthSnapshot {
	clusterCAHealth.mu.Lock()
	defer clusterCAHealth.mu.Unlock()
	return clusterCAHealthSnapshot{
		SignRefusals:     clusterCAHealth.signRefusals,
		Last:             clusterCAHealth.last,
		Reason:           clusterCAHealth.lastReason,
		RotationFailures: clusterCAHealth.rotationFailures,
		RotationErr:      clusterCAHealth.lastRotErr,
		RotationDegraded: !clusterCAHealth.lastRotFail.IsZero() &&
			!clusterCAHealth.lastRotOK.After(clusterCAHealth.lastRotFail),
	}
}

// resetClusterCAHealthForTest clears the process-global record so tests do not
// inherit each other's faults under -count=2 -shuffle=on.
func resetClusterCAHealthForTest() {
	clusterCAHealth.mu.Lock()
	// Fields are reset individually: assigning a zero struct over the record
	// would replace the mutex we are holding, and the deferred Unlock would
	// then release a different, never-locked one.
	clusterCAHealth.signRefusals = 0
	clusterCAHealth.last = time.Time{}
	clusterCAHealth.lastReason = ""
	clusterCAHealth.rotationFailures = 0
	clusterCAHealth.lastRotErr = ""
	clusterCAHealth.lastRotFail = time.Time{}
	clusterCAHealth.lastRotOK = time.Time{}
	clusterCAHealth.logAt = time.Time{}
	clusterCAHealth.alertAt = time.Time{}
	clusterCAHealth.mu.Unlock()
}
