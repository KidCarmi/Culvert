package main

// ca_health.go — Root-CA usability health plane (CHAOS-28, register rows CA-1/CA-2).
//
// The inspection CA is the one piece of state whose failure is invisible from
// inside the appliance: an expired Root CA does not stop the gateway, does not
// error, and does not change a single counter — it just makes every forged leaf
// unacceptable to every client. The operator sees a wave of per-site
// certificate warnings and nothing else; the proxy's `/health` still said
// `ssl_inspection: ready` because Ready() only asks whether a CA is loaded.
//
// This file is the sink for the engine's publish-once usability observers. It
// mirrors storage_health.go's contract exactly, because the failure shape is
// the same (an external condition that fires from arbitrary goroutines at
// arbitrary rates, for as long as the condition lasts):
//
//   - count every event, so magnitude is never lost to rate limiting;
//   - rate-limit the LOG and the ALERT on independent gates;
//   - never spawn a delivery goroutine when nothing subscribes to the event;
//   - report recovery on EVIDENCE (a CA that verifies usable again), never on
//     elapsed time.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/ca"
)

// caUnusableAlertInterval rate-limits the cert_expiry alert and the log line
// emitted for an unusable Root CA. An expired CA fails EVERY inspected
// connection, so an ungated producer would emit one line and one webhook per
// CONNECT — turning a diagnosable outage into a log flood and a webhook queue
// overflow that drops the alerts an operator actually needs. The counters carry
// the magnitude; one signal per interval carries the page.
const caUnusableAlertInterval = 5 * time.Minute

// caUsabilityHealth is the process-wide record of Root-CA usability faults.
type caUsabilityHealth struct {
	mu sync.Mutex

	// refusals is every leaf-sign the ENGINE refused; blocks is every CONNECT
	// the dispatcher failed closed before a handshake was attempted. They are
	// counted separately because they answer different questions: refusals
	// prove the engine guard fired, blocks measure customer impact.
	refusals int64
	blocks   int64

	last       time.Time // most recent observed fault
	lastReason string    // sanitised, key-material-free detail
	lastOK     time.Time // most recent OBSERVED usable verification

	// persistFailures counts rotations that generated a new CA but could not
	// write it to the bundle path (register row CA-2). It is CUMULATIVE — the
	// right shape for a Prometheus counter and the wrong shape for a status
	// row, so the two are tracked separately. lastPersistFail/lastPersistOK
	// carry the CURRENT state: an operator who restores the volume and
	// force-rotates has fixed the problem, and a warning keyed on the
	// cumulative counter would keep contradicting them until process restart.
	//
	// Same "recovery on evidence" rule as the connection-fault record above:
	// only an observed successful bundle write clears it, never elapsed time.
	persistFailures int64
	lastPersistErr  string
	lastPersistFail time.Time
	lastPersistOK   time.Time

	logAt   time.Time
	alertAt time.Time
}

var caUsability caUsabilityHealth

// caEverUnusable short-circuits the recovery observer, so the healthy path
// stays a single relaxed atomic load.
var caEverUnusable atomic.Bool

// fireCAUnusableAlert delivers the cert_expiry alert for an unusable Root CA.
// Package-level seam so tests observe the transition synchronously instead of
// racing the process-global alerts sink (the -count/-shuffle determinism class
// the CI gate catches).
var fireCAUnusableAlert = func(detail string) {
	// Nobody subscribed → do nothing at all, and in particular do not spawn a
	// goroutine. This producer is driven by an external fault and fires from
	// the request path, which is exactly where the per-request alert-producer
	// contract applies (see the HasSubscriber gate documented in CLAUDE.md).
	if !globalAlertStore.HasSubscriber("cert_expiry") {
		return
	}
	go fireAlert("cert_expiry", AlertPayload{
		Host:   "culvert-ca",
		Detail: detail,
		Source: "ca",
	})
}

func init() {
	ca.UnusableObserver = noteCAUnusable
	ca.RotationPersistFailureObserver = noteCARotationPersistFailure
	ca.RotationPersistSuccessObserver = noteCARotationPersisted
}

// noteCAUnusable is the engine observer for a refused leaf sign. It runs
// synchronously on the connection's goroutine, so it does memory-only work and
// hands the alert off.
func noteCAUnusable(reason string) {
	recordCAUsabilityFault(sanitizeLog(reason), true)
}

// noteCAConnectBlocked records a CONNECT that was failed closed by the
// dispatcher because the CA could not produce a usable leaf. Distinct from a
// sign refusal: the dispatcher gate fires FIRST, so on a running gateway the
// blocks counter is the one that moves and the refusals counter stays at zero
// unless some other caller reached the engine directly.
func noteCAConnectBlocked(reason string) {
	recordCAUsabilityFault(sanitizeLog(reason), false)
}

func recordCAUsabilityFault(safeReason string, engineRefusal bool) {
	now := time.Now()
	caEverUnusable.Store(true)

	caUsability.mu.Lock()
	if engineRefusal {
		caUsability.refusals++
	} else {
		caUsability.blocks++
	}
	caUsability.last = now
	caUsability.lastReason = safeReason
	refusals, blocks := caUsability.refusals, caUsability.blocks
	doLog := caUsability.logAt.IsZero() || now.Sub(caUsability.logAt) >= caUnusableAlertInterval
	if doLog {
		caUsability.logAt = now
	}
	doAlert := caUsability.alertAt.IsZero() || now.Sub(caUsability.alertAt) >= caUnusableAlertInterval
	if doAlert {
		caUsability.alertAt = now
	}
	caUsability.mu.Unlock()

	// The observer is installed at init, which can precede setupLogger.
	if doLog && logger != nil {
		logger.Printf("CA: SSL inspection is DOWN — the Root CA cannot sign a usable leaf: %q "+
			"(%d connections blocked, %d sign refusals since boot). Rotate the Root CA and "+
			"redistribute it to clients.", safeReason, blocks, refusals)
	}
	if doAlert {
		fireCAUnusableAlert(fmt.Sprintf(
			"SSL inspection is DOWN — the Root CA cannot sign a usable leaf: %s (%d connections blocked since boot)",
			safeReason, blocks))
	}
}

// noteCARotationPersistFailure records a rotation that produced a new CA but
// could not persist it (register row CA-2). Always logged and always alerted:
// unlike the per-connection fault above it fires at most once per rotation
// attempt (a 24h cadence), so it is bounded by construction and needs no gate.
func noteCARotationPersistFailure(reason string) {
	safe := sanitizeLog(reason)
	now := time.Now()
	caUsability.mu.Lock()
	caUsability.persistFailures++
	caUsability.lastPersistErr = safe
	caUsability.lastPersistFail = now
	n := caUsability.persistFailures
	caUsability.mu.Unlock()

	if logger != nil {
		logger.Printf("CA: auto-rotation generated a new Root CA but could NOT persist it (%d since boot): %q "+
			"— the new CA is in memory only and will be LOST on restart", n, safe)
	}
	if globalAlertStore.HasSubscriber("cert_expiry") {
		go fireAlert("cert_expiry", AlertPayload{
			Host: "culvert-ca",
			Detail: fmt.Sprintf("Root CA rotated but NOT persisted (%d failures since boot): %s — "+
				"the replacement CA exists in memory only and the next restart will rotate again", n, safe),
			Source: "ca",
		})
	}
}

// noteCARotationPersisted records an OBSERVED successful bundle write. It is
// what clears the persistence warning — see caRotationPersistDegraded. The
// cumulative counter is deliberately NOT decremented: it feeds a Prometheus
// counter, which must never go backwards, and the historical fact that a save
// once failed stays worth knowing.
func noteCARotationPersisted() {
	now := time.Now()
	caUsability.mu.Lock()
	caUsability.lastPersistOK = now
	caUsability.mu.Unlock()
}

// caRotationPersistDegraded reports whether the CURRENTLY-active Root CA may be
// memory-only: a bundle write has failed and no successful one has been observed
// since. This is what the diagnostics row, /api/ca/status and the admin panel
// key on — not the cumulative counter, which would latch the warning for the
// life of the process even after the operator fixed the volume and re-rotated.
func caRotationPersistDegraded() bool {
	caUsability.mu.Lock()
	defer caUsability.mu.Unlock()
	if caUsability.lastPersistFail.IsZero() {
		return false
	}
	return !caUsability.lastPersistOK.After(caUsability.lastPersistFail)
}

// noteCAUsable records an OBSERVED successful usability verification. This is
// the only thing that clears the degraded state: silence is not recovery. A CA
// that is still expired looks exactly like a healthy one if nothing happens to
// need a leaf, so an elapsed-time heuristic would report a node recovered
// without a single successful verification behind it.
func noteCAUsable() {
	if !caEverUnusable.Load() {
		return
	}
	now := time.Now()
	caUsability.mu.Lock()
	caUsability.lastOK = now
	caUsability.mu.Unlock()
}

// caUsabilitySnapshot is a consistent read of the fault record. PersistFailures
// is CUMULATIVE (the counter); PersistDegraded is the CURRENT state (the status
// row) — see caRotationPersistDegraded for why they must not be conflated.
type caUsabilitySnapshot struct {
	Refusals        int64
	Blocks          int64
	Last            time.Time
	Reason          string
	PersistFailures int64
	PersistErr      string
	PersistDegraded bool
}

func caUsabilityFailures() caUsabilitySnapshot {
	caUsability.mu.Lock()
	defer caUsability.mu.Unlock()
	return caUsabilitySnapshot{
		Refusals:        caUsability.refusals,
		Blocks:          caUsability.blocks,
		Last:            caUsability.last,
		Reason:          caUsability.lastReason,
		PersistFailures: caUsability.persistFailures,
		PersistErr:      caUsability.lastPersistErr,
		PersistDegraded: !caUsability.lastPersistFail.IsZero() &&
			!caUsability.lastPersistOK.After(caUsability.lastPersistFail),
	}
}

// caInspectionUsable is the single live predicate for "can this node inspect
// right now". It also feeds the recovery observer, so every caller that asks
// the question contributes the evidence that clears a past fault.
func caInspectionUsable() bool {
	if err := certMgr.Usable(); err != nil {
		return false
	}
	noteCAUsable()
	return true
}

// caUsabilityDegraded reports whether the Root CA should be treated as broken
// RIGHT NOW: a fault has been observed and no successful verification has been
// seen since. Used by the operator contract, the proxy's /health, /ready and /metrics.
func caUsabilityDegraded() bool {
	caUsability.mu.Lock()
	defer caUsability.mu.Unlock()
	if caUsability.refusals == 0 && caUsability.blocks == 0 {
		return false
	}
	return !caUsability.lastOK.After(caUsability.last)
}

// resetCAUsabilityHealthForTest clears the record. Test-only helper kept beside
// the state it resets, mirroring resetStorageWriteHealthForTest.
func resetCAUsabilityHealthForTest() {
	caUsability.mu.Lock()
	defer caUsability.mu.Unlock()
	caUsability.refusals = 0
	caUsability.blocks = 0
	caUsability.last = time.Time{}
	caUsability.lastReason = ""
	caUsability.lastOK = time.Time{}
	caUsability.persistFailures = 0
	caUsability.lastPersistErr = ""
	caUsability.lastPersistFail = time.Time{}
	caUsability.lastPersistOK = time.Time{}
	caUsability.logAt = time.Time{}
	caUsability.alertAt = time.Time{}
	caEverUnusable.Store(false)
}
