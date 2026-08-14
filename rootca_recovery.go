package main

// rootca_recovery.go — Root-CA load-failure RECOVERY plane (CHAOS-50, register
// row CA-3).
//
// CHAOS-06 made a Root-CA load failure VISIBLE (`sslInspectionLoadError` →
// /healthz, /readyz, the `ca_load_failed` alert). CHAOS-28 made an EXPIRED CA
// fail closed. Neither gave the failure a RECOVERY path, and the gap is the
// shape this register keeps finding: the appliance notices the fault, reports
// it once, and then never re-evaluates it for the life of the process.
//
// Three things were missing and are supplied here.
//
//  1. RETRY. The CA bundle was read exactly once, at startup. The failures that
//     actually happen in production are transient infrastructure faults — a data
//     volume that attaches after the container starts, an NFS/EBS hiccup, a
//     parent directory whose ownership is fixed a minute later, a disk that was
//     full when the first bundle was written. All of them left SSL inspection
//     DISABLED until somebody restarted the process, long after the underlying
//     fault had cleared. A bounded retry converts that class from "operator must
//     notice and restart" to "self-heals in under a minute".
//
//  2. RECOVERY ON EVIDENCE. `sslInspectionLoadError` was WRITE-ONLY: nothing in
//     the process ever cleared it. An operator who fixed the CA at runtime — via
//     the admin force-rotate or a custom-CA upload — kept a red `/healthz`
//     ssl_inspection row, a failing `ca` readiness check and a permanently
//     `not_ready` /readyz?strict=1 until the next restart. That inverts the rule
//     the rest of this plane follows (ca_health.go, storage_health.go): degraded
//     state clears on OBSERVED evidence, never on elapsed time — but it must
//     actually clear when the evidence arrives.
//
//  3. RECOVERY MUST NOT MINT. `LoadOrInitCA` generates and persists a BRAND-NEW
//     root when the bundle path does not exist. That is correct for first boot
//     and wrong for a retry: if the fault is an unmounted volume, the path is
//     absent, and a retry that minted would silently replace the fleet's trust
//     anchor with one no client has ever been told to trust — and write it to
//     the container's ephemeral layer. The retry here therefore re-reads the
//     CONFIGURED bundle (LoadCA) and never mints. Minting a root is a trust
//     decision; it belongs to an operator pressing a button, not to a timer.
//
// Bounded by construction, per the project's "avoid infinite retries" rule:
// caLoadRetryBudget attempts on an exponential backoff, then a terminal log line
// that names the manual recovery and no further work.

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Retry schedule. Package variables rather than constants so the tests can
// compress it (the ca_health.go / auth gate idiom of injecting the clock rather
// than sleeping the real one); production never writes them.
var (
	// caLoadRetryInitial is the first backoff. Short enough that the common
	// container-start volume race self-heals before the first client CONNECT
	// matters, long enough that a permanently-wrong passphrase costs a handful
	// of file reads rather than a spin.
	caLoadRetryInitial = 5 * time.Second

	// caLoadRetryMax caps the backoff.
	caLoadRetryMax = 5 * time.Minute

	// caLoadRetryBudget bounds the number of attempts. With the schedule above
	// this spans roughly 25 minutes, which covers the transient-infrastructure
	// class without retrying forever against a fault only a human can clear
	// (wrong passphrase, corrupt bundle). After the budget the state is
	// terminal and stays reported.
	caLoadRetryBudget = 10
)

// caLoadRecoveryState is the process-wide record of the retry campaign. It
// exists so the admin surfaces can distinguish "still trying" from "gave up",
// which are very different instructions to an operator.
type caLoadRecoveryState struct {
	mu        sync.Mutex
	attempts  int64
	recovered bool
	gaveUp    bool
	lastErr   string
}

var caLoadRecovery caLoadRecoveryState

// caInspectBypassed counts CONNECTs that policy selected for INSPECTION but
// which proceeded as an unscanned tunnel because no Root CA was loaded.
//
// This is the fail-OPEN half of the CA fault surface and it had no counter at
// all: an expired CA moves culvert_ca_inspect_blocked_total (fail closed,
// CHAOS-28) while a CA that never loaded moved nothing, even though it is the
// direction with security consequences — DLP, AV, YARA, CDR and DPI are all off
// for those sessions. An operator could not answer "how much traffic left this
// gateway uninspected during the incident" from any surface in the appliance.
var caInspectBypassed atomic.Int64

// caInspectBypassLogGate rate-limits the runtime warning. The condition holds
// for every inspect-matched CONNECT for as long as the CA is missing, so an
// ungated log line is a flood; the counter carries magnitude.
var caInspectBypassLogGate struct {
	mu sync.Mutex
	at time.Time
}

const caInspectBypassLogInterval = 5 * time.Minute

// noteCAInspectUnavailableBypass records an inspect-matched CONNECT that fell
// through to bypass because the Root CA is not loaded.
//
// Not on any healthy hot path: the dispatcher reaches this only when
// certMgr.Ready() is false, which on a working appliance never happens. A
// mutex here is therefore free, and the startup log line alone was not enough —
// it scrolls away, and nothing afterwards says the gateway is STILL passing
// inspect-matched traffic through unscanned.
func noteCAInspectUnavailableBypass() {
	n := caInspectBypassed.Add(1)

	now := time.Now()
	caInspectBypassLogGate.mu.Lock()
	due := caInspectBypassLogGate.at.IsZero() || now.Sub(caInspectBypassLogGate.at) >= caInspectBypassLogInterval
	if due {
		caInspectBypassLogGate.at = now
	}
	caInspectBypassLogGate.mu.Unlock()

	if due && logger != nil {
		logger.Printf("SSLCA: no Root CA loaded — %d inspect-matched CONNECT(s) have been forwarded UNINSPECTED "+
			"(no DLP/AV/YARA/CDR/DPI on those sessions); restore the CA bundle or rotate a new Root CA", n)
	}
}

// caInspectBypassCount reports the fail-open counter for the metrics and admin
// surfaces.
func caInspectBypassCount() int64 { return caInspectBypassed.Load() }

// noteSSLInspectionRecovered clears the recorded startup load failure after
// OBSERVED evidence that inspection works again.
//
// Callers must only invoke it once the evidence actually covers the fault they
// are clearing. The recorded failure has two causes — the CA could not be
// loaded, or it was loaded but could not be PERSISTED (LoadOrInitCA runs InitCA
// before SaveCA, so a save failure leaves a recorded failure with Ready() true)
// — so an action that installs a live CA without writing it to the bundle path
// resolves only half of them. That is why the admin paths clear this only after
// a successful persist.
func noteSSLInspectionRecovered(how string) {
	if sslInspectionLoadFailure() == "" {
		return
	}
	sslInspectionLoadError.Store("")
	caLoadRecovery.mu.Lock()
	caLoadRecovery.recovered = true
	caLoadRecovery.gaveUp = false
	caLoadRecovery.lastErr = ""
	caLoadRecovery.mu.Unlock()
	if logger != nil {
		logger.Printf("SSLCA: Root CA recovered (%s) — SSL inspection re-enabled", sanitizeLog(how))
	}
}

// attemptInspectionCARecovery performs ONE recovery attempt, choosing the action
// that matches the fault:
//
//   - no bundle path configured  → the failure was InitCA itself (entropy);
//     re-init, since there is no persisted root to contradict.
//   - a CA is loaded             → the failure was the SaveCA half; re-persist.
//     Re-loading would be wrong: the live CA is fine, its durability is not.
//   - otherwise                  → re-read the CONFIGURED bundle. Never
//     LoadOrInitCA: a missing path here means the volume is gone, and minting
//     would silently swap the fleet's trust anchor (see the file header).
func attemptInspectionCARecovery(cfg rootCAStartupConfig) error {
	switch {
	case cfg.Path == "":
		return certMgr.InitCA()
	case certMgr.Ready():
		return certMgr.SaveCA(cfg.Path, cfg.Passphrase)
	default:
		return certMgr.LoadCA(cfg.Path, cfg.Passphrase)
	}
}

// startInspectionCARecoveryLoop arms the bounded retry campaign. It is a no-op
// when no failure was recorded, so a healthy boot spawns no goroutine.
func startInspectionCARecoveryLoop(ctx context.Context, cfg rootCAStartupConfig) {
	if sslInspectionLoadFailure() == "" {
		return
	}
	go runInspectionCARecoveryLoop(ctx, cfg)
}

func runInspectionCARecoveryLoop(ctx context.Context, cfg rootCAStartupConfig) {
	backoff := caLoadRetryInitial
	for attempt := 1; attempt <= caLoadRetryBudget; attempt++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		// The operator may have fixed it by hand in the meantime (force-rotate,
		// custom-CA upload). Nothing left to recover.
		if sslInspectionLoadFailure() == "" {
			return
		}

		err := attemptInspectionCARecovery(cfg)

		caLoadRecovery.mu.Lock()
		caLoadRecovery.attempts++
		if err != nil {
			caLoadRecovery.lastErr = sanitizeLog(err.Error())
		}
		caLoadRecovery.mu.Unlock()

		if err == nil {
			noteSSLInspectionRecovered(fmt.Sprintf("automatic recovery succeeded on attempt %d", attempt))
			return
		}
		if logger != nil {
			logger.Printf("SSLCA: Root CA recovery attempt %d/%d failed: %q — retrying in %s",
				attempt, caLoadRetryBudget, sanitizeLog(err.Error()), backoff)
		}

		backoff *= 2
		if backoff > caLoadRetryMax {
			backoff = caLoadRetryMax
		}
	}

	caLoadRecovery.mu.Lock()
	caLoadRecovery.gaveUp = true
	caLoadRecovery.mu.Unlock()
	if logger != nil {
		logger.Printf("SSLCA: Root CA recovery gave up after %d attempts — SSL inspection stays DISABLED "+
			"(inspect-matched TLS is forwarded UNINSPECTED). Fix the bundle/passphrase and restart, "+
			"or rotate a new Root CA from the admin UI and redistribute it.", caLoadRetryBudget)
	}
}

// caLoadRecoverySnapshot is a consistent read for the admin surfaces.
type caLoadRecoverySnapshot struct {
	Attempts  int64
	Recovered bool
	GaveUp    bool
	LastErr   string
}

func caLoadRecoveryStatus() caLoadRecoverySnapshot {
	caLoadRecovery.mu.Lock()
	defer caLoadRecovery.mu.Unlock()
	return caLoadRecoverySnapshot{
		Attempts:  caLoadRecovery.attempts,
		Recovered: caLoadRecovery.recovered,
		GaveUp:    caLoadRecovery.gaveUp,
		LastErr:   caLoadRecovery.lastErr,
	}
}

// resetCALoadRecoveryForTest clears the recovery record and the fail-open
// counter. Test-only helper kept beside the state it resets, mirroring
// resetCAUsabilityHealthForTest.
func resetCALoadRecoveryForTest() {
	caLoadRecovery.mu.Lock()
	caLoadRecovery.attempts = 0
	caLoadRecovery.recovered = false
	caLoadRecovery.gaveUp = false
	caLoadRecovery.lastErr = ""
	caLoadRecovery.mu.Unlock()
	caInspectBypassed.Store(0)
	caInspectBypassLogGate.mu.Lock()
	caInspectBypassLogGate.at = time.Time{}
	caInspectBypassLogGate.mu.Unlock()
}
