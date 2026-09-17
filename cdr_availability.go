package main

// CDR backend-availability plane (CHAOS-66).
//
// Three rules live here, and they are coupled:
//
//  1. An enrolled-but-unreachable CDR backend obeys fail_mode.  The pool
//     picker returns nil both when NO instance is enrolled and when every
//     enrolled instance's breaker is open.  Those are different events:
//     the first means CDR was never deployed on this node, the second
//     means the CDR backend is DOWN -- the exact condition the operator's
//     `fail_mode` setting exists to govern.  Collapsing them into one
//     silent pass meant a node configured `fail_mode: closed` failed
//     CLOSED for the first few transient errors and then, the instant its
//     own circuit breaker declared the backend down, failed OPEN for the
//     entire rest of the outage -- the security control switching itself
//     off precisely when its own health logic said the backend was gone.
//
//  2. The bypass is COUNTED and LOGGED.  recordCDRTerminal has no case for
//     "SKIPPED" and runCDRStage logs only on "ERROR", so before this the
//     bypass moved no counter, wrote no log line and raised no alert: the
//     dashboard, /metrics and the `cdr` diagnostics row were all green on a
//     node delivering every file undisarmed.
//
//  3. The alert is HasSubscriber-gated and its Detail is a BOUNDED reason
//     class.  This producer sits on the per-response-body inspect path, so
//     the repo's standing per-request alert contract applies (see CLAUDE.md):
//     ungated, it paid a goroutine spawn + payload build + dedup-mutex round
//     trip on every file during an outage, on the default posture of no
//     webhooks configured at all.  And Store.Dispatch dedups on
//     `event + ":" + Detail`, so the previous raw `err.Error()` -- a gRPC
//     transport error, which embeds the target address and the ephemeral
//     LOCAL port -- minted a distinct dedup key per request that the 30s
//     window could not suppress by construction, fanning out into the
//     500-entry retry queue where it evicts real threat alerts (WK-12/RS-5,
//     the same defect CHAOS-64 closed for fireDNSFailureAlert).

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// cdrUnavailableLogInterval rate-limits the per-request failure log: onset
// is logged immediately, then at most one line per interval, then one
// recovery line naming the suppressed count.  A mitigation for a
// write-amplification defect must not be one itself.
const cdrUnavailableLogInterval = time.Minute

var (
	// statCDRUnavailable counts requests that found every enrolled instance
	// unavailable.  Distinct from statCDRErrors (a call that was made and
	// failed): this is a call that was never attempted.
	statCDRUnavailable int64

	// statCDRNotDeployed counts requests where CDR is enabled but no
	// instance is enrolled.  Deliberately its own counter -- a
	// provisioning gap and a backend outage call for different actions.
	statCDRNotDeployed int64
)

// cdrErrorReasonClass maps a Sanitize/transport error to a BOUNDED reason
// class.  The vocabulary is closed and low-cardinality on purpose: it is a
// Dispatch dedup key and a metric label, and an unbounded value gives the
// dedup key one value per request.  The full cause reaches the
// rate-limited log line and nowhere else.
func cdrErrorReasonClass(err error) string {
	if err == nil {
		return "none"
	}
	if IsFileTooLarge(err) {
		return "file_too_large"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if st, ok := status.FromError(err); ok {
		if class := cdrGRPCCodeClass(st.Code()); class != "" {
			return class
		}
	}
	if strings.Contains(err.Error(), "tls") || strings.Contains(err.Error(), "certificate") {
		return "tls_error"
	}
	return "call_failed"
}

// cdrGRPCCodeClass maps a gRPC status code to a reason class, or "" when
// the code carries no more information than "the call failed".  Split out
// of cdrErrorReasonClass to keep that function under the cyclop threshold.
func cdrGRPCCodeClass(c codes.Code) string {
	switch c {
	case codes.Unavailable:
		return "unavailable"
	case codes.DeadlineExceeded:
		return "timeout"
	case codes.ResourceExhausted:
		return "resource_exhausted"
	case codes.Unauthenticated:
		return "unauthenticated"
	case codes.PermissionDenied:
		return "permission_denied"
	case codes.Unimplemented:
		return "unimplemented"
	case codes.Internal:
		return "backend_internal"
	default:
		return ""
	}
}

// cdrFailureLogGate carries the rate-limit state for the failure log.
type cdrFailureLogGate struct {
	mu         sync.Mutex
	lastLogged time.Time
	suppressed int64
	lastReason string
}

var cdrCallFailureGate cdrFailureLogGate

// noteCDRCallFailure reports whether this failure should be logged.  Onset
// (and any change of reason class) logs immediately; otherwise at most one
// line per cdrUnavailableLogInterval.  The magnitude lives in the counter.
func noteCDRCallFailure(reason string, now time.Time) bool {
	cdrCallFailureGate.mu.Lock()
	defer cdrCallFailureGate.mu.Unlock()
	if cdrCallFailureGate.lastLogged.IsZero() ||
		reason != cdrCallFailureGate.lastReason ||
		now.Sub(cdrCallFailureGate.lastLogged) >= cdrUnavailableLogInterval {
		cdrCallFailureGate.lastLogged = now
		cdrCallFailureGate.lastReason = reason
		cdrCallFailureGate.suppressed = 0
		return true
	}
	cdrCallFailureGate.suppressed++
	return false
}

// resetCDRAvailabilityForTest clears the process-global gate + counters so
// tests do not inherit each other's rate-limit state.
func resetCDRAvailabilityForTest() {
	cdrCallFailureGate.mu.Lock()
	cdrCallFailureGate.lastLogged = time.Time{}
	cdrCallFailureGate.suppressed = 0
	cdrCallFailureGate.lastReason = ""
	cdrCallFailureGate.mu.Unlock()
	atomic.StoreInt64(&statCDRUnavailable, 0)
	atomic.StoreInt64(&statCDRNotDeployed, 0)
}

// fireCDRUnavailableAlert delivers the `cdr_unavailable` alert.
//
// HasSubscriber-gated because this producer is reached from the
// per-response-body inspect path -- the standing contract in CLAUDE.md.
// The gate changes no behaviour (Dispatch filters non-matching webhooks
// anyway) but is reached only AFTER the goroutine spawn, payload build and
// dedup-mutex round trip, which is pure waste on the default posture of no
// webhooks configured -- and lands hardest during exactly the outage that
// produces the alert.
//
// Detail is a bounded reason class, never a raw error (see the file header).
func fireCDRUnavailableAlert(reason string) {
	if globalAlertStore == nil || !globalAlertStore.HasSubscriber("cdr_unavailable") {
		return
	}
	go fireAlert("cdr_unavailable", AlertPayload{
		Source: "cdr",
		Detail: "cdr backend unavailable: " + reason,
	})
}

// cdrUnavailableOutcome decides what happens to a file when the pool could
// not hand out an instance.  See rule 1 in the file header for why the
// empty-pool and all-unavailable cases are deliberately NOT the same.
func cdrUnavailableOutcome(cfg CDRConfig) *cdrRunResult {
	if cdrPool.Len() == 0 {
		// CDR is enabled but nothing is enrolled: the engine was never
		// deployed here.  Blocking every download would convert a
		// provisioning gap into a fleet-wide outage, and the `cdr`
		// diagnostics row already reports this as a hard FAIL with the
		// operator action attached.  Counted so it is not silent.
		atomic.AddInt64(&statCDRNotDeployed, 1)
		return cdrPassSkipped("SKIPPED_NOT_DEPLOYED")
	}
	// Instances ARE enrolled and none can serve: the CDR backend is down.
	// This is the condition fail_mode governs, so route it through the same
	// decision an in-flight call error takes -- one posture for one fault.
	atomic.AddInt64(&statCDRUnavailable, 1)
	if noteCDRCallFailure("all_instances_unavailable", time.Now()) {
		logger.Printf("CDR: all %d enrolled instance(s) unavailable — applying fail_mode (failOpen=%v)",
			cdrPool.Len(), cfg.CDRFailOpen())
	}
	fireCDRUnavailableAlert("all_instances_unavailable")
	return cdrErrorOutcome("cdr_unavailable", "", "", 0, cfg)
}

// cdrBackendAvailable reports whether any enrolled instance could serve a
// request right now.  Non-reserving -- safe for status surfaces.
func cdrBackendAvailable() bool {
	return cdrPool.PeekAvailable() != nil
}
