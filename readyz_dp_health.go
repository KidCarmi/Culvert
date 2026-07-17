package main

// CHAOS-09 — DP dependency health on /ready.
//
// A data-plane node that lost its Control Plane keeps serving traffic on its
// last-known-good config (deliberate: HA-1 posture), and a node whose cert
// renewal keeps failing slides toward the expiry brick — but before this file
// neither condition was visible to a readiness probe: /ready stayed green and
// the load balancer never learned the node was degraded.
//
// Two rows are added to /ready, present only when the process runs as a DP
// (audit.DPMode()):
//
//	cp_poll   — fail once CP polling has been continuously failing for longer
//	            than dpCPPollFailGrace (a single missed 30s poll or a CP
//	            rolling restart must not flip fleet-wide probe rows).
//	node_cert — fail while the node cert is inside its renewal window (or
//	            expired) AND renewal is failing (the CHAOS-12 alert path is
//	            the writer; success clears it).
//
// Both rows are REPORT-ONLY for the default verdict, mirroring the ca /
// policy_loaded / state_file_* posture: gating the default verdict on
// CP-poll failure would let a CP outage eject the entire DP fleet from the
// load balancer at once. Operators who *want* dependency-degraded nodes
// ejected opt in per probe with /ready?strict=1 (see handleReady).

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
)

// dpCPPollFailGrace is how long CP polling must be continuously failing
// before the cp_poll row flips to fail: 10 poll intervals (30s each), so a
// CP rolling update/restart — drain plus container swap, well under this —
// never marks the whole DP fleet degraded.
const dpCPPollFailGrace = 5 * time.Minute

// dpCPPollFailingSince is the UnixNano timestamp of the healthy→failing
// transition of dpControlPlanePollFailing (0 = healthy). Written only via
// dpMarkCPPollFailing / dpMarkCPPollHealthy, the poll loop's entry points.
var dpCPPollFailingSince atomic.Int64

// dpMarkCPPollFailing flags CP polling as failing, stamping the transition
// time on the first failure only (the probe wants "failing since", not
// "last failure").
func dpMarkCPPollFailing() {
	if dpControlPlanePollFailing.CompareAndSwap(false, true) {
		dpCPPollFailingSince.Store(time.Now().UnixNano())
	}
}

// dpMarkCPPollHealthy clears the failing flag and the transition stamp.
func dpMarkCPPollHealthy() {
	dpControlPlanePollFailing.Store(false)
	dpCPPollFailingSince.Store(0)
}

// dpNodeCertRenewal is the probe-facing state of the DP cert-renewal loop.
// Unlike the dpCertExpiryAlert latch (which fires each escalation once), this
// is overwritten on every failed attempt so the /ready row always shows the
// current days-left and last error, and cleared on successful renewal.
var dpNodeCertRenewal struct {
	mu      sync.Mutex
	failing bool
	days    int // days until NotAfter at the last failed attempt (negative = expired)
	lastErr string
}

func recordDPCertRenewalFailure(days int, renewErr error) {
	dpNodeCertRenewal.mu.Lock()
	dpNodeCertRenewal.failing = true
	dpNodeCertRenewal.days = days
	dpNodeCertRenewal.lastErr = ""
	if renewErr != nil {
		dpNodeCertRenewal.lastErr = renewErr.Error()
	}
	dpNodeCertRenewal.mu.Unlock()
}

func clearDPCertRenewalFailure() {
	dpNodeCertRenewal.mu.Lock()
	dpNodeCertRenewal.failing = false
	dpNodeCertRenewal.days = 0
	dpNodeCertRenewal.lastErr = ""
	dpNodeCertRenewal.mu.Unlock()
}

func dpCertRenewalFailureSnapshot() (failing bool, days int, lastErr string) {
	dpNodeCertRenewal.mu.Lock()
	defer dpNodeCertRenewal.mu.Unlock()
	return dpNodeCertRenewal.failing, dpNodeCertRenewal.days, dpNodeCertRenewal.lastErr
}

// appendDPHealthChecks adds the cp_poll and node_cert rows to /ready when
// running as a data plane. Contributes nothing on a CP/standalone node, so
// every existing probe consumer outside DP mode is byte-identical.
func appendDPHealthChecks(checks map[string]*readinessCheck) {
	if !audit.DPMode() {
		return
	}

	cp := &readinessCheck{Status: "ok"}
	if dpControlPlanePollFailing.Load() {
		since := dpCPPollFailingSince.Load()
		if since != 0 && time.Since(time.Unix(0, since)) >= dpCPPollFailGrace {
			cp.Status = "fail"
			cp.Detail = fmt.Sprintf(
				"control plane unreachable for %s — serving last-known-good config; policy/auth updates are not arriving",
				time.Since(time.Unix(0, since)).Round(time.Second))
		} else {
			// Failing but inside the grace window (or a bare flag with no
			// transition stamp): not yet a probe-visible failure.
			cp.Detail = "control plane poll failing (within grace window)"
		}
	}
	checks["cp_poll"] = cp

	cert := &readinessCheck{Status: "ok"}
	if failing, days, lastErr := dpCertRenewalFailureSnapshot(); failing {
		cert.Status = "fail"
		if days < 0 {
			cert.Detail = fmt.Sprintf(
				"node certificate EXPIRED %d day(s) ago and renewal is failing (last error: %s)", -days, lastErr)
		} else {
			cert.Detail = fmt.Sprintf(
				"node certificate expires in %d day(s) and renewal is failing (last error: %s)", days, lastErr)
		}
	}
	checks["node_cert"] = cert
}
