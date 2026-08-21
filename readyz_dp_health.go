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
//
// DISCLOSURE CONTRACT (shared with appendCAReadinessCheck and
// appendStateFileChecks): /ready is served UNAUTHENTICATED on the proxy port,
// so every detail on these rows is a FIXED, operator-directed string. Both
// rows used to be built with fmt.Sprintf over live internals and published:
//
//	cp_poll   → "control plane unreachable for 12m3s — serving last-known-good
//	             config; policy/auth updates are not arriving"
//	node_cert → "node certificate EXPIRED 4 day(s) ago and renewal is failing
//	             (last error: RenewCert RPC: ... dial tcp 10.0.3.7:9443:
//	             connect: connection refused)"
//
// which hands any client on the network the control plane's internal address
// and port, the raw gRPC/TLS transport error, the exact remaining lifetime of
// this node's mTLS identity, and — the part that actually arms an attacker —
// an explicit statement of the ENFORCEMENT POSTURE: that policy and auth
// updates are not arriving, i.e. a revoked credential or a newly-blocked
// destination is still being honoured here, and for how long it has been so.
// A row STATUS names a degraded subsystem; a row DETAIL must not name the
// security consequence or measure it.
//
// Nothing is lost to the operator. Both causes are already logged by their own
// loops on every occurrence ("DataPlane: GetConfig error" in
// controlplane_client.go, "DataPlane: cert renewal check" in dp_enrollment.go),
// the cert failure additionally fires the latched cert_expiry alert, and the
// CP-reachability posture is spelled out in full on the role-gated
// /api/diagnostics dp_last_known_good_config contract row. The verdicts are
// unchanged: report-only by default, gating under ?strict=1.

import (
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
// is refreshed on every failed attempt and cleared on successful renewal.
//
// It holds ONLY the boolean, deliberately. Its sole consumer is the
// unauthenticated /ready row above, so a days-left int or a lastErr string
// retained here is one fmt.Sprintf away from the public surface — which is
// exactly how the raw renewal error and the cert's remaining lifetime came to
// be published. The days count and the cause stay where they belong: the
// process log and the latched cert_expiry alert, both written by
// alertDPCertRenewalFailure's caller before it reaches this recorder.
var dpNodeCertRenewal struct {
	mu      sync.Mutex
	failing bool
}

func recordDPCertRenewalFailure() {
	dpNodeCertRenewal.mu.Lock()
	dpNodeCertRenewal.failing = true
	dpNodeCertRenewal.mu.Unlock()
}

func clearDPCertRenewalFailure() {
	dpNodeCertRenewal.mu.Lock()
	dpNodeCertRenewal.failing = false
	dpNodeCertRenewal.mu.Unlock()
}

// dpCertRenewalFailing reports whether the last renewal attempt inside the
// renewal window failed. It is the whole probe-facing state.
func dpCertRenewalFailing() bool {
	dpNodeCertRenewal.mu.Lock()
	defer dpNodeCertRenewal.mu.Unlock()
	return dpNodeCertRenewal.failing
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
		// Fixed string, identical on both branches: no elapsed time, and no
		// statement of what stops arriving. Only the STATUS distinguishes a
		// sustained outage from one still inside the grace window — the detail
		// carries no measurement an observer could use to size the stale-config
		// window. The full posture is on the role-gated /api/diagnostics
		// (dp_last_known_good_config) and in the log.
		cp.Detail = "control plane connectivity is degraded — see server logs"
		since := dpCPPollFailingSince.Load()
		if since != 0 && time.Since(time.Unix(0, since)) >= dpCPPollFailGrace {
			cp.Status = "fail"
		}
		// Otherwise: failing but inside the grace window (or a bare flag with no
		// transition stamp) — not yet a probe-visible failure.
	}
	checks["cp_poll"] = cp

	cert := &readinessCheck{Status: "ok"}
	if dpCertRenewalFailing() {
		cert.Status = "fail"
		// Fixed string: no remaining lifetime, no expired/expiring distinction,
		// no renewal cause. All three are in the log and the cert_expiry alert.
		cert.Detail = "node certificate renewal is failing — see server logs"
	}
	checks["node_cert"] = cert
}
