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
//
// EVERY detail on these rows is a FIXED string, for the reason recorded on
// appendCAReadinessCheck (healthcheck.go): /ready is served by
// routeProxyListenerBuiltin on the PROXY listener, unauthenticated and with no
// IP guard, so every client that can use the gateway reads whatever is written
// here. Both rows used to interpolate:
//
//	cp_poll   → "control plane unreachable for 12m41s — serving last-known-good
//	             config; policy/auth updates are not arriving"
//	node_cert → "node certificate expires in 3 day(s) and renewal is failing
//	             (last error: RenewCert RPC: ... dial tcp 10.0.1.5:9443: ...)"
//
// That published the Control Plane's internal address and port, raw
// dial/x509/filesystem causes from the renewal path (renewDPCert wraps
// atomicWriteFile, so an unwritable volume put "/data/node.crt: permission
// denied" on the public surface), and a precise countdown to the moment this
// node's cluster identity dies. It also stated the ENFORCEMENT POSTURE in the
// plainest terms available — "policy/auth updates are not arriving" tells an
// unauthenticated observer exactly when this node is serving stale policy, so a
// destination blocked minutes ago, or an account just revoked at the IdP, is
// knowably still honoured here. That is the disclosure appendCAReadinessCheck's
// contract forbids by name, and the reason this rule is stated on both files.
//
// Nothing is lost to the operator. Every CP-poll failure is logged by
// DataPlaneClient ("DataPlane: GetConfig error"), and every renewal failure is
// logged by dpCertRenewalLoop AND raised as a latched cert_expiry alert with the
// days-left escalation. The rows, their statuses, and the report-only/strict
// verdict split are unchanged, so probe and load-balancer behaviour is
// byte-identical — only the operator-only cause is withheld.
//
// The failure state itself (days-left, last error) is still RECORDED in
// dpNodeCertRenewal for the role-gated surfaces; it is simply not published
// here. See readyz_dp_detail_disclosure_test.go for the pinned contract.
func appendDPHealthChecks(checks map[string]*readinessCheck) {
	if !audit.DPMode() {
		return
	}

	cp := &readinessCheck{Status: "ok"}
	if dpControlPlanePollFailing.Load() {
		since := dpCPPollFailingSince.Load()
		if since != 0 && time.Since(time.Unix(0, since)) >= dpCPPollFailGrace {
			cp.Status = "fail"
			cp.Detail = "control plane connectivity degraded — see server logs"
		}
		// Failing but inside the grace window (or a bare flag with no transition
		// stamp): by this row's own definition "not yet a probe-visible failure",
		// so it publishes NOTHING. The previous "(within grace window)" detail
		// contradicted that — an ok row that still handed every client on the
		// network the same degradation fingerprint the fail row is redacted for.
	}
	checks["cp_poll"] = cp

	cert := &readinessCheck{Status: "ok"}
	// days/lastErr are deliberately not read: both branches collapse to one fixed
	// string. Separate wording for the expired branch would leak the same posture
	// ("this node's cluster identity is already dead") a status of "fail" does not.
	if failing, _, _ := dpCertRenewalFailureSnapshot(); failing {
		cert.Status = "fail"
		cert.Detail = "node certificate renewal is failing — see server logs"
	}
	checks["node_cert"] = cert
}
