package main

// cluster_ca_validity.go — cluster-CA usability gate (CHAOS-50, register row CA-13).
//
// This is the CHAOS-28 contract, applied to the OTHER CA.
//
// CHAOS-28 established that `x509.CreateCertificate` never checks the parent's
// NotBefore/NotAfter, so an expired issuer keeps minting well-formed
// certificates that every relying party rejects. It fixed that for the
// inspection CA (`internal/ca`) and left the identical hole open in the
// **cluster** CA — the trust root for CP↔DP mTLS, node enrollment, and node
// cert renewal — because the lifecycle and blast radius are different enough to
// deserve their own sweep. This is that sweep.
//
// The cluster-CA version of the failure is quieter and lasts longer:
//
//   - `clusterCA.Ready()` is `cert != nil && key != nil`. It is the gate the
//     enrollment RPC uses (controlplane_server.go), so an expired cluster CA
//     reports `enrollEnabled: true`, accepts an enrollment token, signs a CSR,
//     and returns HTTP-equivalent success with a certificate that can never
//     complete an mTLS handshake. The DP writes it to disk, believes it is
//     enrolled, and fails to connect forever. The CP holds a registered node
//     record for a node that will never appear.
//   - Node certificates were minted with a FIXED one-year lifetime regardless
//     of how much life the issuer had left. Any cluster CA with under a year
//     remaining — which includes every CA inside its own 30-day auto-rotation
//     window, and every custom CA an operator imports with a shorter life —
//     produced node certs that outlive their issuer. Those nodes' renewal
//     clocks (`certNeedsRenewal`, 30 days before the NODE cert expires) do not
//     fire, so nothing renews them, and the whole fleet drops off mTLS at the
//     instant the CA expires.
//
// Refusing to sign costs no availability that signing would have preserved: a
// node cert chained to an expired issuer fails path validation in Go's own TLS
// stack, so the enrollment was already dead. What changes is that the appliance
// now knows, says so on a metric and a health probe, and names the remediation
// instead of producing N indistinguishable "certificate signed by unknown
// authority" errors on N data-plane nodes.

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// clusterCAClockSkewTolerance is how far the cluster CA's NotBefore may sit in
// the future before the CA is treated as unusable. It matches the backdating
// SignCSR already applies to the node certs it issues, so both ends of the same
// window use one tolerance — and it keeps a node with a bad RTC, or one that
// just took an NTP step backwards, from refusing to enroll anything.
const clusterCAClockSkewTolerance = 5 * time.Minute

// clusterCAUnusableAlertInterval rate-limits the log line and the cert_expiry
// alert for an unusable cluster CA. A reconnect storm drives every node at the
// enrollment/renewal RPC at once, so an ungated producer would emit one line and
// one webhook per node per attempt. The counters carry the magnitude; one signal
// per interval carries the page.
const clusterCAUnusableAlertInterval = 5 * time.Minute

// errClusterCAUnusable is the umbrella sentinel returned by clusterCA.Usable
// and by SignCSR when the cluster CA cannot issue a certificate any peer will
// accept. Callers match it with errors.Is; the wrapped text carries the
// operator-actionable detail and contains no key material.
//
// errClusterCAExpired and errClusterCANotYetValid are wrapped ALONGSIDE it (Go
// multi-%w) so a caller can tell the two apart. They are not cosmetic: the two
// states have opposite remediations. An expired CA needs a rotation or an
// import; a not-yet-valid one means this Control Plane's clock is behind, and
// rotating the trust root in response would be an unnecessary, fleet-wide
// operation that does not fix the actual fault. Reporting both as "expired"
// steers the operator into exactly that mistake.
var (
	errClusterCAUnusable    = errors.New("cluster CA unusable")
	errClusterCAExpired     = errors.New("expired")
	errClusterCANotYetValid = errors.New("not yet valid")
)

// clusterCAUsable is the pure validity predicate, split out so tests can drive
// it with an explicit clock instead of waiting ten years for a CA to expire.
func clusterCAUsable(cert *x509.Certificate, now time.Time) error {
	if cert == nil {
		return fmt.Errorf("%w: no cluster CA loaded", errClusterCAUnusable)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("%w: %w at %s (%s ago)", errClusterCAUnusable, errClusterCAExpired,
			cert.NotAfter.UTC().Format(time.RFC3339),
			now.Sub(cert.NotAfter).Round(time.Second))
	}
	if now.Add(clusterCAClockSkewTolerance).Before(cert.NotBefore) {
		return fmt.Errorf("%w: %w until %s (system clock may have rolled back)",
			errClusterCAUnusable, errClusterCANotYetValid,
			cert.NotBefore.UTC().Format(time.RFC3339))
	}
	return nil
}

// clusterCAUnusableKind classifies an Usable() error into a stable, machine-
// readable token for /healthz, the admin API, and the GUI's remediation text.
// "" means usable.
func clusterCAUnusableKind(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errClusterCAExpired):
		return "expired"
	case errors.Is(err, errClusterCANotYetValid):
		return "not_yet_valid"
	default:
		return "unavailable"
	}
}

// clusterCAUnusableRemediation returns the operator action that actually fixes
// the given kind. Kept next to the classifier so the two can never drift.
func clusterCAUnusableRemediation(kind string) string {
	if kind == "not_yet_valid" {
		return "Correct this Control Plane's system clock (NTP) — the cluster CA is not yet valid by more than the allowed skew. Do NOT rotate the CA; the trust root is fine."
	}
	return "Rotate or import a cluster CA (Cluster → CA) to restore enrollment."
}

// Usable reports whether the cluster CA can currently issue a node certificate
// that a peer will accept. nil means yes.
//
// Deliberately SEPARATE from Ready(), for the same reason CHAOS-28 kept the two
// apart on the inspection CA: Ready() answers "is a CA installed", and a caller
// that conflates the two questions silently converts an expiry into a different
// failure mode than the one that actually happened.
func (ca *clusterCA) Usable() error {
	ca.mu.RLock()
	cert := ca.cert
	ca.mu.RUnlock()
	return clusterCAUsable(cert, time.Now())
}

// Expiry returns the cluster CA's NotAfter, or the zero time when no CA is
// loaded. Used by the metrics writer, which omits the expiry series entirely
// rather than reporting 0 (which reads as "expires now") on a CA-less node.
func (ca *clusterCA) Expiry() time.Time {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	if ca.cert == nil {
		return time.Time{}
	}
	return ca.cert.NotAfter
}

// clampNodeCertValidity narrows a proposed node-certificate window so the leaf
// can never outlive — or predate — its issuer.
//
// RFC 5280 path validation evaluates every certificate in the chain at the time
// of use, so an issuer-outliving node cert is never more useful than one clamped
// to the issuer. It is only harder to diagnose, and it actively defeats the
// recovery machinery: the DP renewal loop triggers off the NODE cert's expiry,
// so a node cert that claims a year of life while its issuer has ten days left
// keeps the node quiet through the exact window in which it needed to renew.
//
// Clamping makes that window self-correcting: inside the CA's own 30-day
// rotation window, issued node certs are short, so the DP renewal loop keeps
// checking back and picks up the rotated CA as soon as it lands.
func clampNodeCertValidity(notBefore, notAfter time.Time, caCert *x509.Certificate) (leafNotBefore, leafNotAfter time.Time) {
	if caCert == nil {
		return notBefore, notAfter
	}
	if notBefore.Before(caCert.NotBefore) {
		notBefore = caCert.NotBefore
	}
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	return notBefore, notAfter
}

// ─── Health record ──────────────────────────────────────────────────────────

// clusterCAUsabilityHealth is the process-wide record of cluster-CA usability
// faults. Same shape and same rules as caUsabilityHealth (ca_health.go):
// cumulative counters carry magnitude for Prometheus, independent log/alert
// gates carry the page, and recovery is reported on OBSERVED evidence — a sign
// that actually succeeded — never on elapsed time.
type clusterCAUsabilityHealth struct {
	mu sync.Mutex

	// refusals is every CSR sign the CA refused because it was outside its own
	// validity window. clamped counts node certs whose requested lifetime was
	// shortened to the issuer's. They answer different questions: refusals prove
	// the guard fired (enrollment is down), clamped proves the CA is inside its
	// rotation window and the fleet is being kept renewable.
	refusals int64
	clamped  int64

	last       time.Time // most recent observed fault
	lastReason string    // sanitised, key-material-free detail
	lastOK     time.Time // most recent OBSERVED successful issuance

	logAt   time.Time
	alertAt time.Time
}

var clusterCAUsability clusterCAUsabilityHealth

// clusterCAEverUnusable short-circuits the recovery observer so the healthy
// path stays a single relaxed atomic load.
var clusterCAEverUnusable atomic.Bool

// clusterCAUsabilitySnapshot is the read model for /metrics, Info(), and tests.
type clusterCAUsabilitySnapshot struct {
	Refusals   int64
	Clamped    int64
	Last       time.Time
	LastReason string
	LastOK     time.Time
}

func clusterCAUsabilityFailures() clusterCAUsabilitySnapshot {
	clusterCAUsability.mu.Lock()
	defer clusterCAUsability.mu.Unlock()
	return clusterCAUsabilitySnapshot{
		Refusals:   clusterCAUsability.refusals,
		Clamped:    clusterCAUsability.clamped,
		Last:       clusterCAUsability.last,
		LastReason: clusterCAUsability.lastReason,
		LastOK:     clusterCAUsability.lastOK,
	}
}

// fireClusterCAUnusableAlert delivers the cert_expiry alert for an unusable
// cluster CA. Package-level seam so tests observe the transition synchronously
// instead of racing the process-global alerts sink (the -count/-shuffle
// determinism class the CI gate catches).
var fireClusterCAUnusableAlert = func(detail string) {
	// Nobody subscribed → do nothing at all, and in particular do not spawn a
	// goroutine. SignCSR is reached from the enrollment and renewal RPCs, which
	// a reconnect storm drives concurrently — the per-request alert-producer
	// contract (CLAUDE.md) applies.
	if !globalAlertStore.HasSubscriber("cert_expiry") {
		return
	}
	go fireAlert("cert_expiry", AlertPayload{
		Host:   "culvert-cluster-ca",
		Detail: detail,
		Source: "cluster_ca",
	})
}

// noteClusterCASignRefused records a CSR sign refused because the cluster CA was
// outside its validity window. Runs synchronously on the RPC's goroutine, so it
// does memory-only work and hands the alert off.
func noteClusterCASignRefused(reason, kind string) {
	safe := sanitizeLog(reason)
	fix := clusterCAUnusableRemediation(kind)
	now := time.Now()
	clusterCAEverUnusable.Store(true)

	clusterCAUsability.mu.Lock()
	clusterCAUsability.refusals++
	refusals := clusterCAUsability.refusals
	clusterCAUsability.last = now
	clusterCAUsability.lastReason = safe
	doLog := clusterCAUsability.logAt.IsZero() || now.Sub(clusterCAUsability.logAt) >= clusterCAUnusableAlertInterval
	if doLog {
		clusterCAUsability.logAt = now
	}
	doAlert := clusterCAUsability.alertAt.IsZero() || now.Sub(clusterCAUsability.alertAt) >= clusterCAUnusableAlertInterval
	if doAlert {
		clusterCAUsability.alertAt = now
	}
	clusterCAUsability.mu.Unlock()

	if doLog && logger != nil {
		logger.Printf("ClusterCA: node enrollment and cert renewal are DOWN — the cluster CA "+
			"cannot issue a certificate peers will accept: %q (%d issuances refused since boot). %s",
			safe, refusals, fix)
	}
	if doAlert {
		fireClusterCAUnusableAlert(fmt.Sprintf(
			"Node enrollment and cert renewal are DOWN — the cluster CA cannot issue a usable "+
				"certificate: %s (%d issuances refused since boot). %s", safe, refusals, fix))
	}
}

// noteClusterCANodeCertClamped records a node certificate whose lifetime was
// shortened to the issuer's. Not a fault — it is the mechanism working — but it
// is the leading indicator that the cluster CA is inside its rotation window,
// and it explains an otherwise surprising uptick in renewal traffic.
func noteClusterCANodeCertClamped() {
	clusterCAUsability.mu.Lock()
	clusterCAUsability.clamped++
	clusterCAUsability.mu.Unlock()
}

// noteClusterCAUsable records an OBSERVED successful issuance. Recovery is
// reported on evidence, never on elapsed time: a still-expired CA looks exactly
// like a healthy one if nothing happens to need a certificate.
func noteClusterCAUsable() {
	if !clusterCAEverUnusable.Load() {
		return
	}
	now := time.Now()
	clusterCAUsability.mu.Lock()
	recovering := !clusterCAUsability.last.IsZero() && clusterCAUsability.lastOK.Before(clusterCAUsability.last)
	clusterCAUsability.lastOK = now
	refusals := clusterCAUsability.refusals
	clusterCAUsability.mu.Unlock()

	if recovering && logger != nil {
		logger.Printf("ClusterCA: node enrollment RECOVERED — the cluster CA issued a usable "+
			"certificate (%d signs were refused while it was unusable)", refusals)
	}
}

// clusterCAUsabilityDegraded reports whether the most recent evidence says the
// cluster CA could not issue. Used by the admin surface; recovery is keyed on an
// observed success, matching the storage_health.go contract.
func clusterCAUsabilityDegraded() bool {
	if !clusterCAEverUnusable.Load() {
		return false
	}
	clusterCAUsability.mu.Lock()
	defer clusterCAUsability.mu.Unlock()
	return !clusterCAUsability.last.IsZero() && clusterCAUsability.lastOK.Before(clusterCAUsability.last)
}

// resetClusterCAUsabilityHealthForTest clears the process-global record so
// -count=2 / -shuffle=on runs stay deterministic.
func resetClusterCAUsabilityHealthForTest() {
	clusterCAUsability.mu.Lock()
	defer clusterCAUsability.mu.Unlock()
	clusterCAUsability.refusals = 0
	clusterCAUsability.clamped = 0
	clusterCAUsability.last = time.Time{}
	clusterCAUsability.lastReason = ""
	clusterCAUsability.lastOK = time.Time{}
	clusterCAUsability.logAt = time.Time{}
	clusterCAUsability.alertAt = time.Time{}
	clusterCAEverUnusable.Store(false)
}
