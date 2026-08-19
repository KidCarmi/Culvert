package main

// cluster_ca_validity.go — cluster-CA usability gate (CHAOS-50, register row CA-13).
//
// CHAOS-28 established that a Root CA outside its OWN validity window can still
// sign — neither x509.CreateCertificate nor the ECDSA primitive checks the
// parent's NotBefore/NotAfter — and closed that hole for the INSPECTION CA. The
// cluster CA is the same engine shape with none of the same guards, and its
// failure is wider in one specific way: the artefact it mints is not a leaf that
// one client rejects, it is the node identity the ENTIRE control plane runs on.
//
// The terminal state, reproduced before this file existed:
//
//   1. The cluster CA reaches NotAfter (rotation was failing, or never ran — see
//      the coupling defect fixed in ca.go).
//   2. Every enrolled DP's client cert now chains to an expired root, so
//      buildServerTLS's pool cannot verify it: `x509: certificate has expired`
//      at the handshake. Config sync stops fleet-wide. Go's path validation
//      checks the validity window of EVERY certificate in the chain, roots
//      included, so nothing in the fleet is exempt.
//   3. The obvious recovery — re-enroll — still WORKED, because Enroll uses
//      tls.VerifyClientCertIfGiven and needs no client cert. SignCSR happily
//      signed a fresh node cert with the dead CA, the node persisted it,
//      reconnected, and failed the handshake again with the same opaque error.
//      An operator can loop there indefinitely: every surface reports success.
//
// So the recovery path did not just fail, it manufactured evidence that it had
// worked. That is what this gate removes. Refusing to sign costs no
// availability that signing would have preserved — the cert was unusable from
// birth — and it converts an unbounded loop of opaque TLS errors into one
// countable, named, actionable event on the node that can actually fix it.
//
// The real recovery is rotation (auto, at 30 days, or a manual ImportCA), which
// does not go through this gate.

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// clusterCARenewalWindow is the horizon inside which a cluster CA is treated as
// expiring soon. It is deliberately the SAME 30 days as clusterCARotateWithin
// (RotateIfNeeded) and as the DP-side certNeedsRenewal window, so "the CA is
// inside its rotation window" and "node certs clamped by this CA are inside
// their renewal window" are one condition rather than three that drift apart.
const clusterCARenewalWindow = 30 * 24 * time.Hour

// errClusterCAUnusable is the sentinel returned by clusterCA.Usable and by
// SignCSR when the cluster CA cannot produce a node certificate that any peer
// in the cluster will accept. Callers match it with errors.Is; the wrapped text
// carries the operator-actionable detail (which bound was violated, and when)
// and contains no key material.
var errClusterCAUnusable = errors.New("cluster CA unusable")

// clusterCAUsable is the pure validity predicate, split out from the method so
// tests can drive it with an explicit clock instead of waiting ten years for a
// CA to expire.
func clusterCAUsable(cert *x509.Certificate, now time.Time) error {
	if cert == nil {
		return fmt.Errorf("%w: no cluster CA loaded", errClusterCAUnusable)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("%w: expired at %s (%s ago)", errClusterCAUnusable,
			cert.NotAfter.UTC().Format(time.RFC3339),
			now.Sub(cert.NotAfter).Round(time.Second))
	}
	// NotBefore is checked STRICTLY — no future-skew tolerance. This is the one
	// place the cluster CA deliberately diverges from the inspection CA's
	// caClockSkewTolerance, and the reason is that the verifier which rejects the
	// certificate lives on THIS node, using THIS clock.
	//
	// The inspection CA's tolerance absorbs disagreement between two machines: a
	// CA generated seconds ago on a peer with a faster clock should not take the
	// gateway down. Here the CP verifies DP client certs against this very CA
	// (buildServerTLS's ClientCAs pool), so tolerating a future NotBefore makes
	// the node contradict ITSELF — its signer says "fine" while its own x509
	// verifier says "not yet valid". clampNodeCertValidity then pins the leaf's
	// NotBefore to the CA's, so the issued certificate is unusable for the whole
	// skew window, on the node that just issued it. That is precisely the
	// issue-something-that-cannot-work behaviour this file exists to remove;
	// tolerating it here would have reintroduced it in miniature.
	//
	// Refusing instead costs a bounded, self-clearing delay that the DP's
	// reconnect backoff already handles, and it produces a counted, alerted,
	// operator-readable reason naming the clock. Clock ROLLBACK lands in the same
	// branch and the same verdict is correct for it: if this node believes the
	// current time precedes the CA's start, its own verifier will reject
	// everything the CA signs, so "unusable" is the honest report.
	//
	// Self-generated CAs are unaffected: RotateIfNeeded backdates NotBefore by an
	// hour, so only an imported or replicated CA can reach this branch.
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("%w: not valid until %s (system clock may have rolled back, or the CA was issued by a host whose clock is ahead)",
			errClusterCAUnusable, cert.NotBefore.UTC().Format(time.RFC3339))
	}
	return nil
}

// Usable reports whether the cluster CA can currently sign a node certificate
// the cluster's mTLS peers will accept. nil means yes.
//
// This is deliberately SEPARATE from Ready(), for the same reason
// ca.Manager.Usable() is separate from ca.Manager.Ready(): Ready() answers "is
// a CA installed", which is the question the enrollment gates and the
// bootstrap/UI surfaces have always asked, and several of them use it to decide
// whether the feature exists at all. Folding validity into Ready() would make
// an expired CA read as "enrollment not configured" — hiding a trust outage
// behind a not-configured message, which is the wrong story on the surface an
// operator reaches for first.
func (ca *clusterCA) Usable() error {
	ca.mu.RLock()
	cert := ca.cert
	ca.mu.RUnlock()
	return clusterCAUsable(cert, time.Now())
}

// Expiry returns the cluster CA's NotAfter, or the zero time when no CA is
// loaded. The zero value is meaningful to callers: a metric must be OMITTED
// rather than rendered as 0, which would read as "expires now".
func (ca *clusterCA) Expiry() time.Time {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	if ca.cert == nil {
		return time.Time{}
	}
	return ca.cert.NotAfter
}

// clampNodeCertValidity narrows a proposed node-certificate window so the cert
// can never outlive — or predate — the cluster CA that issued it.
//
// Unclamped, this was materially worse than the leaf case CHAOS-28 fixed. A
// forged inspection leaf claimed 24h it might not have; a node cert claims a
// FULL YEAR, so in ordinary operation a node enrolled at any point in the CA's
// final year holds a certificate whose stated expiry is months past its
// issuer's. That is the state that makes a cluster trust incident hardest to
// diagnose: `GET /api/cluster/nodes` reports every node's cert as valid for
// months, the node's own checkDPCertExpiry agrees, and yet every handshake
// fails — because RFC 5280 path validation evaluates the whole chain at the
// time of use, and the root is dead. Nothing in the fleet was looking at the
// only date that mattered.
//
// Clamping does not shorten any window that would otherwise have worked; it
// makes the certificate state honest about when trust actually ends. The
// downstream effect is intentional and is the point: a clamped cert inside the
// DP's 30-day renewal window puts the node into renewal, which is exactly the
// behaviour that turns a silent cliff into visible pressure. Because the clamp
// horizon and the CA's own rotation window are both 30 days
// (clusterCARenewalWindow), a healthy CP rotates before any clamp is reachable,
// so on a healthy fleet this function is inert.
func clampNodeCertValidity(notBefore, notAfter time.Time, ca *x509.Certificate) (leafNotBefore, leafNotAfter time.Time, clampedToIssuer bool) {
	if ca == nil {
		return notBefore, notAfter, false
	}
	clamped := false
	if notBefore.Before(ca.NotBefore) {
		notBefore = ca.NotBefore
		clamped = true
	}
	if notAfter.After(ca.NotAfter) {
		notAfter = ca.NotAfter
		clamped = true
	}
	return notBefore, notAfter, clamped
}
