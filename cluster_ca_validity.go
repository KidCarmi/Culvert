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
//
// The validity POLICY (the predicate, the sentinels, the kind classifier and
// its remediation text, the issuer clamp and the shared renewal window) is
// owned by internal/clusterca (ADR-0048, IM-013). This file is main's binding:
// the root names below delegate to the package so no caller changed, and the
// clusterCA methods that read the instance's certificate under its lock stay
// here with the instance (enrollment.go).

import (
	"crypto/x509"
	"time"

	"github.com/KidCarmi/Culvert/internal/clusterca"
)

// clusterCARenewalWindow binds clusterca.RenewalWindow: the SAME 30 days as
// clusterCARotateWithin (RotateIfNeeded) and the DP-side certNeedsRenewal
// window.
const clusterCARenewalWindow = clusterca.RenewalWindow

// errClusterCAUnusable is the sentinel returned by clusterCA.Usable and by
// SignCSR when the cluster CA cannot produce a node certificate that any peer
// accepts (clusterca.ErrUnusable; the same error value, so errors.Is matches
// either name). The expiry-versus-clock-fault sentinels that are wrapped
// alongside it (ported from the competing CHAOS-50 implementation on PR #1179)
// are read only through clusterCAUnusableKind, so main binds no name for them.
var errClusterCAUnusable = clusterca.ErrUnusable

// clusterCAUnusableKind binds clusterca.UnusableKind: "expired",
// "not_yet_valid", "unavailable", or "" for nil.
func clusterCAUnusableKind(err error) string { return clusterca.UnusableKind(err) }

// clusterCAUnusableRemediation binds clusterca.Remediation: a clock fault must
// NOT be answered with a fleet-wide trust-root rotation.
func clusterCAUnusableRemediation(kind string) string { return clusterca.Remediation(kind) }

// clusterCAUsable binds the pure validity predicate (clusterca.Usable). NotBefore
// is checked strictly, with no future-skew tolerance; the package documents why
// the cluster CA diverges from the inspection CA's caClockSkewTolerance here.
func clusterCAUsable(cert *x509.Certificate, now time.Time) error {
	return clusterca.Usable(cert, now)
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

// clampNodeCertValidity binds clusterca.ClampNodeValidity: a node certificate
// can never outlive — or predate — the cluster CA that issued it. On a healthy
// fleet it is inert, because the clamp horizon and the CA's rotation window are
// both clusterCARenewalWindow.
func clampNodeCertValidity(notBefore, notAfter time.Time, ca *x509.Certificate) (leafNotBefore, leafNotAfter time.Time, clampedToIssuer bool) {
	return clusterca.ClampNodeValidity(notBefore, notAfter, ca)
}
