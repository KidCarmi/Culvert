package main

// cluster_ca_validity.go — cluster-CA usability gate (CHAOS-29, register row CA-13).
//
// This is the SAME defect class CHAOS-28 closed in the inspection CA, in the
// other CA. Neither x509.CreateCertificate nor the ECDSA primitive checks the
// PARENT certificate's NotBefore/NotAfter, so a cluster CA outside its own
// validity window kept signing perfectly well-formed Data Plane node
// certificates that no peer will ever accept.
//
// The blast radius is different, and worse in one specific way. The inspection
// CA fails toward "inspected HTTPS is down"; the cluster CA fails toward "the
// fleet cannot talk to its Control Plane" — every DP↔CP mTLS handshake fails
// path validation at the expired root, so config sync, heartbeat, and audit
// aggregation all stop. And unlike the inspection CA, the failure is
// SELF-SUSTAINING: a DP whose cert stopped working re-enrolls, the CP happily
// signs it with the same dead CA, and the new cert fails exactly as the old one
// did. The recovery path runs, reports success, and changes nothing — the
// register calls that shape "fake recovery", and it is the reason this gate
// belongs on the SIGN path rather than only on a health probe.
//
// Refusing costs no availability that signing would have preserved: a node cert
// chained to an expired issuer fails verification in Go's own TLS stack, which
// is what both ends of this connection use. What changes is that the appliance
// says so, once, loudly — instead of issuing N certificates that cannot work.

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// clusterCAClockSkewTolerance is how far the cluster CA's NotBefore may sit in
// the future before the CA is treated as unusable.
//
// It matches internal/ca's caClockSkewTolerance deliberately: both CAs face the
// same two clock faults (a node booting with a bad RTC, and NTP stepping
// backwards), and a CA generated seconds ago on a peer whose clock runs
// slightly fast must not take enrollment down. It is also the same window
// SignCSR already backdates node certs into, so the two ends of one window use
// one tolerance.
const clusterCAClockSkewTolerance = 5 * time.Minute

// ErrClusterCAUnusable is the sentinel returned when the cluster CA cannot
// produce a node certificate any peer would accept. Callers match it with
// errors.Is; the wrapped text carries the operator-actionable detail (which
// bound was violated, and when) and contains no key material.
var ErrClusterCAUnusable = errors.New("cluster CA unusable")

// Usable reports whether the cluster CA can currently sign a node certificate
// that the mTLS peer will accept. nil means yes.
//
// Deliberately SEPARATE from Ready(), for the same reason the inspection CA
// keeps the two apart: Ready() answers "is a CA installed", and callers use it
// to decide whether enrollment is offered at all. Folding validity into Ready()
// would convert an expired CA into "enrollment not configured" — a misleading
// answer that sends the operator to look at the wrong thing entirely.
func (ca *clusterCA) Usable() error {
	ca.mu.RLock()
	cert := ca.cert
	key := ca.key
	ca.mu.RUnlock()
	if key == nil {
		return fmt.Errorf("%w: cluster CA not initialized", ErrClusterCAUnusable)
	}
	return clusterCAUsable(cert, time.Now())
}

// clusterCAUsable is the pure validity predicate, split out so tests can drive
// it with an explicit clock instead of waiting ten years for a CA to expire.
func clusterCAUsable(cert *x509.Certificate, now time.Time) error {
	if cert == nil {
		return fmt.Errorf("%w: cluster CA not initialized", ErrClusterCAUnusable)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("%w: expired at %s (%s ago)", ErrClusterCAUnusable,
			cert.NotAfter.UTC().Format(time.RFC3339),
			now.Sub(cert.NotAfter).Round(time.Second))
	}
	if now.Add(clusterCAClockSkewTolerance).Before(cert.NotBefore) {
		return fmt.Errorf("%w: not valid until %s (system clock may have rolled back)", ErrClusterCAUnusable,
			cert.NotBefore.UTC().Format(time.RFC3339))
	}
	return nil
}

// clampNodeCertValidity narrows a proposed node-certificate validity window so
// the node cert can never outlive — or predate — the cluster CA that signed it.
//
// This one matters more than its inspection-CA counterpart, because a node cert
// is not just a credential: it is the CLOCK the renewal loop runs on.
// certNeedsRenewal (dp_enrollment.go) asks how long the NODE cert has left, and
// the CP hands out a flat 365-day cert regardless of how much life the issuer
// has. A DP enrolled against a CA with 45 days left therefore received a cert
// that looked healthy for a year, so its renewal loop stayed quiet for 335 days
// while the CA underneath it died — the node had a valid certificate and no
// trust, and nothing on the node was watching the thing that actually broke.
//
// Clamping makes the node cert expire no later than its issuer, which pulls the
// DP's existing 30-day renewal window in front of the CA's expiry. The renewal
// then fires while the CA is still alive, and rotation's dual-CA overlap has
// something to hand it. RFC 5280 path validation evaluates every certificate in
// the chain at the time of use, so an issuer-outliving node cert was never more
// useful than a clamped one — only harder to diagnose.
func clampNodeCertValidity(notBefore, notAfter time.Time, caCert *x509.Certificate) (nodeNotBefore, nodeNotAfter time.Time) {
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

// clusterCAIssuanceRefusal returns the error to refuse a certificate-issuance
// request with, or nil when the CA can sign. It records the refusal on the
// health plane, so every path that declines to issue funds the same counter and
// alert regardless of where in the request it decided.
//
// It exists because the refusal has to happen at TWO points, and only one of
// them is the sign path. `Enroll` calls `admitEnrollment` first, which validates
// and CONSUMES the one-use enrollment token — so refusing at the sign path alone
// took the node's token, gave back nothing, and left it unable to retry once an
// operator replaced the CA. An enrollment outage that also destroys the
// credentials needed to recover from it is worse than the outage; the
// precondition therefore runs BEFORE anything is consumed, and the sign-path
// gate stays as the backstop that cannot be bypassed.
func clusterCAIssuanceRefusal(ca *clusterCA) error {
	if err := ca.Usable(); err != nil {
		statClusterCASignRefused.Add(1)
		noteClusterCAUnusable(err.Error())
		return err
	}
	noteClusterCAUsable()
	return nil
}
