package main

// cluster_ca_validity.go — cluster-CA usability gate (CHAOS-29, register row CA-13).
//
// This is the CHAOS-28 argument applied to the OTHER CA. The inspection CA and
// the cluster CA share one defect class and nothing else: different lifecycle
// (10-year self-signed, generated once at CP bootstrap), different blast radius
// (node enrollment and CP↔DP mTLS, not client HTTPS), different recovery
// (rotation plus a fleet-wide re-trust, not just a client push).
//
// The shared defect: neither x509.CreateCertificate nor the ECDSA primitive
// checks the ISSUER's own NotBefore/NotAfter, and nothing else did either. An
// expired cluster CA therefore kept signing node certificates that are
// well-formed, correctly chained, and rejected by every peer that validates
// them — because RFC 5280 path validation evaluates the whole chain at time of
// use, and the issuer in that chain is dead.
//
// The observable shape of that failure was the worst one this register
// recognises. `SignCSR` returned nil error. The enrollment RPC returned success.
// The node stored the certificate. `culvert_cluster_ca_rotations_total` did not
// move, because nothing rotated. `Ready()` — `cert != nil && key != nil` — stayed
// true. The node then failed its next mTLS handshake with an opaque
// `x509: certificate has expired or is not yet valid`, pointing at the NODE's
// certificate, which is freshly issued and perfectly valid. The appliance
// reported a successful enrollment and produced material guaranteed not to work.
//
// Refusing to sign costs no availability that signing would have preserved: the
// certificate was already dead on arrival. What changes is that the CP now says
// so, once, loudly, with the violated bound named — instead of N nodes
// discovering it independently at handshake time.
//
// It is also fail-CLOSED in the direction that matters. A refused enrollment is
// a node that does not join the cluster; there is no branch here that admits an
// unauthenticated peer, degrades mTLS, or widens trust. Compare the inspection
// CA, where the equivalent "just let it through" fix would have silently
// disabled decryption fleet-wide.

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// clusterCAClockSkewTolerance is how far the cluster CA's NotBefore may sit in
// the future before the CA is treated as unusable.
//
// It matters more here than for the inspection CA, because the cluster CA is
// replicated to HA peers (ha.go ImportCASilent) and a peer whose clock runs
// slightly ahead can hand over a CA that is, by the receiver's clock, not yet
// valid. Refusing to enroll for five minutes after a CA handover because two
// machines disagree about the second would be a self-inflicted outage. It
// matches caClockSkewTolerance so both CAs use one tolerance.
const clusterCAClockSkewTolerance = 5 * time.Minute

// ErrClusterCAUnusable is the sentinel returned when the cluster CA cannot sign
// a node certificate any peer would accept. Callers match it with errors.Is; the
// wrapped text names the violated bound and carries no key material.
var ErrClusterCAUnusable = errors.New("cluster CA unusable")

// clusterCAUsable is the pure validity predicate, split out so tests drive it
// with an explicit clock instead of waiting ten years for a CA to expire.
func clusterCAUsable(cert *x509.Certificate, now time.Time) error {
	if cert == nil {
		return fmt.Errorf("%w: no cluster CA loaded", ErrClusterCAUnusable)
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

// Usable reports whether the cluster CA can currently sign a node certificate
// that a cluster peer will accept. nil means yes.
//
// Deliberately SEPARATE from Ready(), for the same reason internal/ca keeps the
// two apart: Ready() answers "is a CA installed", which is the question the
// enrollment surfaces already use to decide whether this node can enroll anyone
// at all. Folding validity into it would change what "enrollment disabled"
// means on every one of those call sites at once, silently, at the moment the
// CA expires.
func (ca *clusterCA) Usable() error {
	ca.mu.RLock()
	cert := ca.cert
	ca.mu.RUnlock()
	return clusterCAUsable(cert, time.Now())
}

// CAExpiry returns the cluster CA's NotAfter, or the zero time when no CA is
// loaded. Zero is what the metrics writer keys on to OMIT the expiry series
// rather than publish a 0 that reads as "expires now" on every node that has no
// cluster CA — which is every standalone and every Data Plane node.
func (ca *clusterCA) CAExpiry() time.Time {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	if ca.cert == nil {
		return time.Time{}
	}
	return ca.cert.NotAfter
}

// SignRefusals returns the number of CSR signings refused because the cluster CA
// was outside its own validity window. Label-free, per the CA-2 metrics
// contract: no node ID, serial, fingerprint or key material.
func (ca *clusterCA) SignRefusals() int64 { return ca.signRefusals.Load() }

// clampNodeCertValidity narrows a proposed node-certificate window so the node
// cert can never outlive — or predate — the cluster CA that issued it.
//
// Unclamped, this was not a corner case: node certs are issued for a fixed
// 365 days and the cluster CA rotates when it has 30 days left, so EVERY
// certificate signed in the last month of a CA's life outlived its issuer, by
// up to eleven months. The resulting incident is the hardest kind to read — the
// node certificate looks valid to anyone who inspects it, the chain does not
// validate, and the failure appears to move around as different peers
// revalidate at different moments.
//
// Clamping costs the node nothing it could have used: an issuer-outliving cert
// is never accepted after the issuer's NotAfter anyway. It makes the node's own
// expiry tell the truth, which is what the DP renewal loop keys on
// (certNeedsRenewal, dp_enrollment.go) — so a clamped cert also pulls the node's
// renewal forward to before the CA cliff instead of after it.
func clampNodeCertValidity(notBefore, notAfter time.Time, issuer *x509.Certificate) (time.Time, time.Time) {
	if issuer == nil {
		return notBefore, notAfter
	}
	if notBefore.Before(issuer.NotBefore) {
		notBefore = issuer.NotBefore
	}
	if notAfter.After(issuer.NotAfter) {
		notAfter = issuer.NotAfter
	}
	return notBefore, notAfter
}
