package main

// cluster_ca_validity.go — cluster-CA usability guard and issuer clamp
// (CHAOS-50, register row CA-13).
//
// This is the CHAOS-28 contract applied to the OTHER CA. The inspection CA got
// `Usable()` (distinct from `Ready()`), a fail-closed sign path, and a leaf
// validity clamp because `x509.CreateCertificate` does not check the parent's
// own validity window — an expired issuer keeps minting well-formed children
// that every relying party rejects. The cluster CA had none of it.
//
// The blast radius is different enough to be worth stating. The cluster CA
// signs the node certificates that carry CP↔DP mTLS. When it goes outside its
// validity window:
//
//   - `Enroll` and `RenewCert` keep returning HTTP-200-shaped success with a
//     certificate that cannot complete a handshake with anything. The operator
//     watches an enrollment "succeed" and the node never connects.
//   - Every DP whose client certificate chains to it is ejected at once, which
//     also removes the transport those nodes would use to ask for a new one.
//
// That last point is why the clamp matters more here than it did for the
// inspection CA. The DP renewal loop (`certNeedsRenewal`, dp_enrollment.go)
// decides when to renew by reading the LEAF's NotAfter. An unclamped leaf minted
// in the CA's final year claims up to 365 days of life past its own issuer, so
// the loop sees a healthy certificate and stays quiet — straight through the
// 30-day dual-CA overlap window that exists precisely so the fleet can re-key.
// The node wakes up after the overlap closed, with a certificate whose issuer is
// gone from the CP's trust pool, and cannot reach the RPC that would fix it.
// Manual re-enrollment is the only way back.
//
// Clamping makes the existing CHAOS-12 renewal machinery cover CA rotation for
// free: a leaf that expires with its issuer crosses the 30-day renewal threshold
// at the same moment the CA crosses its own 30-day rotation threshold, so the
// node renews inside the overlap window and self-heals.

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// clusterCAClockSkewTolerance mirrors caClockSkewTolerance: a node whose clock
// has rolled back (NTP step, VM restore, dead RTC battery) must not brick its
// own cluster PKI over a few minutes of skew. Wide enough to absorb ordinary
// skew, far narrower than any certificate lifetime.
const clusterCAClockSkewTolerance = 5 * time.Minute

// clusterCARenewalOverlap is the dual-CA overlap window RotateIfNeeded uses. It
// is repeated here because the clamp's whole purpose is to line the DP renewal
// threshold up with it — see certNeedsRenewal (30 days) in dp_enrollment.go.
const clusterCARenewalOverlap = 30 * 24 * time.Hour

// errClusterCAUnusable is returned by the sign path when the cluster CA is
// outside its own validity window. Callers match with errors.Is so the RPC layer
// can distinguish "this appliance cannot issue right now" (a fixable operational
// state) from "your CSR is bad" (a caller error).
var errClusterCAUnusable = errors.New("cluster CA is outside its validity window")

// usableLocked reports whether the cluster CA can sign a node certificate that
// relying parties will actually accept. The caller must hold ca.mu.
//
// Deliberately DISTINCT from Ready(). Ready() answers "is a CA loaded", which is
// the right question for "should this node offer enrollment at all" and the
// wrong question for "will the certificate I am about to mint work". Folding the
// validity check into Ready() would silently turn enrollment OFF at the instant
// the CA expires, which reads to an operator as a configuration problem rather
// than an expiry, and would take the admin API's status surface down with it.
func (ca *clusterCA) usableLocked() error {
	if ca.cert == nil || ca.key == nil {
		return fmt.Errorf("cluster CA not initialized")
	}
	now := time.Now()
	if now.Add(clusterCAClockSkewTolerance).Before(ca.cert.NotBefore) {
		return fmt.Errorf("%w: not valid until %s", errClusterCAUnusable,
			ca.cert.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.Add(-clusterCAClockSkewTolerance).After(ca.cert.NotAfter) {
		return fmt.Errorf("%w: expired %s", errClusterCAUnusable,
			ca.cert.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// Usable reports whether the cluster CA can currently issue a node certificate
// that will complete an mTLS handshake. nil means yes.
func (ca *clusterCA) Usable() error {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.usableLocked()
}

// Expiry returns the cluster CA's NotAfter, or the zero time when no CA is
// loaded. The zero value is load-bearing: the metrics writer omits the expiry
// series entirely rather than exporting 0, which would read as "expires now" on
// every node that has no cluster CA at all.
func (ca *clusterCA) Expiry() time.Time {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	if ca.cert == nil {
		return time.Time{}
	}
	return ca.cert.NotAfter
}

// clampNodeCertValidity constrains a node-certificate template to its issuer's
// validity window, at BOTH ends, and reports whether it had to change anything.
//
// A certificate that outlives its issuer is not merely useless — it is the state
// that makes an expiry incident hardest to diagnose, because every tool that
// inspects the leaf alone reports it as valid and only full chain validation
// fails. Clamping means the leaf tells the truth about how long it will work,
// which is what both the DP renewal loop and a human with `openssl x509` read.
func clampNodeCertValidity(tmpl, issuer *x509.Certificate) bool {
	if tmpl == nil || issuer == nil {
		return false
	}
	clamped := false
	if tmpl.NotBefore.Before(issuer.NotBefore) {
		tmpl.NotBefore = issuer.NotBefore
		clamped = true
	}
	if tmpl.NotAfter.After(issuer.NotAfter) {
		tmpl.NotAfter = issuer.NotAfter
		clamped = true
	}
	return clamped
}
