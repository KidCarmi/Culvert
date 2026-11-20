package clusterca

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// RenewalWindow is the horizon inside which a cluster CA is treated as
// expiring soon. It is deliberately the SAME 30 days as the control plane's CA
// rotation horizon and the data-plane node-certificate renewal window, so "the
// CA is inside its rotation window" and "node certificates clamped by this CA
// are inside their renewal window" are one condition rather than three that
// drift apart.
const RenewalWindow = 30 * 24 * time.Hour

// ErrUnusable is the sentinel returned (wrapped) when the cluster CA cannot
// produce a node certificate that any peer in the cluster will accept. Callers
// match it with errors.Is; the wrapped text carries the operator-actionable
// detail (which bound was violated, and when) and contains no key material.
var ErrUnusable = errors.New("cluster CA unusable")

// ErrExpired and ErrNotYetValid are wrapped ALONGSIDE ErrUnusable so callers
// can tell a genuine expiry (recovery: rotate or import a new trust root) from
// a CLOCK fault (recovery: fix NTP; rotating would churn the fleet's trust root
// for nothing).
var (
	ErrExpired     = errors.New("expired")
	ErrNotYetValid = errors.New("not yet valid")
)

// UnusableKind classifies a Usable error into a stable, machine-readable kind
// for metrics and health surfaces: "expired", "not_yet_valid", or
// "unavailable" (no CA loaded, or anything else). It returns "" for nil.
func UnusableKind(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrExpired):
		return "expired"
	case errors.Is(err, ErrNotYetValid):
		return "not_yet_valid"
	default:
		return "unavailable"
	}
}

// Remediation returns the operator action that actually fixes the given
// UnusableKind. It is kept next to the classifier so the two can never drift;
// a clock fault must NOT be answered with a fleet-wide trust-root rotation.
func Remediation(kind string) string {
	if kind == "not_yet_valid" {
		return "Correct this Control Plane's system clock (NTP) — the cluster CA is not yet valid. Do NOT rotate the CA; the trust root is fine."
	}
	return "Rotate or import a cluster CA (Cluster → CA) to restore enrollment."
}

// Usable is the cluster CA validity predicate: nil means a certificate signed
// by cert at instant now will be accepted by the cluster's mTLS peers. A nil
// cert means no cluster CA is loaded. The caller supplies the clock so tests
// can drive it explicitly instead of waiting ten years for a CA to expire.
func Usable(cert *x509.Certificate, now time.Time) error {
	if cert == nil {
		return fmt.Errorf("%w: no cluster CA loaded", ErrUnusable)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("%w: %w at %s (%s ago)", ErrUnusable, ErrExpired,
			cert.NotAfter.UTC().Format(time.RFC3339),
			now.Sub(cert.NotAfter).Round(time.Second))
	}
	// NotBefore is checked STRICTLY — no future-skew tolerance. This is the one
	// place the cluster CA deliberately diverges from the inspection CA's
	// clock-skew tolerance, and the reason is that the verifier which rejects
	// the certificate lives on THIS node, using THIS clock.
	//
	// The inspection CA's tolerance absorbs disagreement between two machines: a
	// CA generated seconds ago on a peer with a faster clock should not take the
	// gateway down. Here the control plane verifies data-plane client certs
	// against this very CA, so tolerating a future NotBefore makes the node
	// contradict ITSELF — its signer says "fine" while its own x509 verifier
	// says "not yet valid". ClampNodeValidity then pins the leaf's NotBefore to
	// the CA's, so the issued certificate is unusable for the whole skew window,
	// on the node that just issued it. That is precisely the
	// issue-something-that-cannot-work behaviour this gate exists to remove;
	// tolerating it here would reintroduce it in miniature.
	//
	// Refusing instead costs a bounded, self-clearing delay that the data
	// plane's reconnect backoff already handles, and it produces a counted,
	// alerted, operator-readable reason naming the clock. Clock ROLLBACK lands
	// in the same branch and the same verdict is correct for it: if this node
	// believes the current time precedes the CA's start, its own verifier will
	// reject everything the CA signs, so "unusable" is the honest report.
	//
	// Self-generated CAs are unaffected: rotation backdates NotBefore by an
	// hour, so only an imported or replicated CA can reach this branch.
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("%w: %w until %s (system clock may have rolled back, or the CA was issued by a host whose clock is ahead)",
			ErrUnusable, ErrNotYetValid, cert.NotBefore.UTC().Format(time.RFC3339))
	}
	return nil
}

// ClampNodeValidity narrows a proposed node-certificate window so the
// certificate can never outlive — or predate — the cluster CA that issues it.
// clampedToIssuer reports whether either bound moved. A nil ca leaves the
// window unchanged.
//
// Unclamped, a node enrolled at any point in the CA's final year would hold a
// certificate whose stated expiry is months past its issuer's: node listings
// and the node's own expiry check report it valid while every handshake fails,
// because RFC 5280 path validation evaluates the whole chain at the time of
// use. Clamping does not shorten any window that would otherwise have worked;
// it makes the certificate honest about when trust actually ends. A clamped
// certificate inside the data plane's 30-day renewal window puts the node into
// renewal, which turns a silent cliff into visible pressure. Because the clamp
// horizon and the CA's rotation window are both RenewalWindow, a healthy
// control plane rotates before any clamp is reachable, so on a healthy fleet
// this function is inert.
func ClampNodeValidity(notBefore, notAfter time.Time, ca *x509.Certificate) (leafNotBefore, leafNotAfter time.Time, clampedToIssuer bool) {
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
