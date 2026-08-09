package ca

// validity.go — Root-CA usability gate (CHAOS-28, register row CA-1).
//
// A Root CA that is outside its OWN validity window can still sign: neither
// x509.CreateCertificate nor the ECDSA primitive checks the parent's NotBefore
// or NotAfter. So an expired inspection CA kept minting perfectly well-formed
// leaves that EVERY client rejects — the terminal state is a fleet-wide
// inspected-HTTPS outage whose only symptom is an opaque per-site certificate
// warning (SEC_ERROR_EXPIRED_ISSUER_CERTIFICATE / "certificate has expired"),
// with no alert, no metric, and no health-probe row moving.
//
// That is the worst class of failure this project recognises: the control did
// not degrade, it produced output that cannot work, silently. The guard here
// makes the sign path refuse instead, so the condition is a single, loud,
// countable event rather than N indistinguishable client-side TLS errors.
//
// Refusing does not COST availability that signing would have preserved: a leaf
// chained to an expired issuer fails path validation in every mainstream client,
// so the traffic was already dead. What changes is that the appliance now knows.

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// caClockSkewTolerance is how far the Root CA's NotBefore may sit in the future
// before the CA is treated as unusable. Clock skew and clock rollback are both
// in scope (a node that boots with a bad RTC, or NTP stepping backwards), and a
// CA generated seconds ago on a peer with a slightly faster clock must not take
// the gateway down. It matches the backdating already applied to forged leaves
// in signLeaf, so the two ends of the same window use one tolerance.
const caClockSkewTolerance = 5 * time.Minute

// ErrCAUnusable is the sentinel returned by Usable and by the sign path when the
// Root CA cannot produce a leaf any client would accept. Callers match it with
// errors.Is; the wrapped text carries the operator-actionable detail (which
// bound was violated, and when) and contains no key material.
var ErrCAUnusable = errors.New("root CA unusable")

// UnusableObserver is invoked (with mu NOT held) every time the sign path
// refuses because the Root CA is outside its validity window. Publish-once:
// package main wires it to the refusal counter, a rate-limited log line, and
// the cert_expiry alert. nil ⇒ no-op — the engine never depends on metrics
// wiring (ADR-0003). reason is pre-formatted, key-material-free text.
//
// It is called on EVERY refusal, not on the transition: rate limiting belongs
// to the sink, which is the only layer that knows what an operator is willing
// to be paged about. The engine's own counter (SignRefusals) carries magnitude.
var UnusableObserver func(reason string)

// RotationPersistFailureObserver is invoked when auto-rotation generated a
// replacement CA but could NOT write it to the bundle path. That is a
// materially different state from a clean rotation and must not be reported as
// success: the new CA lives only in RAM, so the next restart reloads the OLD
// near-expiry bundle and the appliance rotates again — a fresh, different root
// on every boot, while clients keep being provisioned with a root that changes
// under them. Publish-once, wired by package main. nil ⇒ no-op.
var RotationPersistFailureObserver func(reason string)

// RotationPersistSuccessObserver is the other half of the pair: it fires when a
// rotation's bundle write SUCCEEDED. It exists because the persistence warning
// must clear on EVIDENCE — an operator who restores the volume and force-rotates
// has fixed the problem, and a warning that stays latched until process restart
// would keep telling them otherwise. A cumulative counter is the right shape for
// the metric and the wrong shape for a status row; the two are tracked
// separately. Publish-once, wired by package main. nil ⇒ no-op.
//
// Neither observer fires when no bundle path is configured: nothing was written,
// so there is nothing to be degraded — or recovered — about.
var RotationPersistSuccessObserver func()

// Usable reports whether the Root CA can currently sign a leaf that a client
// will accept. nil means yes. The returned error wraps ErrCAUnusable and is
// safe to log or surface to an admin-role API (no key material, no path).
//
// This is deliberately SEPARATE from Ready(): Ready() answers "is a CA
// installed", which is the question the CONNECT dispatcher has always used to
// choose between inspecting and bypassing, and widening it to include validity
// would silently convert an expired CA into a fleet-wide bypass — turning an
// availability failure into a silent security-control outage, the exact
// inversion this register calls its worst cross-cutting theme.
func (cm *Manager) Usable() error {
	cm.mu.RLock()
	cert := cm.caCert
	cm.mu.RUnlock()
	return caUsable(cert, time.Now())
}

// caUsable is the pure validity predicate, split out so tests can drive it with
// an explicit clock instead of waiting ten years for a CA to expire.
func caUsable(cert *x509.Certificate, now time.Time) error {
	if cert == nil {
		return fmt.Errorf("%w: no Root CA loaded", ErrCAUnusable)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("%w: expired at %s (%s ago)", ErrCAUnusable,
			cert.NotAfter.UTC().Format(time.RFC3339),
			now.Sub(cert.NotAfter).Round(time.Second))
	}
	if now.Add(caClockSkewTolerance).Before(cert.NotBefore) {
		return fmt.Errorf("%w: not valid until %s (system clock may have rolled back)", ErrCAUnusable,
			cert.NotBefore.UTC().Format(time.RFC3339))
	}
	return nil
}

// SignRefusals returns the number of leaf-sign attempts refused because the
// Root CA was outside its validity window. Lock-free; label-free (no host, no
// serial, no fingerprint — the CA-2 metrics contract).
func (cm *Manager) SignRefusals() int64 { return cm.signRefusals.Load() }

// clampLeafValidity narrows a proposed leaf validity window so the leaf can
// never outlive — or predate — its issuer.
//
// Without the clamp, a leaf minted in the last 24 hours of the CA's life
// carried a NotAfter beyond the CA's own, which is the state that produces the
// most confusing incident of all: the leaf looks valid, the chain does not, and
// the failure moves around as clients revalidate at different moments. RFC 5280
// path validation evaluates every certificate in the chain at the time of use,
// so an issuer-outliving leaf is never more useful than one clamped to the
// issuer — it is only harder to diagnose.
func clampLeafValidity(notBefore, notAfter time.Time, ca *x509.Certificate) (leafNotBefore, leafNotAfter time.Time) {
	if ca == nil {
		return notBefore, notAfter
	}
	if notBefore.Before(ca.NotBefore) {
		notBefore = ca.NotBefore
	}
	if notAfter.After(ca.NotAfter) {
		notAfter = ca.NotAfter
	}
	return notBefore, notAfter
}
