package ca

// provenance.go — who is allowed to renew the inspection CA.
//
// Automatic renewal re-issues the CA certificate as a self-signed certificate
// (RotateIfNeeded). That is only legitimate for a CA Culvert itself generated:
// its trust was distributed as "the Culvert root", and Culvert owns its
// lifecycle. A CA the operator imported — a customer root, or an intermediate
// issued by an enterprise PKI — derives its trust from a relationship Culvert
// is not a party to, and a self-signed replacement silently ends it.
//
// Authority therefore comes from a RECORD of how the CA arrived, never from the
// certificate's subject, issuer or self-signed status: a customer root is
// self-signed too, and an operator may name an imported CA anything.

import (
	"crypto/ecdsa"
	"crypto/x509"
	"time"
)

// Provenance records how the active CA came to be installed.
type Provenance string

const (
	// ProvenanceUnknown is a bundle with no record: every bundle written before
	// provenance was tracked, and any bundle staged on disk by hand. Culvert
	// keeps signing with it but will not renew it until an operator classifies
	// it (SetLegacyProvenance), force-rotates, or re-imports it.
	ProvenanceUnknown Provenance = ""
	// ProvenanceManaged is a root Culvert generated (InitCA). Culvert owns its
	// lifecycle and renews it automatically.
	ProvenanceManaged Provenance = "culvert-managed"
	// ProvenanceImported is a CA an administrator supplied (LoadCustomCA). Its
	// issuer and trust distribution belong to the operator; Culvert never
	// replaces it on its own.
	ProvenanceImported Provenance = "imported"
)

// provenancePEMType is the PEM block that carries the record inside the bundle
// plaintext. It sits beside the CERTIFICATE and EC PRIVATE KEY blocks, so it is
// written atomically with them and travels with backup/restore. Builds that
// predate it skip unknown block types, so a downgrade still loads the bundle.
const provenancePEMType = "CULVERT CA PROVENANCE"

// ParseProvenance maps an operator-supplied or stored value to a Provenance.
// Anything unrecognised is ProvenanceUnknown with ok=false, which fails toward
// "do not renew".
func ParseProvenance(s string) (p Provenance, ok bool) {
	switch Provenance(s) {
	case ProvenanceManaged:
		return ProvenanceManaged, true
	case ProvenanceImported:
		return ProvenanceImported, true
	}
	return ProvenanceUnknown, false
}

// RenewalWithheldObserver is invoked from RotateIfNeeded when the CA is inside
// its renewal window but Culvert is not its lifecycle authority, so nothing was
// renewed. Publish-once: package main wires it to a log line and the
// cert_expiry alert. nil ⇒ no-op.
var RenewalWithheldObserver func(p Provenance, expiry time.Time)

// Provenance returns the recorded provenance of the active CA.
func (cm *Manager) Provenance() Provenance {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.provenance
}

// SetLegacyProvenance is the operator's classification of a bundle that
// carries no provenance record. It applies only to such bundles — a recorded
// provenance always wins — and takes effect for the CA already loaded and for
// any later load. It is not written to disk until the next SaveCA.
func (cm *Manager) SetLegacyProvenance(p Provenance) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.legacyProvenance = p
	if cm.caCert != nil && cm.provenance == ProvenanceUnknown {
		cm.provenance = p
	}
}

// installCALocked makes cert/key the active CA. Callers must hold mu.
func (cm *Manager) installCALocked(cert *x509.Certificate, key *ecdsa.PrivateKey, p Provenance) {
	cm.caCert = cert
	cm.caKey = key
	cm.provenance = p
	// A CA that is not its own issuer is an intermediate: the client's trust
	// anchor is further up, so the client can only build a path if this
	// certificate is served with the leaf. Whether it is self-signed decides
	// what goes on the wire, and nothing about who may renew it.
	cm.caChainRaw = nil
	if cert.CheckSignatureFrom(cert) != nil {
		cm.caChainRaw = cert.Raw
	}
	cm.resetLeafCacheLocked()
}
