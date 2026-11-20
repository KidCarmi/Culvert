// Package clusterca owns the cluster CA's validity policy (CHAOS-50, register
// row CA-13; ADR-0048): when the control plane's cluster CA may sign a node
// certificate, how an unusable CA is classified for health and metrics
// surfaces, which operator action fixes each class, and the clamp that keeps a
// node certificate inside its issuer's validity window.
//
// The cluster CA is the trust root of the whole control plane. Every enrolled
// data-plane node's mTLS client certificate chains to it, and Go's path
// validation checks the validity window of every certificate in the chain,
// roots included. A CA outside its own window can still sign (neither
// x509.CreateCertificate nor the ECDSA primitive checks the parent's
// NotBefore/NotAfter), so without this gate a re-enrollment against a dead CA
// "succeeds" and produces a certificate that fails every handshake.
//
// The policy deliberately differs from the inspection CA's (internal/ca): it
// applies no future clock-skew tolerance to NotBefore, because the verifier
// that would reject the issued certificate runs on the same node, against the
// same clock, as the signer. See Usable.
//
// Package main owns the CA instance (key material, rotation, import,
// replication, persistence and every call site). This package is pure: it
// holds no mutable package-level state (only error sentinels), starts no
// goroutines and does no I/O or logging. Callers pass the current time.
package clusterca
