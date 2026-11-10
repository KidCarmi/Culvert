// Package pseudonym is the keyed-HMAC destination pseudonymizer behind the
// traffic-redaction posture (ADR-0044). A Pseudonymizer owns one node-local
// 32-byte key, its non-secret generation id, and a pool of key-bound HMACs.
// Tokens are "h_" + 12 lowercase hex characters of HMAC-SHA256 over the
// host-only normalized destination; they are a persisted, correlatable
// identifier, so the algorithm and output are byte-stable.
//
// Fail-closed: with no key installed Pseudonymize returns Sentinel, never the
// plaintext. Package main owns the instance, the posture flag
// (decRedactHosts), persistence of the key/id in admin settings, and every
// call site; this package owns only the key state and the token derivation.
// It holds no package-level state, starts no goroutines and does no I/O or
// logging.
package pseudonym
