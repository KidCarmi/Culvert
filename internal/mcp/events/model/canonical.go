package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// CanonicalBytes returns the deterministic canonical encoding of the event used
// for its intrinsic digest. The encoding is JSON over the map-free Event struct
// with the EventDigest field zeroed, so a canonically-equivalent event always
// serialises identically: encoding/json emits struct fields in declaration order
// and slices in element order, and the Event has NO map field, so there is no
// unstable map serialisation in the hash (EVENT-MODEL.md §4b integrity rule).
//
// CanonicalBytes never fails for a validated event; the returned error covers
// only a pathological encoder failure and is surfaced rather than swallowed.
func (e Event) CanonicalBytes() ([]byte, error) {
	c := e
	c.EventDigest = ""
	return json.Marshal(c)
}

// Digest returns the hex-encoded SHA-256 of CanonicalBytes. It is stable across
// nodes and restarts (a pure function of the synced content fields).
func (e Event) Digest() (string, error) {
	b, err := e.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Marshal returns the FULL event encoding, including the EventDigest field, for
// durable storage. It is distinct from CanonicalBytes (which zeroes the digest to
// compute it): the stored record carries the digest so recovery can verify it
// without recomputation ambiguity. ComputeDigest must have been called first.
func (e Event) Marshal() ([]byte, error) { return json.Marshal(e) }

// ComputeDigest computes the intrinsic digest and stores it in EventDigest,
// returning the digest. The pipeline calls this once before commit.
func (e *Event) ComputeDigest() (string, error) {
	d, err := e.Digest()
	if err != nil {
		return "", err
	}
	e.EventDigest = d
	return d, nil
}

// VerifyDigest recomputes the intrinsic digest and reports whether it matches the
// stored EventDigest. Used on recovery and export to detect a mutated record.
func (e Event) VerifyDigest() bool {
	if e.EventDigest == "" {
		return false
	}
	d, err := e.Digest()
	if err != nil {
		return false
	}
	return constantTimeEqualHex(d, e.EventDigest)
}

// constantTimeEqualHex compares two hex digests without an early-return timing
// oracle. Both are non-secret, but a constant-time compare keeps the integrity
// check uniform.
func constantTimeEqualHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
