// Package noderecord is the envelope codec for the SaaS feed's node-local
// durable records: the rollback floor, the activation record, the authority
// record and the generation metadata that package main writes under the feed's
// data directory (roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md, Part B, §B.3).
//
// It owns two rules those records share:
//
//   - The canonical bytes. A record is stored as, and accepted only as, the
//     feed protocol's canonical JSON (compact, HTML escaping disabled, fixed
//     struct field order, no trailing newline). The encoder is the protocol's
//     own (urlcatfeed.CanonicalJSON), so a node-local record and a signed feed
//     document cannot drift apart; this package does not carry a second copy.
//   - The seal. Each record stores a CRC-32C (Castagnoli) over the canonical
//     bytes of its checksum-omitted view, written as exactly 8 lowercase hex
//     digits.
//
// The seal is corruption detection, NOT authenticity: any local writer can
// recompute a valid checksum. Content authenticity comes only from the
// Sigstore signatures the feed runtime re-verifies (§B.9). That is why the
// seal lives here and not in package urlcatfeed, which is the signed
// protocol's trust kernel.
//
// The package holds no state: no package variable, no init, no goroutine, no
// I/O and no logging. Every function is a pure function of its argument and is
// safe for concurrent use. The record types, their field validation, the
// strict decoders, the sentinel errors, the files and the write quorum stay
// with their owners in package main (ADR-0053).
package noderecord
