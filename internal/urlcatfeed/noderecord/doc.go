// Package noderecord is the envelope codec for the SaaS feed's node-local
// durable records: the rollback floor, the activation record, the authority
// record and the generation metadata that package main writes under the feed's
// data directory (roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md, Part B, §B.3).
//
// It owns three rules those records share:
//
//   - The canonical bytes. A record is stored as, and accepted only as, the
//     feed protocol's canonical JSON (compact, HTML escaping disabled, fixed
//     struct field order, no trailing newline). The encoder is the protocol's
//     own (urlcatfeed.CanonicalJSON), so a node-local record and a signed feed
//     document cannot drift apart; this package does not carry a second copy.
//   - The seal. Each record stores a CRC-32C (Castagnoli) over the canonical
//     bytes of its checksum-omitted view, written as exactly 8 lowercase hex
//     digits.
//   - The envelope. Decode accepts bytes as a record only if they are within
//     the record's size bound, decode strictly (unknown fields refused), are
//     followed by nothing, and are byte for byte the record's canonical
//     bytes. The floor, activation and authority records each carried a copy
//     of those steps; each now names its size bound and its own sentinel
//     errors in an Envelope, so no two record kinds share an error value.
//
// The seal is corruption detection, NOT authenticity: any local writer can
// recompute a valid checksum. Content authenticity comes only from the
// Sigstore signatures the feed runtime re-verifies (§B.9). That is why the
// seal lives here and not in package urlcatfeed, which is the signed
// protocol's trust kernel.
//
// The package holds no state: no package variable, no init, no goroutine, no
// I/O and no logging. Every function is a pure function of its arguments and
// is safe for concurrent use. The record types, their field validation and
// seal check, the sentinel errors, the size bounds, the files and the write
// quorum stay with their owners in package main (ADR-0053, ADR-0059).
package noderecord
