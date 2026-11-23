// Package authposture owns the durable proxy-authentication posture ratchet
// (owner decision "Durable Authentication Posture", 2026-11-23; ADR-0063).
//
// It answers exactly one question: "is proxy authentication required on this
// node even when no usable proxy identity provider is left?" Once the answer
// is yes it stays yes. It is not an authentication engine: it verifies no
// credential, knows no provider and decides no request. Package main asks it
// that one question on the request path and tells it when a provider was
// first activated.
//
// A Ratchet is a monotonic boolean backed by one small JSON marker file:
//
//   - Established is an atomic load, so the proxy hot path pays no lock, no
//     allocation and no I/O for it.
//   - Establish is write-ahead: the marker is durably written (through the
//     injected writer, which in production is the repository's atomic
//     temp+fsync+rename+dir-fsync helper) BEFORE the in-memory flag flips, and
//     an error is returned, with nothing changed, when it cannot be. A caller
//     that must not report an activation the ratchet has not recorded calls
//     Establish before it publishes the activation.
//   - EstablishFailClosed is for activations that cannot be refused (a
//     provider loaded at startup from configuration that is itself on disk):
//     the flag flips even when the write fails, and the status records that
//     the marker is not durable. A later Establish retries the write.
//   - Nothing clears it. There is no method that lowers the flag; Open never
//     lowers a flag already raised in memory.
//
// Reading the marker is fail-closed. A marker that is present but corrupt (not
// valid JSON, an unknown version, an established record without a timestamp,
// trailing data, unknown fields) or unreadable (a permission error, a
// directory in its place) is treated as ESTABLISHED, and the status names the
// problem so the owner can surface it. Only a missing file is not established,
// and Open reports it as such so the owner can run its migration (derive the
// posture from other durable evidence); RecordFresh then writes a "fresh"
// record so the migration runs once, not on every start.
//
// MergeForRestore is the monotonic merge a backup restore applies: whatever
// side establishes (or is unreadable) wins, the current node first, and a
// "fresh" record is never carried over, so the restored node re-derives it from
// the data it now holds.
//
// The package has no package-level state, no init, starts no goroutine and
// logs nothing. It reads the marker with os.ReadFile unless a reader is
// injected, and writes only through the injected writer. Every Ratchet is
// independent; the zero value is usable and in-memory only (not established,
// no file) until Open names a file.
package authposture
