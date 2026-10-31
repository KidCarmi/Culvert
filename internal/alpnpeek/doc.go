// Package alpnpeek extracts the ALPN protocol list from a buffered plaintext TLS
// ClientHello (ADR-0042). It is a stdlib-free leaf: it holds no state, performs
// no I/O and does no logging. Package main (proxy_tunnel_h2.go, peekClientALPN)
// owns the buffered reader and the "http/1.1" fallback decision; this package
// owns only the parse.
//
// Read-only ClientHello ALPN extraction for the HTTP/2-inspection ALPN
// intersection (plan C1). The SSL-inspect path handshakes the UPSTREAM leg
// before the client leg, so it needs the client's offered ALPN protocols BEFORE
// shaping the upstream offer — earlier than tls.Server's GetConfigForClient
// callback fires. The inspect path already peeks the first client byte to detect
// TLS (proxy_tunnel.go); this parses the ALPN extension out of the same buffered,
// plaintext ClientHello WITHOUT consuming it (the buffered reader is handed to
// tls.Server via readerConn, so the real handshake re-reads the identical bytes).
//
// Security posture (reviewers flagged this as new attack surface):
//   - It parses attacker-influenced bytes, so it is written to NEVER over-read
//     and NEVER panic — every field length is bounds-checked against the slice
//     before use, and any inconsistency returns ok=false.
//   - It is fail-closed: on any parse failure / truncation / absent ALPN the
//     caller treats the client as offering only "http/1.1" (the inspectable
//     HTTP/1.1-downgrade path), so a malformed or fragmented ClientHello can
//     never trick the proxy into a protocol the client did not actually offer.
//   - It reads ONLY the plaintext handshake record; the HTTP/2 connection preface
//     is post-handshake ciphertext on a different layer and cannot be reached or
//     stranded here.
//   - It is fuzzed (FuzzParseClientHelloALPN).
package alpnpeek
