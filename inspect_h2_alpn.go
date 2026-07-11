package main

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

// tlsHandshakeClientHello is the handshake message type for ClientHello.
const tlsHandshakeClientHello = 0x01

// tlsRecordHandshake is the TLS record content type for handshake records.
const tlsRecordHandshake = 0x16

// extALPN is the ALPN TLS extension type (RFC 7301).
const extALPN = 0x0010

// parseClientHelloALPN extracts the client's offered ALPN protocol list from a
// buffered TLS ClientHello. buf must begin at the TLS record header (the first
// byte the client sends, 0x16). It returns the protocol list in offer order and
// ok=true only on a fully-consistent parse that contained an ALPN extension.
//
// ok=false (caller falls back to []string{"http/1.1"}) when: buf is not a
// handshake record, the ClientHello spans beyond buf (fragmented / not fully
// buffered), any length field is inconsistent, or no ALPN extension is present.
// It never reads past len(buf) and never panics.
func parseClientHelloALPN(buf []byte) (protos []string, ok bool) {
	// TLS record header: type(1) version(2) length(2).
	if len(buf) < 5 || buf[0] != tlsRecordHandshake {
		return nil, false
	}
	recLen := int(buf[3])<<8 | int(buf[4])
	rec := buf[5:]
	if recLen == 0 || recLen > len(rec) {
		// ClientHello not fully buffered in this record slice → fail closed.
		return nil, false
	}
	rec = rec[:recLen]

	// Handshake header: msg_type(1) length(3).
	if len(rec) < 4 || rec[0] != tlsHandshakeClientHello {
		return nil, false
	}
	hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
	body := rec[4:]
	if hsLen > len(body) {
		return nil, false
	}
	body = body[:hsLen]

	// ClientHello body: version(2) random(32) then variable-length fields.
	c := cursor{b: body}
	if !c.skip(2 + 32) { // legacy_version + random
		return nil, false
	}
	if !c.skipVec8() { // legacy_session_id <0..32>
		return nil, false
	}
	if !c.skipVec16() { // cipher_suites <2..2^16-2>
		return nil, false
	}
	if !c.skipVec8() { // legacy_compression_methods <1..2^8-1>
		return nil, false
	}
	// extensions <0..2^16-1>; absent extensions (older ClientHellos) => no ALPN.
	extBytes, hasExt := c.readVec16()
	if !hasExt {
		return nil, false
	}
	return scanExtensionsForALPN(extBytes)
}

// scanExtensionsForALPN walks the ClientHello extensions block and returns the
// ALPN protocol list if present. ok=false if no ALPN extension is found or any
// extension length is inconsistent.
func scanExtensionsForALPN(extBytes []byte) ([]string, bool) {
	ec := cursor{b: extBytes}
	for ec.remaining() >= 4 {
		extType := int(ec.b[ec.i])<<8 | int(ec.b[ec.i+1])
		ec.i += 2
		extData, okData := ec.readVec16()
		if !okData {
			return nil, false
		}
		if extType == extALPN {
			return parseALPNExtension(extData)
		}
	}
	return nil, false
}

// parseALPNExtension parses an ALPN extension body: ProtocolNameList<2..2^16-1>
// where each entry is opaque ProtocolName<1..2^8-1>. Returns ok=false on any
// inconsistency or an empty list.
func parseALPNExtension(data []byte) ([]string, bool) {
	c := cursor{b: data}
	list, ok := c.readVec16()
	if !ok || c.remaining() != 0 {
		return nil, false
	}
	lc := cursor{b: list}
	var out []string
	for lc.remaining() > 0 {
		n := int(lc.b[lc.i])
		lc.i++
		if n == 0 || lc.i+n > len(lc.b) {
			return nil, false
		}
		out = append(out, string(lc.b[lc.i:lc.i+n]))
		lc.i += n
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// cursor is a bounds-checked forward reader over a byte slice; every method
// verifies the slice has enough bytes before advancing and reports false rather
// than panicking on a short buffer.
type cursor struct {
	b []byte
	i int
}

func (c *cursor) remaining() int { return len(c.b) - c.i }

func (c *cursor) skip(n int) bool {
	if n < 0 || c.i+n > len(c.b) {
		return false
	}
	c.i += n
	return true
}

// skipVec8 skips a vector prefixed with a 1-byte length.
func (c *cursor) skipVec8() bool {
	if c.remaining() < 1 {
		return false
	}
	n := int(c.b[c.i])
	c.i++
	return c.skip(n)
}

// skipVec16 skips a vector prefixed with a 2-byte length.
func (c *cursor) skipVec16() bool {
	if c.remaining() < 2 {
		return false
	}
	n := int(c.b[c.i])<<8 | int(c.b[c.i+1])
	c.i += 2
	return c.skip(n)
}

// readVec16 returns the body of a vector prefixed with a 2-byte length and
// advances past it. ok=false if the length runs past the buffer.
func (c *cursor) readVec16() ([]byte, bool) {
	if c.remaining() < 2 {
		return nil, false
	}
	n := int(c.b[c.i])<<8 | int(c.b[c.i+1])
	c.i += 2
	if c.i+n > len(c.b) {
		return nil, false
	}
	out := c.b[c.i : c.i+n]
	c.i += n
	return out, true
}

// clientOffersH2 reports whether the parsed ALPN offer includes "h2". Used by the
// C1 intersection: native H2 inspection only offers h2 upstream when the client
// itself offered h2 (else an HTTP/1.1-only client would be stranded).
func clientOffersH2(protos []string) bool {
	for _, p := range protos {
		if p == "h2" {
			return true
		}
	}
	return false
}
