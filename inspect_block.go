package main

import "fmt"

// blockResponder abstracts emitting a policy block onto an inspected tunnel so
// the same block-decision logic serves both the HTTP/1.1 keep-alive loop
// (h1BlockResponder) and the HTTP/2 per-stream path (added later in the
// H2-inspection program). It is the seam the PAN-OS-style architecture review
// identified: the block DECISION (which counter, which reason) already lives in
// scanBlockConn/dpiBlock/inspectFileBlocked; only the wire EMISSION was hardcoded
// to HTTP/1.1.
//
// PR1 ships ONLY the pre-commit operation — the sole shape all three current
// tunnel block writers exercise today (they all block before any response byte
// reaches the client). The POST-COMMIT operation (late block on a stream-through
// gRPC/SSE response → protocol-valid gRPC trailer, SSE termination, or RST_STREAM
// as a last resort, always with an audit reason code — review corrections C3/C5)
// is deliberately NOT frozen here: its signature must be derived from the real
// inspection lifecycle extracted in PR2 and act on actual stream state (whether
// headers/DATA are flushed, whether a trailer window remains, the stream handle),
// not merely a content-type string. It is added when that lifecycle is extracted.
type blockResponder interface {
	blockBeforeResponse(contentType, body string)
}

// h1BlockResponder writes HTTP/1.1 block responses onto a raw inspected-tunnel
// conn (the client side of an SSL-inspected tunnel, where an http.ResponseWriter
// is not available). Its exact byte output is locked by the PR0 characterization
// tests (TestCharacterize_ScanBlockConnBytes / _DPIBlockBytes) and the PR1 unit
// test — this refactor must reproduce it verbatim.
type h1BlockResponder struct {
	w interface {
		Write([]byte) (int, error)
	}
}

// blockBeforeResponse writes a complete HTTP/1.1 403 Forbidden with a text body
// and Connection: close (which prevents H1 keep-alive reuse from bypassing the
// block on a pipelined retry). Byte-identical to the pre-refactor writers.
func (h h1BlockResponder) blockBeforeResponse(contentType, body string) {
	fmt.Fprintf(h.w, //nolint:errcheck // best-effort write of the 403 block response
		"HTTP/1.1 403 Forbidden\r\n"+
			"Content-Type: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n%s",
		contentType, len(body), body,
	)
}
