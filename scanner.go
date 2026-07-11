package main

// scanner.go — DPI block-response writer + counter, and the package-main shim
// for the relocated ContentScanner engine (internal/scanner, ADR-0002). The
// ContentScanner pattern engine moved to the package; the 403-writer dpiBlock,
// its statDPIBlocked counter, and the pure isTextContentType helper stay here
// (they are response/observability concerns, not part of the scan engine, and
// statDPIBlocked is read by events/metrics/otlp/ui directly).

import (
	"strings"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/scanner"
)

// ContentScanner is the package-main alias for the relocated DPI engine so the
// many consumers (controlplane, configversion, inspection_rules, proxy,
// scan_svc, security_scan, ui) and the test suite stay unqualified.
type ContentScanner = scanner.ContentScanner

// dpiScanner is the global DPI pattern engine, shared across all inspected
// tunnels (1 MiB per-response buffer cap).
var dpiScanner = scanner.New(1 << 20)

// newContentScanner constructs a ContentScanner with the given buffer cap.
// Thin wrapper over scanner.New kept for the test suite, which previously built
// ContentScanner with a struct literal over the now-unexported fields.
var newContentScanner = scanner.New

// matchDPIRegexWithTimeout is re-exposed unqualified for the scanner unit test
// (the engine func is scanner.MatchRegexWithTimeout).
var matchDPIRegexWithTimeout = scanner.MatchRegexWithTimeout

// statDPIBlocked counts response bodies blocked by DPI signature matches.
var statDPIBlocked int64

// isTextContentType reports whether a Content-Type header value indicates
// human-readable text that is worth regex-scanning.  Binary formats (images,
// video, compressed archives) are deliberately excluded — scanning them is
// expensive and rarely useful for signature-based detection.
func isTextContentType(ct string) bool {
	if ct == "" {
		return false
	}
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/") ||
		strings.HasPrefix(ct, "application/json") ||
		strings.HasPrefix(ct, "application/xml") ||
		strings.HasPrefix(ct, "application/xhtml") ||
		strings.HasPrefix(ct, "application/javascript") ||
		strings.HasPrefix(ct, "application/x-www-form-urlencoded")
}

// dpiBlock sends an HTTP 403 Forbidden response to dst and increments the
// DPI blocked counter.  It is called inside inspected tunnels after a
// signature match is detected in a buffered response body.
func dpiBlock(dst interface{ Write([]byte) (int, error) }, host, pattern string) {
	atomic.AddInt64(&statDPIBlocked, 1)
	logger.Printf("DPI_BLOCKED host=%s pattern=%q", host, pattern)
	const body = "Blocked by content inspection policy\r\n"
	h1BlockResponder{w: dst}.blockBeforeResponse("text/plain; charset=utf-8", body)
}
