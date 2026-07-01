package main

// connlimit.go — Request tracing helpers. The per-IP connection limiter
// (ConnLimiter) moved to internal/connlimit (ADR-0002); see connlimit_vars.go
// for the package-main shim. These ID/trace generators are request-scoped
// tracing, not connection limiting, so they stay in package main.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// ─── Request ID generation ──────────────────────────────────────────────────

// generateRequestID creates a random 16-char hex string for request tracing.
func generateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}

// generateTraceparent creates a W3C Trace Context traceparent header value.
// Format: "00-{trace-id}-{parent-id}-01"  (version 00, sampled flag 01)
// See https://www.w3.org/TR/trace-context/
func generateTraceparent() string {
	var buf [24]byte // 16 (trace-id) + 8 (parent-id)
	if _, err := rand.Read(buf[:]); err != nil {
		return "00-00000000000000000000000000000000-0000000000000000-01"
	}
	return fmt.Sprintf("00-%s-%s-01", hex.EncodeToString(buf[:16]), hex.EncodeToString(buf[16:]))
}
