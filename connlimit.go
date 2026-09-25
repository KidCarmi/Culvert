package main

// connlimit.go — Request tracing helpers. The per-IP connection limiter
// (ConnLimiter) moved to internal/connlimit (ADR-0002); see connlimit_vars.go
// for the package-main shim. These ID/trace generators are request-scoped
// tracing, not connection limiting, so they stay in package main.

import (
	"crypto/rand"
	"encoding/hex"
)

// ─── Canonical tracing header keys ──────────────────────────────────────────

// headerRequestID and headerTraceparent are the tracing header names in
// CANONICAL MIME form — the form net/textproto stores them under.
//
// net/http's Header.Get/Set/Add/Del all route the key through
// textproto.CanonicalMIMEHeaderKey first. That function has a fast path that
// scans for already-canonical input and returns it verbatim, and a slow path
// that copies the key into a []byte, rewrites the casing and allocates the
// result. "X-Request-ID" takes the SLOW path — the canonical spelling is
// "X-Request-Id", so the trailing 'D' fails the scan — while "X-Request-Id"
// takes the fast one. Measured on this machine (Go 1.26, 4-core Xeon):
//
//	Header.Get("X-Request-ID")   96.3 ns/op   16 B/op   1 allocs/op
//	Header.Get("X-Request-Id")   28.7 ns/op    0 B/op   0 allocs/op
//	Header.Set("X-Request-ID")  136.0 ns/op   32 B/op   2 allocs/op
//	Header.Set("X-Request-Id")   67.0 ns/op   16 B/op   1 allocs/op
//
// setupRequestTracing (proxy.go) performs one Get and two Sets on this key for
// EVERY proxied request — HTTP, CONNECT and WebSocket alike — so the
// non-canonical literal cost ~204 ns and 3 allocations per request purely to
// re-derive a constant.
//
// Using the canonical spelling is BYTE-IDENTICAL on the wire, not merely
// compatible: Set already stored the value under CanonicalMIMEHeaderKey(key),
// so the map key — and therefore what Header.Write emits — was "X-Request-Id"
// before this change too. Only the redundant re-derivation is removed. Pinned
// by TestRequestTracing_CanonicalKeysAreWireIdentical.
//
// Do not "fix" these back to the shoutier spelling: HTTP field names are
// case-insensitive (RFC 9110 §5.1) and this one is chosen to match what Go
// canonicalizes to.
const (
	headerRequestID   = "X-Request-Id"
	headerTraceparent = "Traceparent"
	// headerTracestate is never READ by Culvert — it is deleted, and only when
	// setupRequestTracing mints a replacement traceparent. W3C Trace Context
	// makes tracestate meaningful only relative to its traceparent, so a
	// tracestate that outlives the traceparent it was issued under is orphaned
	// vendor data, not propagation.
	headerTracestate = "Tracestate"
)

// requestIDHexLen is the width of a generated request ID (8 random bytes, hex).
const requestIDHexLen = 16

// traceparentLen is the fixed width of a W3C traceparent value:
// "00-" + 32 hex trace-id + "-" + 16 hex parent-id + "-01".
const traceparentLen = 55

// zeroRequestID and zeroTraceparent are the CSPRNG-failure fallbacks. They are
// well-formed but carry no entropy; rand.Read does not fail on any supported
// platform, so these exist only so a failure cannot produce a malformed header.
const (
	zeroRequestID   = "0000000000000000"
	zeroTraceparent = "00-00000000000000000000000000000000-0000000000000000-01"
)

// ─── Request ID generation ──────────────────────────────────────────────────

// generateRequestID creates a random 16-char hex string for request tracing.
//
// This is the LONE-ID form, kept for callers that need a request ID without a
// traceparent (the admin-plane crash recorder, and the request path when the
// client already supplied its own traceparent). The request path's common case
// — a client that supplied neither header — uses generateTraceIDs instead.
func generateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return zeroRequestID
	}
	return hex.EncodeToString(b)
}

// generateTraceparent creates a W3C Trace Context traceparent header value.
// Format: "00-{trace-id}-{parent-id}-01"  (version 00, sampled flag 01)
// See https://www.w3.org/TR/trace-context/
//
// It delegates to generateTraceIDs and discards the request ID rather than
// carrying a second copy of the byte layout. That draws 8 CSPRNG bytes it does
// not use (~20 ns) on a path reached only when the client supplied an
// X-Request-ID but no traceparent; one layout is worth more than the draw.
func generateTraceparent() string {
	_, tp := generateTraceIDs()
	return tp
}

// generateTraceIDs returns a fresh request ID and W3C traceparent from ONE
// CSPRNG draw and ONE string allocation — the shape setupRequestTracing needs
// when the client supplied neither header, which is the norm for direct client
// traffic and therefore very nearly every proxied request.
//
// Both savings are measured, not assumed (Go 1.26, 4-core Xeon @2.8GHz):
//
//   - crypto/rand.Read carries a fixed per-call cost of ~27 ns on top of
//     ~2.5 ns/byte, so two draws of 8 and 24 bytes cost 131 ns where one draw
//     of 32 costs 106 ns.
//   - The two IDs are laid out end to end in one stack buffer and converted
//     once, then returned as slices of that single string. Slicing a string is
//     free (the header values share one 71-byte backing array), so this is
//     1 allocation where the separate generators paid 2.
//
// Together: 250 ns / 2 allocs → 195 ns / 1 alloc.
//
// The two IDs are cut from DISJOINT random bytes — the request ID from bytes
// 0:8, the trace-id from 8:24 and the parent-id from 24:32 — so sharing one
// draw does not correlate them, and the request ID is not recoverable from the
// traceparent a downstream origin receives.
func generateTraceIDs() (reqID, traceparent string) {
	var buf [32]byte // 8 (request id) + 16 (trace-id) + 8 (parent-id)
	if _, err := rand.Read(buf[:]); err != nil {
		return zeroRequestID, zeroTraceparent
	}
	var out [requestIDHexLen + traceparentLen]byte
	hex.Encode(out[0:16], buf[0:8]) // request id
	out[16], out[17], out[18] = '0', '0', '-'
	hex.Encode(out[19:51], buf[8:24]) // trace-id
	out[51] = '-'
	hex.Encode(out[52:68], buf[24:32]) // parent-id
	out[68], out[69], out[70] = '-', '0', '1'
	s := string(out[:])
	return s[:requestIDHexLen], s[requestIDHexLen:]
}
