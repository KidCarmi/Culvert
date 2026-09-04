// Package upstreamclient is the bounded, Model-A upstream MCP client for the
// Gateway capability (PR-11). It reuses the PR-1 kernel (internal/mcp/jsonrpc +
// internal/mcp/protocol + internal/mcp/session) for the upstream-server-facing leg
// — there is NO second permissive decoder — and the PR-7 destination controls
// (internal/mcp/inspection/destination) for SSRF classification, resolve→connect
// DNS pinning, connect-time peer verification, and redirect rejection.
//
// It speaks ONLY remote Streamable HTTP, ONLY the admitted V1 methods
// (initialize, notifications/initialized, ping, notifications/cancelled,
// tools/list, tools/call), and ONLY the supported protocol versions
// (2025-11-25 / 2025-06-18). No batch, no legacy SSE, no automatic downgrade, no
// arbitrary/extension methods, no server-originated sampling/elicitation. The
// upstream endpoint comes ONLY from the registered server record — never a
// request-supplied URL. No client token is ever forwarded upstream.
package upstreamclient

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// RetryMode selects how MaxReadRetries is INTERPRETED. It exists because the
// historical encoding could not express "no transport retries" at all: zero means
// "use the safe default" (2) and negatives are rejected, so every configuration —
// including a deliberately retry-free one — got a retrying client.
//
// That ambiguity is a security property, not a style question. The First
// Controlled Canary requires that ONE accepted execution reservation produce AT
// MOST ONE physical side-effect-bearing tool invocation; a transport that may
// silently re-send an idempotent read turns one authorized effect into up to
// three, and the emergency kill is not re-read between those attempts. The mode
// is therefore explicit and closed: no magic sentinel, no overloaded zero.
type RetryMode uint8

const (
	// RetryDefault is the zero value and preserves the historical behavior for
	// every existing caller: MaxReadRetries==0 fills with the safe default.
	RetryDefault RetryMode = iota
	// RetryDisabled performs EXACTLY ONE physical attempt per Call, whatever the
	// method's idempotency or the failure's pre-response classification. Setting a
	// non-zero MaxReadRetries alongside it is a contradiction and fails closed.
	RetryDisabled
)

// valid reports whether the mode is a known value. An unknown mode fails closed
// rather than defaulting to the retrying behavior.
func (m RetryMode) valid() bool { return m == RetryDefault || m == RetryDisabled }

// LimitConfig bounds every upstream resource. Zero in a field means the safe
// default.
type LimitConfig struct {
	MaxConnsPerServer int           // bounded per-server connection pool
	MaxQueuePerServer int           // bounded per-server request queue
	MaxInFlight       int           // bounded concurrent upstream calls per server
	MaxResponseBytes  int           // response header+body byte ceiling
	MaxRedirects      int           // redirect hops (0 ⇒ redirects rejected outright)
	ConnectTimeout    time.Duration // dial timeout
	TLSTimeout        time.Duration // TLS handshake timeout
	RequestTimeout    time.Duration // whole-request deadline
	PinTTL            time.Duration // resolve→connect pin lifetime
	MaxReadRetries    int           // bounded retry budget for idempotent reads
	// RetryMode interprets MaxReadRetries. Zero (RetryDefault) keeps the historical
	// fill-with-default behavior; RetryDisabled means exactly one physical attempt.
	RetryMode RetryMode
}

// Limits is the immutable validated bounds set.
type Limits struct {
	c     LimitConfig
	valid bool
}

// Default bound values.
const (
	defMaxConnsPerServer = 32
	defMaxQueuePerServer = 64
	defMaxInFlight       = 16
	defMaxResponseBytes  = 4 << 20 // 4 MiB
	defMaxRedirects      = 0       // reject redirects by default
	defConnectTimeout    = 5 * time.Second
	defTLSTimeout        = 5 * time.Second
	defRequestTimeout    = 30 * time.Second
	defPinTTL            = 30 * time.Second
	defMaxReadRetries    = 2
)

// DefaultLimits returns the safe default bounds.
func DefaultLimits() Limits { l, _ := NewLimits(LimitConfig{}); return l }

// NewLimits validates and freezes a bounds set, filling zero fields with defaults.
func NewLimits(c LimitConfig) (Limits, error) {
	if !c.RetryMode.valid() {
		return Limits{}, mcperr.New(mcperr.ReasonListenerConfigInvalid, "upstreamclient.limits", "unknown retry mode")
	}
	// A retry-free client that also carries a retry budget is a contradiction. Fail
	// closed rather than silently honoring one half: the caller must say what it means.
	if c.RetryMode == RetryDisabled && c.MaxReadRetries != 0 {
		return Limits{}, mcperr.New(mcperr.ReasonListenerConfigInvalid, "upstreamclient.limits", "retry-disabled mode must not set a retry budget")
	}
	out := fillLimitDefaults(c)
	if limitConfigHasNegative(out) {
		return Limits{}, mcperr.New(mcperr.ReasonListenerConfigInvalid, "upstreamclient.limits", "negative limit")
	}
	return Limits{c: out, valid: true}, nil
}

// RetryFreeLimits returns bounds identical to base but with transport retries
// EXPLICITLY disabled. This is the First-Canary upstream client shape: one
// reservation, one attempt, at most one side-effect-bearing physical invocation.
func RetryFreeLimits(base LimitConfig) (Limits, error) {
	base.RetryMode = RetryDisabled
	base.MaxReadRetries = 0
	return NewLimits(base)
}

// fillLimitDefaults replaces each zero field with its safe default. MaxRedirects is
// intentionally omitted — its zero value (reject redirects) IS the intended default.
func fillLimitDefaults(c LimitConfig) LimitConfig {
	out := c
	if out.MaxConnsPerServer == 0 {
		out.MaxConnsPerServer = defMaxConnsPerServer
	}
	if out.MaxQueuePerServer == 0 {
		out.MaxQueuePerServer = defMaxQueuePerServer
	}
	if out.MaxInFlight == 0 {
		out.MaxInFlight = defMaxInFlight
	}
	if out.MaxResponseBytes == 0 {
		out.MaxResponseBytes = defMaxResponseBytes
	}
	if out.ConnectTimeout == 0 {
		out.ConnectTimeout = defConnectTimeout
	}
	if out.TLSTimeout == 0 {
		out.TLSTimeout = defTLSTimeout
	}
	if out.RequestTimeout == 0 {
		out.RequestTimeout = defRequestTimeout
	}
	if out.PinTTL == 0 {
		out.PinTTL = defPinTTL
	}
	// Only RetryDefault fills the retry budget. Under RetryDisabled the budget stays
	// zero: filling it here is exactly the bug this mode exists to remove.
	if out.RetryMode == RetryDefault && out.MaxReadRetries == 0 {
		out.MaxReadRetries = defMaxReadRetries
	}
	return out
}

// limitConfigHasNegative reports whether any bound is negative (a fail-closed error).
func limitConfigHasNegative(c LimitConfig) bool {
	return c.MaxConnsPerServer < 0 || c.MaxQueuePerServer < 0 || c.MaxInFlight < 0 ||
		c.MaxResponseBytes < 0 || c.MaxRedirects < 0 || c.MaxReadRetries < 0 ||
		c.ConnectTimeout < 0 || c.TLSTimeout < 0 || c.RequestTimeout < 0 || c.PinTTL < 0
}

// Valid reports whether the limits were constructed.
func (l Limits) Valid() bool { return l.valid }

// RetriesDisabled reports whether this client performs exactly one physical
// attempt per Call. Call consults it BEFORE any idempotency/pre-response test, so
// no failure classification can reintroduce a second side-effect-bearing send.
func (l Limits) RetriesDisabled() bool { return l.c.RetryMode == RetryDisabled }

// MaxConnsPerServer returns the per-server connection pool bound.
func (l Limits) MaxConnsPerServer() int { return l.c.MaxConnsPerServer }

// MaxQueuePerServer returns the per-server queue bound.
func (l Limits) MaxQueuePerServer() int { return l.c.MaxQueuePerServer }

// MaxInFlight returns the per-server in-flight bound.
func (l Limits) MaxInFlight() int { return l.c.MaxInFlight }

// MaxResponseBytes returns the response byte ceiling.
func (l Limits) MaxResponseBytes() int { return l.c.MaxResponseBytes }

// MaxRedirects returns the redirect-hop bound (0 ⇒ reject redirects).
func (l Limits) MaxRedirects() int { return l.c.MaxRedirects }

// ConnectTimeout returns the dial timeout.
func (l Limits) ConnectTimeout() time.Duration { return l.c.ConnectTimeout }

// TLSTimeout returns the TLS handshake timeout.
func (l Limits) TLSTimeout() time.Duration { return l.c.TLSTimeout }

// RequestTimeout returns the whole-request deadline.
func (l Limits) RequestTimeout() time.Duration { return l.c.RequestTimeout }

// PinTTL returns the resolve→connect pin lifetime.
func (l Limits) PinTTL() time.Duration { return l.c.PinTTL }

// MaxReadRetries returns the idempotent-read retry budget.
func (l Limits) MaxReadRetries() int { return l.c.MaxReadRetries }
