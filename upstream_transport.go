package main

// upstream_transport.go — P5.3 / S6 ownership surface for the shared
// upstream-direction *http.Transport.
//
// Model:
//   - The transport is held behind atomic.Pointer.
//   - Writes are serialized by upstreamTransportWriteMu.
//   - The operator's TLS template (upstreamOpTLSCfg) is held under
//     the same mutex and NEVER attached directly to a published
//     transport — each swap attaches a fresh Clone() so the stdlib's
//     lazy h2 setup (which mutates Transport.TLSClientConfig.NextProtos
//     and TLSClientConfig pointer on first RoundTrip) writes onto the
//     CLONE, not onto the template.
//   - cloneTransport copies static config fields ONLY. It does NOT
//     copy TLSClientConfig or TLSNextProto, because both are
//     stdlib-lazy-mutated and reading them races against in-flight
//     RoundTrip calls (caught by the P5.3 race tests).
//   - swapUpstreamTransport auto-attaches a Clone of the operator's
//     TLS template to the new transport when the updater closure
//     does not provide its own TLSClientConfig.
//
// Rules (also documented in CLAUDE.md):
//
//   - getUpstreamTransport() returns a read-only snapshot. Callers
//     MUST NOT mutate the returned transport's fields.
//   - swapUpstreamTransport(update) is the only approved mutation
//     API. The update closure receives the current transport and
//     MUST return a NEW *http.Transport — it MUST NOT mutate the
//     input. Use cloneTransport to seed the new instance.
//   - Mutators that change TLS state MUST update upstreamOpTLSCfg
//     from inside the closure (under the write mutex). The swap
//     attaches a Clone of upstreamOpTLSCfg to the new transport.
//
// Background: roadmap/UPSTREAM-TRANSPORT-DISCOVERY.md (P5.1),
// roadmap/UPSTREAM-TRANSPORT-OWNERSHIP-MODEL.md (P5.3 design),
// roadmap/UPSTREAM-TRANSPORT-LAB-PLAN.md (P5.2.1).

import (
	"crypto/tls"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// upstreamTransportPtr holds the current published transport. Reads
// via Load() are the hot-path read surface.
var upstreamTransportPtr atomic.Pointer[http.Transport]

// upstreamTransportWriteMu serializes writers. Readers do NOT take
// this lock. It also protects upstreamOpTLSCfg.
var upstreamTransportWriteMu sync.Mutex

// upstreamOpTLSCfg is the operator's TLS template. Protected by
// upstreamTransportWriteMu. NEVER attached directly to a published
// transport — swapUpstreamTransport attaches Clone() copies so the
// stdlib's lazy h2 setup mutates the clone, not the template. nil
// when no TLS state is configured (HTTP-only upstreams).
var upstreamOpTLSCfg *tls.Config

func init() {
	upstreamTransportPtr.Store(newBaseUpstreamTransport())
}

// getUpstreamTransport returns the currently-published transport.
// The returned pointer MUST be treated as read-only.
func getUpstreamTransport() *http.Transport {
	return upstreamTransportPtr.Load()
}

// swapUpstreamTransport is the only approved mutation API.
//
// 1. Takes the writer mutex (serializing writers).
// 2. Loads the current transport.
// 3. Invokes update(old) for a NEW *http.Transport. The closure
//    may also update upstreamOpTLSCfg under the held lock.
// 4. If newT is nil or equal to old, returns without swapping.
// 5. If newT.TLSClientConfig is nil and upstreamOpTLSCfg is non-nil,
//    attaches a Clone of upstreamOpTLSCfg to newT.TLSClientConfig.
//    This is the race-safety contract: stdlib's lazy h2 setup
//    mutates the CLONE, not the operator's template.
// 6. Stores the new transport.
// 7. Synchronously calls old.CloseIdleConnections() to release the
//    previous transport's idle keepalive connections. In-flight
//    requests holding the old transport via their per-request
//    http.Client are NOT interrupted.
func swapUpstreamTransport(update func(old *http.Transport) *http.Transport) {
	upstreamTransportWriteMu.Lock()
	defer upstreamTransportWriteMu.Unlock()
	old := upstreamTransportPtr.Load()
	newT := update(old)
	if newT == nil || newT == old {
		return
	}
	if newT.TLSClientConfig == nil && upstreamOpTLSCfg != nil {
		newT.TLSClientConfig = cloneTLSConfig(upstreamOpTLSCfg)
	}
	upstreamTransportPtr.Store(newT)
	if old != nil {
		old.CloseIdleConnections()
	}
}

// newBaseUpstreamTransport constructs the initial transport with the
// static pool sizing and buffer constants the proxy hot path needs.
// TLSClientConfig and TLSNextProto are intentionally left nil — the
// stdlib will lazy-init them on first request, or the swap path will
// attach a clone of upstreamOpTLSCfg.
func newBaseUpstreamTransport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   64,
		MaxConnsPerHost:       0, // unlimited — let the OS handle it
		IdleConnTimeout:       120 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DisableCompression:    false,
		WriteBufferSize:       64 * 1024, // 64 KB
		ReadBufferSize:        64 * 1024, // 64 KB
	}
}

// cloneTransport produces a fresh *http.Transport with the static
// configuration fields copied from old. Two fields are
// INTENTIONALLY NOT copied because the stdlib mutates them lazily
// on first RoundTrip (caught by the P5.3 race tests):
//
//   - TLSClientConfig: stdlib's h2 setup assigns a fresh *tls.Config
//     here if nil, and appends "h2" / "http/1.1" to its NextProtos
//     slice. Reading the field while another goroutine drives
//     RoundTrip races. The swap path attaches a Clone of
//     upstreamOpTLSCfg instead.
//   - TLSNextProto: stdlib's h2 setup assigns a fresh map here if
//     nil. Same race surface. The new transport gets its own
//     lazy-init on first request.
//
// Internal connection-pool state (idle conns, perHost maps) is
// non-exported and not copied; a new transport starts its own pool.
// Function fields, slices, and maps are copied by reference (Go's
// value semantics for struct copies are field-by-field).
//
// If old is nil, returns a fresh base transport.
func cloneTransport(old *http.Transport) *http.Transport {
	if old == nil {
		return newBaseUpstreamTransport()
	}
	return &http.Transport{
		Proxy:                  old.Proxy,
		DialContext:            old.DialContext,
		DialTLSContext:         old.DialTLSContext,
		TLSHandshakeTimeout:    old.TLSHandshakeTimeout,
		DisableKeepAlives:      old.DisableKeepAlives,
		DisableCompression:     old.DisableCompression,
		MaxIdleConns:           old.MaxIdleConns,
		MaxIdleConnsPerHost:    old.MaxIdleConnsPerHost,
		MaxConnsPerHost:        old.MaxConnsPerHost,
		IdleConnTimeout:        old.IdleConnTimeout,
		ResponseHeaderTimeout:  old.ResponseHeaderTimeout,
		ExpectContinueTimeout:  old.ExpectContinueTimeout,
		ProxyConnectHeader:     old.ProxyConnectHeader,
		GetProxyConnectHeader:  old.GetProxyConnectHeader,
		MaxResponseHeaderBytes: old.MaxResponseHeaderBytes,
		WriteBufferSize:        old.WriteBufferSize,
		ReadBufferSize:         old.ReadBufferSize,
		ForceAttemptHTTP2:      old.ForceAttemptHTTP2,
		// TLSClientConfig and TLSNextProto: see docstring — not copied.
	}
}

// cloneTLSConfig returns a deep clone of old via the stdlib
// (*tls.Config).Clone(). Caller must own old exclusively — typically
// this means old is upstreamOpTLSCfg (held under the write mutex)
// or a freshly-allocated *tls.Config inside a swap closure.
//
// If old is nil, returns an empty *tls.Config — callers set
// MinVersion explicitly (mTLS branch → TLS 1.2; OCSP-only → TLS 1.3,
// preserving pre-P5.3 semantics).
func cloneTLSConfig(old *tls.Config) *tls.Config {
	if old == nil {
		return &tls.Config{} // #nosec G402 -- MinVersion is set by the caller branch (mTLS=TLS1.2, OCSP=TLS1.3)
	}
	return old.Clone()
}
