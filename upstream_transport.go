package main

// upstream_transport.go — P5.3 / S6 ownership surface for the shared
// upstream-direction *http.Transport.
//
// The transport is held behind atomic.Pointer with a package-level
// writer mutex serializing swaps. The model is "immutable-after-
// publish by convention" — atomic.Pointer.Load() returns a plain
// *http.Transport whose fields remain mutable, so the contract is
// enforced as a stack: API shape (no in-place mutator on the read
// surface) + this file's docstrings + CLAUDE.md note + code review
// + the P5.2 contract tests + the P5.3 race tests in
// upstream_transport_race_test.go (any unsynchronized concurrent
// write trips the race detector).
//
// Rules (also documented in CLAUDE.md):
//
//   - getUpstreamTransport() returns a read-only snapshot. Callers
//     MUST NOT mutate any of the returned transport's fields.
//   - To change the transport, call swapUpstreamTransport(update).
//     The update closure receives the current transport and MUST
//     return a NEW *http.Transport — it MUST NOT mutate the input.
//   - cloneTransport and cloneTLSConfig are the only approved
//     helpers for seeding a new instance from an existing one.
//   - All hot-path readers (proxy.go) and all writer call sites
//     (applyUpstreamProxy, loadMTLSAndOCSP, apiOCSPConfig) route
//     through this surface. No other access is permitted.
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
// via Load() are the hot-path read surface. Writes via Store() must
// go through swapUpstreamTransport so the writer mutex serializes
// concurrent swaps and the old transport's idle conns get closed.
var upstreamTransportPtr atomic.Pointer[http.Transport]

// upstreamTransportWriteMu serializes writers. Readers do NOT take
// this lock. Without it, two concurrent writers could each Load the
// same starting transport, build their respective new versions, and
// the second Store would clobber the first writer's update.
var upstreamTransportWriteMu sync.Mutex

func init() {
	upstreamTransportPtr.Store(newBaseUpstreamTransport())
}

// getUpstreamTransport returns the currently-published transport.
// The returned pointer MUST be treated as read-only. To mutate, use
// swapUpstreamTransport.
func getUpstreamTransport() *http.Transport {
	return upstreamTransportPtr.Load()
}

// swapUpstreamTransport is the only approved mutation API. It:
//  1. Takes the writer mutex (serializing concurrent writers).
//  2. Loads the current transport.
//  3. Invokes update(old) to obtain a NEW *http.Transport.
//  4. If update returned the same pointer, returns without swapping
//     (no-op cleanly handles "writer decided nothing changed").
//  5. Stores the new transport.
//  6. Synchronously calls old.CloseIdleConnections() to release the
//     previous transport's idle keepalive connections. In-flight
//     requests holding the old transport via their per-request
//     http.Client are NOT interrupted — they retain a strong
//     reference and only IDLE conns are torn down.
//
// The update closure MUST NOT mutate its input. Use cloneTransport
// to seed a new instance.
func swapUpstreamTransport(update func(old *http.Transport) *http.Transport) {
	upstreamTransportWriteMu.Lock()
	defer upstreamTransportWriteMu.Unlock()
	old := upstreamTransportPtr.Load()
	newT := update(old)
	if newT == nil || newT == old {
		return
	}
	upstreamTransportPtr.Store(newT)
	if old != nil {
		old.CloseIdleConnections()
	}
}

// newBaseUpstreamTransport constructs the initial transport with the
// static pool sizing and buffer constants the proxy hot path needs.
// Used by init() and by tests that want a clean transport baseline.
// Field values mirror the pre-P5.3 declaration in proxy.go.
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

// cloneTransport produces a fresh *http.Transport with the exported
// configuration fields copied from old. Internal connection-pool
// state (idle conns, perHost maps) is intentionally NOT copied — a
// new transport must start its own pool. Function fields, pointer
// fields, maps, and slices are copied by reference; the TLSClientConfig
// pointer is reused as-is and callers that intend to mutate TLS state
// MUST replace cloned.TLSClientConfig with cloneTLSConfig(cloned.TLSClientConfig)
// before mutating, so the old (shared) *tls.Config is never modified.
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
		TLSClientConfig:        old.TLSClientConfig,
		TLSHandshakeTimeout:    old.TLSHandshakeTimeout,
		DisableKeepAlives:      old.DisableKeepAlives,
		DisableCompression:     old.DisableCompression,
		MaxIdleConns:           old.MaxIdleConns,
		MaxIdleConnsPerHost:    old.MaxIdleConnsPerHost,
		MaxConnsPerHost:        old.MaxConnsPerHost,
		IdleConnTimeout:        old.IdleConnTimeout,
		ResponseHeaderTimeout:  old.ResponseHeaderTimeout,
		ExpectContinueTimeout:  old.ExpectContinueTimeout,
		TLSNextProto:           old.TLSNextProto,
		ProxyConnectHeader:     old.ProxyConnectHeader,
		GetProxyConnectHeader:  old.GetProxyConnectHeader,
		MaxResponseHeaderBytes: old.MaxResponseHeaderBytes,
		WriteBufferSize:        old.WriteBufferSize,
		ReadBufferSize:         old.ReadBufferSize,
		ForceAttemptHTTP2:      old.ForceAttemptHTTP2,
	}
}

// cloneTLSConfig returns a deep clone of old via the stdlib
// (*tls.Config).Clone(). Use this whenever an updater closure needs
// to mutate TLS state (Certificates, VerifyPeerCertificate, etc.) —
// without it, the mutation would touch the *tls.Config the OLD
// transport still references, reintroducing the R-2/R-4 race class.
//
// If old is nil, returns an empty *tls.Config (no MinVersion set —
// callers that care about MinVersion set their own default; this
// preserves the pre-P5.3 asymmetry where the mTLS branch defaulted
// to TLS 1.2 and the OCSP branch defaulted to TLS 1.3 depending on
// which one ran first).
func cloneTLSConfig(old *tls.Config) *tls.Config {
	if old == nil {
		return &tls.Config{} // #nosec G402 -- MinVersion is set by the caller branch (mTLS=TLS1.2, OCSP=TLS1.3) to preserve pre-P5.3 semantics
	}
	return old.Clone()
}
