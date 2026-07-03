// Package sse is the Server-Sent-Events client hub: registration under a
// connection cap, fan-out broadcast with slow-client eviction, and the
// hub-level observability counters. Extracted from package main's events.go
// per ADR-0002 as a pure stdlib leaf. The dashboard broadcaster (which
// assembles the payload from main's stats globals), the /api/events handler
// (auth, framing, mid-stream revalidation), and the Prometheus exposition
// stay in package main; main reads the counters through the accessors.
package sse

import (
	"sync"
	"sync/atomic"
)

// DefaultMaxClients is the default connection cap (see Hub.SetMaxClients).
const DefaultMaxClients = 256

// Hub manages SSE client channels for a live event stream.
// All methods are safe for concurrent use.
type Hub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}

	// maxClients caps concurrent connections. Each connection holds a
	// goroutine and an HTTP stream with no write deadline, so without a cap
	// any viewer credential could exhaust goroutines/FDs by opening streams.
	// 0 disables the cap. Per-hub (pre-extraction it was a package-level
	// var in main); it is the seam for the planned admin-configurable
	// connection limit.
	maxClients atomic.Int64

	// Observability counters (exposed by main via /metrics).
	evicted  atomic.Int64 // slow clients evicted by Broadcast
	rejected atomic.Int64 // connections rejected at the cap (counted by the handler via AddRejected)
}

// NewHub returns an empty hub with the default connection cap.
func NewHub() *Hub {
	h := &Hub{clients: make(map[chan []byte]struct{})}
	h.maxClients.Store(DefaultMaxClients)
	return h
}

// Register adds the client channel to the hub. It reports false — without
// registering — when the hub is already at the connection cap.
func (h *Hub) Register(ch chan []byte) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if limit := h.maxClients.Load(); limit > 0 && int64(len(h.clients)) >= limit {
		return false
	}
	h.clients[ch] = struct{}{}
	return true
}

// Unregister removes the client channel from the hub.
func (h *Hub) Unregister(ch chan []byte) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
}

// Broadcast sends msg to every registered client. Clients whose channel is
// full are closed and removed (B21: prevents stale connections from
// accumulating and missing state updates) and counted in Evicted.
func (h *Hub) Broadcast(msg []byte) {
	h.mu.Lock()
	for ch := range h.clients {
		select {
		case ch <- msg:
		default:
			close(ch)
			delete(h.clients, ch)
			h.evicted.Add(1)
		}
	}
	h.mu.Unlock()
}

// ClientCount returns the number of connected clients.
func (h *Hub) ClientCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// MaxClients returns the current connection cap (0 = uncapped).
func (h *Hub) MaxClients() int64 { return h.maxClients.Load() }

// SetMaxClients sets the connection cap (0 disables it). Existing
// connections are not evicted when the cap is lowered.
func (h *Hub) SetMaxClients(n int64) { h.maxClients.Store(n) }

// Evicted returns the cumulative count of slow clients evicted by Broadcast.
func (h *Hub) Evicted() int64 { return h.evicted.Load() }

// Rejected returns the cumulative count of connections rejected at the cap.
func (h *Hub) Rejected() int64 { return h.rejected.Load() }

// AddRejected increments the rejected-connection counter. Called by the
// stream handler when Register reports the hub is full (the handler owns
// the HTTP 503, so it owns the count).
func (h *Hub) AddRejected() { h.rejected.Add(1) }

// ── Test support ─────────────────────────────────────────────────────────────

// ClientsForTest returns the currently registered channels. Test support for
// integration tests that diff the client set to find the channel a handler
// registered (replaces the pre-extraction whitebox map iteration).
func (h *Hub) ClientsForTest() []chan []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]chan []byte, 0, len(h.clients))
	for ch := range h.clients {
		out = append(out, ch)
	}
	return out
}

// EvictForTest closes and removes ch, mirroring Broadcast's B21 slow-client
// eviction (without touching the evicted counter). Test support for the
// handler test that simulates an eviction mid-stream.
func (h *Hub) EvictForTest(ch chan []byte) {
	h.mu.Lock()
	if _, ok := h.clients[ch]; ok {
		close(ch)
		delete(h.clients, ch)
	}
	h.mu.Unlock()
}
