package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// sseHub manages Server-Sent Events (SSE) connections for the live dashboard.
// Clients connect to /api/events and receive JSON stats every second.
type sseHub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

var hub = &sseHub{clients: make(map[chan []byte]struct{})}

func (h *sseHub) register(ch chan []byte) {
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
}

func (h *sseHub) unregister(ch chan []byte) {
	h.mu.Lock()
	delete(h.clients, ch)
	h.mu.Unlock()
}

func (h *sseHub) broadcast(msg []byte) {
	h.mu.Lock()
	for ch := range h.clients {
		select {
		case ch <- msg:
		default:
			// B21: Close and remove slow clients instead of silently dropping messages.
			// This prevents stale connections from accumulating and missing state updates.
			close(ch)
			delete(h.clients, ch)
		}
	}
	h.mu.Unlock()
}

// ClientCount returns the number of connected SSE clients.
func (h *sseHub) ClientCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// DashboardPayload is sent to SSE clients every second.
type DashboardPayload struct {
	ActiveConns   int64          `json:"activeConns"`
	TotalRequests int64          `json:"totalRequests"`
	Blocked       int64          `json:"blocked"`
	AuthFail      int64          `json:"authFail"`
	RPS           float64        `json:"rps"`         // requests per second (1-min avg)
	TopCountries  []CountryCount `json:"topCountries"`
	UptimeSec         int64          `json:"uptimeSec"`
	ClamBlocked       int64          `json:"clamBlocked"`
	YARABlocked       int64          `json:"yaraBlocked"`
	DPIBlocked        int64          `json:"dpiBlocked"`
	ThreatFeedBlocked int64          `json:"threatFeedBlocked"`
	UpdateAvailable   bool           `json:"updateAvailable,omitempty"`
	LatestVersion     string         `json:"latestVersion,omitempty"`
}

// sseBroadcaster owns the live-dashboard ticker that pushes DashboardPayload
// updates to the global SSE hub. The goroutine exits when its context is
// cancelled — which is the only stop signal in production (appLifecycleCtx
// is cancelled by runProxyUntilShutdown). P1.2 / S4.SSE.
type sseBroadcaster struct {
	interval time.Duration
	done     chan struct{}
}

// newSSEBroadcaster returns a broadcaster that ticks at the given interval.
// Production callers use time.Second; tests pass a smaller interval to keep
// cancellation tests fast without changing production behaviour.
func newSSEBroadcaster(interval time.Duration) *sseBroadcaster {
	return &sseBroadcaster{
		interval: interval,
		done:     make(chan struct{}),
	}
}

// Done returns a channel that is closed after run returns. Because
// ticker.Stop is deferred before close(done) (defers run in LIFO order),
// the implementation stops the ticker before Done closes.
func (b *sseBroadcaster) Done() <-chan struct{} { return b.done }

// run blocks until ctx is cancelled. Stops the underlying ticker and closes
// b.done on exit. Must not be called more than once on the same broadcaster.
func (b *sseBroadcaster) run(ctx context.Context) {
	defer close(b.done)
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.tick()
		}
	}
}

// tick assembles one DashboardPayload and broadcasts it to the SSE hub.
// Skipped silently when no clients are connected. Body is byte-equivalent
// to the original startSSEBroadcaster ticker body — payload schema, hub
// behaviour, and dashboard contract are unchanged.
func (b *sseBroadcaster) tick() {
	if hub.ClientCount() == 0 {
		return
	}
	series, _, _ := tsGet()
	var sum int64
	for _, v := range series {
		sum += v
	}
	rps := float64(sum) / 60.0

	globalUpdateInfo.mu.RLock()
	updAvail := globalUpdateInfo.updateAvailable
	updLatest := globalUpdateInfo.latestVersion
	globalUpdateInfo.mu.RUnlock()

	payload := DashboardPayload{
		ActiveConns:       getActiveConns(),
		TotalRequests:     atomic.LoadInt64(&statTotal),
		Blocked:           atomic.LoadInt64(&statBlocked),
		AuthFail:          atomic.LoadInt64(&statAuthFail),
		RPS:               rps,
		TopCountries:      countryTraffic.Top(15),
		UptimeSec:         int64(time.Since(startTime).Seconds()),
		ClamBlocked:       atomic.LoadInt64(&statClamBlocked),
		YARABlocked:       atomic.LoadInt64(&statYARABlocked),
		DPIBlocked:        atomic.LoadInt64(&statDPIBlocked),
		ThreatFeedBlocked: atomic.LoadInt64(&statThreatFeedBlocked),
		UpdateAvailable:   updAvail,
		LatestVersion:     updLatest,
	}
	data, _ := json.Marshal(payload)
	hub.broadcast(data)
}

// startSSEBroadcaster spawns the live-dashboard broadcaster goroutine
// parented to ctx. Production interval is 1 s. Returns the *sseBroadcaster
// so tests (and, eventually, the Phase 2 shutdown registry) can wait on
// Done(). The production caller in initBackgroundServices discards the
// handle; the goroutine exits when appLifecycleCtx is cancelled.
func startSSEBroadcaster(ctx context.Context) *sseBroadcaster {
	b := newSSEBroadcaster(time.Second)
	go b.run(ctx)
	return b
}

// apiEvents is the SSE endpoint. Clients connect and receive live dashboard data.
func apiEvents(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Restrict SSE to same-origin requests only (no CORS wildcard).
	// The dashboard is served from the same origin, so no CORS header is needed.

	ch := make(chan []byte, 4)
	hub.register(ch)
	defer hub.unregister(ch)

	// Send an initial ping so the client knows we're connected.
	fmt.Fprintf(w, "event: connected\ndata: {}\n\n")
	flusher.Flush()

	for {
		select {
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// apiCountryTraffic returns the top destination countries for the dashboard.
func apiCountryTraffic(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(countryTraffic.Top(20))
}
