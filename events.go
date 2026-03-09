package main

import (
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
		default: // skip slow clients
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
	UptimeSec     int64          `json:"uptimeSec"`
}

// startSSEBroadcaster runs the ticker that pushes stats to all SSE clients.
func startSSEBroadcaster() {
	ticker := time.NewTicker(time.Second)
	go func() {
		for range ticker.C {
			if hub.ClientCount() == 0 {
				continue
			}
			series := tsGet()
			var sum int64
			for _, v := range series {
				sum += v
			}
			rps := float64(sum) / 60.0

			payload := DashboardPayload{
				ActiveConns:   getActiveConns(),
				TotalRequests: atomic.LoadInt64(&statTotal),
				Blocked:       atomic.LoadInt64(&statBlocked),
				AuthFail:      atomic.LoadInt64(&statAuthFail),
				RPS:           rps,
				TopCountries:  countryTraffic.Top(15),
				UptimeSec:     int64(time.Since(startTime).Seconds()),
			}
			data, _ := json.Marshal(payload)
			hub.broadcast(data)
		}
	}()
}

// apiEvents is the SSE endpoint. Clients connect and receive live dashboard data.
func apiEvents(w http.ResponseWriter, r *http.Request) {
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(countryTraffic.Top(20))
}
