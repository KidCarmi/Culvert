package main

// alerts.go — Webhook alert delivery for security events.
//
// Supported events:
//   "threat_detected"   — ClamAV / YARA / threat-feed block
//   "policy_block"      — PBAC policy blocked a request
//   "auth_lockout"      — admin UI brute-force lockout
//   "cert_expiry"       — CA certificate nearing expiry (fired on startup if ≤30 days)
//
// Each webhook is stored in an in-memory list backed by a JSON file.
// Delivery is async (fire-and-forget goroutine), never blocks the request path.
// Failed deliveries are logged and silently discarded (no retry).
// If a signing secret is configured, a HMAC-SHA256 signature is added as
// X-ProxyShield-Signature: sha256=<hex>.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// ── Data types ────────────────────────────────────────────────────────────────

// AlertWebhook describes a single webhook endpoint.
type AlertWebhook struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	URL     string   `json:"url"`
	Events  []string `json:"events"`  // e.g. ["threat_detected","policy_block"]
	Enabled bool     `json:"enabled"`
	Secret  string   `json:"secret,omitempty"` // HMAC-SHA256 signing secret (never returned in list)
}

// AlertPayload is the JSON body POSTed to each matching webhook.
type AlertPayload struct {
	Event     string `json:"event"`
	Timestamp string `json:"timestamp"`
	Actor     string `json:"actor"`  // client IP or username
	Host      string `json:"host"`
	Detail    string `json:"detail"` // virus name / rule name / pattern
	Source    string `json:"source"` // "clamav","yara","threatfeed","policy","auth"
}

// ── Store ─────────────────────────────────────────────────────────────────────

type AlertStore struct {
	mu       sync.RWMutex
	hooks    []AlertWebhook
	filePath string
}

var globalAlertStore = &AlertStore{}

func (as *AlertStore) Init(path string) {
	as.filePath = path
	if path == "" {
		return
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Printf("AlertStore: load %s: %v", path, err)
		}
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if err := json.Unmarshal(data, &as.hooks); err != nil {
		logger.Printf("AlertStore: parse %s: %v", path, err)
	}
}

func (as *AlertStore) save() {
	if as.filePath == "" {
		return
	}
	data, _ := json.MarshalIndent(as.hooks, "", "  ") // #nosec G117 -- Secret is the HMAC signing key; intentionally persisted so webhooks survive restart
	tmp := as.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil { // #nosec G306
		logger.Printf("AlertStore: write %s: %v", tmp, err)
		return
	}
	os.Rename(tmp, as.filePath) //nolint:errcheck
}

func (as *AlertStore) List() []AlertWebhook {
	as.mu.RLock()
	defer as.mu.RUnlock()
	out := make([]AlertWebhook, len(as.hooks))
	for i, h := range as.hooks {
		h.Secret = "" // never expose secret in list
		out[i] = h
	}
	return out
}

func (as *AlertStore) Add(h AlertWebhook) AlertWebhook {
	h.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	as.mu.Lock()
	defer as.mu.Unlock()
	as.hooks = append(as.hooks, h)
	as.save()
	sanitised := h
	sanitised.Secret = ""
	return sanitised
}

func (as *AlertStore) Update(id string, upd AlertWebhook) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	for i, h := range as.hooks {
		if h.ID == id {
			upd.ID = id
			if upd.Secret == "" {
				upd.Secret = h.Secret // preserve existing secret if not updated
			}
			as.hooks[i] = upd
			as.save()
			return true
		}
	}
	return false
}

func (as *AlertStore) Delete(id string) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	for i, h := range as.hooks {
		if h.ID == id {
			as.hooks = append(as.hooks[:i], as.hooks[i+1:]...)
			as.save()
			return true
		}
	}
	return false
}

func (as *AlertStore) GetByID(id string) (AlertWebhook, bool) {
	as.mu.RLock()
	defer as.mu.RUnlock()
	for _, h := range as.hooks {
		if h.ID == id {
			return h, true
		}
	}
	return AlertWebhook{}, false
}

// ── Delivery ──────────────────────────────────────────────────────────────────

// fireAlert dispatches payload to all enabled webhooks matching event.
// Always non-blocking: delivery happens in background goroutines.
func fireAlert(event string, payload AlertPayload) {
	payload.Event = event
	if payload.Timestamp == "" {
		payload.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	globalAlertStore.mu.RLock()
	hooks := make([]AlertWebhook, len(globalAlertStore.hooks))
	copy(hooks, globalAlertStore.hooks)
	globalAlertStore.mu.RUnlock()

	for _, h := range hooks {
		if !h.Enabled {
			continue
		}
		matched := false
		for _, ev := range h.Events {
			if ev == event || ev == "*" {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		go deliverWebhook(h, payload)
	}
}

func deliverWebhook(h AlertWebhook, payload AlertPayload) {
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	// Webhook URLs are admin-configured (not user-tainted) — no SSRF risk.
	req, err := http.NewRequest(http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		logger.Printf("Alert webhook %q: build request error: %v", sanitizeLog(h.Name), err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ProxyShield-Alerts/1.0")
	if h.Secret != "" {
		mac := hmac.New(sha256.New, []byte(h.Secret))
		mac.Write(body)
		req.Header.Set("X-ProxyShield-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logger.Printf("Alert webhook %q: delivery error: %v", h.Name, err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		logger.Printf("Alert webhook %q: non-2xx response %d", h.Name, resp.StatusCode)
	}
}
