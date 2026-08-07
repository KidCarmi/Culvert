package alerts

// store.go — the webhook alert delivery engine, moved from package main's
// alerts.go (ADR-0002). The seam in alerts.go (Payload / Sink / SetSink /
// Fire) is unchanged: producers still fire through the installed sink, and
// package main still installs its fireAlert wrapper (which dispatches on the
// process-wide store) at init. What moved here is the implementation that
// wrapper delegates to: the Store (webhook CRUD + delivery history), the
// Dispatch fan-out (dedup + bounded concurrency + retry enqueue), the
// SSRF-guarded HTTP delivery with HMAC signing, and the persistent retry
// queue.
//
// Supported events:
//   "threat_detected"       — a request was blocked by ClamAV, YARA, or the DPI/threat-feed
//                             scanner (log status THREAT_BLOCKED/SCAN_BLOCKED/DPI_BLOCKED;
//                             metrics culvert_{clamav,yara,dpi,threat_feed}_blocked_total).
//                             Event name kept as "detected" rather than renamed to "blocked"
//                             to preserve existing webhook subscriptions.
//   "policy_block"          — PBAC policy blocked a request
//   "auth_lockout"          — admin UI brute-force lockout
//   "cert_expiry"           — CA certificate nearing expiry (fired on startup if ≤30 days)
//   "ca_load_failed"        — Root CA load/init failed at startup: SSL inspection disabled (fail-open)
//   "scan_timeout"          — ClamAV / YARA scan timeout (infrastructure issue)
//   "scan_clam_error"       — ClamAV scan error mid-request: content forwarded unscanned (fail-open, CHAOS-10)
//   "scan_skipped"          — response body exceeds scan size limit, forwarded unscanned
//   "upstream_pool_down"    — all parent proxies down: egress failing open to DIRECT (chain bypassed, CHAOS-11)
//   "storage_write_failed"  — a durable write to the data directory failed: persisted state is being lost (CHAOS-45)
//   "idp_unreachable"       — external identity backend (LDAP/OIDC) unreachable: authentication failing closed (CHAOS-47)
//   "state_file_corrupt"    — corrupt state file quarantined at startup (CHAOS-05/07)
//   "cluster_node_reenrolled" — expired-but-registered node re-enrolled with a fresh token (CHAOS-12)
//   "ha_sync_panic"         — a standby HA sync round panicked and was contained: state replication
//                             is stalled and this node's automatic failover is suppressed (CHAOS-25)
//
// Each webhook is stored in an in-memory list backed by a JSON file.
// Delivery is async, never blocks the request path.
// F16: Failed deliveries are retried with exponential backoff (3 attempts,
// 5s/15s/45s). Retry queue persists to disk for restart survival.
// If a signing secret is configured, a HMAC-SHA256 signature is added as
// X-Culvert-Signature: sha256=<hex>.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/obs"
	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// webhookSem bounds concurrent webhook delivery goroutines to prevent
// unbounded goroutine accumulation under heavy alert load (P4).
var webhookSem = make(chan struct{}, 10)

// dedupTTL is the window within which duplicate event+detail alerts are
// suppressed (Q17).
const dedupTTL = 30 * time.Second

// ValidateURL checks that a webhook URL is well-formed (http/https with a
// non-empty host). Unlike main's validateExternalURL, it does not perform DNS
// resolution at config time — the SSRF check is deferred to delivery time via
// the ssrf-guarded dialer so that operator-configured internal endpoints
// remain usable.
func ValidateURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("malformed URL: %w", err)
	}
	if !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("URL must use http:// or https:// scheme")
	}
	if u.Host == "" {
		return fmt.Errorf("URL must include a host")
	}
	return nil
}

// ── Data types ────────────────────────────────────────────────────────────────

// Webhook describes a single webhook endpoint.
type Webhook struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	URL     string   `json:"url"`
	Events  []string `json:"events"` // e.g. ["threat_detected","policy_block"]
	Enabled bool     `json:"enabled"`
	Secret  string   `json:"secret,omitempty"` // HMAC-SHA256 signing secret (never returned in list)
}

// ── Delivery History (Finding 8.1) ────────────────────────────────────────────

// Delivery records a single webhook delivery attempt.
type Delivery struct {
	Timestamp   string `json:"timestamp"`
	WebhookID   string `json:"webhookId"`
	WebhookName string `json:"webhookName"`
	Event       string `json:"event"`
	StatusCode  int    `json:"statusCode,omitempty"` // 0 if delivery failed before HTTP
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
	Attempt     int    `json:"attempt"` // 1-based
}

const maxDeliveryHistory = 200

// ── Store ─────────────────────────────────────────────────────────────────────

// Store holds the configured webhooks and the delivery-attempt history. The
// zero value is usable (main's process-wide singleton and several tests
// construct it as &Store{} / &AlertStore{}); Init sets the persistence path.
type Store struct {
	mu       sync.RWMutex
	hooks    []Webhook
	filePath string

	// saveMu serializes persistence so that disk I/O happens with mu RELEASED.
	// mu guards the in-memory hook set that HasSubscriber reads on the proxy
	// request path; save() fsyncs both the file and its directory, so holding mu
	// across it would stall every blocked request and DNS-failure subscriber
	// check for the duration of a disk write — unbounded on a degraded volume.
	// saveMu is taken only AFTER mu is released, so a mutation never waits on an
	// in-flight fsync while holding the lock readers need either.
	//
	// Letting writers reach the disk out of order is the price of that: each
	// snapshot carries a monotonic sequence number (saveSeq, guarded by mu) and
	// the writer drops any snapshot older than the last one persisted (savedSeq,
	// guarded by saveMu). The newest snapshot always wins, so disk converges to
	// the latest state rather than to whichever writer happened to finish last.
	saveMu   sync.Mutex
	saveSeq  uint64 // guarded by mu
	savedSeq uint64 // guarded by saveMu

	histMu  sync.Mutex
	history []Delivery // ring buffer, newest last

	// dedup prevents duplicate deliveries for the same event+detail within
	// dedupTTL (Q17). Key = "event:detail", value = last fire time. Per-store
	// (pre-extraction it was package-global in main; production has a single
	// store, so behavior is unchanged — and tests that swap in a fresh store
	// automatically get a fresh dedup window).
	dedupMu  sync.Mutex
	dedupMap map[string]time.Time
}

// RecordDelivery appends a delivery record to the in-memory history ring.
func (as *Store) RecordDelivery(d Delivery) {
	as.histMu.Lock()
	as.history = append(as.history, d)
	if len(as.history) > maxDeliveryHistory {
		as.history = as.history[len(as.history)-maxDeliveryHistory:]
	}
	as.histMu.Unlock()
}

// DeliveryHistory returns the most recent delivery records (newest first).
func (as *Store) DeliveryHistory() []Delivery {
	as.histMu.Lock()
	cp := make([]Delivery, len(as.history))
	copy(cp, as.history)
	as.histMu.Unlock()
	// Reverse so newest is first.
	for i, j := 0, len(cp)-1; i < j; i, j = i+1, j-1 {
		cp[i], cp[j] = cp[j], cp[i]
	}
	return cp
}

// Init sets the persistence path and loads any persisted webhooks.
func (as *Store) Init(path string) {
	as.filePath = path
	if path == "" {
		return
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured path
	if err != nil {
		if !os.IsNotExist(err) {
			obs.Printf("AlertStore: load %s: %v", path, err)
		}
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if err := json.Unmarshal(data, &as.hooks); err != nil {
		obs.Printf("AlertStore: parse %s: %v", path, err)
		return
	}
	// RISK-003: secrets are AES-GCM encrypted at rest. Decrypt into the
	// in-memory cleartext form used for HMAC signing. Legacy cleartext (no
	// enc prefix) passes through unchanged and is migrated on the next save.
	dir := filepath.Dir(path)
	for i := range as.hooks {
		pt, err := decryptWebhookSecret(as.hooks[i].Secret, dir)
		if err != nil {
			// Unrecoverable (corrupt blob or lost key): drop the secret so
			// deliveries continue UNSIGNED rather than signing with garbage.
			// The admin must re-enter it; we do not auto-resave (no data loss
			// on a transient key-read failure).
			obs.Printf("AlertStore: webhook %q secret decrypt failed, disabling signing: %v", obs.Sanitize(as.hooks[i].ID), err)
			as.hooks[i].Secret = ""
			continue
		}
		as.hooks[i].Secret = pt
	}
}

// noopSave is the persistence step for a mutation that had nothing to write
// (no configured file path, or no matching webhook).
var noopSave = func() {}

// beginSaveLocked snapshots the state persistence needs and returns the closure
// that performs the actual disk I/O. Callers hold mu on entry and MUST release
// it before invoking the returned closure.
//
// This split is what keeps fsync off the read path. save() encrypts each secret
// (which may read a key file) and calls fileutil.AtomicWrite, which fsyncs the
// temp file AND the parent directory. Previously that ran under mu, so an
// operator adding a webhook blocked every concurrent reader — including
// HasSubscriber, which the proxy now consults synchronously on the block and
// DNS-failure paths. The returned closure touches no shared state until mu is
// released, so neither the write nor the wait for a preceding write can stall a
// reader. Ordering is restored by sequence number rather than by lock order (see
// the saveMu/saveSeq comment on Store).
func (as *Store) beginSaveLocked() func() {
	if as.filePath == "" {
		return noopSave
	}
	as.saveSeq++
	seq := as.saveSeq
	path := as.filePath
	hooks := make([]Webhook, len(as.hooks))
	copy(hooks, as.hooks)
	return func() {
		if saveBarrier != nil {
			saveBarrier()
		}
		as.saveMu.Lock()
		defer as.saveMu.Unlock()
		if seq < as.savedSeq {
			return // a newer snapshot already reached disk; this one is stale
		}
		as.savedSeq = seq
		as.save(path, hooks)
	}
}

// saveBarrier is a test-only seam invoked at the very start of the persist
// closure — that is, at the first instant persistence runs. Production leaves it
// nil (a nil check, no behavior). It exists because the mu-is-released invariant
// is otherwise untestable without a scheduling race: a test cannot otherwise know
// when a mutation has reached persistence, so a reader might complete before the
// writer ever took the lock and pass a broken implementation. Mirrors the
// existing retryFile test seam in this file.
var saveBarrier func()

// save encrypts and writes the given hook snapshot. It must be called with mu
// RELEASED and saveMu held (see beginSaveLocked) — it performs fsync-backed
// disk I/O and must never block a reader.
func (as *Store) save(path string, hooks []Webhook) {
	if path == "" {
		return
	}
	// RISK-003: encrypt each secret before it touches disk. The in-memory
	// as.hooks keeps the cleartext (needed for HMAC signing), so encrypt a copy.
	dir := filepath.Dir(path)
	encHooks := make([]Webhook, len(hooks))
	copy(encHooks, hooks)
	for i := range encHooks {
		enc, err := encryptWebhookSecret(encHooks[i].Secret, dir)
		if err != nil {
			// Fail closed: never fall back to writing the cleartext secret.
			obs.Printf("AlertStore: webhook secret encrypt failed, not persisting: %v", err)
			return
		}
		encHooks[i].Secret = enc
	}
	data, _ := json.MarshalIndent(encHooks, "", "  ") // #nosec G117 -- Secret holds AES-GCM ciphertext at rest (RISK-003), not the cleartext key
	// RISK-017 closure made this path live in production for the first time,
	// so it was upgraded from the pre-Bucket-4 WriteFile+Rename to the
	// fsynced atomic writer in the same change.
	if err := fileutil.AtomicWrite(path, data, 0o600); err != nil {
		obs.Printf("AlertStore: write %s: %v", path, err)
	}
}

// List returns the webhooks with secrets redacted.
func (as *Store) List() []Webhook {
	as.mu.RLock()
	defer as.mu.RUnlock()
	out := make([]Webhook, len(as.hooks))
	for i, h := range as.hooks {
		h.Secret = "" // never expose secret in list
		out[i] = h
	}
	return out
}

// HasSubscriber reports whether any ENABLED webhook is subscribed to event
// (directly or via the "*" catch-all). Cheap: one RLock, no allocation.
//
// It lets a producer skip the work of firing an alert nobody will receive —
// including, for producers that dispatch asynchronously, skipping the
// goroutine spawn entirely. That matters beyond efficiency: a producer driven
// by an external fault (a failing disk) would otherwise inject goroutine churn
// into every process that has no webhooks configured at all, which is the
// default posture and the state of every test binary.
func (as *Store) HasSubscriber(event string) bool {
	as.mu.RLock()
	defer as.mu.RUnlock()
	for i := range as.hooks {
		if !as.hooks[i].Enabled {
			continue
		}
		for _, ev := range as.hooks[i].Events {
			if ev == event || ev == "*" {
				return true
			}
		}
	}
	return false
}

// Add stores a new webhook and returns it (secret redacted).
func (as *Store) Add(h Webhook) Webhook {
	h.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	as.mu.Lock()
	as.hooks = append(as.hooks, h)
	persist := as.beginSaveLocked()
	as.mu.Unlock()
	persist() // fsync-backed disk I/O, deliberately outside mu
	sanitised := h
	sanitised.Secret = ""
	return sanitised
}

// Update replaces the webhook with the given ID. An empty Secret in upd
// preserves the existing secret.
func (as *Store) Update(id string, upd Webhook) bool {
	as.mu.Lock()
	persist, ok := noopSave, false
	for i := range as.hooks {
		if as.hooks[i].ID != id {
			continue
		}
		upd.ID = id
		if upd.Secret == "" {
			upd.Secret = as.hooks[i].Secret // preserve existing secret if not updated
		}
		as.hooks[i] = upd
		persist, ok = as.beginSaveLocked(), true
		break
	}
	as.mu.Unlock()
	persist() // fsync-backed disk I/O, deliberately outside mu
	return ok
}

// Delete removes the webhook with the given ID.
func (as *Store) Delete(id string) bool {
	as.mu.Lock()
	persist, ok := noopSave, false
	for i := range as.hooks {
		if as.hooks[i].ID == id {
			as.hooks = append(as.hooks[:i], as.hooks[i+1:]...)
			persist, ok = as.beginSaveLocked(), true
			break
		}
	}
	as.mu.Unlock()
	persist() // fsync-backed disk I/O, deliberately outside mu
	return ok
}

// GetByID returns the webhook with the given ID (secret included — callers
// use it for delivery/signing, never for display).
func (as *Store) GetByID(id string) (Webhook, bool) {
	as.mu.RLock()
	defer as.mu.RUnlock()
	for _, h := range as.hooks {
		if h.ID == id {
			return h, true
		}
	}
	return Webhook{}, false
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

// Dispatch fans payload out to all enabled webhooks matching event.
// Always non-blocking: delivery happens in background goroutines.
// Q17: Duplicate events with the same event+detail are suppressed within
// dedupTTL. package main's fireAlert wrapper (installed as the alerts.Fire
// sink) calls this on the process-wide store.
func (as *Store) Dispatch(event string, payload Payload) {
	payload.Event = event
	if payload.Timestamp == "" {
		payload.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	// Q17: Dedup — skip if same event+detail fired recently.
	if as.dedupSuppressed(event + ":" + payload.Detail) {
		return
	}

	as.mu.RLock()
	hooks := make([]Webhook, len(as.hooks))
	copy(hooks, as.hooks)
	as.mu.RUnlock()

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
		// Use semaphore to bound concurrent deliveries (P4).
		hookCopy := h
		pCopy := payload
		select {
		case webhookSem <- struct{}{}:
			go func() {
				defer func() { <-webhookSem }()
				if ok := as.Deliver(hookCopy, pCopy); !ok {
					enqueueRetry(hookCopy.ID, pCopy, 1) // F16: retry on failure
				}
			}()
		default:
			enqueueRetry(hookCopy.ID, pCopy, 0) // F16: queue when semaphore full
		}
	}
}

// dedupSuppressed records the dedup key and reports whether an identical
// event+detail fired within dedupTTL (Q17). Stale entries are pruned on
// every pass to cap map growth.
func (as *Store) dedupSuppressed(dedupKey string) bool {
	as.dedupMu.Lock()
	defer as.dedupMu.Unlock()
	if as.dedupMap == nil {
		as.dedupMap = map[string]time.Time{}
	}
	if last, ok := as.dedupMap[dedupKey]; ok && time.Since(last) < dedupTTL {
		return true
	}
	as.dedupMap[dedupKey] = time.Now()
	// Prune stale entries (cap map growth).
	for k, t := range as.dedupMap {
		if time.Since(t) > dedupTTL {
			delete(as.dedupMap, k)
		}
	}
	return false
}

// ResetDedupForTest clears the Q17 dedup window so a test can fire the same
// event+detail twice and observe both deliveries (needed under -count>1 /
// -shuffle=on where a previous run already fired the pair).
func (as *Store) ResetDedupForTest() {
	as.dedupMu.Lock()
	as.dedupMap = map[string]time.Time{}
	as.dedupMu.Unlock()
}

// ── Delivery ──────────────────────────────────────────────────────────────────

// validWebhookURL matches http:// or https:// followed by at least one host
// character. Used as a CodeQL-recognised RegexpCheck barrier guard for
// go/request-forgery (CodeQL treats regexp.MatchString on the tainted value
// as a sanitiser in both branches).
var validWebhookURL = regexp.MustCompile(`^https?://[^/]`)

// Deliver performs one delivery attempt (attempt=1) and records the result.
// Exposed for main's webhook-test admin endpoint; Dispatch and the retry
// loop use it internally.
func (as *Store) Deliver(h Webhook, payload Payload) bool {
	return as.deliverAttempt(h, payload, 1)
}

// deliverAttempt performs the actual HTTP POST and records the result.
func (as *Store) deliverAttempt(h Webhook, payload Payload, attempt int) bool {
	record := Delivery{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		WebhookID:   h.ID,
		WebhookName: h.Name,
		Event:       payload.Event,
		Attempt:     attempt,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		record.Error = "json marshal: " + err.Error()
		as.RecordDelivery(record)
		return false
	}
	// Regexp barrier: CodeQL recognises Regexp.MatchString as an SSRF
	// sanitiser, breaking the taint chain on h.URL.
	if !validWebhookURL.MatchString(h.URL) {
		obs.Printf("Alert webhook %q: invalid URL, skipping delivery", obs.Sanitize(h.Name))
		record.Error = "invalid URL"
		as.RecordDelivery(record)
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		obs.Printf("Alert webhook %q: build request error: %v", obs.Sanitize(h.Name), err)
		record.Error = err.Error()
		as.RecordDelivery(record)
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Culvert-Alerts/1.0")
	if h.Secret != "" {
		mac := hmac.New(sha256.New, []byte(h.Secret))
		mac.Write(body)
		req.Header.Set("X-Culvert-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	// SSRF defence-in-depth: ssrf.SafeDialContext resolves DNS and rejects
	// connections to private/loopback IPs at the dial level.
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{DialContext: ssrf.SafeDialContext},
	}
	resp, err := client.Do(req)
	if err != nil {
		obs.Printf("Alert webhook %q: delivery error: %v", h.Name, err)
		record.Error = err.Error()
		as.RecordDelivery(record)
		return false
	}
	resp.Body.Close()
	record.StatusCode = resp.StatusCode
	if resp.StatusCode >= 400 {
		obs.Printf("Alert webhook %q: non-2xx response %d", h.Name, resp.StatusCode)
		record.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		as.RecordDelivery(record)
		return false
	}
	record.Success = true
	as.RecordDelivery(record)
	return true
}

// ── F16: Alert Retry Queue ────────────────────────────────────────────────────

const (
	retryMax      = 3
	retryBaseSec  = 5 // exponential: 5s, 15s, 45s
	retryQueueMax = 500
)

// retryFile is a var (not const) so tests can redirect writes to a temp dir.
// Production code never reassigns it.
var retryFile = "/data/alert_retry_queue.json"

// retryEntry represents a failed webhook delivery queued for retry.
type retryEntry struct {
	WebhookID string    `json:"webhook_id"`
	Payload   Payload   `json:"payload"`
	Attempt   int       `json:"attempt"`
	NextRetry time.Time `json:"next_retry"`
}

var (
	retryMu    sync.Mutex
	retryQueue []retryEntry

	// retryExhaustedTotal / retryDroppedTotal count deliveries that were
	// permanently given up on (all attempts used, or the queue was full) so
	// an admin can see alerting degradation on the delivery-history API
	// instead of only in the log line below.
	retryExhaustedTotal atomic.Int64
	retryDroppedTotal   atomic.Int64
)

// RetryQueueDepth returns the number of failed deliveries currently queued
// for retry.
func RetryQueueDepth() int {
	retryMu.Lock()
	defer retryMu.Unlock()
	return len(retryQueue)
}

// RetryExhaustedTotal returns the count of deliveries that used up all retry
// attempts and were permanently dropped.
func RetryExhaustedTotal() int64 {
	return retryExhaustedTotal.Load()
}

// RetryDroppedTotal returns the count of deliveries dropped because the
// retry queue was at capacity (retryQueueMax).
func RetryDroppedTotal() int64 {
	return retryDroppedTotal.Load()
}

// enqueueRetry adds a failed delivery to the retry queue.
func enqueueRetry(hookID string, payload Payload, attempt int) {
	if attempt >= retryMax {
		retryExhaustedTotal.Add(1)
		obs.Printf("Alert retry exhausted for webhook %q event %q after %d attempts",
			obs.Sanitize(hookID), obs.Sanitize(payload.Event), attempt)
		return
	}
	backoff := time.Duration(retryBaseSec) * time.Second
	for i := 0; i < attempt; i++ {
		backoff *= 3
	}
	entry := retryEntry{
		WebhookID: hookID,
		Payload:   payload,
		Attempt:   attempt,
		NextRetry: time.Now().Add(backoff),
	}
	retryMu.Lock()
	if len(retryQueue) < retryQueueMax {
		retryQueue = append(retryQueue, entry)
	} else {
		retryDroppedTotal.Add(1)
		obs.Printf("Alert retry queue full (%d entries), dropping retry for webhook %q event %q",
			retryQueueMax, obs.Sanitize(hookID), obs.Sanitize(payload.Event))
	}
	saveRetryQueueLocked()
	retryMu.Unlock()
}

// StartRetryLoop runs a background loop that retries failed deliveries.
// current resolves the store on every pass, so package main can pass a
// closure over its process-wide singleton (tolerating test reassignment —
// the pre-extraction loop read the global on each tick the same way).
func StartRetryLoop(ctx context.Context, current func() *Store) {
	// Load persisted retry queue on startup.
	retryMu.Lock()
	if data, err := os.ReadFile(retryFile); err == nil {
		_ = json.Unmarshal(data, &retryQueue)
	}
	retryMu.Unlock()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// CHAOS-24: contain the ROUND. This loop is the only thing that
			// re-delivers failed webhooks, so letting a panic kill the process
			// would turn a bad queue entry into a gateway outage; letting it
			// kill the goroutine would silently strand every retry forever.
			obs.SafeCall("alerts_retry", func() { processRetryQueue(current()) })
		}
	}
}

func processRetryQueue(store *Store) {
	now := time.Now()

	retryMu.Lock()
	var ready []retryEntry
	var remaining []retryEntry
	for i := range retryQueue {
		if now.After(retryQueue[i].NextRetry) {
			ready = append(ready, retryQueue[i])
		} else {
			remaining = append(remaining, retryQueue[i])
		}
	}
	retryQueue = remaining
	if len(ready) > 0 {
		saveRetryQueueLocked()
	}
	retryMu.Unlock()

	if store == nil {
		return
	}
	for i := range ready {
		hook, ok := store.GetByID(ready[i].WebhookID)
		if !ok || !hook.Enabled {
			continue
		}
		if ok := store.Deliver(hook, ready[i].Payload); !ok {
			enqueueRetry(ready[i].WebhookID, ready[i].Payload, ready[i].Attempt+1)
		}
	}
}

func saveRetryQueueLocked() {
	data, err := json.Marshal(retryQueue)
	if err != nil {
		return
	}
	_ = fileutil.AtomicWrite(retryFile, data, 0o600)
}
