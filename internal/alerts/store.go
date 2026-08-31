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
//   "identity_backend_unreachable" — external identity backend (LDAP/OIDC) unreachable: authentication failing closed (CHAOS-47).
//                             Deliberately not "idp_unreachable" — Culvert's "IdP" vocabulary is reserved for the
//                             federated Identity Provider registry (auth_idp.go, the "Identity Providers" GUI panel),
//                             a distinct, uncached subsystem (CHAOS-49) this alert does not cover.
//   "auth_verify_saturated" — every credential-hashing slot is busy, so authentication is failing
//                             CLOSED for CAPACITY rather than for credentials (CHAOS-57). Distinct
//                             from identity_backend_unreachable, which is about a remote backend:
//                             this one says THIS node is at its own CPU bound, and the two need
//                             opposite responses (add capacity / shed load vs. fix the directory).
//                             Rate-limited to one per 5 min; the magnitude lives in
//                             culvert_auth_verify_saturated_total.
//   "state_file_corrupt"    — corrupt state file quarantined at startup (CHAOS-05/07)
//   "cluster_node_reenrolled" — expired-but-registered node re-enrolled with a fresh token (CHAOS-12)
//   "ha_sync_panic"         — a standby HA sync round panicked and was contained: state replication
//                             is stalled and this node's automatic failover is suppressed (CHAOS-25)
//   "socks5_listener_down"  — the SOCKS5 accept loop has been unable to accept connections for a
//                             sustained period, or has stopped entirely: SOCKS5 clients cannot
//                             connect (CHAOS-54). Fired once per episode, never per retry.
//   "mcp_gateway_down"      — MCP enablement was requested but the capability is not serving:
//                             activation failed, the listener degraded, or it stopped while still
//                             configured (RISK-027). Fired once per episode, never per request.
//                             MCP is REPORT-ONLY for SWG readiness — this alert says the MCP
//                             capability is down, never that the proxy is.
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
	"net"
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

const (
	// maxDedupEntries hard-caps the Q17 dedup map (CHAOS-27). The key embeds
	// the alert Detail, which on the request path carries the attacker-chosen
	// host, so the key space is attacker-controlled — the same reason topHosts
	// is capped. 4096 keys × 30s covers any realistic legitimate alert rate.
	maxDedupEntries = 4096
	// dedupPruneEvery amortises the O(len) expiry scan: it used to run on
	// every dispatch while holding the process-wide dedup mutex.
	dedupPruneEvery = 256
	// dedupPruneMinInterval bounds how often the over-cap path may fall back
	// to that scan. The insert-counted schedule above cannot see a QUIET
	// period — entries expire with time, not with inserts — so the cap check
	// needs a time-based trigger too, rate-limited so a sustained flood does
	// not pay the scan per alert. One O(cap) scan per second is ~40µs.
	dedupPruneMinInterval = time.Second
)

// dedupEvicted counts dedup keys dropped by the cap, so a flooded alert key
// space is visible to operators instead of silently degrading suppression.
var dedupEvicted atomic.Int64

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

	// SigningDegraded is a READ-ONLY status field, set only on the redacted
	// copies List returns: this webhook was configured WITH a signing secret,
	// but the stored secret could not be decrypted (a lost or unreadable
	// .alert_webhook_key), so deliveries carry no X-Culvert-Signature.
	//
	// It exists because Secret is blanked in List — which makes "no secret was
	// ever configured" and "the configured secret is gone and deliveries are
	// now UNSIGNED" render identically in the admin UI. An operator who cannot
	// see the second case has no reason to re-enter the secret, and a receiver
	// that verifies the HMAC silently stops accepting this node's alerts.
	//
	// Never persisted: save() clears it before marshalling (and a hook loaded
	// from disk derives it from sealedSecret, never from the file).
	SigningDegraded bool `json:"signing_degraded,omitempty"`

	// sealedSecret holds the on-disk value for a secret that failed to decrypt
	// at load. Unexported, so it never reaches the wire or the file as a field
	// of its own — save() writes it back verbatim into Secret's slot.
	//
	// Keeping it is what makes the failure RECOVERABLE. The in-memory Secret is
	// blanked (never sign with garbage), but blanking it on disk as well would
	// destroy key material that is merely un-unwrappable right now: restore the
	// key file and the secret works again. Without this field, the next save of
	// ANY webhook — an unrelated add, edit, delete or enable-toggle, since
	// save() rewrites the whole list — overwrote the ciphertext with "" and the
	// secret was gone for good.
	sealedSecret string
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
	//
	// CHAOS-27: the key embeds Detail, which for the request-path producers
	// (threat_detected / policy_block) carries the attacker-supplied host, so
	// the key space is attacker-controlled and the map is bounded by
	// maxDedupEntries. dedupSincePrune amortises the O(len) expiry scan.
	dedupMu         sync.Mutex
	dedupMap        map[string]time.Time
	dedupSincePrune int
	dedupLastPrune  time.Time
	// dedupPruneRuns counts O(len) expiry scans. It exists so the amortisation
	// contract is testable: a regression that restores the scan-every-dispatch
	// behaviour is a memory-safe change that silently reintroduces the CPU
	// failure mode, and only this counter distinguishes the two.
	dedupPruneRuns int
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

// legacyEventNames maps a retired event name to its current replacement, so a
// webhook subscribed under the old name keeps firing after the rename instead
// of silently losing its subscription (see the "threat_detected" precedent in
// the event catalog above, which chose to keep an outdated name rather than
// break subscriptions — this achieves the same non-breaking outcome while
// still letting the wire name read correctly).
var legacyEventNames = map[string]string{
	"idp_unreachable": "identity_backend_unreachable",
}

// normalizeEventNames rewrites retired event names to their current
// replacements. It is applied at EVERY ingress into the store — Init (disk),
// Add and Update (admin API, config import) — because a subscription that
// misses the rename is not a cosmetic defect: HasSubscriber compares names
// exactly, so the webhook stops firing, the admin UI stops recognizing the
// checked box, and the failure mode is a security alert that silently never
// arrives. Detection loss is the one kind of loss an operator cannot notice.
//
// Migrating only on load is not enough, because disk is not the only ingress:
//
//   - `POST /api/config/import` reconstructs webhooks through Add. A config
//     exported before the rename — the exact artifact a disaster-recovery
//     restore or an upgrade rehearsal replays — carries the retired name, and
//     without normalization here it is written straight back into the live
//     store, permanently unsubscribed.
//   - `POST/PUT /api/alerts/webhooks` accepts whatever event list the caller
//     sends. Operator automation written against the documented pre-rename
//     name would silently unsubscribe itself on its next apply.
//
// The mapping is one-way and closed: it can only carry a subscription forward
// to the SAME event under its current name. It never adds an event the caller
// did not ask for and never removes one, so it cannot widen or narrow what a
// webhook receives.
//
// Duplicates that the migration itself creates (a hook listing both the
// retired and the current name) are collapsed, order-preserving, so List and
// the admin UI show one checkbox rather than two aliases of one event.
// Dispatch already stops at the first match, so this changes no delivery
// behaviour — only what the operator sees.
func normalizeEventNames(events []string) []string {
	if len(events) == 0 {
		return events
	}
	out := make([]string, 0, len(events))
	seen := make(map[string]struct{}, len(events))
	for _, ev := range events {
		if renamed, ok := legacyEventNames[ev]; ok {
			ev = renamed
		}
		if _, dup := seen[ev]; dup {
			continue
		}
		seen[ev] = struct{}{}
		out = append(out, ev)
	}
	return out
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
	// Event-name migration: a webhook persisted before an alert event was
	// renamed must keep firing under its new name (see normalizeEventNames).
	// Migrated in memory on every load — like the legacy-cleartext-secret
	// migration below, this does not force an immediate resave; the next
	// legitimate mutation persists the new name.
	for i := range as.hooks {
		as.hooks[i].Events = normalizeEventNames(as.hooks[i].Events)
	}
	// RISK-003: secrets are AES-GCM encrypted at rest. Decrypt into the
	// in-memory cleartext form used for HMAC signing. Legacy cleartext (no
	// enc prefix) passes through unchanged and is migrated on the next save.
	dir := filepath.Dir(path)
	for i := range as.hooks {
		// SigningDegraded is DERIVED, never read from the file: a hand-edited
		// or imported document must not be able to assert a status the store
		// has not observed for itself.
		as.hooks[i].SigningDegraded = false
		pt, err := decryptWebhookSecret(as.hooks[i].Secret, dir)
		if err != nil {
			// Undecryptable (corrupt blob, or — the reachable case — a key
			// file that is missing or unreadable): drop the CLEARTEXT so
			// deliveries continue UNSIGNED rather than signing with garbage,
			// but KEEP the stored ciphertext in sealedSecret so the next save
			// writes it back untouched. Blanking it on disk too would turn a
			// recoverable state (restore .alert_webhook_key ⇒ signing works
			// again) into permanent destruction of key material, triggered by
			// an unrelated admin edit.
			//
			// The state is no longer log-only: List() reports SigningDegraded,
			// the admin UI badges it, and /api/diagnostics carries the
			// alert_webhook_signing operator-contract row. Unsigned delivery
			// from a webhook the operator believes is signed is a silent
			// authenticity failure — it must be visible where the webhook is.
			obs.Printf("AlertStore: webhook %q secret decrypt failed, disabling signing (ciphertext preserved for recovery): %v", obs.Sanitize(as.hooks[i].ID), err)
			as.hooks[i].sealedSecret = as.hooks[i].Secret
			as.hooks[i].Secret = ""
			continue
		}
		as.hooks[i].sealedSecret = ""
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
		// Status field, never persisted (it is derived at load).
		encHooks[i].SigningDegraded = false
		if encHooks[i].Secret == "" && encHooks[i].sealedSecret != "" {
			// This hook's stored secret could not be decrypted at load. Write
			// the ORIGINAL ciphertext back byte-for-byte: re-encrypting the
			// blanked cleartext would persist an empty secret and destroy key
			// material that is still recoverable (see Webhook.sealedSecret).
			encHooks[i].Secret = encHooks[i].sealedSecret
			continue
		}
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
//
// SigningDegraded is the one status bit that travels with the redacted copy:
// with Secret blanked, it is the ONLY way an operator can tell a webhook that
// never had a signing secret from one whose secret is unusable and whose
// deliveries are therefore unsigned. It carries no key material — just the
// fact that the configured one could not be unwrapped.
func (as *Store) List() []Webhook {
	as.mu.RLock()
	defer as.mu.RUnlock()
	out := make([]Webhook, len(as.hooks))
	for i, h := range as.hooks {
		h.SigningDegraded = h.sealedSecret != ""
		h.Secret = "" // never expose secret in list
		h.sealedSecret = ""
		out[i] = h
	}
	return out
}

// SigningDegradedCount returns how many webhooks were configured with a signing
// secret that could not be decrypted at load, so their deliveries go out
// UNSIGNED. Zero on every healthy node; non-zero means either the node-local
// key file (.alert_webhook_key) was lost — the reachable case is restoring a
// backup onto a fresh volume, since the key is deliberately never archived —
// or it was unreadable when the store loaded.
//
// Feeds the alert_webhook_signing operator-contract row; carries no secret.
func (as *Store) SigningDegradedCount() int {
	as.mu.RLock()
	defer as.mu.RUnlock()
	n := 0
	for i := range as.hooks {
		if as.hooks[i].sealedSecret != "" {
			n++
		}
	}
	return n
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
//
// Retired event names are migrated on the way in (normalizeEventNames): this
// is the ingress used by both the admin API and `POST /api/config/import`, so
// a pre-rename config export replayed by a restore keeps its subscription
// instead of coming back permanently unsubscribed.
func (as *Store) Add(h Webhook) Webhook {
	h.Events = normalizeEventNames(h.Events)
	h.SigningDegraded = false // status is derived, never accepted from a caller
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
//
// Retired event names are migrated on the way in (normalizeEventNames), so an
// API client still sending a pre-rename name does not silently unsubscribe the
// hook it is editing.
func (as *Store) Update(id string, upd Webhook) bool {
	upd.Events = normalizeEventNames(upd.Events)
	as.mu.Lock()
	persist, ok := noopSave, false
	for i := range as.hooks {
		if as.hooks[i].ID != id {
			continue
		}
		upd.ID = id
		upd.SigningDegraded = false // status is derived, never accepted from a caller
		if upd.Secret == "" {
			upd.Secret = as.hooks[i].Secret // preserve existing secret if not updated
			// Carry the un-unwrappable ciphertext across too: an edit that does
			// not touch the secret must not be the thing that destroys it.
			upd.sealedSecret = as.hooks[i].sealedSecret
		} else {
			// A caller-supplied secret REPLACES the degraded one. Cleared
			// explicitly rather than relying on the caller's zero value, so the
			// invariant "sealedSecret != \"\" implies Secret == \"\"" holds even
			// for an in-package caller that round-trips a GetByID copy.
			upd.sealedSecret = ""
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
// event+detail fired within dedupTTL (Q17).
//
// CHAOS-27: the dedup key is "event:detail", and the request-path producers
// put the requested host in Detail — so a scanning flood against thousands of
// distinct hosts produces thousands of DISTINCT keys that the window cannot
// suppress by construction. Two properties therefore have to hold under that
// load, and neither did:
//
//   - Bounded memory. Growth was limited only by (alert rate × dedupTTL), on
//     the same attacker-controlled key space that topHosts (store.go) is
//     already hard-capped for.
//   - Bounded CPU. The expiry scan ran on EVERY dispatch, O(len(map)) under a
//     process-wide mutex — quadratic in the flood, with every other alert
//     producer blocked behind the lock.
//
// The scan is now amortised (at most once per dedupPruneEvery inserts) and
// the map is hard-capped by a separate O(over-cap) eviction. Eviction fails
// toward MORE deliveries, never fewer: dropping a live key can only cost one
// extra delivery of a duplicate, and that fan-out is still bounded by the
// 10-slot delivery semaphore and the 500-cap retry queue. Silencing a real
// alert to save memory would be the wrong trade for a security control.
func (as *Store) dedupSuppressed(dedupKey string) bool {
	as.dedupMu.Lock()
	defer as.dedupMu.Unlock()
	if as.dedupMap == nil {
		as.dedupMap = map[string]time.Time{}
	}
	now := time.Now()
	if last, ok := as.dedupMap[dedupKey]; ok && now.Sub(last) < dedupTTL {
		return true
	}
	as.dedupMap[dedupKey] = now
	as.dedupSincePrune++
	// Two different costs, deliberately kept apart. The expiry scan is O(len)
	// and runs on a schedule; the cap is enforced every insert but costs only
	// O(number over cap) — which, once the map is full, is one deletion. A
	// single check of `len > cap` calling the O(len) scan would have made a
	// sustained flood pay a full scan PER alert: bounded memory, but the same
	// quadratic CPU under the same process-wide mutex.
	if as.dedupSincePrune >= dedupPruneEvery {
		as.pruneExpiredLocked(now)
	}
	if len(as.dedupMap) > maxDedupEntries {
		// Over cap. Before charging an eviction, make sure the excess is LIVE.
		// The prune schedule counts INSERTS but entries expire with TIME, and a
		// quiet period has no inserts — so a map left full by a finished flood
		// sits there entirely stale, and evicting from it would fabricate a
		// saturation signal on a monotonic counter (and could drop the key just
		// inserted). Rate-limited by time so a SUSTAINED flood, where the scan
		// finds nothing to reclaim, still does not pay O(len) per alert.
		if now.Sub(as.dedupLastPrune) >= dedupPruneMinInterval {
			as.pruneExpiredLocked(now)
		}
		as.evictOverCapLocked(now, dedupKey)
	}
	return false
}

// pruneExpiredLocked drops keys older than dedupTTL and re-arms both prune
// triggers. O(len); amortised by the caller. Caller holds dedupMu.
func (as *Store) pruneExpiredLocked(now time.Time) {
	as.dedupPruneRuns++
	as.dedupSincePrune = 0
	as.dedupLastPrune = now
	for k, t := range as.dedupMap {
		if now.Sub(t) > dedupTTL {
			delete(as.dedupMap, k)
		}
	}
}

// evictOverCapLocked enforces maxDedupEntries. Expiry alone is rate-bound,
// not size-bound: a fast enough flood adds keys faster than dedupTTL retires
// them. The caller guarantees the map has been pruned recently, so anything
// evicted here is a LIVE key and the eviction counter means what it says.
//
// keep is the key just inserted, skipped so the alert that triggered this
// call is never the one dropped. Go randomises map iteration order, so the
// rest is a random eviction and not an oldest-first one — under a flood every
// live entry is inside the same 30s window anyway, and the cost of evicting
// the wrong one is one duplicate delivery, never a missed alert.
//
// A key that has already expired is deleted but NOT charged: it was dead, so
// dropping it is reclamation, not saturation. That keeps the counter exact
// even in the window between an entry expiring and the next prune reclaiming
// it, so `dedup_evictions_total` only ever means "live keys arrived faster
// than the window could hold them". Caller holds dedupMu.
func (as *Store) evictOverCapLocked(now time.Time, keep string) {
	over := len(as.dedupMap) - maxDedupEntries
	if over <= 0 {
		return
	}
	deleted, charged := 0, 0
	for k, t := range as.dedupMap {
		if k == keep {
			continue
		}
		delete(as.dedupMap, k)
		deleted++
		if now.Sub(t) <= dedupTTL {
			charged++
		}
		if deleted >= over {
			break
		}
	}
	dedupEvicted.Add(int64(charged))
}

// DedupEvictionsTotal reports how many dedup keys were evicted by the
// CHAOS-27 cap. Non-zero means the alert key space is being flooded (a
// scanning/beaconing wave, or a producer emitting unique Detail text per
// request) and that duplicate suppression is degraded — alerts may be
// delivered more than once per window, never fewer.
func DedupEvictionsTotal() int64 { return dedupEvicted.Load() }

// DedupTracked reports how many dedup keys are currently held (≤ the cap).
func (as *Store) DedupTracked() int {
	as.dedupMu.Lock()
	defer as.dedupMu.Unlock()
	return len(as.dedupMap)
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

// ── Delivery client (CHAOS-27) ────────────────────────────────────────────────
//
// ONE shared, pooled client for every webhook delivery. It used to be built
// per attempt, inside deliverAttempt:
//
//	client := &http.Client{Timeout: 5s, Transport: &http.Transport{DialContext: ...}}
//
// which is the documented net/http footgun. After a successful POST the
// keep-alive connection is returned to that Transport's idle pool — a pool
// nothing holds a reference to any more, whose zero-value IdleConnTimeout
// means "never expire", and which net/http does not finalize. Its persistConn
// read/write goroutines keep the Transport (and the socket) alive until the
// PEER decides to close. So every delivered alert cost one FD and two
// goroutines, held for as long as the receiver tolerated an idle connection.
//
// The P4 semaphore did not bound this: it caps CONCURRENT deliveries (10),
// not CUMULATIVE sockets. Neither did the Q17 dedup window, because its key
// embeds the attacker-supplied host (see dedupSuppressed). A scanning flood
// against a deployment with a webhook configured is therefore a slow FD leak
// in the alerting plane that ends in `accept: too many open files` in the
// PROXY plane — the alert path taking down the data path, and worst exactly
// when alert volume peaks, i.e. while under attack.
//
// Reuse does not weaken the SSRF guard. ssrf.SafeDialContext runs on every
// DIAL, and a pooled connection is a connection to an address that already
// passed the check; reuse cannot reach an address that was never validated.
// IdleConnTimeout bounds how long a validated-then-rebound host stays
// reachable, matching the pooled clients already used for feed and OTLP
// egress (internal/blocklistfeed, internal/otlp).
func newDeliveryTransport(dial func(context.Context, string, string) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		DialContext:           dial,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// deliveryClient is the process-wide webhook delivery client. The per-attempt
// deadline is unchanged: 5s here plus the caller's request context.
var deliveryClient = &http.Client{
	Timeout:   5 * time.Second,
	Transport: newDeliveryTransport(ssrf.SafeDialContext),
}

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
	// SSRF defence-in-depth: the shared client dials through
	// ssrf.SafeDialContext, which resolves DNS and rejects connections to
	// private/loopback IPs at the dial level (CHAOS-27: shared, not per
	// attempt — see deliveryClient).
	resp, err := deliveryClient.Do(req)
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
