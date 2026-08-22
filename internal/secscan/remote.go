package secscan

// Remote scan client — sends scan requests to a scan microservice sidecar
// instead of running ClamAV/YARA/DPI in-process. Moved from package main
// (scan_remote.go) per ADR-0006; the sidecar SERVER (scan_svc.go) stays in
// main, sharing the ScanResponse wire type via alias.
//
// When -scan-svc-url is set (or scan_svc.url in config), the proxy delegates
// all body scanning to the remote service. The local Scanner and DPI engine
// are not initialised.
//
// This provides process isolation: a regex catastrophic backtracking or ClamAV
// crash in the sidecar does not take down the proxy process.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
	"github.com/KidCarmi/Culvert/internal/hashcache"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// ScanResponse is the JSON wire type between the scan sidecar and this
// client. The sidecar server (package main, scan_svc.go) produces it; keep
// the field set in sync with the server handler.
type ScanResponse struct {
	Clean      bool   `json:"clean"`
	Blocked    bool   `json:"blocked"`
	Reason     string `json:"reason,omitempty"`
	Source     string `json:"source,omitempty"`      // "clamav", "yara", "dpi"
	Hash       string `json:"hash,omitempty"`        // SHA-256 of scanned content
	DPIPattern string `json:"dpi_pattern,omitempty"` // matched DPI pattern
	ElapsedMS  int64  `json:"elapsed_ms"`
}

// RemoteScanner sends scan requests to a scan microservice.
type RemoteScanner struct {
	mu      sync.RWMutex
	baseURL string // e.g. "http://localhost:8484"
	client  *http.Client
	excl    HashExcluder // nil → no hash allowlist

	// enabled is atomic for the same reason as Scanner.enabled: Enabled() is
	// consulted once per plain-HTTP response (proxy_http.go scanHTTPResponseBody)
	// and the overwhelmingly common answer is "no remote scanner configured",
	// which should not cost a round trip on this struct's RWMutex. The methods
	// that need baseURL/client still take mu; they just read the flag atomically.
	//
	// This struct is small enough (56 B) that enabled lands on the same 64-byte
	// line as mu, so an RLock elsewhere does invalidate it. Measured and accepted
	// rather than padded: mu is taken ONLY when a sidecar is configured, and only
	// by ScanBody/Health/Status, each of which then makes an HTTP round trip that
	// dwarfs a cache miss. In the default posture mu is never taken at all.
	// Scanner and threatfeed.Feed are large enough that their flags already sit
	// on a separate line.
	enabled atomic.Bool
}

// Init configures the remote scanner client.
//
// The client timeout is a BACKSTOP only. Every request this client makes now
// carries its own context deadline — the shared scan budget for /scan, five
// seconds for the admin probes — and those always fire first. It used to be
// the only bound on a scan, at 60 s, i.e. six times the budget the local path
// gives the identical decision.
func (rs *RemoteScanner) Init(baseURL string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.baseURL = baseURL
	rs.client = &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	rs.enabled.Store(true)
	obs.Printf("ScanSvc: remote scanner at %s", baseURL)
}

// SetExclusions injects the admin-managed hash allowlist so the remote path
// honours it exactly as Scanner.ScanBody does.
//
// Without this the allowlist was structurally dead in sidecar deployments: an
// admin clearing a false positive by hash saw the entry accepted, persisted and
// audited, and the object kept being blocked, with nothing anywhere saying the
// setting did not apply to this deployment.
func (rs *RemoteScanner) SetExclusions(excl HashExcluder) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.excl = excl
}

// Enabled reports whether remote scanning is configured.
//
// Lock-free by contract — see the enabled field.
// TestRemoteScannerEnabled_IsLockFree pins the property.
func (rs *RemoteScanner) Enabled() bool {
	return rs.enabled.Load()
}

// URL returns the configured base URL.
func (rs *RemoteScanner) URL() string {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return rs.baseURL
}

// remoteScanFail records a sidecar FAULT — a condition under which the content
// is forwarded UNSCANNED (fail-open, register row WK-2b).
//
// class is a bounded reason class, cause is the full text. The split is
// load-bearing in both directions:
//
//   - The alert carries only class, because the alert store dedups on
//     "event:detail" within a 30 s window. Passing err.Error() through put a
//     transport error in the key, and those embed the EPHEMERAL LOCAL PORT
//     ("read tcp 127.0.0.1:54012->…: connection reset by peer"), so a sidecar
//     resetting connections produced a distinct key per request. Dedup could
//     not suppress it by construction, and the fan-out landed in the 500-entry
//     retry queue — where a fault in a scanner can evict real threat alerts.
//   - The log carries cause, because that is where an operator needs the
//     actual error, and it is rate-limited: this fires once per proxied
//     response for as long as the sidecar is unwell, and logging every
//     occurrence degrades the node hardest exactly when it is already
//     degraded. The counter carries the magnitude; the line carries the cause.
//     Same count-everything / gate-the-noise discipline as storage_health.go.
//
// The HasSubscriber gate is the contract package main's fireDNSFailureAlert
// documents, applied to the other producer whose rate is set by a fault rather
// than by the operator. In the default posture (no webhooks configured) it
// removes a goroutine, a payload build and a dedup-mutex round trip from every
// response of a node that is already having a bad day.
func remoteScanFail(class, cause string) {
	AddRemoteScanFail()
	if degradedLogAllowed(&lastRemoteFailLog) {
		obs.Warnf("ScanSvc: remote scan failed (%s): %s — forwarding UNSCANNED (fail-open); total %d",
			class, cause, RemoteScanFailTotal())
	}
	if !alerts.HasSubscriber("scan_svc_down") {
		return
	}
	go alerts.Fire("scan_svc_down", alerts.Payload{
		Source: "remote_scan",
		Detail: class,
	})
}

// remoteScanRefused records a fail-CLOSED remote outcome: the sidecar did not
// produce a verdict within the scan budget, or reported itself at capacity.
//
// It deliberately reuses the LOCAL path's vocabulary — Source "timeout",
// statScanTimeout, hence culvert_scan_timeout_total and the request path's
// existing scan_timeout alert — because it is the same decision. "The scan did
// not finish in time" is one condition with one posture, and which of the two
// scanning back ends happens to be deployed must not change it.
func remoteScanRefused(hash string) *Result {
	atomic.AddInt64(&statScanTimeout, 1)
	if degradedLogAllowed(&lastRemoteRefusalLog) {
		obs.Warnf("ScanSvc: remote scan did not complete within %s for hash %s — blocking (fail-closed)",
			scanBodyTimeout(), hash)
	}
	return &Result{Blocked: true, Reason: "scan timeout", Source: "timeout", Hash: hash}
}

var (
	lastRemoteFailLog    atomic.Int64
	lastRemoteRefusalLog atomic.Int64
)

// maxRemoteScanResponse bounds the sidecar's /scan reply. The verdict is a
// handful of short fields; anything larger is a wrong endpoint or a wedged
// service, and neither should be read into the proxy's heap.
const maxRemoteScanResponse = 4096

// ScanBody sends data to the remote scan service and returns the result.
//
// POSTURE — the whole point of this function, and previously the thing it got
// wrong. Three outcomes, not two:
//
//   - VERDICT: the sidecar answered. Blocked → block, clean → forward. The
//     answer must be AFFIRMATIVE; see the Clean check below.
//   - BUDGET or CAPACITY: the scan did not finish in time, or the sidecar
//     reported itself full. Fail CLOSED, exactly as the local path does for the
//     identical condition. This is the inversion CHAOS-53 exists to fix: the
//     deadline was private (30 s, three times the local budget), so exceeding
//     it surfaced as an ordinary transport error, was classified as a sidecar
//     fault, and took the fail-OPEN branch — a security control switched off by
//     SLOWNESS, on healthy infrastructure, with the process's own fail-closed
//     budget never consulted. It is the same defect CHAOS-52 fixed in the local
//     path (WK-15), left standing in the deployment the CHAOS-52 runbook
//     RECOMMENDS as the remedy for it.
//   - FAULT: the sidecar is unreachable, erroring, or unintelligible. Fail
//     OPEN, counted and alerted. This posture is unchanged and remains the
//     recorded owner decision (WK-2b, the sibling of the local path's WK-1b); what
//     changes is that it is now reached
//     only by an actual fault.
func (rs *RemoteScanner) ScanBody(data []byte, contentType string) *Result {
	rs.mu.RLock()
	if !rs.enabled.Load() {
		rs.mu.RUnlock()
		return nil
	}
	baseURL := rs.baseURL
	client := rs.client
	excl := rs.excl
	rs.mu.RUnlock()

	// The hash is computed HERE, from the bytes actually scanned, and is never
	// taken from the reply. The sidecar's Hash field feeds the admin
	// allowlist/cache-evict surfaces, so trusting it would let a compromised or
	// merely buggy sidecar name any object it liked in the operator's UI.
	hash := hashcache.SHA256Hex(data)
	if excl != nil && excl.IsHashExcluded(hash) {
		return nil
	}

	// One budget for both scanning back ends. scanBodyTimeout() is the same
	// value ScanBody's local path uses, so the deadline that decides fail-closed
	// is the deadline that fires.
	ctx, cancel := context.WithTimeout(context.Background(), scanBodyTimeout())
	defer cancel()

	remoteScanInflight.Add(1)
	defer remoteScanInflight.Add(-1)

	result, class, cause := rs.scanOnce(ctx, client, baseURL, data, contentType, hash)
	switch class {
	case remoteOutcomeVerdict:
		return result
	case remoteOutcomeBudget:
		return remoteScanRefused(hash)
	case remoteOutcomeCapacity:
		atomic.AddInt64(&statRemoteScanSaturated, 1)
		return remoteScanRefused(hash)
	default:
		remoteScanFail(class, cause)
		return nil // fail-open (WK-2b)
	}
}

// Bounded outcome classes. Everything except the first two is a FAULT, and the
// string doubles as the alert detail — hence the fixed, low-cardinality set.
const (
	remoteOutcomeVerdict  = "verdict"
	remoteOutcomeBudget   = "budget exceeded"
	remoteOutcomeCapacity = "sidecar at capacity"
	remoteFaultRequest    = "request build error"
	remoteFaultTransport  = "transport error"
	remoteFaultRead       = "response read error"
	remoteFaultParse      = "response parse error"
	remoteFaultNoVerdict  = "no verdict in response"
)

// scanOnce performs the round trip and classifies the outcome. Split out so the
// posture decision above reads as one switch.
func (rs *RemoteScanner) scanOnce(ctx context.Context, client *http.Client, baseURL string, data []byte, contentType, hash string) (*Result, string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/scan", bytes.NewReader(data))
	if err != nil {
		return nil, remoteFaultRequest, err.Error()
	}
	if contentType != "" {
		req.Header.Set("X-Content-Type", contentType)
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := client.Do(req)
	if err != nil {
		if budgetGone(ctx, err) {
			return nil, remoteOutcomeBudget, err.Error()
		}
		return nil, remoteFaultTransport, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusTooManyRequests {
			// The sidecar is telling us it is full. That is capacity, not a
			// fault, and CHAOS-52 settled the posture for capacity: the outer
			// budget decides, and it decides fail-closed. The shipped sidecar
			// never emits 429 today; a load balancer or a third-party scanner
			// in front of it can, and classifying it correctly costs nothing.
			return nil, remoteOutcomeCapacity, "HTTP 429"
		}
		// The status code IS the class here: it is bounded (a few dozen
		// values), stable across requests, and the actionable half of the
		// message — so it can safely be the dedup key, unlike the transport
		// error text it used to be concatenated with.
		return nil, fmt.Sprintf("sidecar returned HTTP %d", resp.StatusCode), resp.Status
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteScanResponse))
	if err != nil {
		if budgetGone(ctx, err) {
			return nil, remoteOutcomeBudget, err.Error()
		}
		return nil, remoteFaultRead, err.Error()
	}

	var sr ScanResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, remoteFaultParse, err.Error()
	}

	if sr.Blocked {
		return &Result{
			Blocked: true,
			Reason:  sr.Reason,
			Source:  sr.Source,
			Hash:    hash,
		}, remoteOutcomeVerdict, ""
	}

	// A verdict must be AFFIRMATIVE. Absence of Blocked used to be read as
	// "clean", so ANY 200 whose body parsed as JSON admitted the content: `{}`,
	// `null`, a health-check envelope, a load balancer's maintenance page that
	// happens to be JSON. Scanning was then off with no counter, no log and no
	// alert — the pure silent-failure case, and the one shape an operator
	// cannot discover from any surface the product exposes. The shipped sidecar
	// sets Clean explicitly (scan_svc.go), so nothing about a correct
	// deployment changes.
	if !sr.Clean {
		return nil, remoteFaultNoVerdict, "sidecar reported neither clean nor blocked"
	}
	return nil, remoteOutcomeVerdict, ""
}

// budgetGone reports whether err is the scan budget expiring rather than a
// fault. Both the context's own error and the wrapped deadline are checked: a
// *url.Error from client.Do wraps context.DeadlineExceeded, while a body read
// cut short by the same deadline surfaces as an i/o error with only the
// context to distinguish it.
func budgetGone(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded)
}

// Health checks the remote scan service liveness.
func (rs *RemoteScanner) Health() error {
	rs.mu.RLock()
	if !rs.enabled.Load() {
		rs.mu.RUnlock()
		return fmt.Errorf("remote scanner not configured")
	}
	baseURL := rs.baseURL
	client := rs.client
	rs.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/health", http.NoBody)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection can be reused; an unread body
	// leaves the connection unusable and makes every admin poll open a new one.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxRemoteStatusResponse))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// Status fetches the remote scanner status (mirrors /api/security-scan/status).
func (rs *RemoteScanner) Status() (map[string]interface{}, error) {
	rs.mu.RLock()
	if !rs.enabled.Load() {
		rs.mu.RUnlock()
		return nil, fmt.Errorf("remote scanner not configured")
	}
	baseURL := rs.baseURL
	client := rs.client
	rs.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/status", http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Bounded: this decoded whatever the far end sent, without limit, into the
	// proxy's heap — on an ADMIN endpoint reachable by any viewer, against a
	// URL an operator can point anywhere (a typo'd port, a wedged sidecar, a
	// service returning a stream). The status map is a few hundred bytes.
	var status map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRemoteStatusResponse)).Decode(&status); err != nil {
		return nil, err
	}
	return status, nil
}

// maxRemoteStatusResponse bounds the /status and /health replies. Generous
// next to the real payload, and finite, which is the property that matters.
const maxRemoteStatusResponse = 64 << 10
