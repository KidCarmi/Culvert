package main

// Phase 2b proxy integration for the Sluice CDR engine.
//
// safeCDRSanitize is the single entry point called from handleTunnelInspect
// AFTER the body has been buffered and magic-byte/polyglot checks have run,
// but BEFORE ClamAV/YARA scanning.  It orchestrates one Sanitize RPC per
// response and returns a cdrRunResult the caller uses to branch:
//
//   - cdrPass   : keep the original bytes, continue down the pipeline
//   - cdrSwap   : replace body with sanitized bytes, continue down the pipeline
//   - cdrBlock  : refuse delivery, caller must return a block page
//
// All Sluice-facing code runs behind a defer-recover so a bug in the client
// or the proto path can never corrupt the response or panic the process —
// on recover we fall back to cdrBlock (fail-closed for panics, always, no
// matter what fail_mode says; never ship "maybe-unsafe" bytes).
//
// What's NOT here (by design — CLAUDE.md "no speculative abstractions"):
//   - Connection pooling / load balancing  (Phase 2c)
//   - Per-instance health gauge             (Phase 2c)
//   - Circuit breaker                       (Phase 2c)
//   - Forensics retention of original bytes (Phase 2c+)

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// ─── Outcome + result shape ─────────────────────────────────────────────────

type cdrOutcome int

const (
	cdrPass  cdrOutcome = iota // caller uses the original body
	cdrSwap                    // caller uses cdrRunResult.Body (sanitized)
	cdrBlock                   // caller returns a block page
)

// cdrRunResult is the stable, transport-agnostic shape handleTunnelInspect
// receives.  Intentionally decoupled from the proto types so the caller
// never imports sluicev1 directly.
type cdrRunResult struct {
	Outcome     cdrOutcome
	Status      string // human-readable: CLEAN | SANITIZED | BLOCKED | ERROR | UNSUPPORTED | SKIPPED | CACHED
	Body        []byte // populated when Outcome == cdrSwap
	BlockReason string // populated when Outcome == cdrBlock
	Threats     []CDRThreat
	ProfileName string
	Mode        string // stringified sluicev1.Mode
	DurationMs  int64
	Cached      bool
}

// Convenience constructors keep the orchestrator branches short.
func cdrPassSkipped(status string) *cdrRunResult {
	return &cdrRunResult{Outcome: cdrPass, Status: status}
}
func cdrPassClean(profile, mode string, threats []CDRThreat, ms int64, cached bool) *cdrRunResult {
	return &cdrRunResult{Outcome: cdrPass, Status: "CLEAN", ProfileName: profile, Mode: mode, Threats: threats, DurationMs: ms, Cached: cached}
}
func cdrPassUnsupported(profile, mode string, ms int64, cached bool) *cdrRunResult {
	return &cdrRunResult{Outcome: cdrPass, Status: "UNSUPPORTED", ProfileName: profile, Mode: mode, DurationMs: ms, Cached: cached}
}
func cdrSwapResult(body []byte, threats []CDRThreat, profile, mode string, ms int64) *cdrRunResult {
	return &cdrRunResult{Outcome: cdrSwap, Status: "SANITIZED", Body: body, Threats: threats, ProfileName: profile, Mode: mode, DurationMs: ms}
}
func cdrBlockResult(reason string, threats []CDRThreat, profile, mode string, ms int64, cached bool) *cdrRunResult {
	return &cdrRunResult{Outcome: cdrBlock, Status: "BLOCKED", BlockReason: reason, Threats: threats, ProfileName: profile, Mode: mode, DurationMs: ms, Cached: cached}
}

// ─── Hash cache ────────────────────────────────────────────────────────────

// cdrCacheEntry stores a decision that can be reused for identical content.
// SANITIZED results are deliberately NOT cached — the sanitized bytes are
// too large to keep in RAM and caching only the verdict would force us to
// re-call Sluice anyway (no win).  See design doc for the full rationale.
type cdrCacheEntry struct {
	status      string // CLEAN | UNSUPPORTED | BLOCKED
	blockReason string
	threats     []CDRThreat
	profile     string
	mode        string
	expiresAt   time.Time

	// epoch taken from cdrPolicyStore.Epoch() at write time.  Reads compare
	// to the current epoch; stale entries are treated as miss — this auto-
	// invalidates the cache when any policy mutation occurs, without a
	// thundering-herd Clear() after an admin edit.
	epoch int64
}

type cdrHashCache struct {
	mu      sync.Mutex
	entries map[string]*cdrCacheEntry
	maxSize int
	ttl     time.Duration
	hits    atomic.Int64
	misses  atomic.Int64
}

// cdrCache is the package-wide hash cache.  Bounded to 10_000 entries with a
// 1 hour TTL — tuning knobs land in Phase 2c alongside the admin GUI.
var cdrCache = newCDRHashCache(10_000, time.Hour)

func newCDRHashCache(maxSize int, ttl time.Duration) *cdrHashCache {
	return &cdrHashCache{
		entries: make(map[string]*cdrCacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// Get returns the cached entry for `hash` if present, not expired, and not
// epoch-stale.  All three checks must pass for a cache hit.
func (c *cdrHashCache) Get(hash string, currentEpoch int64) (*cdrCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[hash]
	if !ok {
		c.misses.Add(1)
		return nil, false
	}
	if time.Now().After(e.expiresAt) || e.epoch != currentEpoch {
		delete(c.entries, hash)
		c.misses.Add(1)
		return nil, false
	}
	c.hits.Add(1)
	return e, true
}

// Put inserts / replaces an entry.  On capacity overflow, evicts ~25% of
// the oldest entries (by expiry) to avoid per-entry LRU bookkeeping.
func (c *cdrHashCache) Put(hash string, entry *cdrCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxSize {
		c.evictSomeLocked()
	}
	c.entries[hash] = entry
}

// evictSomeLocked drops the earliest-expiring 25% of entries.  Must be
// called under c.mu.
func (c *cdrHashCache) evictSomeLocked() {
	target := len(c.entries) / 4
	if target < 1 {
		target = 1
	}
	// Cheapest correctness: iterate and drop first `target` found.
	// Entries have TTL so ordering imperfection only wastes a handful of slots.
	i := 0
	for k := range c.entries {
		if i >= target {
			break
		}
		delete(c.entries, k)
		i++
	}
}

// Stats returns (hits, misses, size).  Used by metrics exposition.
func (c *cdrHashCache) Stats() (hits, misses int64, size int) {
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	return c.hits.Load(), c.misses.Load(), n
}

// ─── Orchestrator ──────────────────────────────────────────────────────────

// safeCDRSanitize runs one Sanitize RPC and classifies the result.  It
// NEVER panics: a deferred recover converts any panic into a fail-closed
// cdrBlock outcome regardless of the configured fail_mode.  The caller is
// expected to treat cdrBlock as authoritative and refuse the response.
func safeCDRSanitize(ctx context.Context, req cdrRequestContext, body []byte, ct string, id ProxyIdentity, cfg CDRConfig) (out *cdrRunResult) {
	defer func() {
		if r := recover(); r != nil {
			atomic.AddInt64(&statCDRPanics, 1)
			logger.Printf("CDR: PANIC recovered: %v (request_id=%s)", r, sanitizeLog(req.RequestID))
			out = cdrBlockResult("cdr_panic", nil, "", "", 0, false)
		}
	}()

	// Gate + pool pick.  Pool picker returns nil when every instance's
	// circuit breaker is open OR no clients are enrolled.  Either way
	// we skip CDR for this request — the caller's fail_mode then
	// decides whether to still deliver the file.
	if !cfg.Enabled {
		return cdrPassSkipped("SKIPPED")
	}
	pooled := cdrPickPooled()
	if pooled == nil {
		return cdrPassSkipped("SKIPPED")
	}
	client := pooled.Client
	instanceName := pooled.Name

	// Oversize skip before any Sluice contact.  Uses min(cfg cap,
	// profile cap) so Culvert enforces the tighter of the two —
	// defence-in-depth against a file Sluice would reject anyway.
	if skipped := cdrGateOversize(body, cfg, pooled.ProfileCap(), req.Host); skipped != nil {
		return skipped
	}

	// Policy decision + cache lookup.  Cache hit short-circuits the RPC.
	decision := cdrPolicyStore.Evaluate(id.ClientIP, id.Identity, id.AuthSource, req.Host, id.Groups, cfg)
	profile := decision.ProfileName
	modeStr := decision.Mode.String()
	sum := sha256.Sum256(body)
	hashHex := hex.EncodeToString(sum[:])
	epoch := cdrPolicyStore.Epoch()
	if hit := cdrCacheLookup(hashHex, epoch); hit != nil {
		return hit
	}

	// One RPC call + outcome classification.
	header := cdrBuildHeader(req, ct, body, profile, decision.Mode)
	callCtx, cancel := cdrCallContext(ctx, cfg)
	if cancel != nil {
		defer cancel()
	}
	t0 := time.Now()
	res, err := client.Sanitize(callCtx, header, cdrBodyReader(body))
	ms := time.Since(t0).Milliseconds()
	if err != nil {
		if !IsFileTooLarge(err) {
			cdrMarkOutcome(instanceName, true)
		}
		return cdrHandleCallError(err, profile, modeStr, ms, cfg)
	}
	return cdrClassifyResult(res, instanceName, profile, modeStr, ms, hashHex, epoch, cfg)
}

// cdrGateOversize returns SKIPPED_OVERSIZE when body is over the
// effective per-file cap.  The effective cap is
// `min(cfg.maxFileSizeBytes(), profileCap)` when profileCap > 0, else
// just the config cap.  This protects against sending a file that
// Sluice would reject anyway — saves the round-trip.  Nil when the
// request can proceed.
func cdrGateOversize(body []byte, cfg CDRConfig, profileCap int64, host string) *cdrRunResult {
	effective := cfg.maxFileSizeBytes()
	if profileCap > 0 && profileCap < effective {
		effective = profileCap
	}
	if int64(len(body)) <= effective {
		return nil
	}
	atomic.AddInt64(&statCDROversizeSkipped, 1)
	logger.Printf("CDR: skip oversize %d > %d (host=%q)", len(body), effective, sanitizeLog(host))
	return cdrPassSkipped("SKIPPED_OVERSIZE")
}

// cdrCacheLookup translates a hash-cache hit into a cdrRunResult, or
// returns nil on miss (and increments the miss counter).
func cdrCacheLookup(hashHex string, epoch int64) *cdrRunResult {
	e, ok := cdrCache.Get(hashHex, epoch)
	if !ok {
		atomic.AddInt64(&statCDRCacheMisses, 1)
		return nil
	}
	atomic.AddInt64(&statCDRCacheHits, 1)
	switch e.status {
	case "CLEAN":
		return cdrPassClean(e.profile, e.mode, e.threats, 0, true)
	case "UNSUPPORTED":
		return cdrPassUnsupported(e.profile, e.mode, 0, true)
	case "BLOCKED":
		return cdrBlockResult(e.blockReason, e.threats, e.profile, e.mode, 0, true)
	}
	// Unknown cached status (shouldn't happen — only the three above are
	// ever inserted).  Treat as miss.
	return nil
}

// cdrBuildHeader constructs the SanitizeHeader with Culvert's tags +
// policy-version propagation rules.
func cdrBuildHeader(req cdrRequestContext, ct string, body []byte, profile string, mode pb.Mode) *pb.SanitizeHeader {
	return &pb.SanitizeHeader{
		Filename:      cdrFilenameFromURL(req.URL),
		ContentType:   ct,
		ContentLength: int64(len(body)),
		RequestId:     req.RequestID,
		TraceParent:   req.TraceParent,
		ProfileName:   profile,
		Mode:          mode,
		Tags:          map[string]string{"direction": "download"},
		PolicyVersion: cdrPolicyVersionString(),
	}
}

// cdrCallContext derives the per-call deadline.  Returns the derived
// context and an optional cancel fn the caller must defer.
func cdrCallContext(ctx context.Context, cfg CDRConfig) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, nil
	}
	timeout := 35 * time.Second
	if cfg.TimeoutSec > 0 {
		timeout = time.Duration(cfg.TimeoutSec) * time.Second
	}
	return context.WithTimeout(ctx, timeout)
}

// cdrClassifyResult turns a successful Sluice response into the
// appropriate cdrRunResult, marks the CB, and caches the decision
// where safe.  Split out of safeCDRSanitize to keep that function's
// cyclomatic under the linter threshold.
func cdrClassifyResult(res *cdrRunSanitizeResult, instance, profile, mode string, ms int64, hashHex string, epoch int64, cfg CDRConfig) *cdrRunResult {
	switch res.Status {
	case pb.Status_CLEAN:
		cdrMarkOutcome(instance, false)
		cdrCache.Put(hashHex, &cdrCacheEntry{
			status: "CLEAN", profile: profile, mode: mode,
			expiresAt: time.Now().Add(cdrCache.ttl), epoch: epoch,
		})
		return cdrPassClean(profile, mode, nil, ms, false)
	case pb.Status_SANITIZED:
		cdrMarkOutcome(instance, false)
		return cdrSwapResult(res.SanitizedData, res.Threats, profile, mode, ms)
	case pb.Status_BLOCKED:
		cdrMarkOutcome(instance, false)
		reason := res.ErrorMessage
		if reason == "" {
			reason = "cdr_blocked"
		}
		cdrCache.Put(hashHex, &cdrCacheEntry{
			status: "BLOCKED", blockReason: reason, threats: res.Threats,
			profile: profile, mode: mode,
			expiresAt: time.Now().Add(cdrCache.ttl), epoch: epoch,
		})
		return cdrBlockResult(reason, res.Threats, profile, mode, ms, false)
	case pb.Status_UNSUPPORTED:
		cdrMarkOutcome(instance, false)
		cdrCache.Put(hashHex, &cdrCacheEntry{
			status: "UNSUPPORTED", profile: profile, mode: mode,
			expiresAt: time.Now().Add(cdrCache.ttl), epoch: epoch,
		})
		return cdrPassUnsupported(profile, mode, ms, false)
	case pb.Status_ERROR:
		cdrMarkOutcome(instance, true)
		return cdrErrorOutcome(res.ErrorMessage, profile, mode, ms, cfg)
	}
	// Unknown status — defensive.  Treat like ERROR.
	cdrMarkOutcome(instance, true)
	return cdrErrorOutcome(fmt.Sprintf("unknown_status_%d", res.Status), profile, mode, ms, cfg)
}

// cdrRunSanitizeResult is a type alias so cdrClassifyResult can take the
// Sluice result without importing the generated proto directly at every
// call site.  The underlying type is CDRResult from cdr.go.
type cdrRunSanitizeResult = CDRResult

// cdrStageDecision is the narrow interface handleTunnelInspect sees.
// Pulled out of cdr_proxy.go into a compact struct so the proxy hot
// path reads as "call runCDRStage → either break or update body".
type cdrStageDecision struct {
	blocked  bool
	body     []byte // original or sanitized bytes for downstream scanners
	scanBody []byte // decompressed-for-scan view
}

// runCDRStage is the proxy-side orchestration of one CDR decision.
// Keeps handleTunnelInspect slim (stays under the existing gocognit
// budget) while still driving:
//   - the safeCDRSanitize call
//   - metric counters
//   - audit record
//   - block-page write on BLOCKED
//   - body/scanBody swap on SANITIZED
//
// Callers treat `blocked=true` as "break out of the keep-alive loop".
// The underlying connection is closed by the caller, not by us, so
// we DON'T write the block page here except through scanBlockConn —
// same contract as ClamAV/YARA's scanBlockConn integration.
//
//nolint:gocognit // orchestration splits poorly; already extracted from handleTunnelInspect
func runCDRStage(r *http.Request, req *http.Request, body, scanBody []byte, ct, ce string,
	clientTLS net.Conn, hostOnly, clientIP string, id ProxyIdentity) cdrStageDecision {
	if cdrActiveClient() == nil {
		return cdrStageDecision{body: body, scanBody: scanBody}
	}
	res := safeCDRSanitize(r.Context(), cdrRequestContext{
		Host:        hostOnly,
		URL:         req.URL.Path,
		RequestID:   req.Header.Get("X-Request-ID"),
		TraceParent: req.Header.Get("Traceparent"),
	}, body, ct, id, cdrActiveConfig())
	recordCDRTerminal(res.Status)
	recordThreatDetections(res.Threats)

	switch res.Outcome {
	case cdrBlock:
		atomic.AddInt64(&statBlocked, 1)
		recordRequest(clientIP, "CONNECT", hostOnly, "CDR_BLOCKED", res.ProfileName, res.BlockReason, id.Identity, "inspect")
		logger.Printf("CDR_BLOCKED %s -> %q reason=%q profile=%q mode=%q threats=%q",
			clientIP, sanitizeLog(hostOnly),
			sanitizeLog(res.BlockReason), sanitizeLog(res.ProfileName),
			sanitizeLog(res.Mode), sanitizeLog(cdrSummariseThreats(res.Threats)))
		scanBlockConn(clientTLS, hostOnly, res.BlockReason, "cdr")
		return cdrStageDecision{blocked: true}
	case cdrSwap:
		atomic.AddInt64(&statCDRBytesOut, int64(len(res.Body)))
		newBody := res.Body
		newScan := decompressForScan(newBody, ce)
		recordRequest(clientIP, "CONNECT", hostOnly, "CDR_SANITIZED", res.ProfileName, cdrSummariseThreats(res.Threats), id.Identity, "inspect")
		logger.Printf("CDR_SANITIZED %s -> %q profile=%q mode=%q threats=%q duration_ms=%d",
			clientIP, sanitizeLog(hostOnly), sanitizeLog(res.ProfileName),
			sanitizeLog(res.Mode), sanitizeLog(cdrSummariseThreats(res.Threats)),
			res.DurationMs)
		return cdrStageDecision{body: newBody, scanBody: newScan}
	case cdrPass:
		if res.Status == "ERROR" {
			recordRequest(clientIP, "CONNECT", hostOnly, "CDR_ERROR", res.ProfileName, res.BlockReason, id.Identity, "inspect")
			logger.Printf("CDR_ERROR %s -> %q (fail-open) reason=%q",
				clientIP, sanitizeLog(hostOnly), sanitizeLog(res.BlockReason))
		}
		return cdrStageDecision{body: body, scanBody: scanBody}
	}
	return cdrStageDecision{body: body, scanBody: scanBody}
}

// cdrHandleCallError maps a Sanitize() transport error to an outcome.
//   - file_too_large application errors: NOT a fail-mode event; pass through
//     with a log, since the file is too big for Sluice but the client
//     deserves to see it (same behaviour as any other scan being skipped).
//   - everything else (Unavailable / DeadlineExceeded / Internal / etc.):
//     routed through cdrErrorOutcome which applies fail_mode.
func cdrHandleCallError(err error, profile, mode string, ms int64, cfg CDRConfig) *cdrRunResult {
	if IsFileTooLarge(err) {
		atomic.AddInt64(&statCDROversizeSkipped, 1)
		logger.Printf("CDR: sluice rejected oversize — %v", err)
		return cdrPassSkipped("SKIPPED_OVERSIZE")
	}
	logger.Printf("CDR: call error: %v", err)
	go fireAlert("cdr_unavailable", AlertPayload{
		Source: "cdr",
		Detail: fmt.Sprintf("sluice call failed: %v", err),
	})
	return cdrErrorOutcome(err.Error(), profile, mode, ms, cfg)
}

// cdrErrorOutcome applies the configured fail_mode to an error event.
func cdrErrorOutcome(reason, profile, mode string, ms int64, cfg CDRConfig) *cdrRunResult {
	atomic.AddInt64(&statCDRErrors, 1)
	if cfg.CDRFailOpen() {
		atomic.AddInt64(&statCDRFailOpen, 1)
		return &cdrRunResult{
			Outcome:    cdrPass,
			Status:     "ERROR",
			ProfileName: profile,
			Mode:        mode,
			BlockReason: reason, // surfaced for the audit event only
			DurationMs:  ms,
		}
	}
	atomic.AddInt64(&statCDRFailClosed, 1)
	return cdrBlockResult(reason, nil, profile, mode, ms, false)
}

// cdrBodyReader wraps body bytes in an io.Reader — kept as a helper so
// tests can inject a fault-injecting reader without touching safeCDRSanitize.
func cdrBodyReader(body []byte) *cdrByteReader { return &cdrByteReader{buf: body} }

type cdrByteReader struct {
	buf []byte
	pos int
}

func (r *cdrByteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.buf) {
		return 0, io.EOF
	}
	n := copy(p, r.buf[r.pos:])
	r.pos += n
	return n, nil
}

// ─── Support types + helpers ──────────────────────────────────────────────

// ProxyIdentity is the authenticated context passed from the top-level
// proxy handler down into CDR.  Kept minimal to avoid speculative coupling;
// additional fields can be added as Phase 2c wires more context.
type ProxyIdentity struct {
	ClientIP   string
	Identity   string
	AuthSource string
	Groups     []string
}

// cdrRequestContext carries the per-request metadata CDR needs without
// pulling an *http.Request into this file (keeps test surface small).
type cdrRequestContext struct {
	Host        string // hostname (no port) for policy matching
	URL         string // full path + query for filename extraction
	RequestID   string // from X-Request-ID header
	TraceParent string // from Traceparent header (W3C)
}

// cdrFilenameFromURL extracts a best-effort filename from the URL path,
// used as the hint Sluice feeds its magic-byte detector.  Returns "" when
// no meaningful filename is present.
func cdrFilenameFromURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	// Quick strip of query + fragment without a full url.Parse — this runs
	// on every CDR call and must be cheap.  Fall back to url.Parse only
	// when the quick path produces something odd.
	p := rawURL
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if strings.Contains(p, "%") {
		if u, err := url.Parse(rawURL); err == nil {
			p = u.Path
		}
	}
	return path.Base(p)
}

// cdrPolicyVersionString returns the log-only policy version identifier
// ("<version>@<updated>") the wire contract treats as an opaque token.
func cdrPolicyVersionString() string {
	v, updated := cdrPolicyStore.Version()
	return fmt.Sprintf("cdr-v%d@%s", v, updated)
}

// cdrSummariseThreats produces a compact human-readable list of threat
// types for audit logs, capped to avoid explosion.
func cdrSummariseThreats(threats []CDRThreat) string {
	if len(threats) == 0 {
		return ""
	}
	const maxListed = 8
	parts := make([]string, 0, len(threats))
	for i, t := range threats {
		if i >= maxListed {
			parts = append(parts, fmt.Sprintf("+%d_more", len(threats)-maxListed))
			break
		}
		parts = append(parts, t.Type)
	}
	return strings.Join(parts, ",")
}

// maxFileSizeBytes returns the effective per-file cap (bytes), honouring
// the YAML override with a sensible default of 50 MiB.
func (c CDRConfig) maxFileSizeBytes() int64 {
	if c.MaxFileSizeMB > 0 {
		return int64(c.MaxFileSizeMB) << 20
	}
	return 50 << 20
}
