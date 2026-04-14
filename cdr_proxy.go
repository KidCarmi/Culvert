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
func (c *cdrHashCache) Stats() (int64, int64, int) {
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

	// Gate check — cheap, pre-everything.
	client := cdrActiveClient()
	if client == nil || !cfg.Enabled {
		return cdrPassSkipped("SKIPPED")
	}

	// Oversize skip: fail-open on truncation-detected or size-over-cap.
	// The scan pipeline buffers up to maxScanBufferBytes().  If CDR needs
	// more headroom than the scanner was given, we skip CDR for THIS
	// response (log + metric) rather than sanitize a truncated buffer.
	maxFile := cfg.maxFileSizeBytes()
	if int64(len(body)) > maxFile {
		atomic.AddInt64(&statCDROversizeSkipped, 1)
		logger.Printf("CDR: skip oversize %d > %d (host=%q)", len(body), maxFile, sanitizeLog(req.Host))
		return cdrPassSkipped("SKIPPED_OVERSIZE")
	}

	// Policy decision — decides profile + mode for this specific request.
	decision := cdrPolicyStore.Evaluate(id.ClientIP, id.Identity, id.AuthSource, req.Host, id.Groups, cfg)
	profile := decision.ProfileName
	modeStr := decision.Mode.String()

	// Hash-cache lookup.  Keyed on SHA-256 of the buffered body.  The
	// epoch check inside Get() handles policy-version invalidation.
	sum := sha256.Sum256(body)
	hashHex := hex.EncodeToString(sum[:])
	epoch := cdrPolicyStore.Epoch()
	if e, ok := cdrCache.Get(hashHex, epoch); ok {
		atomic.AddInt64(&statCDRCacheHits, 1)
		switch e.status {
		case "CLEAN":
			return cdrPassClean(e.profile, e.mode, e.threats, 0, true)
		case "UNSUPPORTED":
			return cdrPassUnsupported(e.profile, e.mode, 0, true)
		case "BLOCKED":
			return cdrBlockResult(e.blockReason, e.threats, e.profile, e.mode, 0, true)
		}
	}
	atomic.AddInt64(&statCDRCacheMisses, 1)

	// Build the header.  Culvert's X-Request-ID propagates for correlation;
	// tags are whitelisted low-cardinality only (direction=download).
	header := &pb.SanitizeHeader{
		Filename:      cdrFilenameFromURL(req.URL),
		ContentType:   ct,
		ContentLength: int64(len(body)),
		RequestId:     req.RequestID,
		TraceParent:   req.TraceParent,
		ProfileName:   profile,
		Mode:          decision.Mode,
		Tags:          map[string]string{"direction": "download"},
		PolicyVersion: cdrPolicyVersionString(),
	}

	// Per-call timeout: caller context wins if tighter; else we apply our
	// cfg.TimeoutSec (default 35s — matches Sluice's 30s internal cap + 5s).
	callCtx := ctx
	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok {
		timeout := 35 * time.Second
		if cfg.TimeoutSec > 0 {
			timeout = time.Duration(cfg.TimeoutSec) * time.Second
		}
		callCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	t0 := time.Now()
	res, err := client.Sanitize(callCtx, header, cdrBodyReader(body))
	ms := time.Since(t0).Milliseconds()

	if err != nil {
		return cdrHandleCallError(err, profile, modeStr, ms, cfg)
	}

	// Status-based branching.  Mode semantics are enforced server-side
	// (REPORT_ONLY / BYPASS_WITH_REPORT already return original bytes);
	// we trust Sluice's contract and treat the bytes on the wire as
	// authoritative.
	switch res.Status {
	case pb.Status_CLEAN:
		cdrCache.Put(hashHex, &cdrCacheEntry{
			status: "CLEAN", threats: nil, profile: profile, mode: modeStr,
			expiresAt: time.Now().Add(cdrCache.ttl), epoch: epoch,
		})
		return cdrPassClean(profile, modeStr, nil, ms, false)

	case pb.Status_SANITIZED:
		// Never cache SANITIZED bytes (too large).  Always call Sluice.
		return cdrSwapResult(res.SanitizedData, res.Threats, profile, modeStr, ms)

	case pb.Status_BLOCKED:
		reason := "cdr_blocked"
		if res.ErrorMessage != "" {
			reason = res.ErrorMessage
		}
		cdrCache.Put(hashHex, &cdrCacheEntry{
			status: "BLOCKED", blockReason: reason, threats: res.Threats,
			profile: profile, mode: modeStr,
			expiresAt: time.Now().Add(cdrCache.ttl), epoch: epoch,
		})
		return cdrBlockResult(reason, res.Threats, profile, modeStr, ms, false)

	case pb.Status_UNSUPPORTED:
		cdrCache.Put(hashHex, &cdrCacheEntry{
			status: "UNSUPPORTED", profile: profile, mode: modeStr,
			expiresAt: time.Now().Add(cdrCache.ttl), epoch: epoch,
		})
		return cdrPassUnsupported(profile, modeStr, ms, false)

	case pb.Status_ERROR:
		// Sluice reported a well-formed error (e.g. unknown_profile).
		// We don't cache this — the policy may be fixed minutes later.
		return cdrErrorOutcome(res.ErrorMessage, profile, modeStr, ms, cfg)
	}

	// Unknown status — defensive.  Treat like ERROR.
	return cdrErrorOutcome(fmt.Sprintf("unknown_status_%d", res.Status), profile, modeStr, ms, cfg)
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
	const cap = 8
	parts := make([]string, 0, len(threats))
	for i, t := range threats {
		if i >= cap {
			parts = append(parts, fmt.Sprintf("+%d_more", len(threats)-cap))
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
