// Release Catalog Distribution — P1.5 Slice c (HTTP CatalogProvider).
//
// HTTPCatalogProvider is a TRANSPORT that stages a catalog candidate
// (index.json + index.json.sig + referenced manifests) from an HTTP(S) origin
// into a fresh temp dir, which the caller then hands to LoadVerifiedCatalog (the
// P1.3 trust boundary) exactly like a local-dir source.
//
// The §5.1 contract is the heart of this slice: because manifests cannot be
// fetched without first reading their refs out of the index, the provider runs
// a TWO-PHASE verify — it verifies the index signature over the RAW index bytes
// BEFORE parsing the index to enumerate manifest fetches. A forged/unsigned
// index (in enforce mode) therefore triggers ZERO manifest requests. The final
// LoadVerifiedCatalog over the staged dir re-verifies everything (defense in
// depth, incl. the manifest_sha256 hash check that authenticates each fetched
// manifest).
//
// Scope (roadmap/D1.6d-P1.5-catalog-distribution-plan.md — Slice c): the HTTP
// transport + two-phase verify + staging + cleanup + timeout + minimal
// retry/backoff + conditional (ETag/If-Modified-Since) fetch. NO GUI, NO
// dispatch, NO agent changes, NO air-gap bundle, NO CP→DP propagation. The
// provider is transport-only apart from the §5.1 index-verify gate.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"
)

// errCatalogUnchanged is returned by Stage when the origin reports the index is
// unchanged (HTTP 304 to a conditional request) — the caller keeps the current
// catalog and does no further work.
var errCatalogUnchanged = errors.New("release catalog: unchanged (304)")

const httpCatalogDefaultTimeout = 30 * time.Second

// HTTPCatalogProvider fetches and stages a catalog candidate from an HTTP(S)
// base URL. It is constructed once and may be reused; ETag/Last-Modified state
// is retained between Stage calls for conditional fetches.
type HTTPCatalogProvider struct {
	base     *url.URL
	client   *http.Client
	trust    TrustStore
	maxBytes int64

	// guard is the SSRF check applied to the host before every dial (plan §4).
	// Production wires isPrivateHost; tests set it to nil to allow loopback.
	guard func(hostport string) error

	// minimal retry/backoff hooks (default: no retry).
	retries int
	backoff func(attempt int) time.Duration

	// stageBase is the parent dir for the temp staging dir ("" ⇒ os.TempDir()).
	stageBase string

	mu           sync.Mutex
	lastETag     string
	lastModified string
}

// NewHTTPCatalogProvider builds a provider for baseURL (http or https). trust is
// used for the §5.1 Phase-1 index-signature gate.
func NewHTTPCatalogProvider(baseURL string, trust TrustStore) (*HTTPCatalogProvider, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("release catalog: parse base URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("release catalog: base URL scheme %q must be http or https", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("release catalog: base URL has no host")
	}
	p := &HTTPCatalogProvider{
		base:     u,
		trust:    trust,
		maxBytes: catalogMaxReadBytes,
		guard:    isPrivateHost, // defense-in-depth SSRF guard (dial-time + redirects)
	}
	// The SSRF guard is enforced at DIAL time (on the actually-resolved address,
	// closing the DNS-rebind gap) and on every redirect hop — not as a racy
	// preflight host check. p.guard==nil (tests) makes both no-ops for loopback.
	p.client = &http.Client{
		Timeout:       httpCatalogDefaultTimeout,
		CheckRedirect: p.checkRedirect,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           p.safeDialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}
	return p, nil
}

// safeDialContext resolves the host and dials a PUBLIC resolved IP directly, so
// the address checked is the address dialed (no TOCTOU / DNS-rebind window). It
// rejects any private/internal address. With p.guard==nil it dials normally
// (tests/loopback).
func (p *HTTPCatalogProvider) safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if p.guard == nil {
		return dialer.DialContext(ctx, network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("release catalog: resolve %s: %w", host, err)
	}
	var lastErr error
	for i := range ips {
		ip := ips[i].IP
		if isPrivateIP(ip) {
			lastErr = fmt.Errorf("release catalog: SSRF: %s resolves to private address %s", host, ip)
			continue
		}
		conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("release catalog: no public address for %s", host)
	}
	return nil, lastErr
}

// checkRedirect re-applies the SSRF guard to each redirect target host (the
// redirected dial is ALSO guarded by safeDialContext) and caps the hop count.
func (p *HTTPCatalogProvider) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("release catalog: too many redirects")
	}
	if p.guard != nil {
		if err := p.guard(req.URL.Host); err != nil {
			return fmt.Errorf("release catalog: SSRF guard (redirect to %s): %w", req.URL.Host, err)
		}
	}
	return nil
}

// SetStageBase sets the parent directory for the temp staging dir. Callers that
// will atomically rename the staged dir into place MUST point this at the SAME
// filesystem as the destination (e.g. the data dir), otherwise os.Rename fails
// with EXDEV. "" keeps the default (os.TempDir()). Must be called before Stage.
func (p *HTTPCatalogProvider) SetStageBase(dir string) { p.stageBase = dir }

// SetRetry configures the minimal retry/backoff hook. retries is the number of
// EXTRA attempts after the first on a transport error; backoff(attempt) is the
// delay before attempt N (>=1). Either zero disables retry.
func (p *HTTPCatalogProvider) SetRetry(retries int, backoff func(attempt int) time.Duration) {
	p.retries = retries
	p.backoff = backoff
}

// Stage fetches and stages a catalog candidate into a fresh temp dir and returns
// its path. The CALLER owns the returned dir and must remove it after handing it
// to LoadVerifiedCatalog. On ANY failure the staging dir is removed before
// return (atomic cleanup) and a non-nil error is returned; errCatalogUnchanged
// is returned (with no dir) when the origin reports a 304.
func (p *HTTPCatalogProvider) Stage(ctx context.Context) (stagingDir string, err error) {
	stage, err := os.MkdirTemp(p.stageBase, "catalog-http-stage-*")
	if err != nil {
		return "", err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(stage)
		}
	}()

	// ── Phase 1: fetch + VERIFY the index before trusting its contents (§5.1) ──
	idxBytes, etag, lastMod, notModified, err := p.fetchIndex(ctx)
	if err != nil {
		return "", err
	}
	if notModified {
		return "", errCatalogUnchanged
	}
	// Fetch each scheme's sidecar ONLY when that scheme is configured, so neither
	// sidecar's absence/error can block the OTHER scheme. A 403/500 on .sig at an
	// origin that uses non-404 for absent objects must NOT reject a keyless-only
	// catalog, and vice-versa. Each present sidecar then participates in
	// verifyIndexSignature's scheme selection exactly like the local-dir source —
	// a present-but-invalid artifact rejects (no downgrade).
	sigBytes, sigMissing, err := p.fetchSignatureIfConfigured(ctx)
	if err != nil {
		return "", err
	}
	bundleBytes, bundleMissing, err := p.fetchSigstoreBundleIfConfigured(ctx)
	if err != nil {
		return "", err
	}
	src := bytesSignatureSource{
		sig: sigBytes, missing: sigMissing,
		bundle: bundleBytes, bundleMissing: bundleMissing,
	}
	if err := verifyIndexSignature(idxBytes, src, p.trust); err != nil {
		// Forged/unsigned (enforce) index ⇒ reject here, having fetched NO manifests.
		return "", err
	}

	// ── Phase 2: index is trusted — enumerate + fetch manifests into staging ──
	if err := p.stageVerified(ctx, stage, idxBytes, src); err != nil {
		return "", err
	}

	p.storeValidators(etag, lastMod)
	committed = true
	return stage, nil
}

// stageVerified writes the (already-verified) index + sidecars and fetches each
// referenced manifest into the staging dir. The index is parsed here ONLY after
// its signature was checked in Phase 1 (§5.1). Both sidecars (.sig and .sigstore)
// are persisted so a subsequent LoadVerifiedCatalog over the staged dir re-verifies
// under the SAME scheme that accepted it here (no scheme drift between fetch and
// re-verify).
func (p *HTTPCatalogProvider) stageVerified(ctx context.Context, stage string, idxBytes []byte, src bytesSignatureSource) error {
	var idx catalogIndexFile
	if err := json.Unmarshal(idxBytes, &idx); err != nil {
		return fmt.Errorf("release catalog: parse verified index: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(stage, "manifests"), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(stage, "index.json"), idxBytes, 0o600); err != nil {
		return err
	}
	if !src.missing {
		if err := os.WriteFile(filepath.Join(stage, "index.json.sig"), src.sig, 0o600); err != nil {
			return err
		}
	}
	if !src.bundleMissing {
		if err := os.WriteFile(filepath.Join(stage, "index.json.sigstore"), src.bundle, 0o600); err != nil {
			return err
		}
	}
	for i := range idx.Releases {
		ref := idx.Releases[i].ManifestRef
		if err := catalogValidateManifestRef(ref); err != nil {
			return err // bare-name/traversal gate (P1.2 §4.5) before any fetch/write
		}
		manBytes, err := p.fetch(ctx, path.Join("manifests", ref))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(stage, "manifests", ref), manBytes, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// ─── fetch helpers ───────────────────────────────────────────────────────────

// fetchIndex does a conditional GET of index.json (If-None-Match /
// If-Modified-Since from the retained validators). It returns the body + the new
// validators, or notModified when the origin answers 304.
func (p *HTTPCatalogProvider) fetchIndex(ctx context.Context) (body []byte, etag, lastMod string, notModified bool, err error) {
	p.mu.Lock()
	inm, ims := p.lastETag, p.lastModified
	p.mu.Unlock()

	resp, err := p.doGet(ctx, "index.json", func(req *http.Request) {
		if inm != "" {
			req.Header.Set("If-None-Match", inm)
		}
		if ims != "" {
			req.Header.Set("If-Modified-Since", ims)
		}
	})
	if err != nil {
		return nil, "", "", false, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, "", "", true, nil
	case http.StatusOK:
		b, rerr := readAllBounded(resp.Body, p.maxBytes)
		if rerr != nil {
			return nil, "", "", false, fmt.Errorf("release catalog: read index: %w", rerr)
		}
		return b, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"), false, nil
	default:
		return nil, "", "", false, fmt.Errorf("release catalog: index HTTP %d", resp.StatusCode)
	}
}

// fetchSignatureIfConfigured GETs index.json.sig, but ONLY when the ed25519 scheme
// is configured (the trust ring is non-empty). When it is not (e.g. a Sigstore-only
// store), no request is made and the sidecar is reported missing — verifyIndexSignature
// skips the ed25519 branch in that case, so the value is inert and an ed25519-sidecar
// fetch error can never block a keyless catalog.
func (p *HTTPCatalogProvider) fetchSignatureIfConfigured(ctx context.Context) (sig []byte, missing bool, err error) {
	if len(p.trust.keys) == 0 {
		return nil, true, nil
	}
	return p.fetchSignature(ctx)
}

// fetchSignature GETs index.json.sig; a 404 yields missing=true (unsigned —
// handled per mode by verifyIndexSignature).
func (p *HTTPCatalogProvider) fetchSignature(ctx context.Context) (sig []byte, missing bool, err error) {
	resp, err := p.doGet(ctx, "index.json.sig", nil)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil, true, nil
	case http.StatusOK:
		b, rerr := readAllBounded(resp.Body, p.maxBytes)
		if rerr != nil {
			return nil, false, fmt.Errorf("release catalog: read signature: %w", rerr)
		}
		return b, false, nil
	default:
		return nil, false, fmt.Errorf("release catalog: signature HTTP %d", resp.StatusCode)
	}
}

// fetchSigstoreBundleIfConfigured GETs index.json.sigstore, but ONLY when the
// Sigstore scheme is configured (trust carries a verifier). When it is not, no
// request is made and the sidecar is reported missing — verifyIndexSignature skips
// the Sigstore branch entirely in that case, so the value is inert. A 404 yields
// missing=true (handled per mode by scheme selection, exactly like .sig).
func (p *HTTPCatalogProvider) fetchSigstoreBundleIfConfigured(ctx context.Context) (bundle []byte, missing bool, err error) {
	if p.trust.sigstore == nil {
		return nil, true, nil
	}
	resp, err := p.doGet(ctx, "index.json.sigstore", nil)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotFound:
		return nil, true, nil
	case http.StatusOK:
		b, rerr := readAllBounded(resp.Body, p.maxBytes)
		if rerr != nil {
			return nil, false, fmt.Errorf("release catalog: read sigstore bundle: %w", rerr)
		}
		return b, false, nil
	default:
		return nil, false, fmt.Errorf("release catalog: sigstore bundle HTTP %d", resp.StatusCode)
	}
}

func (p *HTTPCatalogProvider) fetch(ctx context.Context, rel string) ([]byte, error) {
	resp, err := p.doGet(ctx, rel, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release catalog: %s HTTP %d", rel, resp.StatusCode)
	}
	return readAllBounded(resp.Body, p.maxBytes)
}

// doGet issues a GET for rel under the base URL with the SSRF guard, the
// per-request decorator, and the minimal retry/backoff loop.
func (p *HTTPCatalogProvider) doGet(ctx context.Context, rel string, decorate func(*http.Request)) (*http.Response, error) {
	u := *p.base
	u.Path = path.Join("/", u.Path, rel) // anchor at "/" so a path-less base URL still yields /rel
	// SSRF is enforced at dial time (safeDialContext) and on redirects
	// (checkRedirect), not as a racy preflight host check.
	target := u.String()

	var lastErr error
	for attempt := 0; attempt <= p.retries; attempt++ {
		if attempt > 0 && p.backoff != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(p.backoff(attempt)):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
		if err != nil {
			return nil, err
		}
		if decorate != nil {
			decorate(req)
		}
		resp, err := p.client.Do(req)
		if err == nil {
			return resp, nil
		}
		lastErr = err // transport error — retry if configured
	}
	return nil, fmt.Errorf("release catalog: GET %s: %w", rel, lastErr)
}

func (p *HTTPCatalogProvider) storeValidators(etag, lastMod string) {
	p.mu.Lock()
	p.lastETag, p.lastModified = etag, lastMod
	p.mu.Unlock()
}

// readAllBounded reads up to max bytes; more than max is an error (oversize),
// and a short/truncated body surfaces as the underlying read error.
func readAllBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds the %d-byte bound", limit)
	}
	return data, nil
}

// bytesSignatureSource adapts in-memory sidecar bytes to the SignatureSource and
// sigstoreSource interfaces so the HTTP provider can reuse verifyIndexSignature.
// A "missing" sidecar surfaces as os.ErrNotExist so scheme selection can tell
// absent (fall-through) apart from present-but-invalid (reject).
type bytesSignatureSource struct {
	sig           []byte
	missing       bool
	bundle        []byte
	bundleMissing bool
}

func (b bytesSignatureSource) ReadSignature() ([]byte, error) {
	if b.missing {
		return nil, os.ErrNotExist
	}
	return b.sig, nil
}

func (b bytesSignatureSource) ReadSigstoreBundle() ([]byte, error) {
	if b.bundleMissing {
		return nil, os.ErrNotExist
	}
	return b.bundle, nil
}
