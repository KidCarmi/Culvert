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
	return &HTTPCatalogProvider{
		base:     u,
		client:   &http.Client{Timeout: httpCatalogDefaultTimeout},
		trust:    trust,
		maxBytes: catalogMaxReadBytes,
		guard:    isPrivateHost, // defense-in-depth SSRF guard
	}, nil
}

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
	sigBytes, sigMissing, err := p.fetchSignature(ctx)
	if err != nil {
		return "", err
	}
	if err := verifyIndexSignature(idxBytes, bytesSignatureSource{sig: sigBytes, missing: sigMissing}, p.trust); err != nil {
		// Forged/unsigned (enforce) index ⇒ reject here, having fetched NO manifests.
		return "", err
	}

	// ── Phase 2: index is trusted — enumerate + fetch manifests into staging ──
	if err := p.stageVerified(ctx, stage, idxBytes, sigBytes, sigMissing); err != nil {
		return "", err
	}

	p.storeValidators(etag, lastMod)
	committed = true
	return stage, nil
}

// stageVerified writes the (already-verified) index + signature and fetches each
// referenced manifest into the staging dir. The index is parsed here ONLY after
// its signature was checked in Phase 1 (§5.1).
func (p *HTTPCatalogProvider) stageVerified(ctx context.Context, stage string, idxBytes, sigBytes []byte, sigMissing bool) error {
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
	if !sigMissing {
		if err := os.WriteFile(filepath.Join(stage, "index.json.sig"), sigBytes, 0o600); err != nil {
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
	if p.guard != nil {
		if err := p.guard(u.Host); err != nil {
			return nil, fmt.Errorf("release catalog: SSRF guard: %w", err)
		}
	}
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

// bytesSignatureSource adapts in-memory signature bytes to the P1.3
// SignatureSource interface so the HTTP provider can reuse verifyIndexSignature.
type bytesSignatureSource struct {
	sig     []byte
	missing bool
}

func (b bytesSignatureSource) ReadSignature() ([]byte, error) {
	if b.missing {
		return nil, os.ErrNotExist
	}
	return b.sig, nil
}
