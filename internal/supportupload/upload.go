// Package supportupload is the appliance-side client for M6 "Optional secure
// upload" (docs/support/SECURE-UPLOAD-ARCHITECTURE.md §4): a resumable,
// SSRF-guarded, chunked, outbound-only HTTPS uploader to a TAC upload gateway.
//
// It is a PURE ENGINE — it opens no connections on its own and is wired to no
// trigger. The caller supplies the (already E2E-encrypted) bundle bytes and the
// per-bundle identity; the client performs init → offset-idempotent chunk PUTs →
// complete, and returns the gateway's signed receipt. The queue/state machine
// and the per-bundle consent gate that decide WHETHER and WHEN to call it live
// in later slices; nothing here can cause egress until something invokes it.
//
// Every outbound dial is SSRF-guarded at the network layer (ssrf.SafeDialContext
// checks the post-resolution address, closing the DNS-rebind window) and on
// every redirect hop (ssrf.PrivateHost) — a compromised or misconfigured origin
// cannot be pointed at internal infrastructure.
package supportupload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

const (
	// defaultChunkSize is used when the gateway's init response does not pin one.
	defaultChunkSize = 4 << 20 // 4 MiB
	// maxRespBytes bounds every response body read (all responses are tiny JSON).
	maxRespBytes = 64 << 10
	// defaultTimeout bounds each individual request (not the whole transfer).
	defaultTimeout = 60 * time.Second
	maxRedirects   = 5
)

// Meta is the per-bundle identity sent at init (SECURE-UPLOAD-ARCHITECTURE.md §4).
// BundleSHA256 is the hash of the bytes being uploaded (the encrypted bundle);
// the gateway re-verifies it at complete and echoes it in the receipt.
type Meta struct {
	CaseID       string `json:"case_id"`
	BundleID     string `json:"bundle_id"`
	BundleSHA256 string `json:"bundle_sha256"`
	Size         int64  `json:"size"`
	KeyID        string `json:"key_id,omitempty"`
}

// Receipt is the signed proof the gateway returns from :complete.
type Receipt struct {
	CaseID       string `json:"case_id"`
	BundleID     string `json:"bundle_id"`
	BundleSHA256 string `json:"bundle_sha256"`
	ReceivedAt   string `json:"received_at"`
	Sig          string `json:"sig"`
}

// GatewayError is returned for a non-2xx gateway response, preserving the status
// so the caller (queue) can classify entitlement/format/hash rejections vs
// transient 5xx for retry decisions.
type GatewayError struct {
	Status int
	Body   string
}

func (e *GatewayError) Error() string {
	return fmt.Sprintf("upload: gateway status %d: %s", e.Status, e.Body)
}

// Config constructs a Client.
type Config struct {
	Origin     string        // TAC upload base URL (https)
	Credential string        // per-appliance bearer credential (tenant-scoped)
	Timeout    time.Duration // per-request timeout (default 60s)
}

// Client is a resumable, SSRF-guarded upload client. Safe for sequential use by
// one uploader; the queue serializes per-bundle transfers.
type Client struct {
	base       *url.URL
	credential string
	http       *http.Client
	// originGuard rejects a request whose origin host is private/internal,
	// resolving the host and failing closed. It runs BEFORE every request so the
	// origin is validated even when HTTPS_PROXY is set and the SSRF dial guard
	// only sees the proxy address. nil disables it (only the in-package tests,
	// which target a loopback httptest gateway).
	originGuard func(hostport string) error
	// redirectGuard rejects a redirect to a private host; nil disables it (tests).
	redirectGuard func(hostport string) error
}

// NewClient validates the origin (https + host) and builds an SSRF-guarded
// client: the transport dials only public resolved addresses (ssrf.SafeDialContext)
// and every redirect hop is re-checked. Inline url.Parse + scheme + host so the
// guard is visible at the construction boundary.
func NewClient(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Origin)
	if err != nil {
		return nil, fmt.Errorf("upload: parse origin: %w", err)
	}
	if u.Scheme != "https" {
		return nil, errors.New("upload: origin must be https")
	}
	if u.Host == "" {
		return nil, errors.New("upload: origin has no host")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	c := &Client{
		base:          u,
		credential:    cfg.Credential,
		originGuard:   ssrf.PrivateHost,
		redirectGuard: ssrf.PrivateHost,
	}
	c.http = &http.Client{
		Timeout:       timeout,
		CheckRedirect: c.checkRedirect,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           ssrf.SafeDialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}
	return c, nil
}

// checkRedirect re-applies the SSRF guard to each redirect target, refuses any
// downgrade off https, and caps hops. The https check matters because Go
// preserves the Authorization header and replays the PUT body on a same-host
// redirect, so an http:// redirect target would leak the bearer credential and
// chunk bytes over plaintext despite the initial https validation.
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errors.New("upload: too many redirects")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("upload: refusing non-https redirect to %s", req.URL.Scheme+"://"+req.URL.Host)
	}
	if c.redirectGuard != nil {
		if err := c.redirectGuard(req.URL.Host); err != nil {
			return fmt.Errorf("upload: SSRF guard (redirect to %s): %w", req.URL.Host, err)
		}
	}
	return nil
}

// Init opens an upload session and returns its id + the gateway-chosen chunk size.
func (c *Client) Init(ctx context.Context, m Meta) (uploadID string, chunkSize int64, err error) {
	var resp struct {
		UploadID  string `json:"upload_id"`
		ChunkSize int64  `json:"chunk_size"`
		Accepted  bool   `json:"accepted"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/uploads:init", "application/json", m, &resp); err != nil {
		return "", 0, err
	}
	if resp.UploadID == "" {
		return "", 0, errors.New("upload: gateway returned no upload_id")
	}
	cs := resp.ChunkSize
	if cs <= 0 {
		cs = defaultChunkSize
	}
	return resp.UploadID, cs, nil
}

// Status returns the gateway's current received offset — the resume point after a
// dropped connection or a process restart.
func (c *Client) Status(ctx context.Context, uploadID string) (receivedOffset int64, err error) {
	var resp struct {
		ReceivedOffset int64  `json:"received_offset"`
		State          string `json:"state"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/uploads/"+url.PathEscape(uploadID), "", nil, &resp); err != nil {
		return 0, err
	}
	return resp.ReceivedOffset, nil
}

// PutChunk uploads one chunk at the given offset. Idempotent per offset (a
// re-sent offset is a no-op on the gateway), so a retry after a drop is safe.
// Returns the gateway's new received offset.
func (c *Client) PutChunk(ctx context.Context, uploadID string, offset int64, chunk []byte) (receivedOffset int64, err error) {
	path := fmt.Sprintf("/v1/uploads/%s/chunks/%d", url.PathEscape(uploadID), offset)
	var resp struct {
		ReceivedOffset int64 `json:"received_offset"`
	}
	if err := c.do(ctx, http.MethodPut, path, "application/octet-stream", rawBody(chunk), &resp); err != nil {
		return 0, err
	}
	return resp.ReceivedOffset, nil
}

// Complete finalizes the upload. The gateway re-verifies bundleSHA256 against the
// bytes it received and returns the signed receipt; Complete ALSO re-checks the
// receipt's hash equals the expected bundleSHA256 so EVERY completion path — the
// Upload convenience wrapper and the queue's direct Init/Status/PutChunk/Complete
// resume path — rejects a corrupted or mis-issued receipt identically.
func (c *Client) Complete(ctx context.Context, uploadID, bundleSHA256 string) (Receipt, error) {
	var rec Receipt
	body := map[string]string{"bundle_sha256": bundleSHA256}
	if err := c.do(ctx, http.MethodPost, "/v1/uploads/"+url.PathEscape(uploadID)+":complete", "application/json", body, &rec); err != nil {
		return Receipt{}, err
	}
	if rec.BundleSHA256 != bundleSHA256 {
		return Receipt{}, fmt.Errorf("upload: receipt hash %q does not match bundle hash %q", rec.BundleSHA256, bundleSHA256)
	}
	return rec, nil
}

// Upload runs the full resumable transfer of ra[0:size] and returns the signed
// receipt. It consults the gateway's received offset first, so re-invoking it on
// the same freshly-init'd session only sends missing chunks; cross-restart resume
// is driven by the queue via the exposed Init/Status/PutChunk/Complete methods.
// The receipt hash is re-checked against meta.BundleSHA256 (defense in depth over
// the gateway's own complete-time check).
func (c *Client) Upload(ctx context.Context, m Meta, ra io.ReaderAt, size int64) (Receipt, error) {
	m.Size = size
	uploadID, chunkSize, err := c.Init(ctx, m)
	if err != nil {
		return Receipt{}, err
	}
	offset, err := c.Status(ctx, uploadID)
	if err != nil {
		offset = 0 // a fresh session has nothing to resume; status is best-effort here
	}
	buf := make([]byte, chunkSize)
	for offset < size {
		n := chunkSize
		if rem := size - offset; rem < n {
			n = rem
		}
		if _, rerr := ra.ReadAt(buf[:n], offset); rerr != nil && rerr != io.EOF {
			return Receipt{}, fmt.Errorf("upload: read chunk at %d: %w", offset, rerr)
		}
		recv, perr := c.PutChunk(ctx, uploadID, offset, buf[:n])
		if perr != nil {
			return Receipt{}, perr
		}
		if recv <= offset {
			return Receipt{}, fmt.Errorf("upload: gateway did not advance past offset %d", offset)
		}
		offset = recv
	}
	// Complete re-checks the receipt hash for every completion path.
	return c.Complete(ctx, uploadID, m.BundleSHA256)
}

// rawBody wraps chunk bytes for a raw PUT; nil chunk → empty body.
func rawBody(chunk []byte) *bytes.Reader { return bytes.NewReader(chunk) }

// do issues one request and decodes a JSON response. reqBody is JSON-marshaled
// when contentType is application/json, sent raw when it is a *bytes.Reader, and
// omitted when nil. Uses http.NewRequestWithContext; bounded response read.
func (c *Client) do(ctx context.Context, method, path, contentType string, reqBody, out any) error {
	// Preflight the ORIGIN host before every request. SafeDialContext guards the
	// actual dial, but with HTTPS_PROXY set that dial is to the proxy — so a
	// private origin would otherwise be tunneled through an allowed proxy. This
	// resolving check fails closed on the configured origin regardless of proxy.
	if c.originGuard != nil {
		if err := c.originGuard(c.base.Host); err != nil {
			return fmt.Errorf("upload: origin SSRF guard: %w", err)
		}
	}
	body, err := requestBody(contentType, reqBody)
	if err != nil {
		return err
	}
	full := strings.TrimRight(c.base.String(), "/") + path
	req, err := http.NewRequestWithContext(ctx, method, full, body)
	if err != nil {
		return fmt.Errorf("upload: build request: %w", err)
	}
	if contentType != "" && body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	if c.credential != "" {
		req.Header.Set("Authorization", "Bearer "+c.credential)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("upload: %s: %w", method, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &GatewayError{Status: resp.StatusCode, Body: string(data)}
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("upload: decode response: %w", err)
		}
	}
	return nil
}

// requestBody produces the io.Reader for do(): a raw byte reader passes through,
// a JSON content type marshals the value, and nil is an empty body.
func requestBody(contentType string, reqBody any) (io.Reader, error) {
	if reqBody == nil {
		return nil, nil
	}
	if r, ok := reqBody.(*bytes.Reader); ok {
		return r, nil
	}
	if contentType == "application/json" {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("upload: marshal request: %w", err)
		}
		return bytes.NewReader(b), nil
	}
	return nil, fmt.Errorf("upload: unsupported request body for content-type %q", contentType)
}
