// Package health implements the bounded HTTP probe used by the
// restore-commit flow to verify the proxy stack came back up after a
// `docker compose up -d` step.
//
// Contract (D1.6 plan § 6.5):
//
//   - The probe targets the operator-supplied health_base_url +
//     health_path / ready_path. The agent does NOT rely on
//     Docker-network DNS — health_base_url MUST be a host-published
//     endpoint (typically 127.0.0.1:<published-port>).
//   - Bounded total runtime. The probe budget caps wall-clock; if
//     /ready does not return 2xx within the budget, the probe fails
//     with reason=ready_timeout. /health is then probed once on the
//     way out; its result is recorded but does not turn a successful
//     /ready probe into a failure.
//   - Single-shot retries. /ready is polled every 2s until it returns
//     2xx or the budget elapses. /health is probed once after /ready
//     succeeds (or once at the budget boundary if /ready failed).
//   - Single TCP connect timeout per request (3s) so a hung listener
//     can't consume the full budget.
//
// The probe is intentionally simple — no exponential backoff, no
// connection pooling, no caching. Each HTTP request is a fresh
// http.Client.Do.
package health

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Result records the outcome of a probe.
type Result struct {
	// ReadyOK reports whether /ready returned 2xx within the budget.
	ReadyOK bool
	// ReadyDetail is the operator-facing summary of the /ready
	// probe (e.g. "200 OK after 4 attempts in 6s", "timed out
	// after 30s"). Always set.
	ReadyDetail string
	// HealthOK reports whether /health returned 2xx.
	HealthOK bool
	// HealthDetail is the operator-facing summary of the /health
	// probe.
	HealthDetail string
	// TotalDuration is the wall-clock spent by the entire probe
	// (both /ready polling and the /health one-shot).
	TotalDuration time.Duration
}

// Failed reports whether the probe should be treated as a failure for
// the calling operation. /ready is the gating condition; /health
// failure is logged but does not by itself fail the op.
func (r *Result) Failed() bool { return !r.ReadyOK }

// Probe configures one health-probe execution.
type Probe struct {
	// BaseURL is the configured health_base_url (parsed). MUST be
	// non-nil and have a non-empty Host.
	BaseURL *url.URL
	// HealthPath is the configured health_path; must start with "/".
	HealthPath string
	// ReadyPath is the configured ready_path; must start with "/".
	ReadyPath string

	// Budget is the total wall-clock budget for the probe (default 30s).
	Budget time.Duration
	// PollInterval is the gap between /ready attempts (default 2s).
	PollInterval time.Duration
	// RequestTimeout bounds a single HTTP request (default 3s).
	RequestTimeout time.Duration

	// Client may be set by tests to capture or reroute requests.
	// nil → use http.DefaultClient with RequestTimeout.
	Client *http.Client
}

// defaults applies any unset fields. Returns a copy.
func (p Probe) withDefaults() Probe {
	if p.Budget <= 0 {
		p.Budget = 30 * time.Second
	}
	if p.PollInterval <= 0 {
		p.PollInterval = 2 * time.Second
	}
	if p.RequestTimeout <= 0 {
		p.RequestTimeout = 3 * time.Second
	}
	return p
}

// Validate is called by Run before any HTTP traffic. Surfaces
// configuration errors as agent-level errors rather than probe
// failures.
func (p Probe) Validate() error {
	if p.BaseURL == nil {
		return errors.New("health: BaseURL required")
	}
	if p.BaseURL.Host == "" {
		return errors.New("health: BaseURL has empty Host")
	}
	if p.BaseURL.Scheme != "http" && p.BaseURL.Scheme != "https" {
		return fmt.Errorf("health: BaseURL scheme %q must be http or https", p.BaseURL.Scheme)
	}
	if !strings.HasPrefix(p.HealthPath, "/") {
		return fmt.Errorf("health: HealthPath must start with '/', got %q", p.HealthPath)
	}
	if !strings.HasPrefix(p.ReadyPath, "/") {
		return fmt.Errorf("health: ReadyPath must start with '/', got %q", p.ReadyPath)
	}
	return nil
}

// Run executes the probe. It returns a *Result whether or not the
// probe succeeded; the returned error is non-nil ONLY for
// configuration errors (BaseURL missing/invalid).
func (p Probe) Run(ctx context.Context) (*Result, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	p = p.withDefaults()

	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: p.RequestTimeout}
	}

	deadline := time.Now().Add(p.Budget)
	res := &Result{}
	start := time.Now()

	// /ready polling loop.
	attempts := 0
	readyURL := joinURL(p.BaseURL, p.ReadyPath)
	for {
		attempts++
		ok, detail := probeOnce(ctx, client, readyURL, p.RequestTimeout)
		if ok {
			res.ReadyOK = true
			res.ReadyDetail = fmt.Sprintf("%s after %d attempt(s) in %s", detail, attempts, time.Since(start).Truncate(time.Millisecond))
			break
		}
		// Budget exhausted? Stop.
		if time.Now().Add(p.PollInterval).After(deadline) {
			res.ReadyOK = false
			res.ReadyDetail = fmt.Sprintf("ready_timeout: last=%s after %d attempt(s) in %s", detail, attempts, time.Since(start).Truncate(time.Millisecond))
			break
		}
		// Sleep with cancellation awareness.
		select {
		case <-ctx.Done():
			res.ReadyDetail = fmt.Sprintf("ready_cancelled: %v after %d attempt(s)", ctx.Err(), attempts)
			res.TotalDuration = time.Since(start)
			return res, nil
		case <-time.After(p.PollInterval):
		}
	}

	// /health is probed once. Failure here does NOT flip ReadyOK.
	healthURL := joinURL(p.BaseURL, p.HealthPath)
	hOK, hDetail := probeOnce(ctx, client, healthURL, p.RequestTimeout)
	res.HealthOK = hOK
	res.HealthDetail = hDetail
	res.TotalDuration = time.Since(start)
	return res, nil
}

// probeOnce performs a single GET. Returns (ok=true, "200 OK") on
// 2xx; (false, detail) otherwise. The detail string is the operator-
// facing summary (status text, error message). Body is drained but
// not returned.
func probeOnce(ctx context.Context, client *http.Client, target string, perReqTimeout time.Duration) (ok bool, detail string) {
	reqCtx, cancel := context.WithTimeout(ctx, perReqTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return false, fmt.Sprintf("build_request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("transport: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, fmt.Sprintf("%d %s", resp.StatusCode, resp.Status)
	}
	return false, fmt.Sprintf("%d %s", resp.StatusCode, resp.Status)
}

// joinURL produces base.Scheme://base.Host[:port]/path (replaces any
// path on base — operators set path via HealthPath/ReadyPath).
func joinURL(base *url.URL, path string) string {
	u := *base
	u.Path = path
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
