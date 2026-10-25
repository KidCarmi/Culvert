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
//
//   - Bounded total runtime. The probe budget caps wall-clock; if
//     /ready does not return 2xx within the budget, the probe fails
//     with reason=ready_timeout. /health is then probed once on the
//     way out; its result is recorded but does not turn a successful
//     /ready probe into a failure.
//
//   - Single-shot retries. /ready is polled every 2s until it returns
//     2xx or the budget elapses. /health is probed once after /ready
//     succeeds (or once at the budget boundary if /ready failed).
//
//   - Single TCP connect timeout per request (3s) so a hung listener
//     can't consume the full budget.
//
//   - Preservation (owner review, PR #1528). A 2xx /ready alone says the
//     process serves; it does not say the upgrade kept the appliance's
//     admin identity, inspection CA or enforcement. Baseline reads /ready
//     once BEFORE the restart and records which of PreservedReadyChecks
//     were "ok"; Run then requires each of those to be "ok" again (a
//     missing row counts as regressed) before /ready counts as ready.
//     Rows that were not ok before are not required after, so a fresh or
//     half-configured appliance upgrades exactly as before. The list is
//     deliberately LOCAL state only — never a row that depends on an
//     external service (clamav, cp_poll, threat feeds, DNS), because a
//     dependency outage during an upgrade must not roll it back. For the
//     same reason a non-2xx /ready is TOLERATED when /ready was already
//     non-2xx in the baseline AND no row that was "ok" then is failing
//     now: a ClamAV sidecar that was down before the upgrade gates /ready,
//     but it is not something the upgrade broke or a rollback would fix.
//     A /ready that was 2xx before must be 2xx after.
//
// The probe is intentionally simple — no exponential backoff, no
// connection pooling, no caching. Each HTTP request is a fresh
// http.Client.Do.
package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// PreservedReadyChecks are the /ready rows an upgrade must not regress:
// admin setup and session signing (identity/admin), the inspection CA,
// and the policy rows (enforcement). All are computed from local state.
// The proxy pins that it emits these names
// (TestReadiness_AgentPreservedRowsExist in the root module).
var PreservedReadyChecks = []string{"setup_complete", "session_secret", "ca", "policy_loaded", "policy_posture"}

// Snapshot is one parsed /ready answer taken before a restart.
type Snapshot struct {
	Ready     bool     // /ready answered 2xx
	OK        []string // every row reading "ok" (sorted)
	Preserved []string // the PreservedReadyChecks among OK
	Detail    string   // op-log summary
}

// maxReadyBody bounds how much of a /ready body is read for row parsing.
const maxReadyBody = 64 << 10

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
	// Regressed lists Preserve rows that were not "ok" on the last /ready
	// answer (sorted). Gating unless PreserveReportOnly.
	Regressed []string
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
	// ReadyPath is the configured ready_path; must start with "/". It may
	// carry a query (e.g. "/ready?strict=1"), which is sent as given.
	ReadyPath string

	// Preserve is the set of /ready rows that must read "ok" (normally
	// the Baseline taken before the restart). Empty ⇒ 2xx alone gates.
	Preserve []string
	// PreserveReportOnly records regressions in Result.Regressed without
	// gating on them (rollback: restoring service must not fail on it).
	PreserveReportOnly bool
	// Before is the pre-restart Baseline. When it saw a non-2xx /ready,
	// a non-2xx answer now counts as ready provided no row in Before.OK
	// is failing (or missing) — nothing that worked broke. nil ⇒ a
	// non-2xx always fails, the historical contract.
	Before *Snapshot
	// MissingIsUnknown makes a row ABSENT from the answer not count as
	// broken (only an explicit non-"ok" does). Set for rollbacks: the
	// target may be an older release that predates rows the newer one
	// added. An upgrade leaves it false — a vanished row is a regression.
	MissingIsUnknown bool

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
		ok, detail, body := probeOnce(ctx, client, readyURL, p.RequestTimeout)
		ok, detail = p.judgeReady(res, ok, detail, body)
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
	hOK, hDetail, _ := probeOnce(ctx, client, healthURL, p.RequestTimeout)
	res.HealthOK = hOK
	res.HealthDetail = hDetail
	res.TotalDuration = time.Since(start)
	return res, nil
}

// judgeReady applies the baseline to one /ready answer: a non-2xx is
// tolerated when /ready was already non-2xx before and nothing that was
// ok then is failing now, and a 2xx whose preserved rows regressed is not
// ready (unless report-only).
func (p Probe) judgeReady(res *Result, ok bool, detail string, body []byte) (ready bool, why string) {
	if !ok && p.Before != nil && !p.Before.Ready {
		if failing, parsed := failingRows(body); parsed && len(failing) > 0 && len(p.broken(body, p.Before.OK)) == 0 {
			ok = true
			detail += " tolerated: failing [" + strings.Join(failing, ",") + "]; /ready was already non-2xx and no row that was ok broke"
		}
	}
	if ok && len(p.Preserve) > 0 {
		res.Regressed = regressedRows(body, p.Preserve)
		if len(res.Regressed) > 0 && !p.PreserveReportOnly {
			return false, "preserved_check_regressed: " + strings.Join(res.Regressed, ",")
		}
	}
	return ok, detail
}

// Baseline reads /ready ONCE, whatever the HTTP status (a 503 body still
// carries the rows). A stack that does not answer, or answers without the
// row map, yields nil — nothing is preserved or tolerated afterwards —
// with the reason in the returned detail for the op log.
func (p Probe) Baseline(ctx context.Context) (snapshot *Snapshot, detail string) {
	if err := p.Validate(); err != nil {
		return nil, "baseline: " + err.Error()
	}
	p = p.withDefaults()
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: p.RequestTimeout}
	}
	ok, d, body := probeOnce(ctx, client, joinURL(p.BaseURL, p.ReadyPath), p.RequestTimeout)
	rows, parsed := readyRows(body)
	if !parsed {
		return nil, "baseline: no readiness rows (" + d + ")"
	}
	snap := &Snapshot{Ready: ok}
	for k, v := range rows {
		if v == "ok" {
			snap.OK = append(snap.OK, k)
		}
	}
	sort.Strings(snap.OK)
	for _, name := range PreservedReadyChecks {
		if rows[name] == "ok" {
			snap.Preserved = append(snap.Preserved, name)
		}
	}
	failing, _ := failingRows(body)
	snap.Detail = fmt.Sprintf("baseline: %s preserved=[%s] failing=[%s]",
		d, strings.Join(snap.Preserved, ","), strings.Join(failing, ","))
	return snap, snap.Detail
}

// broken returns the want rows that are not "ok" in body, treating an
// absent row as unknown (not broken) when MissingIsUnknown is set.
func (p Probe) broken(body []byte, want []string) []string {
	if !p.MissingIsUnknown {
		return regressedRows(body, want)
	}
	rows, _ := readyRows(body)
	var out []string
	for _, name := range want {
		if st, present := rows[name]; present && st != "ok" {
			out = append(out, name)
		}
	}
	return out
}

// failingRows returns the rows whose status is not "ok" (sorted), and
// whether the body carried a row map at all.
func failingRows(body []byte) ([]string, bool) {
	rows, ok := readyRows(body)
	if !ok {
		return nil, false
	}
	var out []string
	for k, v := range rows {
		if v != "ok" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, true
}

// readyRows parses the proxy's /ready body ({"checks":{name:{"status"}}}).
func readyRows(body []byte) (map[string]string, bool) {
	var rep struct {
		Checks map[string]struct {
			Status string `json:"status"`
		} `json:"checks"`
	}
	if len(body) == 0 || json.Unmarshal(body, &rep) != nil || rep.Checks == nil {
		return nil, false
	}
	rows := make(map[string]string, len(rep.Checks))
	for k, v := range rep.Checks {
		rows[k] = v.Status
	}
	return rows, true
}

// regressedRows returns the want rows that are not "ok" in body (an
// unparseable body regresses all of them), sorted.
func regressedRows(body []byte, want []string) []string {
	rows, _ := readyRows(body)
	var out []string
	for _, name := range want {
		if rows[name] != "ok" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// probeOnce performs a single GET. Returns (ok=true, "200 OK") on
// 2xx; (false, detail) otherwise. The detail string is the operator-
// facing summary (status text, error message). Up to maxReadyBody of
// the body is returned for row parsing; the rest is drained.
func probeOnce(ctx context.Context, client *http.Client, target string, perReqTimeout time.Duration) (ok bool, detail string, body []byte) {
	reqCtx, cancel := context.WithTimeout(ctx, perReqTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return false, fmt.Sprintf("build_request: %v", err), nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("transport: %v", err), nil
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ = io.ReadAll(io.LimitReader(resp.Body, maxReadyBody))
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, fmt.Sprintf("%d %s", resp.StatusCode, resp.Status), body
	}
	return false, fmt.Sprintf("%d %s", resp.StatusCode, resp.Status), body
}

// joinURL produces base.Scheme://base.Host[:port]/path[?query]. Any path
// or query on base is replaced: operators set both via HealthPath /
// ReadyPath. The query is split off here because assigning
// "/ready?strict=1" to URL.Path would escape the "?" and send a request
// for a path that does not exist (owner review, PR #1528).
func joinURL(base *url.URL, path string) string {
	u := *base
	p, q, _ := strings.Cut(path, "?")
	u.Path = p
	u.RawPath = ""
	u.RawQuery = q
	u.Fragment = ""
	return u.String()
}
