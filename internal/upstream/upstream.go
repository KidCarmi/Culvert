// Package upstream implements parent-proxy chaining with failover and
// circuit-breaker protection (ADR-0002 extraction; engine was upstream.go in
// package main).
//
// Culvert can route traffic through one or more parent HTTP proxies with
// automatic failover. When all upstreams are down the proxy falls back to
// direct connections. The package owns the pool state machine (round-robin
// selection, health flags, per-proxy circuit breakers) and the health-check
// loop; package main keeps the singleton, the transport wiring
// (applyUpstreamProxy), and persistence via admin_settings.
//
// Configuration (config.yaml):
//
//	upstream:
//	  proxies:
//	    - url: "http://parent1.corp.com:3128"
//	    - url: "http://parent2.corp.com:3128"
//	  health_interval: "30s"
//	  circuit_breaker:
//	    threshold: 5      # failures before opening circuit
//	    timeout: "60s"    # how long circuit stays open before half-open probe
package upstream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// ─── Circuit breaker states ──────────────────────────────────────────────────

type circuitState int32

const (
	circuitClosed   circuitState = 0 // normal — requests flow through
	circuitOpen     circuitState = 1 // tripped — reject immediately
	circuitHalfOpen circuitState = 2 // probing — allow one request
)

// CircuitBreaker tracks consecutive failures for an upstream proxy.
type CircuitBreaker struct {
	state     atomic.Int32
	failures  atomic.Int64
	threshold int64
	timeout   time.Duration
	openedAt  atomic.Int64 // UnixMilli when circuit was opened
}

func newCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	if threshold <= 0 {
		threshold = 5
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &CircuitBreaker{
		threshold: int64(threshold),
		timeout:   timeout,
	}
}

// Allow returns true if the circuit permits a request.
func (cb *CircuitBreaker) Allow() bool {
	st := circuitState(cb.state.Load())
	switch st {
	case circuitClosed:
		return true
	case circuitOpen:
		// Check if timeout has elapsed → transition to half-open.
		opened := time.UnixMilli(cb.openedAt.Load())
		if time.Since(opened) > cb.timeout {
			cb.state.CompareAndSwap(int32(circuitOpen), int32(circuitHalfOpen))
			return true
		}
		return false
	case circuitHalfOpen:
		return true // allow the probe request
	}
	return false
}

// RecordSuccess resets the failure count and closes the circuit.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.failures.Store(0)
	cb.state.Store(int32(circuitClosed))
}

// RecordFailure increments the failure count and opens the circuit if the
// threshold is reached. It returns true exactly when this call transitioned
// the circuit into the open state (closed/half-open → open), so callers can
// log/alert once per trip instead of once per failure. Failures recorded
// while already open refresh openedAt (extending the open window) and
// return false.
func (cb *CircuitBreaker) RecordFailure() bool {
	n := cb.failures.Add(1)
	if n >= cb.threshold {
		// openedAt is stored before the state flips so a concurrent Allow()
		// observing the open state never reads a stale trip timestamp.
		cb.openedAt.Store(time.Now().UnixMilli())
		return cb.state.Swap(int32(circuitOpen)) != int32(circuitOpen)
	}
	return false
}

// Params returns the breaker's configured threshold and timeout. Exported for
// the main-side persistence-contract tests (SetProxies must inherit
// Configure's params) and for diagnostics; not used on the request path.
func (cb *CircuitBreaker) Params() (threshold int, timeout time.Duration) {
	return int(cb.threshold), cb.timeout
}

// Failures returns the current consecutive-failure count. Exported for admin
// API / diagnostics surfacing; not used on the request path.
func (cb *CircuitBreaker) Failures() int64 {
	return cb.failures.Load()
}

// OpenedAt returns when the circuit last tripped open (zero Time if it has
// never opened, or has since been reset by RecordSuccess). Exported for admin
// API / diagnostics surfacing; not used on the request path.
func (cb *CircuitBreaker) OpenedAt() time.Time {
	if circuitState(cb.state.Load()) == circuitClosed {
		return time.Time{}
	}
	ms := cb.openedAt.Load()
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}

// State returns the current circuit state name.
func (cb *CircuitBreaker) State() string {
	switch circuitState(cb.state.Load()) {
	case circuitClosed:
		return "closed"
	case circuitOpen:
		return "open"
	case circuitHalfOpen:
		return "half-open"
	}
	return "unknown"
}

// ─── Upstream proxy entry ────────────────────────────────────────────────────

// Proxy represents one parent proxy in the chain: its entry (never a
// credential-bearing URL), probe state and circuit breaker.
type Proxy struct {
	Entry ManagedEntry
	// URL is the credential-FREE authority URL (display, legacy status). The
	// authenticated URL is built only by authenticatedURL, per selection.
	URL *url.URL
	CB  *CircuitBreaker

	mu        sync.RWMutex
	probe     ProbeState
	credState string
}

// Probe returns the entry's last probe outcome.
func (up *Proxy) Probe() ProbeState {
	up.mu.RLock()
	defer up.mu.RUnlock()
	return up.probe
}

func (up *Proxy) setProbe(st ProbeState) {
	up.mu.Lock()
	up.probe = st
	up.mu.Unlock()
}

// CredentialState returns the derived credential state.
func (up *Proxy) CredentialState() string {
	up.mu.RLock()
	defer up.mu.RUnlock()
	return up.credState
}

// credentialEligible reports whether the entry may be selected or probed on
// the credential axis: no credential, or a configured one bound to this
// authority. unusable and mismatch are never eligible.
func (up *Proxy) credentialEligible() bool {
	switch up.CredentialState() {
	case CredentialNone, CredentialConfigured:
		return true
	}
	return false
}

// eligible is the C11 predicate: credential-eligible AND (unprobed OR
// healthy) AND the breaker allows.
func (up *Proxy) eligible() bool {
	if !up.credentialEligible() {
		return false
	}
	if st := up.Probe().Status; st != ProbeUnprobed && st != ProbeHealthy {
		return false
	}
	return up.CB.Allow()
}

// Effective modes (C11).
const (
	ModeNoPool           = "no_pool"
	ModeChained          = "chained"
	ModeNoEligibleParent = "no_eligible_parent"
	ModeDirectFallback   = "direct_fallback"
)

// Effective is the backend-derived data-plane truth.
type Effective struct {
	Mode          string `json:"mode"`
	Entries       int    `json:"entries"`
	Eligible      int    `json:"eligible"`
	FallbackTotal int64  `json:"fallbackTotal"`
}

// Pool manages the effective set of parent proxies (YAML-owned + managed)
// with failover. The zero value is a usable empty pool.
type Pool struct {
	mu      sync.RWMutex
	yaml    []ManagedEntry // read-only, from config.yaml
	doc     Document       // managed entries (the durable v2 document)
	proxies []*Proxy       // effective pool, YAML first then managed
	key     *Keyring       // node-local credential key (nil ⇒ every credential unusable)
	keyErr  string         // bounded reason the key is unavailable
	// cbThreshold/cbTimeout are remembered from the last Configure so API
	// mutations inherit the operator-configured circuit-breaker parameters.
	cbThreshold int
	cbTimeout   time.Duration
	idx         atomic.Int64 // round-robin counter

	// Direct-fallback visibility (CHAOS-11): the all-eligible-parents-gone →
	// direct-egress fail-open (PX-2 posture) is observable, never silent.
	fallbackActive atomic.Bool  // pool is currently failing open to direct
	fallbackTotal  atomic.Int64 // requests that fell back to direct since start
}

// Configure sets the YAML-owned entries and the circuit-breaker parameters
// (startup / YAML-reload path). Managed entries are untouched. An invalid
// or duplicate YAML set fails closed: the previous effective pool stays.
func (p *Pool) Configure(entries []Entry, cbThreshold int, cbTimeout time.Duration) error {
	yaml, err := YAMLEntries(entries)
	if err != nil {
		p.mu.Lock()
		p.cbThreshold, p.cbTimeout = cbThreshold, cbTimeout
		p.mu.Unlock()
		obs.Printf("Upstream: YAML upstream entries refused (%s); effective pool unchanged", boundedReason(err))
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cbThreshold, p.cbTimeout = cbThreshold, cbTimeout
	if err := ValidateEffective(yaml, p.doc.Entries); err != nil {
		obs.Printf("Upstream: YAML upstream entries refused (%s); effective pool unchanged", boundedReason(err))
		return err
	}
	p.yaml = yaml
	p.rebuildLocked()
	return nil
}

// SetKey installs the node-local credential key (nil with a bounded reason
// when it is unavailable) and re-derives every credential state.
func (p *Pool) SetKey(k *Keyring, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key, p.keyErr = k, reason
	p.rebuildLocked()
}

// Key returns the loaded key (nil when unavailable) and the bounded reason.
func (p *Pool) Key() (key *Keyring, reason string) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.key, p.keyErr
}

// SetDocument publishes a new MANAGED document after validating the whole
// effective pool (YAML + managed): duplicate authorities or invalid entries
// are refused with a typed error and the running pool stays unchanged.
func (p *Pool) SetDocument(doc Document) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ValidateEffective(p.yaml, doc.Entries); err != nil {
		return err
	}
	p.doc = doc.Clone()
	if p.doc.Schema == 0 {
		p.doc.Schema = DocumentSchema
	}
	// Store entries in their canonical spelling (ValidateEffective proved
	// every one normalizes).
	for i := range p.doc.Entries {
		spec, _ := Normalize(p.doc.Entries[i].Spec())
		e := &p.doc.Entries[i]
		e.Scheme, e.Host, e.Port, e.Username = spec.Scheme, spec.Host, spec.Port, spec.Username
		if e.Source == "" {
			e.Source = SourceManaged
		}
	}
	p.rebuildLocked()
	return nil
}

// Document returns a deep copy of the managed document.
func (p *Pool) Document() Document {
	p.mu.RLock()
	defer p.mu.RUnlock()
	d := p.doc.Clone()
	if d.Revision == 0 {
		// A never-persisted (or pre-v2) document is revision 1, so a
		// client can always echo a non-zero fence token (the 2F-A
		// revision-0 migration convention).
		d.Revision = 1
	}
	return d
}

// YAMLEntries returns copies of the YAML-owned entries.
func (p *Pool) YAMLEntries() []ManagedEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return cloneEntries(p.yaml)
}

// EffectiveEntries returns copies of every effective entry (YAML first).
func (p *Pool) EffectiveEntries() []ManagedEntry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := cloneEntries(p.yaml)
	return append(out, cloneEntries(p.doc.Entries)...)
}

// SetProxies is the LEGACY credential-free replacement of the managed set
// from URLs (import / compatibility paths). A URL carrying a password is
// refused; YAML-owned authorities are skipped (YAML owns them).
func (p *Pool) SetProxies(entries []Entry) error {
	doc, err := p.legacyDocument(entries)
	if err != nil {
		return err
	}
	return p.SetDocument(doc)
}

// legacyDocument builds a managed document from credential-free URLs,
// preserving the identity and credential of an existing managed entry with
// the same canonical authority.
func (p *Pool) legacyDocument(entries []Entry) (Document, error) {
	cur := p.Document()
	yaml := p.YAMLEntries()
	byAuth := map[string]ManagedEntry{}
	for i := range cur.Entries {
		byAuth[cur.Entries[i].AuthorityHash()] = cur.Entries[i]
	}
	yamlAuth := map[string]struct{}{}
	for i := range yaml {
		yamlAuth[yaml[i].AuthorityHash()] = struct{}{}
	}
	next := Document{Schema: DocumentSchema, Revision: cur.Revision + 1}
	now := nowRFC3339()
	for i, e := range entries {
		spec, _, hasPW, err := SpecFromURL(e.URL)
		if err != nil {
			return Document{}, &InvalidEntryError{Index: i, Reason: err.Error()}
		}
		if hasPW {
			return Document{}, &InvalidEntryError{Index: i, Reason: "URL carries a password; credentials are set through the credential endpoint"}
		}
		h := spec.AuthorityHash()
		if _, owned := yamlAuth[h]; owned {
			continue
		}
		if prev, ok := byAuth[h]; ok {
			next.Entries = append(next.Entries, prev)
			continue
		}
		next.Entries = append(next.Entries, ManagedEntry{
			ID: NewManagedID(), Scheme: spec.Scheme, Host: spec.Host, Port: spec.Port, Username: spec.Username,
			Revision: 1, Source: SourceManaged, CreatedAt: now, UpdatedAt: now,
		})
	}
	return next, nil
}

// rebuildLocked derives the effective proxy list from yaml + doc, keeping
// probe/breaker state for entries whose id AND authority are unchanged.
func (p *Pool) rebuildLocked() {
	prev := map[string]*Proxy{}
	for _, up := range p.proxies {
		prev[up.Entry.ID+"|"+up.Entry.AuthorityHash()] = up
	}
	// Replacing the pool resets the direct-fallback transition state (Codex
	// P2): a wiped pool makes direct egress the intentional operating mode
	// again, and a repopulated pool re-derives — and re-alerts — on the next
	// request if the new parents are also down.
	p.fallbackActive.Store(false)
	var out []*Proxy
	add := func(e ManagedEntry) {
		key := e.ID + "|" + e.AuthorityHash()
		up, ok := prev[key]
		if !ok {
			u, err := url.Parse(e.Authority())
			if err != nil {
				return
			}
			up = &Proxy{URL: u, CB: newCircuitBreaker(p.cbThreshold, p.cbTimeout)}
			up.probe = ProbeState{Status: ProbeUnprobed, Reason: ReasonNone}
		}
		up.Entry = e
		if up.Entry.Credential != nil {
			c := *e.Credential
			up.Entry.Credential = &c
		}
		up.mu.Lock()
		up.credState = p.credentialStateLocked(&up.Entry)
		up.mu.Unlock()
		out = append(out, up)
	}
	for i := range p.yaml {
		add(p.yaml[i])
	}
	for i := range p.doc.Entries {
		add(p.doc.Entries[i])
	}
	p.proxies = out
}

// credentialStateLocked derives an entry's credential state: none,
// mismatch (bound to another authority), unusable (no key / wrong key /
// cannot unwrap), configured. The unsealed plaintext is discarded at once.
func (p *Pool) credentialStateLocked(e *ManagedEntry) string {
	if e.Credential == nil {
		return CredentialNone
	}
	if e.Credential.AuthorityHash != e.AuthorityHash() {
		return CredentialMismatch
	}
	if p.key == nil || p.key.KeyID() != e.Credential.KeyID {
		return CredentialUnusable
	}
	if _, err := p.key.Unseal(e.Credential, e.AuthorityHash()); err != nil {
		return CredentialUnusable
	}
	return CredentialConfigured
}

// CBParams returns the circuit-breaker parameters remembered from the last
// Configure.
func (p *Pool) CBParams() (threshold int, timeout time.Duration) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cbThreshold, p.cbTimeout
}

// Entries returns the effective pool as credential-FREE legacy entries
// (YAML first). It never carries a password.
func (p *Pool) Entries() []Entry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Entry, 0, len(p.proxies))
	for _, up := range p.proxies {
		out = append(out, Entry{URL: up.Entry.LegacyURL()})
	}
	return out
}

// LegacyManagedEntries returns the MANAGED entries as credential-free legacy
// URLs (the downgrade-compatible representation persisted beside the v2
// document).
func (p *Pool) LegacyManagedEntries() []Entry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Entry, 0, len(p.doc.Entries))
	for i := range p.doc.Entries {
		out = append(out, Entry{URL: p.doc.Entries[i].LegacyURL()})
	}
	return out
}

// Enabled returns true if any parent proxy is in the effective pool.
func (p *Pool) Enabled() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.proxies) > 0
}

// Next returns the next ELIGIBLE upstream proxy using round-robin selection
// (C11). Returns nil if none is eligible (caller falls back to direct).
func (p *Pool) Next() *Proxy {
	p.mu.RLock()
	proxies := p.proxies
	p.mu.RUnlock()

	n := len(proxies)
	if n == 0 {
		if p.fallbackActive.Load() {
			p.fallbackActive.Store(false)
		}
		return nil
	}
	start := int(p.idx.Add(1)) % n
	for i := 0; i < n; i++ {
		up := proxies[(start+i)%n]
		if up.eligible() {
			p.noteUpstreamAvailable()
			return up
		}
	}
	// No eligible parent — fall back to direct (PX-2 fail-open posture,
	// unchanged). CHAOS-11: count every fallback and alert once per
	// transition so the bypassed parent-proxy chain is never silent.
	p.noteDirectFallback()
	return nil
}

// Effective computes the backend-derived mode: no_pool (empty), chained
// (≥1 eligible), no_eligible_parent (0 eligible, no request fell back yet),
// direct_fallback (0 eligible and a request fell back).
func (p *Pool) Effective() Effective {
	p.mu.RLock()
	proxies := p.proxies
	p.mu.RUnlock()
	eff := Effective{Entries: len(proxies), FallbackTotal: p.fallbackTotal.Load()}
	for _, up := range proxies {
		if up.eligible() {
			eff.Eligible++
		}
	}
	switch {
	case len(proxies) == 0:
		eff.Mode = ModeNoPool
	case eff.Eligible > 0:
		eff.Mode = ModeChained
	case p.fallbackActive.Load():
		eff.Mode = ModeDirectFallback
	default:
		eff.Mode = ModeNoEligibleParent
	}
	return eff
}

// fireFallbackAlert delivers the upstream_pool_down alert on a fallback
// transition. Package-level seam so tests can capture transitions
// SYNCHRONOUSLY instead of listening on the process-global alerts sink.
var fireFallbackAlert = func(detail string) {
	go alerts.Fire("upstream_pool_down", alerts.Payload{
		Detail: detail,
		Source: "upstream",
	})
}

// noteDirectFallback records that a request needed a parent proxy but none
// was eligible. The counter increments per request; the log line + webhook
// alert fire once per transition INTO the fallback state.
func (p *Pool) noteDirectFallback() {
	p.fallbackTotal.Add(1)
	if !p.fallbackActive.Swap(true) {
		obs.Printf("Upstream: NO eligible parent proxy — failing open to DIRECT egress (parent-proxy chain bypassed)")
		const detail = "no eligible parent proxy (unhealthy, credential-ineligible or circuit-open); egress is DIRECT (parent-proxy chain bypassed)"
		if h := FallbackAlertHook; h != nil {
			h(detail)
		} else {
			fireFallbackAlert(detail)
		}
	}
}

// noteUpstreamAvailable clears the direct-fallback state when an eligible
// proxy reappears.
func (p *Pool) noteUpstreamAvailable() {
	if p.fallbackActive.Load() && p.fallbackActive.Swap(false) {
		obs.Printf("Upstream: eligible parent proxy available again — direct-egress fallback ended")
	}
}

// DirectFallback reports whether the pool is currently failing open to
// direct egress and how many requests have done so since startup.
func (p *Pool) DirectFallback() (active bool, total int64) {
	return p.fallbackActive.Load(), p.fallbackTotal.Load()
}

// List returns the effective pool statuses for the UI/API. URLs are
// credential-free authorities.
func (p *Pool) List() []Status {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Status, len(p.proxies))
	for i, up := range p.proxies {
		pr := up.Probe()
		st := Status{
			ID: up.Entry.ID, URL: up.Entry.LegacyURL(), Authority: up.Entry.Authority(),
			Scheme: up.Entry.Scheme, Host: up.Entry.Host, Port: up.Entry.Port, Username: up.Entry.Username,
			Source: string(up.Entry.Source), Revision: up.Entry.Revision,
			CredentialState: up.CredentialState(), Probe: pr,
			Healthy:  pr.Status == ProbeHealthy,
			Eligible: up.eligible(),
			Circuit:  up.CB.State(),
			Failures: up.CB.Failures(),
		}
		if opened := up.CB.OpenedAt(); !opened.IsZero() {
			st.OpenedAtMs = opened.UnixMilli()
			_, timeout := up.CB.Params()
			if remaining := timeout - time.Since(opened); remaining > 0 {
				st.RetryAfterMs = remaining.Milliseconds()
			}
		}
		out[i] = st
	}
	return out
}

// authenticatedURL is the ONLY constructor of a credential-bearing proxy
// URL. It runs after eligibility: a configured credential whose authority
// hash matches is unsealed and placed in the URL userinfo; a credential-free
// entry yields its plain authority. The returned URL is handed to the
// transport and never stored.
func (p *Pool) authenticatedURL(up *Proxy) (*url.URL, error) {
	u := *up.URL
	if up.Entry.Credential == nil {
		return &u, nil
	}
	p.mu.RLock()
	key := p.key
	p.mu.RUnlock()
	pw, err := key.Unseal(up.Entry.Credential, up.Entry.AuthorityHash())
	if err != nil {
		return nil, err
	}
	u.User = url.UserPassword(up.Entry.Username, pw)
	return &u, nil
}

// ProxyFunc returns an http.Transport-compatible proxy selector. When an
// eligible parent exists, it returns that parent's authenticated URL (built
// here and nowhere else); it returns nil (direct connection) otherwise.
//
// If the request context carries an Attribution slot (WithAttribution), the
// selected proxy is recorded there so the caller can feed the request's
// outcome back into that proxy's circuit breaker (CHAOS-11).
func (p *Pool) ProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		up := p.Next()
		if req != nil {
			if a, ok := req.Context().Value(attributionKey{}).(*Attribution); ok {
				a.proxy.Store(up) // nil when falling back to direct — Record then no-ops
			}
		}
		if up == nil {
			return nil, nil // direct connection
		}
		u, err := p.authenticatedURL(up)
		if err != nil {
			// Eligibility said configured but the unwrap failed now (key
			// swapped underneath): never send unauthenticated, fall back.
			obs.Printf("Upstream: %s credential could not be unwrapped at selection; request falls back to DIRECT", up.Entry.Authority())
			p.noteDirectFallback()
			return nil, nil
		}
		return u, nil
	}
}

// ─── Request-outcome attribution (CHAOS-11) ──────────────────────────────────

// attributionKey is the context key carrying the per-request attribution slot.
type attributionKey struct{}

// Attribution records which pool proxy the transport selected for one
// request. Create with WithAttribution; ProxyFunc fills it during RoundTrip.
type Attribution struct {
	proxy atomic.Pointer[Proxy]
}

// WithAttribution returns a child context carrying a fresh attribution slot,
// plus the slot itself.
func WithAttribution(ctx context.Context) (context.Context, *Attribution) {
	a := &Attribution{}
	return context.WithValue(ctx, attributionKey{}, a), a
}

// Record feeds a completed request's outcome into the selected proxy's
// circuit breaker. Nil-safe on both the receiver and the slot's proxy.
//
// A context.Canceled error is deliberately NOT charged to the proxy (our
// client went away). Timeouts DO count. The error is never rendered — only
// its bounded reason class (a transport error can embed the proxy URL).
func (a *Attribution) Record(err error) {
	if a == nil {
		return
	}
	up := a.proxy.Load()
	if up == nil {
		return
	}
	switch {
	case err == nil:
		up.CB.RecordSuccess()
	case errors.Is(err, context.Canceled):
		// client abort — not evidence about the parent proxy
	default:
		if up.CB.RecordFailure() {
			threshold, timeout := up.CB.Params()
			obs.Printf("Upstream: circuit OPEN for %s after %d consecutive request failures (retry in %s; reason=%s)",
				up.Entry.Authority(), threshold, timeout, classifyTransportError(err))
		}
	}
}

// healthCheckURL is the probe target: a stable, minimal, plain-HTTP endpoint
// reachable THROUGH the parent proxy under test.
const healthCheckURL = "http://detectportal.firefox.com/success.txt"

// probeTimeout bounds one probe.
const probeTimeout = 5 * time.Second

// HealthCheck probes every credential-eligible parent with the shared
// classifier and stores the bounded outcome. Credential-ineligible entries
// (unusable, mismatch) are not probed and keep their state.
func (p *Pool) HealthCheck() {
	p.mu.RLock()
	proxies := p.proxies
	p.mu.RUnlock()

	for _, up := range proxies {
		if !up.credentialEligible() {
			continue
		}
		target, err := p.authenticatedURL(up)
		if err != nil {
			up.setProbe(ProbeState{Status: ProbeUnhealthy, Reason: ReasonProxyAuthFailed, CheckedAt: nowRFC3339()})
			continue
		}
		status, reason := p.probeOnce(target)
		prev := up.Probe()
		up.setProbe(ProbeState{Status: status, Reason: reason, CheckedAt: nowRFC3339()})
		if prev.Status != status || prev.Reason != reason {
			obs.Printf("Upstream: %s probe %s (reason=%s)", up.Entry.Authority(), status, reason)
		}
	}
}

// probeOnce runs one bounded probe through the given proxy URL and returns
// the classified outcome. The response body is drained (≤1 KiB) and
// discarded; the transport error is never rendered.
func (p *Pool) probeOnce(proxyURL *url.URL) (status, reason string) {
	client := &http.Client{
		Timeout:   probeTimeout,
		Transport: probeTransportFor(proxyURL),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, healthCheckURL, http.NoBody)
	if err != nil {
		return ProbeUnhealthy, ReasonConnectFailed
	}
	resp, err := client.Do(req)
	if resp != nil {
		defer drainAndClose(resp)
	}
	return ClassifyProbe(resp, err)
}

// ProbeTransport is a TEST-ONLY seam: when non-nil it supplies the
// round-tripper the health probe uses for a given parent proxy, so a test
// can inject a deterministic probe outcome without a network. Production
// leaves it nil.
var ProbeTransport func(proxyURL *url.URL) http.RoundTripper

// FallbackAlertHook is a TEST-ONLY seam: when non-nil it receives the
// direct-fallback transition instead of the asynchronous production alert.
var FallbackAlertHook func(detail string)

func probeTransportFor(proxyURL *url.URL) http.RoundTripper {
	if h := ProbeTransport; h != nil {
		return h(proxyURL)
	}
	return &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		DisableKeepAlives: true,
	}
}

// RunHealthCheckLoop runs pool.HealthCheck at the given interval until ctx is
// cancelled, stopping the underlying ticker on exit. Returns immediately for
// a nil pool or a non-positive interval. P1.3 / S4.UpstreamHealth.
func RunHealthCheckLoop(ctx context.Context, pool *Pool, interval time.Duration) {
	if pool == nil || interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// CHAOS-24: contain the ROUND. This loop is what closes a tripped
			// breaker, so if it dies the pool can never recover a parent proxy
			// and egress stays on the direct fail-open path indefinitely.
			obs.SafeCall("upstream_health", pool.HealthCheck)
		}
	}
}

// boundedReason renders a typed pool error as a bounded reason string
// (never an authority, URL or credential).
func boundedReason(err error) string {
	var dup *DuplicateAuthorityError
	if errors.As(err, &dup) {
		return fmt.Sprintf("duplicate_authority count=%d", dup.Count)
	}
	var inv *InvalidEntryError
	if errors.As(err, &inv) {
		if inv.ID != "" {
			return "invalid_entry id=" + inv.ID
		}
		return fmt.Sprintf("invalid_entry index=%d", inv.Index)
	}
	return "invalid_entry"
}

// ─── Config types ────────────────────────────────────────────────────────────

// Entry is one parent proxy from config.yaml (credential-free URL).
type Entry struct {
	URL string `yaml:"url" json:"url"`
}

// Config is the "upstream" section of config.yaml.
type Config struct {
	Proxies        []Entry `yaml:"proxies" json:"proxies"`
	HealthInterval string  `yaml:"health_interval" json:"healthInterval"` // Go duration
	CircuitBreaker struct {
		Threshold int    `yaml:"threshold" json:"threshold"` // failures before open
		Timeout   string `yaml:"timeout" json:"timeout"`     // Go duration
	} `yaml:"circuit_breaker" json:"circuitBreaker"`
}

// Status is returned by the admin API (credential-free).
type Status struct {
	ID        string `json:"id"`
	URL       string `json:"url"` // legacy field: credential-free authority
	Authority string `json:"authority"`
	Scheme    string `json:"scheme"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Username  string `json:"username,omitempty"`
	Source    string `json:"source"`
	Revision  int64  `json:"revision"`
	// CredentialState is derived (C4): none | configured | unusable | mismatch.
	CredentialState string     `json:"credentialState"`
	Probe           ProbeState `json:"probe"`
	Healthy         bool       `json:"healthy"` // legacy: probe == healthy
	Eligible        bool       `json:"eligible"`
	Circuit         string     `json:"circuit"`
	// Failures is the current consecutive-failure count tracked by the
	// circuit breaker (resets to 0 on RecordSuccess).
	Failures int64 `json:"failures"`
	// OpenedAtMs is when the circuit last tripped open, as Unix
	// milliseconds; 0 when the circuit is closed.
	OpenedAtMs int64 `json:"openedAtMs,omitempty"`
	// RetryAfterMs is the remaining time (ms) until the breaker allows a
	// half-open probe; 0 when the circuit is not open.
	RetryAfterMs int64 `json:"retryAfterMs,omitempty"`
}

// FormatSummary returns a log-friendly summary like "2 proxies (parent1:3128, parent2:3128)".
func FormatSummary(entries []Entry) string {
	if len(entries) == 0 {
		return "direct"
	}
	hosts := make([]string, len(entries))
	for i, e := range entries {
		if u, err := url.Parse(e.URL); err == nil {
			hosts[i] = u.Host
		} else {
			hosts[i] = "invalid"
		}
	}
	return fmt.Sprintf("%d proxies (%s)", len(entries), strings.Join(hosts, ", "))
}

// ─── Test isolation ──────────────────────────────────────────────────────────

// PoolState is a full Pool snapshot for test hermeticity (pair Snapshot with
// Restore around a test that mutates the process-global pool).
type PoolState struct {
	YAML        []ManagedEntry
	Doc         Document
	Key         *Keyring
	KeyErr      string
	CBThreshold int
	CBTimeout   time.Duration
}

// Snapshot captures the pool's configuration (not its probe/breaker state).
func (p *Pool) Snapshot() PoolState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return PoolState{YAML: cloneEntries(p.yaml), Doc: p.doc.Clone(), Key: p.key, KeyErr: p.keyErr, CBThreshold: p.cbThreshold, CBTimeout: p.cbTimeout}
}

// Restore resets the pool to a captured state and rebuilds the effective
// pool from it (probe/breaker state starts fresh).
func (p *Pool) Restore(st PoolState) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.yaml = cloneEntries(st.YAML)
	p.doc = st.Doc.Clone()
	p.key, p.keyErr = st.Key, st.KeyErr
	p.cbThreshold, p.cbTimeout = st.CBThreshold, st.CBTimeout
	p.proxies = nil
	p.fallbackTotal.Store(0)
	p.rebuildLocked()
}
