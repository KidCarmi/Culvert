package main

// Multi-instance connection pool for the Sluice CDR engine.
//
// Phase 2c single-instance singleton (cdrActiveClientV) is lifted into
// this pool.  Each enrolled Sluice becomes a cdrPooledClient bundling:
//
//   - A live *CDRClient (grpc.ClientConn + stub)
//   - A per-instance circuit breaker
//   - Last-known health response + timestamp
//
// safeCDRSanitize (cdr_proxy.go) calls cdrPickPooled() to get the best
// available instance.  The picker ignores clients whose breaker is open
// and round-robins across the rest.  All-open → nil → safeCDRSanitize
// applies fail-mode.
//
// Backwards compatibility: cdrActiveClient() still returns a *CDRClient
// (or nil), so code paths that only need "is CDR live?" keep working.

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// ─── Pool types ────────────────────────────────────────────────────────────

// cdrPooledClient wraps one enrolled instance's runtime state.
type cdrPooledClient struct {
	Name    string
	Client  *CDRClient
	Breaker *cdrCircuitBreaker

	// Health fields — updated by the poller (cdr_health.go).
	healthMu     sync.RWMutex
	lastHealth   *pb.HealthResponse
	lastHealthAt time.Time
	healthy      atomic.Int32 // 0 or 1

	// profileCap is the effective per-file cap (bytes) reported by Sluice
	// on the selected profile.  Zero means "not yet probed / no cap".
	// Client-side enforcement uses min(cfg cap, profileCap) as a
	// defence-in-depth check so oversize files never hit the wire.
	profileCap atomic.Int64
}

// ProfileCap returns the cached per-profile size cap in bytes.  Zero when
// no Health probe has succeeded yet.
func (p *cdrPooledClient) ProfileCap() int64 {
	return p.profileCap.Load()
}

// Healthy reports the poller's latest view.  Lock-free.
func (p *cdrPooledClient) Healthy() bool {
	return p.healthy.Load() == 1
}

// setHealth updates the snapshot atomically.  Used by the poller.
// Also refreshes the cached per-profile size cap from the first profile
// in the response (Sluice v0.1 always surfaces "default" first).
func (p *cdrPooledClient) setHealth(h *pb.HealthResponse) {
	p.healthMu.Lock()
	p.lastHealth = h
	p.lastHealthAt = time.Now()
	p.healthMu.Unlock()
	if h != nil && h.Healthy {
		p.healthy.Store(1)
	} else {
		p.healthy.Store(0)
	}
	// Profile cap: take the cap from the server's default profile.
	// A zero value means "no cap from server" — we keep our own default.
	if h != nil && len(h.Profiles) > 0 && h.Profiles[0] != nil && h.Profiles[0].MaxFileSizeBytes > 0 {
		p.profileCap.Store(h.Profiles[0].MaxFileSizeBytes)
	}
}

// clearHealth marks unhealthy (e.g. after repeated probe failures).
func (p *cdrPooledClient) clearHealth() {
	p.healthMu.Lock()
	p.lastHealth = nil
	p.lastHealthAt = time.Time{}
	p.healthMu.Unlock()
	p.healthy.Store(0)
}

// HealthSnapshot returns a copy of the most recent Health response and its
// timestamp.  Nil response means "no data yet".
func (p *cdrPooledClient) HealthSnapshot() (*pb.HealthResponse, time.Time) {
	p.healthMu.RLock()
	defer p.healthMu.RUnlock()
	return p.lastHealth, p.lastHealthAt
}

// ─── Pool ───────────────────────────────────────────────────────────────────

// cdrClientPool is the process-wide collection of live Sluice clients.
// Rebuilt in full by initCDRClient() each time the registry / config
// changes.  Safe for concurrent access: reads take an RLock, rebuilds
// take the write lock.
type cdrClientPool struct {
	mu      sync.RWMutex
	clients []*cdrPooledClient // in registry order
	rrNext  atomic.Int64       // round-robin cursor
}

// cdrPool is the package-wide pool singleton.
var cdrPool = &cdrClientPool{}

// Len returns the number of clients in the pool (healthy or not).
func (p *cdrClientPool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.clients)
}

// List returns a shallow snapshot of pool members.  Useful for
// observability (/api/cdr/instances) and the health poller.
func (p *cdrClientPool) List() []*cdrPooledClient {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*cdrPooledClient, len(p.clients))
	copy(out, p.clients)
	return out
}

// Get returns the pooled client for an instance name, or nil.
func (p *cdrClientPool) Get(name string) *cdrPooledClient {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, pc := range p.clients {
		if pc.Name == name {
			return pc
		}
	}
	return nil
}

// Pick returns the next available client using round-robin with
// circuit-breaker filtering.  Returns nil when every instance has an
// open breaker (caller applies fail-mode).
//
// Strategy: start from the rr cursor; the first client whose breaker
// Allow() returns true wins.  Advances the cursor before returning so
// subsequent calls on a stable pool spread load.
func (p *cdrClientPool) Pick() *cdrPooledClient {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := len(p.clients)
	if n == 0 {
		return nil
	}
	// Reserve the starting cursor once so concurrent Pick() calls
	// don't all probe the same client.
	start := int(p.rrNext.Add(1)-1) % n
	if start < 0 {
		start += n
	}
	for i := 0; i < n; i++ {
		candidate := p.clients[(start+i)%n]
		if candidate.Breaker.Allow() {
			return candidate
		}
	}
	return nil
}

// replace swaps the pool contents atomically.  Old clients NOT in the new
// set are closed to release their connections.  Instances that exist in
// both old and new keep their Breaker state (we don't want a restart /
// reconfig to forget that a Sluice has been misbehaving for minutes).
func (p *cdrClientPool) replace(newClients []*cdrPooledClient) {
	p.mu.Lock()
	old := p.clients
	p.clients = newClients
	p.mu.Unlock()
	// Close old clients that aren't carried over.
	for _, oc := range old {
		carried := false
		for _, nc := range newClients {
			if nc.Client == oc.Client {
				carried = true
				break
			}
		}
		if !carried && oc.Client != nil {
			_ = oc.Client.Close()
		}
	}
}

// shutdown closes every client in the pool and empties it.  Called from
// shutdownCDRClient during graceful shutdown.
func (p *cdrClientPool) shutdown() {
	p.mu.Lock()
	old := p.clients
	p.clients = nil
	p.mu.Unlock()
	for _, pc := range old {
		if pc.Client != nil {
			_ = pc.Client.Close()
		}
	}
}

// ─── Package-level conveniences ────────────────────────────────────────────

// cdrPickPooled returns the pool-aware selected client with full
// per-instance state (profileCap, breaker, health).  Returns nil when
// no instance is available — callers treat nil as "skip CDR" and apply
// fail_mode.  This is the proxy hot path's selector.
func cdrPickPooled() *cdrPooledClient {
	return cdrPool.Pick()
}

// cdrPoolInstallSingleForTest registers `c` as the sole pool member
// (named "test") for the duration of a unit test.  Tests should defer
// cdrPool.shutdown() to clean up.  Panics outside test environments.
func cdrPoolInstallSingleForTest(c *CDRClient) {
	pc := &cdrPooledClient{
		Name:    "test",
		Client:  c,
		Breaker: newCDRCircuitBreaker(cdrBreakerConfig{}),
	}
	cdrPool.replace([]*cdrPooledClient{pc})
}

// cdrPoolWritePrometheus emits per-instance pool state for /metrics.
// Called from cdrWritePrometheus in cdr_metrics.go.
func cdrPoolWritePrometheus(w interface {
	WriteString(string) (int, error)
}) {
	cdrPool.mu.RLock()
	defer cdrPool.mu.RUnlock()
	if len(cdrPool.clients) == 0 {
		return
	}
	_, _ = w.WriteString("\n# HELP culvert_cdr_pool_instance_healthy Per-instance health (1 = last Health probe succeeded)\n")
	_, _ = w.WriteString("# TYPE culvert_cdr_pool_instance_healthy gauge\n")
	replacer := promLabelEscaper
	for _, pc := range cdrPool.clients {
		safe := replacer.Replace(pc.Name)
		line := fmt.Sprintf("culvert_cdr_pool_instance_healthy{instance=%q} %d\n", safe, pc.healthy.Load())
		_, _ = w.WriteString(line)
	}
	_, _ = w.WriteString("\n# HELP culvert_cdr_pool_breaker_state Per-instance circuit-breaker state (0=closed, 1=open, 2=half_open)\n")
	_, _ = w.WriteString("# TYPE culvert_cdr_pool_breaker_state gauge\n")
	for _, pc := range cdrPool.clients {
		safe := replacer.Replace(pc.Name)
		line := fmt.Sprintf("culvert_cdr_pool_breaker_state{instance=%q} %d\n", safe, pc.Breaker.State())
		_, _ = w.WriteString(line)
	}
	_, _ = w.WriteString("\n# HELP culvert_cdr_pool_breaker_trips_total Per-instance total Allow() denials while breaker is open\n")
	_, _ = w.WriteString("# TYPE culvert_cdr_pool_breaker_trips_total counter\n")
	for _, pc := range cdrPool.clients {
		safe := replacer.Replace(pc.Name)
		stats := pc.Breaker.Stats()
		line := fmt.Sprintf("culvert_cdr_pool_breaker_trips_total{instance=%q} %d\n", safe, stats.TotalTrips)
		_, _ = w.WriteString(line)
	}
}

// promLabelEscaper reuses the Prometheus exposition-format escape rules
// applied to rule names in metrics.go.
var promLabelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

// cdrMarkOutcome reports an instance's outcome to its circuit breaker.
// `isFailure` is the caller's classification (transport / ERROR status
// count; CLEAN / SANITIZED / BLOCKED / UNSUPPORTED / file_too_large
// do NOT count as failures).
func cdrMarkOutcome(instanceName string, isFailure bool) {
	pc := cdrPool.Get(instanceName)
	if pc == nil {
		return
	}
	if isFailure {
		pc.Breaker.OnFailure()
	} else {
		pc.Breaker.OnSuccess()
	}
}

// ─── Construction from the registry ────────────────────────────────────────

// buildCDRPoolFromRegistry enumerates enrolled instances and dials one
// client per enabled entry.  Returns (pool, firstErr) so a partial pool
// still works while admins investigate broken instances through
// /api/cdr/instances.
func buildCDRPoolFromRegistry(cfg CDRConfig, oldPool []*cdrPooledClient) (pool []*cdrPooledClient, firstErr error) {
	instances := cdrInstances.List()
	if len(instances) == 0 {
		return bootstrapPoolFromConfig(cfg)
	}
	for _, inst := range instances {
		if !inst.IsEnabled() {
			continue
		}
		pc, err := dialEnrolledInstance(inst, cfg, oldPool)
		if err != nil {
			logger.Printf("CDR: pool: skipping %q: %v", sanitizeLog(inst.Name), err)
			if firstErr == nil {
				firstErr = fmt.Errorf("instance %q: %w", inst.Name, err)
			}
			continue
		}
		pool = append(pool, pc)
	}
	if len(pool) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return pool, firstErr
}

// bootstrapPoolFromConfig dials a single anonymous client from
// CDRConfig when no instances are enrolled yet.  Used for the
// pre-enrollment / test path.  Kept separate from the registry loop
// so the main function stays under gocognit.
func bootstrapPoolFromConfig(cfg CDRConfig) ([]*cdrPooledClient, error) {
	if cfg.Endpoint == "" || cfg.ServerFingerprint == "" {
		return nil, errors.New("cdr: no enrolled instances and no cdr.endpoint configured")
	}
	pc, err := dialSingleFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	return []*cdrPooledClient{pc}, nil
}

// dialEnrolledInstance builds one pooled client from a registry entry,
// carrying the circuit-breaker state forward if the instance was
// already in the old pool.
func dialEnrolledInstance(inst *CDREnrolledInstance, cfg CDRConfig, oldPool []*cdrPooledClient) (*cdrPooledClient, error) {
	var carriedBreaker *cdrCircuitBreaker
	for _, oc := range oldPool {
		if oc.Name == inst.Name {
			carriedBreaker = oc.Breaker
			break
		}
	}
	ca, cert, key, err := loadCDRCertBundle(inst.CACertPath, inst.ClientCertPath, inst.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("cert load: %w", err)
	}
	clientCfg := CDRClientConfig{
		Endpoint:            inst.Endpoint,
		ServerFingerprintHx: inst.ServerFingerprint,
		CACertPEM:           ca,
		ClientCertPEM:       cert,
		ClientKeyPEM:        key,
	}
	if cfg.TimeoutSec > 0 {
		clientCfg.Timeout = time.Duration(cfg.TimeoutSec) * time.Second
	}
	if cfg.ChunkSizeKB > 0 {
		clientCfg.ChunkSize = cfg.ChunkSizeKB * 1024
	}
	client, derr := NewCDRClient(clientCfg)
	if derr != nil {
		return nil, fmt.Errorf("dial: %w", derr)
	}
	if carriedBreaker == nil {
		carriedBreaker = newCDRCircuitBreaker(cdrBreakerConfig{})
	}
	return &cdrPooledClient{
		Name:    inst.Name,
		Client:  client,
		Breaker: carriedBreaker,
	}, nil
}

// dialSingleFromConfig builds a single pooled client from CDRConfig
// (pre-enrollment / test bootstrap path).  Name = "default".
func dialSingleFromConfig(cfg CDRConfig) (*cdrPooledClient, error) {
	clientCfg := CDRClientConfig{
		Endpoint:            cfg.Endpoint,
		ServerFingerprintHx: cfg.ServerFingerprint,
	}
	if cfg.CertsDir != "" {
		ca, cert, key, err := loadCDRCertBundle(
			cfg.CertsDir+"/ca.pem",
			cfg.CertsDir+"/client.pem",
			cfg.CertsDir+"/client.key",
		)
		if err != nil {
			return nil, err
		}
		clientCfg.CACertPEM = ca
		clientCfg.ClientCertPEM = cert
		clientCfg.ClientKeyPEM = key
	}
	if cfg.TimeoutSec > 0 {
		clientCfg.Timeout = time.Duration(cfg.TimeoutSec) * time.Second
	}
	if cfg.ChunkSizeKB > 0 {
		clientCfg.ChunkSize = cfg.ChunkSizeKB * 1024
	}
	client, err := NewCDRClient(clientCfg)
	if err != nil {
		return nil, err
	}
	return &cdrPooledClient{
		Name:    "default",
		Client:  client,
		Breaker: newCDRCircuitBreaker(cdrBreakerConfig{}),
	}, nil
}
