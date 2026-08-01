// Package broker is the listener-independent, Gateway-only credential broker for
// PR-4. It resolves an immutable CredentialPlan without exposing material (phase 1),
// then — only after an injected pre-materialization gate permits — materializes the
// credential inside a scoped, zeroizing callback (phase 2). It contains plaintext
// strictly inside that callback, prevents client-token passthrough by construction
// (it consumes only the PR-3 resolved identity), validates provider-returned scope
// and power against the plan, caches only encrypted envelopes, and supports bounded
// rotation and immediate revocation. It performs NO network I/O and makes no policy
// decision.
package broker

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/secret"
)

// Deps are the broker's injected dependencies. The registry/catalog are read via
// snapshot accessors; the KEK provider encrypts the cache; the clock is injected
// for deterministic tests.
type Deps struct {
	Profiles *profile.Store
	Registry *registry.Registry
	Catalog  *catalog.Catalog
	KEK      *secret.Provider
	Clock    func() time.Time
}

// Broker is the Gateway credential broker. It is safe for concurrent use.
type Broker struct {
	profiles *profile.Store
	reg      *registry.Registry
	cat      *catalog.Catalog
	kek      *secret.Provider
	now      func() time.Time
	lim      limits.CredentialLimits
	cache    *cache

	providersMu sync.RWMutex
	providers   map[profile.ProviderID]provider.Provider

	stateMu sync.Mutex
	states  map[profile.ID]*profileState
	inflt   map[profile.ID]*call

	sem     chan struct{} // global provider-request concurrency bound (MaxProviderConc)
	planSeq atomic.Uint64
}

// New builds a broker. Registry, Catalog and KEK are required; a nil clock defaults
// to time.Now.
func New(deps Deps, lim limits.CredentialLimits) *Broker {
	clk := deps.Clock
	if clk == nil {
		clk = time.Now
	}
	return &Broker{
		profiles:  deps.Profiles,
		reg:       deps.Registry,
		cat:       deps.Catalog,
		kek:       deps.KEK,
		now:       clk,
		lim:       lim,
		cache:     newCache(lim, clk),
		providers: make(map[profile.ProviderID]provider.Provider),
		states:    make(map[profile.ID]*profileState),
		inflt:     make(map[profile.ID]*call),
		sem:       make(chan struct{}, lim.MaxProviderConc()),
	}
}

// acquireProvider blocks until a global provider-request slot is free (bounding
// concurrency at MaxProviderConc across ALL profiles, so bursts across distinct
// profiles cannot exhaust the provider/process), or fails closed if the context is
// cancelled. releaseProvider returns the slot.
func (b *Broker) acquireProvider(ctx context.Context) error {
	select {
	case b.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return brokerErr(mcperr.ReasonProviderUnavailable, "provider concurrency limit; context cancelled")
	}
}

func (b *Broker) releaseProvider() { <-b.sem }

// RegisterProvider registers a provider under its id, bounded by the provider limit.
func (b *Broker) RegisterProvider(p provider.Provider) error {
	b.providersMu.Lock()
	defer b.providersMu.Unlock()
	if len(b.providers) >= b.lim.MaxProviders() {
		return brokerErr(mcperrResourceLimit, "provider capacity exhausted")
	}
	b.providers[p.ID()] = p
	return nil
}

func (b *Broker) provider(id profile.ProviderID) (provider.Provider, bool) {
	b.providersMu.RLock()
	defer b.providersMu.RUnlock()
	p, ok := b.providers[id]
	return p, ok
}

func (b *Broker) clock() time.Time             { return b.now() }
func (b *Broker) registry() *registry.Snapshot { return b.reg.Current() }
func (b *Broker) catalog() *catalog.Snapshot   { return b.cat.Current() }

// Plan validates the input and returns an immutable CredentialPlan. It is pure with
// respect to secret material: no provider call, no cache decrypt, no plaintext.
func (b *Broker) Plan(in PlanInput) (CredentialPlan, error) {
	planID := "plan-" + strconv.FormatUint(b.planSeq.Add(1), 10)
	return b.plan(in, planID)
}

// stateFor returns (creating if needed) the per-profile state guarding rotation,
// tombstones and the current version. Only the brief stateMu is held here; the
// per-profile lock is taken by callers for the actual operation.
func (b *Broker) stateFor(id profile.ID) *profileState {
	b.stateMu.Lock()
	defer b.stateMu.Unlock()
	st, ok := b.states[id]
	if !ok {
		st = &profileState{id: id, tombstones: make(map[profile.CredentialVersion]struct{})}
		b.states[id] = st
	}
	return st
}
