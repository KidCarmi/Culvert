package denial

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
)

// Config parameterises the aggregator. Bounds are validated event limits threaded
// through by the manager. Window is the coalescing window; MaxBuckets and
// MaxPerSource bound aggregation-key cardinality so an attacker cannot create an
// unbounded number of keys.
type Config struct {
	Capability   model.Capability
	NodeID       string
	Window       time.Duration
	MaxBuckets   int
	MaxPerSource int
	// IDGen mints a safe, unpredictable, prefixed id (evt_/rpl_/cor_). Injected so
	// tests are deterministic and production uses crypto/rand.
	IDGen func(prefix string) string
}

// Observation is one denial event fed to the aggregator BEFORE it can occupy any
// shared queue. Tenant and Principal are set ONLY when verified identity exists
// (the authenticated-but-unauthorized case); for a pre-authentication failure
// they are empty and no tenant is ever invented from an attacker hint.
type Observation struct {
	Now       time.Time
	Listener  string
	Source    string // raw source; normalized internally
	Reason    string
	Tenant    string // "" before identity exists
	Principal string // "" before identity exists
}

type aggregate struct {
	listener     string
	sourceBucket string
	reason       string
	tenant       string
	principal    string
	windowIdx    int64
	count        uint64
	firstSeen    int64
	lastSeen     int64
}

// Aggregator coalesces denial observations into bounded O(1) aggregates.
type Aggregator struct {
	mu        sync.Mutex
	cfg       Config
	buckets   map[string]*aggregate
	perSource map[string]int
	// counters (safe, non-secret).
	admitted uint64
	dropped  uint64 // observations dropped by a cardinality bound (still denied)
}

// NewAggregator builds an aggregator. It does not start any goroutine; the manager
// drives Flush on a bounded cadence.
func NewAggregator(cfg Config) *Aggregator {
	return &Aggregator{cfg: cfg, buckets: map[string]*aggregate{}, perSource: map[string]int{}}
}

// Observe records one denial. It is O(1) and never blocks. It returns true when
// the denial was folded into an aggregate, and false when a cardinality bound
// dropped it (the triggering request is still denied by the caller regardless —
// admission to the aggregate is not admission of the request). A dropped
// observation is counted so the manager can surface denial-lane pressure.
func (a *Aggregator) Observe(o Observation) bool {
	src := NormalizeSource(o.Source)
	win := a.windowIndex(o.Now)
	key := aggKey(o.Listener, src, o.Reason, o.Tenant, o.Principal, win)

	a.mu.Lock()
	defer a.mu.Unlock()

	if agg, ok := a.buckets[key]; ok {
		agg.count++
		ns := o.Now.UnixNano()
		if ns > agg.lastSeen {
			agg.lastSeen = ns
		}
		if ns < agg.firstSeen {
			agg.firstSeen = ns
		}
		a.admitted++
		return true
	}
	// New key: enforce cardinality bounds before creating.
	if len(a.buckets) >= a.cfg.MaxBuckets || a.perSource[src] >= a.cfg.MaxPerSource {
		a.dropped++
		return false
	}
	ns := o.Now.UnixNano()
	a.buckets[key] = &aggregate{
		listener: o.Listener, sourceBucket: src, reason: o.Reason,
		tenant: o.Tenant, principal: o.Principal, windowIdx: win,
		count: 1, firstSeen: ns, lastSeen: ns,
	}
	a.perSource[src]++
	a.admitted++
	return true
}

// Flush returns the denial-aggregate events whose window has closed (windowIdx <
// current window), removing them from the map. force=true flushes every aggregate
// (used at shutdown). The manager commits the returned events into P-DEN; a
// commit failure is the manager's denial-loss/degraded concern, not the
// aggregator's — a returned event is already coalesced O(1).
func (a *Aggregator) Flush(now time.Time, force bool) []*model.Event {
	cur := a.windowIndex(now)
	a.mu.Lock()
	defer a.mu.Unlock()

	var out []*model.Event
	for k, agg := range a.buckets {
		if !force && agg.windowIdx >= cur {
			continue // window still open; keep coalescing
		}
		out = append(out, a.buildEventLocked(agg))
		delete(a.buckets, k)
		if a.perSource[agg.sourceBucket] > 0 {
			a.perSource[agg.sourceBucket]--
			if a.perSource[agg.sourceBucket] == 0 {
				delete(a.perSource, agg.sourceBucket)
			}
		}
	}
	return out
}

// buildEventLocked renders a coalesced aggregate as a denial-aggregate event.
func (a *Aggregator) buildEventLocked(agg *aggregate) *model.Event {
	e := &model.Event{
		SchemaVersion: model.SchemaVersion,
		EventID:       a.cfg.IDGen("evt_"),
		Phase:         model.PhaseDenialAggregate,
		Criticality:   model.CritDenial,
		Partition:     model.PartDen,
		Capability:    a.cfg.Capability,
		ActionClass:   model.ActionClassNone,
		NodeID:        a.cfg.NodeID,
		DomainID:      a.cfg.NodeID + "|" + a.cfg.Capability.String() + "|" + model.PartDen.String(),
		TimeUnixNano:  agg.lastSeen,
		ReplayID:      a.cfg.IDGen("rpl_"),
		CorrelationID: a.cfg.IDGen("cor_"),
		Denial: &model.DenialEvidence{
			DenialReason:      agg.reason,
			ListenerID:        agg.listener,
			SourceBucket:      agg.sourceBucket,
			Count:             agg.count,
			FirstSeenUnixNano: agg.firstSeen,
			LastSeenUnixNano:  agg.lastSeen,
		},
	}
	// Tenant/principal are included ONLY when verified identity existed.
	if agg.tenant != "" {
		e.Identity.Tenant = agg.tenant
	}
	if agg.principal != "" {
		e.Identity.PrincipalID = agg.principal
	}
	_, _ = e.ComputeDigest()
	return e
}

func (a *Aggregator) windowIndex(now time.Time) int64 {
	w := a.cfg.Window.Nanoseconds()
	if w <= 0 {
		w = int64(time.Second)
	}
	return now.UnixNano() / w
}

// Stats is a safe snapshot of the aggregator.
type Stats struct {
	ActiveBuckets int
	Admitted      uint64
	Dropped       uint64
}

// Stats returns a safe snapshot.
func (a *Aggregator) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	return Stats{ActiveBuckets: len(a.buckets), Admitted: a.admitted, Dropped: a.dropped}
}

// aggKey builds the canonical aggregation key. The empty tenant/principal case
// (pre-identity) yields a key with empty attribution fields — an explicitly
// unattributed security scope, never guessed into a tenant.
func aggKey(listener, source, reason, tenant, principal string, win int64) string {
	var b strings.Builder
	b.WriteString(listener)
	b.WriteByte('|')
	b.WriteString(source)
	b.WriteByte('|')
	b.WriteString(reason)
	b.WriteByte('|')
	b.WriteString(tenant)
	b.WriteByte('|')
	b.WriteString(principal)
	b.WriteByte('|')
	b.WriteString(strconv.FormatInt(win, 10))
	return b.String()
}
