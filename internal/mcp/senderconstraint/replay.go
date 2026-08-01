package senderconstraint

import (
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// ReplayCache is a bounded, time-expiring, race-safe, per-capability DPoP-proof
// replay cache. Keys are partitioned by (capability, issuer, client, proof-key
// thumbprint) with the proof jti as the entry within a partition, so no partition
// can grow unbounded from attacker-controlled input and one capability can never
// exhaust the other (each capability has its own total budget). There are no
// per-entry goroutines: expired entries are swept opportunistically on access,
// amortizing cleanup. Full-capacity behavior is explicit and FAILS CLOSED.
type ReplayCache struct {
	mu  sync.Mutex
	cap [2]capState // indexed by protocol.Capability (Gateway, Management)
	lim limits.AuthLimits
	now func() time.Time
}

type capState struct {
	total int
	parts map[string]map[string]time.Time // partitionKey → jti → expiry
}

// NewReplayCache builds a replay cache bounded by lim, using clk (nil ⇒ time.Now).
func NewReplayCache(lim limits.AuthLimits, clk func() time.Time) *ReplayCache {
	if clk == nil {
		clk = time.Now
	}
	c := &ReplayCache{lim: lim, now: clk}
	for i := range c.cap {
		c.cap[i] = capState{parts: make(map[string]map[string]time.Time)}
	}
	return c
}

// PartitionKey builds the replay partition key from the identity-bearing
// dimensions. jti is the per-request entry within the partition.
func PartitionKey(issuer, client, thumbprint string) string {
	// The separator cannot appear in a base64url thumbprint; issuer/client are
	// length-delimited to avoid ambiguity.
	var b strings.Builder
	writeSeg(&b, issuer)
	writeSeg(&b, client)
	writeSeg(&b, thumbprint)
	return b.String()
}

func writeSeg(b *strings.Builder, s string) {
	b.WriteString(itoa(len(s)))
	b.WriteByte(':')
	b.WriteString(s)
	b.WriteByte('|')
}

// CheckAndAdd records a fresh proof jti in its partition and returns nil, or
// ReasonDPoPReplay if the jti was already seen within its (unexpired) window. It
// fails closed (also ReasonDPoPReplay) when the partition or the capability cache
// is at capacity and no expired room can be reclaimed — a required
// sender-constrained profile never admits on best-effort.
func (c *ReplayCache) CheckAndAdd(capb protocol.Capability, partKey, jti string, ttl time.Duration) error {
	if jti == "" {
		return mcperr.New(mcperr.ReasonDPoPMalformed, "senderconstraint.replay", "empty proof jti")
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	cs := &c.cap[capIndex(capb)]
	part := cs.parts[partKey]
	if part != nil {
		cs.total -= sweepPartition(part, now) // reclaim expired room first
		if exp, seen := part[jti]; seen && exp.After(now) {
			return mcperr.New(mcperr.ReasonDPoPReplay, "senderconstraint.replay", "duplicate proof jti")
		}
	}
	// If the capability cache looks full, reclaim expired room across ALL of its
	// partitions before failing closed — otherwise a cache filled across many
	// distinct (attacker-rotated) partitions would reject every new proof
	// indefinitely even after its entries expire, since only the incoming
	// partition was swept above.
	if cs.total >= c.lim.MaxReplayEntries() {
		cs.total -= sweepCapState(cs, now)
		part = cs.parts[partKey] // the full sweep may have deleted an emptied partition
	}
	if cs.total >= c.lim.MaxReplayEntries() {
		return mcperr.New(mcperr.ReasonDPoPReplay, "senderconstraint.replay", "capability replay cache at capacity (fail closed)")
	}
	if part == nil {
		part = make(map[string]time.Time, 4)
		cs.parts[partKey] = part
	}
	if _, exists := part[jti]; !exists && len(part) >= c.lim.MaxReplayPerPart() {
		return mcperr.New(mcperr.ReasonDPoPReplay, "senderconstraint.replay", "replay partition at capacity (fail closed)")
	}
	if _, exists := part[jti]; !exists {
		cs.total++
	}
	part[jti] = now.Add(ttl)
	return nil
}

// Sweep removes all expired entries across both capabilities and returns the count
// reclaimed. Callers may invoke it on a cadence; access-time sweeping already keeps
// hot partitions bounded, so this is a background convenience, not a requirement.
func (c *ReplayCache) Sweep() int {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	reclaimed := 0
	for i := range c.cap {
		cs := &c.cap[i]
		n := sweepCapState(cs, now)
		cs.total -= n
		reclaimed += n
	}
	return reclaimed
}

// Size returns the entry count for a capability (for tests/metrics).
func (c *ReplayCache) Size(capb protocol.Capability) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cap[capIndex(capb)].total
}

// sweepCapState reclaims expired jti across every partition of one capability,
// deleting emptied partitions, and returns the total count removed.
func sweepCapState(cs *capState, now time.Time) int {
	reclaimed := 0
	for pk, part := range cs.parts {
		reclaimed += sweepPartition(part, now)
		if len(part) == 0 {
			delete(cs.parts, pk)
		}
	}
	return reclaimed
}

// sweepPartition deletes expired jti from a partition and returns the count removed.
func sweepPartition(part map[string]time.Time, now time.Time) int {
	removed := 0
	for jti, exp := range part {
		if !exp.After(now) {
			delete(part, jti)
			removed++
		}
	}
	return removed
}

func capIndex(c protocol.Capability) int {
	if c == protocol.Management {
		return 1
	}
	return 0
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
