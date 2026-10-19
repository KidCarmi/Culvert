// Package ipsurrogate is the opt-in browser-to-proxy identity transport
// (F-SSO-SCOPE-1, #1528): after a browser completes an interactive SSO login
// on the admin UI host, the client IP that completed it is bound to the
// authenticated identity for a bounded time, and the proxy attributes traffic
// from that IP to that identity.
//
// Why this exists at all: the SSO session cookie is host-only on the admin UI
// host, so a browser presents it on requests to the UI and on nothing else —
// never on requests to other sites, never inside a CONNECT tunnel. On its own
// a browser SSO login therefore authenticates NO proxied traffic. An IP
// surrogate is the standard way a forward proxy closes that gap, and its
// trade-off is the IP itself: every client behind one address (NAT, a
// terminal server, a shared jump host) is the same "browser". That is why the
// transport is OFF by default, why the operator can exclude source ranges
// from binding, and why a binding expires and is revoked on logout.
//
// The store is the engine only: it holds bindings, bounds them, and answers
// lookups. Deciding WHEN to bind (enabled, source not excluded, the login
// did not arrive through the proxy itself) and what a hit authorises is the
// caller's job.
//
// Lookups run on the proxy's per-request path, so the store is sharded (64
// cache-line-padded shards keyed by a per-store maphash of the address) and
// a disabled store answers with one atomic load. Bindings are never evicted
// to make room: at capacity a bind is REFUSED (the user is challenged as
// before), because evicting a live binding would silently de-authenticate
// someone else.
package ipsurrogate

import (
	"errors"
	"hash/maphash"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Identity is what a binding attributes traffic to. Groups is shared with
// every lookup that hits it and must be treated as read-only.
type Identity struct {
	Sub      string
	Email    string
	Provider string
	Groups   []string
}

// Entry is one binding as reported by List.
type Entry struct {
	Addr     netip.Addr
	Identity Identity
	Bound    time.Time
	Expires  time.Time
}

// ErrFull is returned by Bind when the store holds MaxEntries live bindings.
var ErrFull = errors.New("ipsurrogate: binding table is full")

// ErrInvalid is returned by Bind for an invalid address, an empty subject or
// a non-positive TTL.
var ErrInvalid = errors.New("ipsurrogate: invalid binding")

const shardCount = 64

type entry struct {
	id      Identity
	bound   time.Time
	expires time.Time
}

type shard struct {
	mu   sync.RWMutex
	m    map[netip.Addr]*entry
	hits atomic.Int64 // lookups answered from this shard (a shared counter would be a hot cache line)
	_    [32]byte     // pad past a cache line (RWMutex 24 + map 8 + hits 8 + 32 = 72)
}

// Store holds the bindings.
type Store struct {
	enabled atomic.Bool
	max     int64
	n       atomic.Int64
	seed    maphash.Seed
	shards  [shardCount]shard
}

// New returns a disabled store bounded at maxEntries live bindings.
func New(maxEntries int) *Store {
	if maxEntries < 1 {
		maxEntries = 1
	}
	s := &Store{max: int64(maxEntries), seed: maphash.MakeSeed()}
	for i := range s.shards {
		s.shards[i].m = make(map[netip.Addr]*entry)
	}
	return s
}

// SetEnabled turns lookups (and binds) on or off. Disabling keeps the
// bindings; Clear removes them.
func (s *Store) SetEnabled(on bool) { s.enabled.Store(on) }

// Enabled reports whether the transport is on.
func (s *Store) Enabled() bool { return s.enabled.Load() }

func canon(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

func (s *Store) shardFor(a netip.Addr) *shard {
	b := a.As16()
	return &s.shards[maphash.Bytes(s.seed, b[:])%shardCount]
}

// Bind attributes traffic from addr to id until now+ttl. The most recent
// login on an address wins; when that replaces a LIVE binding of a different
// identity (provider, subject), the replaced identity is returned so the
// caller can make the takeover visible — on a shared address (NAT, terminal
// server) it means traffic moved from one person to another. At capacity,
// expired bindings are swept first; if the store is still full the bind is
// refused with ErrFull.
func (s *Store) Bind(addr netip.Addr, id Identity, ttl time.Duration, now time.Time) (*Identity, error) {
	if !addr.IsValid() || id.Sub == "" || ttl <= 0 {
		return nil, ErrInvalid
	}
	addr = canon(addr)
	id.Groups = append([]string(nil), id.Groups...)
	e := &entry{id: id, bound: now, expires: now.Add(ttl)}
	sh := s.shardFor(addr)
	sh.mu.Lock()
	if cur, ok := sh.m[addr]; ok { // replace (live or expired): no new slot
		sh.m[addr] = e
		sh.mu.Unlock()
		return displaced(cur, id, now), nil
	}
	sh.mu.Unlock()
	if !s.reserve() {
		s.Prune(now)
		if !s.reserve() {
			return nil, ErrFull
		}
	}
	sh.mu.Lock()
	cur, ok := sh.m[addr]
	if ok { // bound concurrently: give the slot back
		s.n.Add(-1)
	}
	sh.m[addr] = e
	sh.mu.Unlock()
	if ok {
		return displaced(cur, id, now), nil
	}
	return nil, nil
}

// displaced returns cur's identity when it was live and belongs to someone
// other than id.
func displaced(cur *entry, id Identity, now time.Time) *Identity {
	if cur == nil || !now.Before(cur.expires) || (cur.id.Sub == id.Sub && cur.id.Provider == id.Provider) {
		return nil
	}
	prev := cur.id
	return &prev
}

// reserve claims one slot under the bound; the CAS keeps concurrent binds on
// different shards from overshooting it.
func (s *Store) reserve() bool {
	for {
		c := s.n.Load()
		if c >= s.max {
			return false
		}
		if s.n.CompareAndSwap(c, c+1) {
			return true
		}
	}
}

// Lookup returns the identity bound to addr. A disabled store, an unbound
// address and an expired binding all miss.
func (s *Store) Lookup(addr netip.Addr, now time.Time) (Identity, bool) {
	if !s.enabled.Load() || !addr.IsValid() {
		return Identity{}, false
	}
	addr = canon(addr)
	sh := s.shardFor(addr)
	sh.mu.RLock()
	e := sh.m[addr]
	sh.mu.RUnlock()
	if e == nil || !now.Before(e.expires) {
		return Identity{}, false
	}
	sh.hits.Add(1)
	return e.id, true
}

// Hits returns how many lookups were answered from a binding.
func (s *Store) Hits() int64 {
	var n int64
	for i := range s.shards {
		n += s.shards[i].hits.Load()
	}
	return n
}

// Revoke removes addr's binding and reports whether one existed.
func (s *Store) Revoke(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = canon(addr)
	sh := s.shardFor(addr)
	sh.mu.Lock()
	_, ok := sh.m[addr]
	if ok {
		delete(sh.m, addr)
		s.n.Add(-1)
	}
	sh.mu.Unlock()
	return ok
}

// RevokeIdentity removes every binding of (provider, sub) — logout in one
// browser ends the user's surrogate everywhere — and returns how many were
// removed. The same subject from another provider is a different identity.
func (s *Store) RevokeIdentity(provider, sub string) int {
	return s.removeWhere(func(_ netip.Addr, e *entry) bool { return e.id.Sub == sub && e.id.Provider == provider })
}

// RemoveIf removes every binding for which drop returns true.
func (s *Store) RemoveIf(drop func(addr netip.Addr, id Identity) bool) int {
	return s.removeWhere(func(a netip.Addr, e *entry) bool { return drop(a, e.id) })
}

// ClampExpiry shortens every binding expiring after until to until, so a
// lowered lifetime applies to bindings that already exist.
func (s *Store) ClampExpiry(until time.Time) {
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for a, e := range sh.m {
			if e.expires.After(until) {
				c := *e
				c.expires = until
				sh.m[a] = &c
			}
		}
		sh.mu.Unlock()
	}
}

// Clear removes every binding and returns how many there were.
func (s *Store) Clear() int { return s.removeWhere(func(netip.Addr, *entry) bool { return true }) }

// Prune removes expired bindings and returns how many were removed.
func (s *Store) Prune(now time.Time) int {
	return s.removeWhere(func(_ netip.Addr, e *entry) bool { return !now.Before(e.expires) })
}

func (s *Store) removeWhere(match func(netip.Addr, *entry) bool) int {
	removed := 0
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for a, e := range sh.m {
			if match(a, e) {
				delete(sh.m, a)
				removed++
			}
		}
		sh.mu.Unlock()
	}
	s.n.Add(int64(-removed))
	return removed
}

// Len returns the number of stored bindings (live or not yet swept).
func (s *Store) Len() int { return int(s.n.Load()) }

// Max returns the binding bound.
func (s *Store) Max() int { return int(s.max) }

// LiveCount returns the number of unexpired bindings without allocating.
func (s *Store) LiveCount(now time.Time) int {
	n := 0
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.RLock()
		for _, e := range sh.m {
			if now.Before(e.expires) {
				n++
			}
		}
		sh.mu.RUnlock()
	}
	return n
}

// List returns the live bindings, oldest bind first, ties by address.
func (s *Store) List(now time.Time) []Entry {
	var out []Entry
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.RLock()
		for a, e := range sh.m {
			if now.Before(e.expires) {
				out = append(out, Entry{Addr: a, Identity: e.id, Bound: e.bound, Expires: e.expires})
			}
		}
		sh.mu.RUnlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Bound.Equal(out[j].Bound) {
			return out[i].Bound.Before(out[j].Bound)
		}
		return out[i].Addr.Less(out[j].Addr)
	})
	return out
}
