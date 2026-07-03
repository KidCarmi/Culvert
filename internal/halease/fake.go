package halease

import (
	"context"
	"sync"
	"time"
)

// Fake is the in-memory Provider used to unit-test the Culvert-side HA
// logic (ADR-0005 S1). It implements the same contract the etcd backend
// does — the shared conformance suite in halease_test.go pins that both
// stay in agreement. Time is injectable so expiry is deterministic.
type Fake struct {
	mu        sync.Mutex
	holder    string
	epoch     int64 // strictly monotonic grant counter
	expiresAt time.Time
	ttl       time.Duration
	now       func() time.Time
}

// NewFake builds a Fake with the given lease TTL.
func NewFake(ttl time.Duration) *Fake {
	return &Fake{ttl: ttl, now: time.Now}
}

// SetNowForTest injects a clock, returning the previous one (deterministic
// expiry in tests).
func (f *Fake) SetNowForTest(now func() time.Time) (prev func() time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	prev = f.now
	f.now = now
	return prev
}

// ExpireForTest force-expires the current lease without changing the holder
// record — the next Acquire wins as if the TTL lapsed.
func (f *Fake) ExpireForTest() {
	f.mu.Lock()
	f.expiresAt = f.now().Add(-time.Second)
	f.mu.Unlock()
}

// heldLocked reports whether a live lease exists. Caller holds f.mu.
func (f *Fake) heldLocked() bool {
	return f.holder != "" && f.now().Before(f.expiresAt)
}

// Acquire implements Provider.
func (f *Fake) Acquire(_ context.Context, candidateID string) (bool, Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.heldLocked() {
		return false, f.statusLocked(), nil
	}
	f.holder = candidateID
	f.epoch++
	f.expiresAt = f.now().Add(f.ttl)
	return true, f.statusLocked(), nil
}

// Renew implements Provider.
func (f *Fake) Renew(_ context.Context, holderID string, epoch int64) (bool, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.heldLocked() || f.holder != holderID || f.epoch != epoch {
		return false, 0, nil
	}
	f.expiresAt = f.now().Add(f.ttl)
	return true, f.ttl, nil
}

// Read implements Provider.
func (f *Fake) Read(_ context.Context) (Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.statusLocked(), nil
}

// Close implements Provider (no resources to release).
func (f *Fake) Close() error { return nil }

// statusLocked builds the Status snapshot. Caller holds f.mu.
func (f *Fake) statusLocked() Status {
	if !f.heldLocked() {
		// Expired or never held: no live holder, but the epoch watermark is
		// preserved (the fencing property is about grants, not reads).
		return Status{Epoch: f.epoch}
	}
	return Status{
		Holder:   f.holder,
		Epoch:    f.epoch,
		ValidFor: f.expiresAt.Sub(f.now()),
	}
}
