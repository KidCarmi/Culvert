package keyedmutex

import "sync"

// Mutex serializes work per string key without holding a global lock during
// the critical section. Construct one with New; the zero value is not usable.
type Mutex struct {
	mu sync.Mutex
	m  map[string]*entry
}

type entry struct {
	mu   sync.Mutex
	refs int
}

// New returns an empty Mutex.
func New() *Mutex { return &Mutex{m: make(map[string]*entry)} }

// Lock acquires the per-key mutex and returns an unlock func that releases it and
// garbage-collects the entry when no waiters remain. The unlock func must be
// called exactly once.
func (k *Mutex) Lock(key string) func() {
	k.mu.Lock()
	e := k.m[key]
	if e == nil {
		e = &entry{}
		k.m[key] = e
	}
	e.refs++
	k.mu.Unlock()

	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		k.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
}
