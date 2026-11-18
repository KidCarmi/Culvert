package alerts

// subscriptions.go — the atomically published read index behind HasSubscriber.
//
// WHY THIS EXISTS
//
// HasSubscriber is consulted SYNCHRONOUSLY on the proxy block path: recordStats
// (store.go) calls it for every request whose status is THREAT_BLOCKED,
// SCAN_BLOCKED, DPI_BLOCKED, POLICY_BLOCK or POLICY_DROP, so that a producer can
// skip the goroutine spawn, the payload allocation and the dedup-mutex round trip
// needed to deliver an alert to nobody. That gate is correct and worth keeping —
// but the check itself used to take as.mu.RLock, on the documented reasoning that
// "a reader lock is cheap".
//
// It is not. sync.RWMutex.RLock/RUnlock are two atomic read-modify-WRITES on one
// shared word, so every blocked request in the process wrote the same cache line
// purely to read a webhook list that in steady state never changes. That is not a
// constant cost but a process-wide THROUGHPUT CEILING, and it lands precisely when
// a gateway is under a scanning or beaconing flood — when block volume is highest
// and latency matters most. It is the same shape already found and fixed in
// internal/threatfeed, internal/connlimit, the IP filter and the top-hosts counter
// (store.go hostCounter), arriving once more on the one remaining per-request
// shared-word read those sweeps did not cover.
//
// Measured on a 4-core Xeon @ 2.30GHz, n=5, medians, ns/op, BOTH shapes in the
// SAME binary (the `_Legacy` benchmarks in subscriptions_bench_test.go keep the
// old RLock+scan alive as a negative control, so this A/B is re-runnable rather
// than a frozen number):
//
//	case                        impl       P=1      P=2      P=4    1→4 tput
//	no hooks (DEFAULT posture)  RWMutex   13.07    96.35   101.70     0.13x
//	                            index      2.06     1.02     0.52     4.00x
//	3 hooks, subscribed (hit)   RWMutex   13.87   122.30   129.50     0.11x
//	                            index      7.76     3.66     1.82     4.27x
//	5 hooks, not subscribed     RWMutex   17.76   163.60   193.80     0.09x
//	                            index      9.08     4.54     2.28     3.98x
//	50 hooks, not subscribed    RWMutex  200.80   352.20   335.10     0.60x
//	                            index      9.17     4.63     2.30     3.98x
//
// Read the 1→4 column first, because it is the finding. Under the RWMutex, four
// cores delivered a NINTH to an eighth of one core's throughput: adding hardware
// made the check slower in absolute terms. The index scales at ~4x on 4 cores —
// the curve now IMPROVES with core count, which is what matters for an appliance
// that ships onto 16- and 32-core hardware.
//
// The worst case was the DEFAULT posture, zero webhooks configured, where every
// blocked request paid two atomic RMWs to iterate an empty slice and return
// false. That default is also the state of every test binary.
//
// The 50-hook row carries a second, independent win: the scan was
// O(hooks × events) on a miss, so a gateway fanning alerts to a large collector
// set paid for its own fan-out on the block path (200.8 ns at P=1, fifteen times
// the one-hook cost). The index is O(1) in the hook count — 9.17 ns whether one
// hook is configured or fifty.
//
// State the cost honestly: at P=1 with a handful of hooks the win is only ~2x,
// because an uncontended RLock is genuinely cheap and the map lookup is not free.
// The case for this change is the concurrency curve, not the single-core constant.
//
// THE SHAPE
//
// The subscription answer is a pure function of the hook set, and the hook set is
// written only by admin CRUD (Add/Update/Delete) and startup load (Init) — rare,
// operator-paced mutations against an unbounded read rate. So the derived index is
// computed once per mutation and published as an IMMUTABLE value behind an
// atomic.Pointer. A steady-state read is one atomic pointer LOAD — no
// read-modify-write on any shared word, nothing for cores to contend over — plus a
// bool test and at most one lookup in a small map.
//
// mu still owns as.hooks and is still the only way to mutate it; it is simply no
// longer taken by the read path. Every site that writes as.hooks republishes the
// index before releasing mu, so the published value can never lag the hook set.
//
// A nil published pointer means "never armed" and is handled by arming it (see
// HasSubscriber). That keeps an in-package zero-value &Store{hooks: ...} — the
// construction several white-box tests use — answering exactly as it always did,
// and it means the fast path cannot be left disarmed by an Init that returned
// early. subscriptions_test.go asserts arming for each production path AND runs
// the whole HasSubscriber contract table against both the scan and the index, so
// the two can never silently diverge.

// subscriptions is the immutable published index of what the ENABLED webhooks are
// subscribed to. Never mutated after publication: a change builds a new value.
//
// catchAll is kept separate from events rather than relying on an "*" entry so
// that the hot path answers a catch-all store with a bool test and no map lookup
// at all.
type subscriptions struct {
	catchAll bool                // some enabled hook subscribes to catchAllEvent
	events   map[string]struct{} // union of the enabled hooks' event names
}

// buildSubscriptions derives the index from a hook set. Pure: same input, same
// answer, no reference to the input retained (Events slices are only read).
//
// It must agree with the original locked scan for every input. That is enforced
// as a differential oracle in subscriptions_test.go, which keeps a copy of the
// pre-change scan and asserts the two answer identically — not a comment.
func buildSubscriptions(hooks []Webhook) *subscriptions {
	s := &subscriptions{}
	for i := range hooks {
		if !hooks[i].Enabled {
			continue
		}
		for _, ev := range hooks[i].Events {
			if ev == catchAllEvent {
				s.catchAll = true
			}
			if s.events == nil {
				// Sized for the common case: a handful of events across a
				// couple of hooks. Growth is a startup/admin-path cost.
				s.events = make(map[string]struct{}, 8)
			}
			s.events[ev] = struct{}{}
		}
	}
	return s
}

// publishSubscriptionsLocked recomputes and publishes the index. Callers hold mu
// (write side) and MUST call it after every mutation of as.hooks, before
// releasing mu, so a reader can never observe a hook set newer than the index.
//
// Deriving under mu costs an operator-paced O(hooks × events) pass. It is
// deliberately NOT deferred to the next read: a lazily invalidated cache would
// put the derivation back on the request path, which is the cost this file exists
// to remove.
func (as *Store) publishSubscriptionsLocked() {
	as.subs.Store(buildSubscriptions(as.hooks))
}

// armSubscriptions publishes the index for a store that has never published one
// (a zero-value &Store{hooks: ...}, or an Init that returned before loading), and
// returns the value now in force.
//
// It takes the WRITE lock: it mutates published state, and two concurrent arms
// must not each derive from a half-written hook set. This runs at most once per
// store in any path that mutates through the API, so it is not a hot path — but
// it is still correct if it races, because whichever value lands is derived from
// the same mu-guarded hooks and any later mutation republishes anyway.
//
// CONSTRAINT this puts on callers: HasSubscriber must never be called by a
// goroutine already holding mu, because sync.RWMutex is not reentrant and this
// would self-deadlock on an unarmed store. No in-package caller does — every
// caller reaches it from package main or from internal/* through the exported
// API or the alerts.SubscriberProbe seam, neither of which can hold mu, and mu
// is unexported so no caller outside this package can. A future in-package
// producer that wants to gate itself must therefore do so OUTSIDE mu, which is
// where a producer belongs anyway: the whole point of the gate is to skip work
// before taking any lock.
func (as *Store) armSubscriptions() *subscriptions {
	as.mu.Lock()
	defer as.mu.Unlock()
	if s := as.subs.Load(); s != nil {
		return s // another goroutine armed it while we waited for mu
	}
	s := buildSubscriptions(as.hooks)
	as.subs.Store(s)
	return s
}

// has answers the subscription question against the published index.
func (s *subscriptions) has(event string) bool {
	if s.catchAll {
		return true
	}
	// A lookup in a nil or empty map returns before hashing the key, so the
	// default posture (no webhooks configured) costs essentially nothing.
	_, ok := s.events[event]
	return ok
}

// publishSubscriptions is publishSubscriptionsLocked for a caller that does NOT
// already hold mu. It exists for Init's load-nothing exits, which return before
// the lock is taken and must still arm the fast path — see Init's comment for why
// the empty case is the one that matters most.
func (as *Store) publishSubscriptions() {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.publishSubscriptionsLocked()
}
