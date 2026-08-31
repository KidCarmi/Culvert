package main

import (
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// auth_verify_cost_chaos_test.go — CHAOS-57 regression gates.
//
// The gates here fall into three kinds, and the distinction is recorded rather
// than blurred, because "verified failing against the pre-fix tree" is a claim
// that only some of them can honestly make:
//
//   - DEFECT gates — five, each verified FAILING against the pre-fix tree
//     (the uncached wrong-username early return restored, and the auth cache
//     collapsed back to one shared partition):
//     RepeatedWrongUsernameIsHashedOnce, SaturationDenialIsNotCached,
//     FailureFloodCannotEvictAValidCredential,
//     BothRejectionBranchesCacheIdentically,
//     ProxyPathRepeatedBogusCredentialHashesOnce.
//
//   - NEW-BEHAVIOUR gates — the admission gate had no pre-fix counterpart, so
//     these cannot fail against a tree that lacks it. They pin the semaphore's
//     contract going forward: SaturationRefusesWithoutHashing,
//     ControlIdleGateAdmits, InFlightNeverExceedsSlots,
//     ProviderPathTakesNoHashingSlot.
//
//   - INVARIANT gates + CONTROLS — properties that held before and must still
//     hold. They pass in BOTH trees by design; that is what makes them
//     controls. They exist because "no hashing happened" and "no authentication
//     happened" are indistinguishable from a counter alone, so a gate that
//     passed because the credential path stopped working entirely would
//     otherwise read as a fix.

// newLocalAuthConfig builds a Config with one local account. The stored hash
// uses MinCost deliberately: these gates count hashes and assert postures, they
// do not measure them, and DefaultCost would add ~74 ms per comparison to every
// test in this file for no added signal. The GATE under test is cost-agnostic.
func newLocalAuthConfig(t *testing.T, user, pass string) *Config {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	return &Config{
		user:     user,
		passHash: h,
		cache:    authCacheStore{entries: map[string]*authCacheEntry{}},
	}
}

// withGate installs a gate for the duration of the test and resets the
// process-global counters. Both are process-wide, so a test that skips this
// reads another test's traffic and leaks its own narrowing into the rest of the
// binary — the fence-pollution class swapAutoExclude exists to prevent.
func withGate(t *testing.T, slots int, budget time.Duration) {
	t.Helper()
	restore := swapAuthVerifyGate(newAuthVerifyGate(slots, budget))
	resetAuthVerifyCostForTest()
	t.Cleanup(func() {
		restore()
		resetAuthVerifyCostForTest()
	})
}

// ── DEFECT gate 1: the wrong-username branch consulted no cache ──────────────
//
// Pre-fix, `verifyAuthWithSnapshot` returned early for a non-matching username
// after an UNCACHED bcrypt against dummyBcryptHash. A repeated IDENTICAL bogus
// username therefore paid a full ~74 ms hash on every request — the amplifier
// CHAOS-57 measured end to end through handleRequest.
func TestChaos57_RepeatedWrongUsernameIsHashedOnce(t *testing.T) {
	withGate(t, 4, authVerifyWaitBudget)
	c := newLocalAuthConfig(t, "alice", "secret")

	const n = 12
	before := authVerifyHashTotal.Load()
	for i := 0; i < n; i++ {
		if c.VerifyAuth("nosuchuser", "x") {
			t.Fatal("a wrong username must never authenticate")
		}
	}
	hashes := authVerifyHashTotal.Load() - before
	if hashes != 1 {
		t.Fatalf("%d identical wrong-username attempts performed %d hashes, want exactly 1 "+
			"(pre-fix this was %d — one uncached bcrypt per request)", n, hashes, n)
	}
}

// ── DEFECT gate 2: nothing bounded concurrent hashing ────────────────────────
//
// Structural, not timing-based: the gate's slots are held explicitly and the
// assertion is that a further verification is REFUSED AND PERFORMS NO HASH.
// That is deterministic on any hardware, at any load, with or without -race —
// the convention TestBenchGate_DistinctIPsDoNotShareALock established here.
func TestChaos57_SaturationRefusesWithoutHashing(t *testing.T) {
	withGate(t, 1, 20*time.Millisecond)

	g := authVerifyGateSingleton.Load()
	release, ok := g.acquire()
	if !ok {
		t.Fatal("could not take the only slot on an idle gate")
	}
	defer release()

	before := authVerifyHashTotal.Load()
	match, admitted := comparePasswordHashGated(dummyBcryptHash, "whatever")
	if admitted {
		t.Fatal("verification must be refused when no hashing slot is free")
	}
	if match {
		t.Fatal("a refused verification must never report a match")
	}
	if got := authVerifyHashTotal.Load(); got != before {
		t.Fatalf("a refused verification must perform NO hash: %d → %d", before, got)
	}
	if authVerifySaturatedTotal.Load() == 0 {
		t.Fatal("saturation must be counted (it is the operator's only signal that " +
			"authentication is failing for capacity rather than for credentials)")
	}
}

// CONTROL for gate 2. A gate that refused everything would pass the test above
// while being a total authentication outage — strictly worse than the defect.
func TestChaos57_ControlIdleGateAdmits(t *testing.T) {
	withGate(t, 1, 20*time.Millisecond)

	before := authVerifyHashTotal.Load()
	_, admitted := comparePasswordHashGated(dummyBcryptHash, "whatever")
	if !admitted {
		t.Fatal("an idle gate must admit; a gate that refuses everything is an outage, not a fix")
	}
	if authVerifyHashTotal.Load() != before+1 {
		t.Fatal("an admitted verification must perform exactly one hash")
	}
	if authVerifySaturatedTotal.Load() != 0 {
		t.Fatal("an admitted verification must not be counted as saturation")
	}
}

// ── DEFECT gate 2b: the gate must RESERVE CPU, not just cap it ───────────────
//
// The first shipped shape was min(GOMAXPROCS, authVerifyMaxSlots), which reads
// like a bound and is not one on a small host: on a 4-core box — the very host
// these measurements come from — it yielded FOUR slots, i.e. four concurrent
// bcrypts on four cores, exactly the 100%-of-the-machine saturation the gate
// exists to prevent. The semaphore would have begun refusing only after the
// data plane was already starved (caught in review by Codex, PR #1280).
//
// The invariant is expressed as headroom rather than as a table lookup, so it
// keeps holding if the constants are ever retuned.
func TestChaos57_SlotSizingReservesCPUForTheDataPlane(t *testing.T) {
	for _, procs := range []int{2, 3, 4, 6, 8, 12, 16, 32, 64, 128} {
		slots := authVerifySlotsFor(procs)

		if slots >= procs {
			t.Errorf("procs=%d: %d slots leaves NO CPU for the data plane — "+
				"a saturated gate would starve the proxy before it refused anything",
				procs, slots)
		}
		if slots > procs/2 {
			t.Errorf("procs=%d: %d slots exceeds half the machine (%d)", procs, slots, procs/2)
		}
		if slots > authVerifyMaxSlots {
			t.Errorf("procs=%d: %d slots exceeds the absolute cap %d — hashing's share "+
				"must not grow with the host", procs, slots, authVerifyMaxSlots)
		}
		if slots < 1 {
			t.Errorf("procs=%d: %d slots — a zero-slot gate fails EVERY authentication "+
				"closed, which is worse than the exhaustion it bounds", procs, slots)
		}
	}

	// The single-CPU floor is a deliberate, recorded degeneration: there is no
	// reservation to make, and refusing all authentication would be worse.
	if got := authVerifySlotsFor(1); got != 1 {
		t.Errorf("procs=1: got %d slots, want the floor of 1", got)
	}
	if got := authVerifySlotsFor(0); got != 1 { // defensive: GOMAXPROCS should never be 0
		t.Errorf("procs=0: got %d slots, want the floor of 1", got)
	}

	// The specific regression: the measured 4-core host must not hand hashing
	// the whole machine.
	if got := authVerifySlotsFor(4); got != 2 {
		t.Errorf("the 4-core host these measurements come from got %d slots, want 2", got)
	}
}

// ── DEFECT gate 3: a saturation denial must not be remembered ────────────────
//
// CHAOS-57 rule 2, and the CHAOS-47 rule it inherits: only an AUTHORITATIVE
// answer may enter the auth cache. Caching a capacity refusal would deny a
// VALID credential for the full five-minute TTL after the load passed — trading
// a CPU-exhaustion bug for the stale-deny bug CHAOS-47 closed.
func TestChaos57_SaturationDenialIsNotCached(t *testing.T) {
	withGate(t, 1, 10*time.Millisecond)
	c := newLocalAuthConfig(t, "alice", "secret")

	g := authVerifyGateSingleton.Load()
	release, ok := g.acquire()
	if !ok {
		t.Fatal("could not take the only slot on an idle gate")
	}

	if c.VerifyAuth("alice", "secret") {
		t.Fatal("a saturated gate must fail CLOSED, never admit an unverified credential")
	}

	// Capacity returns; the same VALID credential must authenticate immediately.
	release()
	if !c.VerifyAuth("alice", "secret") {
		t.Fatal("a saturation denial was remembered: the valid credential is still " +
			"rejected after capacity returned (stale-deny — CHAOS-47's defect)")
	}
}

// ── DEFECT gate 4: a failure flood evicted valid cached credentials ──────────
//
// The auth cache is written by UNAUTHENTICATED traffic. With one shared budget
// and arbitrary eviction, a flood of unique wrong credentials displaced
// successful ones, pushing legitimate users back onto the hashing path at an
// attacker's discretion.
//
// The assertion is STRUCTURAL — the positive partition's size is unchanged —
// rather than "the entry survived", which pre-fix was merely improbable rather
// than impossible and would have made this gate a coin flip.
func TestChaos57_FailureFloodCannotEvictAValidCredential(t *testing.T) {
	store := &authCacheStore{}
	store.set("alice", "secret", true)

	for i := 0; i < maxAuthCacheSize*2; i++ {
		store.set(fmt.Sprintf("attacker-%d", i), fmt.Sprintf("pass-%d", i), false)
	}

	store.mu.Lock()
	positives := len(store.entries)
	negatives := len(store.negatives)
	store.mu.Unlock()

	if positives != 1 {
		t.Fatalf("a failure flood evicted from the SUCCESS partition: %d entries, want 1", positives)
	}
	if negatives > maxAuthCacheSize {
		t.Fatalf("negative partition is unbounded: %d entries, cap %d", negatives, maxAuthCacheSize)
	}
	if ok, hit := store.get("alice", "secret"); !hit || !ok {
		t.Fatal("the valid cached credential did not survive a failure flood")
	}
}

// ── INVARIANT gate: the equaliser hash must never become a verdict ───────────
//
// The fix folds the wrong-username branch onto the shared comparison path,
// which means a comparison now runs against dummyBcryptHash and its result
// reaches a variable that decides authentication. Without the explicit
// !wrongUser conjunction, presenting the equaliser's own plaintext would
// authenticate under ANY username. This gate is the reason that conjunction
// exists; it must never be deleted as redundant.
func TestChaos57_EqualiserPlaintextNeverAuthenticates(t *testing.T) {
	withGate(t, 4, authVerifyWaitBudget)
	c := newLocalAuthConfig(t, "alice", "secret")

	for _, user := range []string{"mallory", "alice", "", "root"} {
		if c.VerifyAuth(user, "culvert-timing-equaliser") {
			t.Fatalf("CRITICAL: the timing-equaliser plaintext authenticated as %q", user)
		}
	}
}

// ── INVARIANT gate: RISK-008 timing equalisation survives the cache change ───
//
// The equaliser's property is that a wrong USERNAME is indistinguishable from a
// wrong PASSWORD. Caching exactly one of the two branches would reintroduce the
// enumeration oracle it exists to close — a bogus username would answer from
// cache while a real username paid a hash, which is the same observable
// difference in the opposite direction. Both branches must cache identically.
func TestChaos57_BothRejectionBranchesCacheIdentically(t *testing.T) {
	withGate(t, 4, authVerifyWaitBudget)

	measure := func(user, pass string) (first, second int64) {
		c := newLocalAuthConfig(t, "alice", "secret")
		before := authVerifyHashTotal.Load()
		c.VerifyAuth(user, pass) //nolint:errcheck // outcome asserted by the caller
		mid := authVerifyHashTotal.Load()
		c.VerifyAuth(user, pass) //nolint:errcheck // repeat must answer from cache
		return mid - before, authVerifyHashTotal.Load() - mid
	}

	wuFirst, wuSecond := measure("nosuchuser", "x") // wrong username
	wpFirst, wpSecond := measure("alice", "wrong")  // wrong password

	if wuFirst != wpFirst || wuSecond != wpSecond {
		t.Fatalf("RISK-008: the two rejection branches no longer cost the same — "+
			"wrong-username (%d, %d) vs wrong-password (%d, %d) hashes on "+
			"(first, repeat). An asymmetry here is a username-enumeration oracle.",
			wuFirst, wuSecond, wpFirst, wpSecond)
	}
	if wuFirst != 1 || wuSecond != 0 {
		t.Fatalf("expected exactly one hash then a cache hit, got (%d, %d)", wuFirst, wuSecond)
	}
}

// ── INVARIANT gate: an external provider must not take a hashing slot ────────
//
// Rule 1: an LDAP bind or OIDC introspection is a NETWORK call bounded by the
// CHAOS-47 probe gate. Routing it through a CPU-sized semaphore would let one
// slow directory throttle a resource it does not consume, and would couple two
// independent failure domains.
type slotWatchingProvider struct{ verified int }

func (p *slotWatchingProvider) Verify(string, string) bool { p.verified++; return true }
func (p *slotWatchingProvider) Name() string               { return "slot-watching-test-provider" }

func TestChaos57_ProviderPathTakesNoHashingSlot(t *testing.T) {
	withGate(t, 1, 10*time.Millisecond)

	g := authVerifyGateSingleton.Load()
	release, ok := g.acquire() // occupy every slot
	if !ok {
		t.Fatal("could not take the only slot on an idle gate")
	}
	defer release()

	prov := &slotWatchingProvider{}
	c := &Config{provider: prov, cache: authCacheStore{entries: map[string]*authCacheEntry{}}}

	if !c.VerifyAuth("bob", "pw") {
		t.Fatal("a provider-backed verification must not be gated by the CPU hashing semaphore")
	}
	if prov.verified != 1 {
		t.Fatalf("provider Verify called %d times, want 1", prov.verified)
	}
	if authVerifySaturatedTotal.Load() != 0 {
		t.Fatal("a provider verification must never be counted as hashing saturation")
	}
}

// ── CONTROL: the credential path still works ─────────────────────────────────
func TestChaos57_ControlValidCredentialAuthenticates(t *testing.T) {
	withGate(t, 4, authVerifyWaitBudget)
	c := newLocalAuthConfig(t, "alice", "secret")

	if !c.VerifyAuth("alice", "secret") {
		t.Fatal("valid credential rejected")
	}
	if !c.VerifyAuth("alice", "secret") { // cached
		t.Fatal("valid credential rejected on the cached repeat")
	}
	if c.VerifyAuth("alice", "wrong") {
		t.Fatal("wrong password accepted")
	}
}

// ── The gate under concurrency ───────────────────────────────────────────────
//
// The race detector plus the in-flight gauge: concurrent verification must
// never exceed the configured slot count. Sampling a gauge is inherently a
// weaker instrument than the structural gate above, so this exists to catch a
// release/acquire imbalance (a leaked slot, a double release) rather than to
// prove the bound — which TestChaos57_SaturationRefusesWithoutHashing already
// does deterministically.
func TestChaos57_InFlightNeverExceedsSlots(t *testing.T) {
	const slots = 2
	withGate(t, slots, 200*time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			comparePasswordHashGated(dummyBcryptHash, fmt.Sprintf("p-%d", i)) //nolint:errcheck // posture asserted via gauges
		}(i)
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	var maxSeen int64
	go func() {
		defer close(done)
		tick := time.NewTicker(200 * time.Microsecond)
		defer tick.Stop()
		for {
			select {
			case <-tick.C:
				if v := authVerifyInFlight.Load(); v > maxSeen {
					maxSeen = v
				}
			case <-stop:
				return
			}
		}
	}()
	wg.Wait()
	close(stop)
	<-done

	if maxSeen > slots {
		t.Fatalf("concurrent hashing reached %d, exceeding the %d-slot bound", maxSeen, slots)
	}
	if got := authVerifyInFlight.Load(); got != 0 {
		t.Fatalf("in-flight gauge did not return to zero: %d (leaked slot?)", got)
	}
}

// ── End to end, through the real request path ────────────────────────────────
//
// The unit gates above exercise Config.VerifyAuth. This one drives the actual
// proxy entry point, because the finding was reachability: the cost is paid by
// handleRequest for any request carrying a Proxy-Authorization header, before
// the requester has proved anything.
func TestChaos57_ProxyPathRepeatedBogusCredentialHashesOnce(t *testing.T) {
	setupAuthGateTest(t)
	withGate(t, 4, authVerifyWaitBudget)

	const n = 10
	before := authVerifyHashTotal.Load()
	cred := "Basic " + base64.StdEncoding.EncodeToString([]byte("nosuchuser:x"))
	for i := 0; i < n; i++ {
		w := httptest.NewRecorder()
		r := makeRequest("http://chaos57.example.test/", nil)
		r.Header.Set("Proxy-Authorization", cred)
		handleRequest(w, r)
		if w.Code != 407 {
			t.Fatalf("request %d: want 407, got %d", i, w.Code)
		}
	}

	hashes := authVerifyHashTotal.Load() - before
	if hashes != 1 {
		t.Fatalf("%d identical unauthenticated proxy requests performed %d password hashes, "+
			"want exactly 1 (at ~74 ms each, %d hashes is %v of CPU an unauthenticated "+
			"client can spend per %d requests)", n, hashes, hashes,
			time.Duration(hashes)*74*time.Millisecond, n)
	}
}
