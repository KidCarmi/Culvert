package main

// auth_cost_chaos_test.go — CHAOS-57 regression gates.
//
// Every DEFECT gate below was verified failing against the pre-fix tree (the
// governor removed from verifyAuthFrom, the arbitrary-eviction cache
// restored). The CONTROL gates exist because several of the defect gates would
// also pass against a "fix" that simply broke authentication — a gate that
// cannot tell a bound from an outage is not a gate.

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/authcost"
	"github.com/KidCarmi/Culvert/internal/authstate"
)

// newAuthTestConfig builds an isolated Config with a local bcrypt account, so
// no test touches the process-wide `cfg` singleton.
func newAuthTestConfig(t *testing.T, user, pass string) *Config {
	t.Helper()
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	if err := c.SetAuth(user, pass); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	return c
}

// installTestGate swaps in a governor with a deterministic ceiling and a
// caller-driven wait deadline, and isolates the process-global health record.
func installTestGate(t *testing.T, maxConcurrent, maxPerClient int) {
	t.Helper()
	resetAuthCostHealthForTest()
	t.Cleanup(resetAuthCostHealthForTest)
	restore := swapAuthCostGate(authcost.New(maxConcurrent, maxPerClient, 5*time.Millisecond))
	t.Cleanup(restore)
}

// ── The defect: unbounded CPU on an unauthenticated path ────────────────────

// DEFECT GATE. Pre-fix, every concurrent proxy-auth attempt ran its own bcrypt
// comparison, so N simultaneous requests put N goroutines onto the CPU at
// ~80 ms each. This asserts the bound exists AT THE AUTHENTICATION CALL, not
// merely inside the engine: the engine can be perfect and still not be wired.
func TestChaos57_ConcurrentVerificationsAreBounded(t *testing.T) {
	installTestGate(t, 2, 2)
	c := newAuthTestConfig(t, "realuser", "correct-horse-battery")

	// Occupy the ceiling ourselves: with every slot held, no verification can
	// proceed, which is the whole property under test.
	held := 0
	for globalAuthCostGate.Stats().InFlight < 2 {
		if r, _ := globalAuthCostGate.Admit(fmt.Sprintf("holder-%d", held)); r != authcost.Admitted {
			t.Fatalf("could not pre-fill the ceiling")
		}
		held++
	}

	// With the ceiling fully held, a verification must be REFUSED rather than
	// queued indefinitely or admitted anyway.
	start := time.Now()
	if c.VerifyAuthFrom("10.0.0.9", "realuser", "correct-horse-battery") {
		t.Fatal("a verification was admitted while the ceiling was fully occupied — the bound is not wired into the auth path")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("refusal took %v — the wait is not bounded", elapsed)
	}
	if got := authCostHealthStatus().Refused; got == 0 {
		t.Fatal("the refusal was not counted — a fail-closed denial must never be silent")
	}

	for i := 0; i < held; i++ {
		globalAuthCostGate.Release(fmt.Sprintf("holder-%d", i))
	}
}

// DEFECT GATE. The wrong-username branch is the cheap one to reach — it needs
// no knowledge of the deployment — and pre-fix it ran an unconditional bcrypt
// against the dummy hash with no cache and no bound. It must now be governed
// exactly like the real branch.
func TestChaos57_WrongUsernamePathIsGoverned(t *testing.T) {
	installTestGate(t, 1, 1)
	c := newAuthTestConfig(t, "realuser", "correct-horse-battery")

	if r, _ := globalAuthCostGate.Admit("holder"); r != authcost.Admitted {
		t.Fatal("could not occupy the ceiling")
	}
	defer globalAuthCostGate.Release("holder")

	if c.VerifyAuthFrom("10.0.0.9", "attacker-username", "whatever") {
		t.Fatal("verification returned true for a wrong username")
	}
	if got := authCostHealthStatus().Refused; got != 1 {
		t.Fatalf("Refused = %d, want 1: the wrong-username branch bypassed the governor, which is the branch a flood actually uses", got)
	}
}

// ── The finding inside the fix: the gate must not become a timing oracle ────

// DEFECT GATE for the fix itself. RISK-008 equalises the wrong-username and
// wrong-password paths so neither is distinguishable by timing. A governor
// consulted only on one branch — or given a budget that differed between them
// — would make "over budget" fast for one and slow for the other, handing back
// exactly the username-enumeration oracle the equalisation removed.
//
// This asserts the structural property that makes that impossible: with the
// ceiling occupied, BOTH a wrong username and a wrong password are refused,
// and both are refused WITHOUT running bcrypt (proved by the elapsed time
// being nowhere near a bcrypt comparison).
func TestChaos57_AdmissionDecisionIsUsernameIndependent(t *testing.T) {
	installTestGate(t, 1, 1)
	c := newAuthTestConfig(t, "realuser", "correct-horse-battery")

	timeOne := func(user, pass string) time.Duration {
		start := time.Now()
		if c.VerifyAuthFrom("10.0.0.9", user, pass) {
			t.Fatalf("VerifyAuthFrom(%q, …) unexpectedly succeeded", user)
		}
		return time.Since(start)
	}

	// Baseline: one ADMITTED wrong-password verification, i.e. a real bcrypt
	// comparison on this machine. Measuring it here rather than hard-coding a
	// millisecond bound keeps the gate hardware-independent — the pre-fix
	// numbers were taken on a 4-core reference box and CI runners are not it.
	bcryptCost := timeOne("realuser", "baseline-wrong-password")

	if r, _ := globalAuthCostGate.Admit("holder"); r != authcost.Admitted {
		t.Fatal("could not occupy the ceiling")
	}
	defer globalAuthCostGate.Release("holder")
	before := authCostHealthStatus()

	wrongUser := timeOne("nosuchuser", "whatever")
	wrongPass := timeOne("realuser", "another-wrong-password")

	// STRUCTURAL half, and the one that cannot flake: over budget, BOTH
	// branches were refused by the governor. If the gate were consulted on only
	// one of them, exactly one refusal would be recorded.
	after := authCostHealthStatus()
	if got := after.Refused - before.Refused; got != 2 {
		t.Fatalf("refusals across the two branches = %d, want 2: the gate is applied asymmetrically, which IS the username-enumeration oracle", got)
	}
	if after.Admitted != before.Admitted {
		t.Fatalf("a verification was admitted while over budget (%d -> %d)", before.Admitted, after.Admitted)
	}

	// TIMING half: neither refusal may have run a comparison. Bounded as a
	// FRACTION of the bcrypt cost measured moments ago on this same machine.
	budget := bcryptCost / 4
	if wrongUser >= budget {
		t.Fatalf("wrong-username refusal took %v against a %v bcrypt — it ran a comparison despite being over budget", wrongUser, bcryptCost)
	}
	if wrongPass >= budget {
		t.Fatalf("wrong-password refusal took %v against a %v bcrypt — it ran a comparison despite being over budget", wrongPass, bcryptCost)
	}
}

// CONTROL for the gate above. Under budget, the two branches must STILL both
// run a comparison — that is what RISK-008's equalisation is. A "fix" that
// skipped bcrypt on the wrong-username branch to save CPU would pass the
// oracle gate above while reintroducing the oracle in the opposite direction.
func TestChaos57_UnderBudgetBothBranchesStillEqualise(t *testing.T) {
	installTestGate(t, 4, 4)
	c := newAuthTestConfig(t, "realuser", "correct-horse-battery")

	timeOne := func(user, pass string) time.Duration {
		start := time.Now()
		c.VerifyAuthFrom("10.0.0.9", user, pass)
		return time.Since(start)
	}
	wrongUser := timeOne("nosuchuser", "whatever")
	wrongPass := timeOne("realuser", "wrong-password-1")

	// Both must be in bcrypt territory. The absolute floor is deliberately
	// generous (bcrypt.DefaultCost measures ~80 ms on the reference box, but CI
	// hardware varies); what matters is that neither is a fast path.
	const bcryptFloor = 5 * time.Millisecond
	if wrongUser < bcryptFloor {
		t.Fatalf("wrong-username took %v — the RISK-008 timing equaliser was skipped, restoring the username-enumeration oracle", wrongUser)
	}
	if wrongPass < bcryptFloor {
		t.Fatalf("wrong-password took %v — no comparison ran", wrongPass)
	}
}

// ── The cache must still work, and must not be the throttle ─────────────────

// CONTROL. The governor must not throttle a client riding a warm cache: the
// cache is consulted BEFORE admission precisely so that a legitimate
// high-rate deployment is not rate-limited by a bound on work it is not doing.
// Without this, the "fix" would be a self-inflicted outage.
func TestChaos57_CachedVerificationsDoNotConsumeTheGovernor(t *testing.T) {
	installTestGate(t, 1, 1)
	c := newAuthTestConfig(t, "realuser", "correct-horse-battery")

	// Warm the cache with one real verification.
	if !c.VerifyAuthFrom("10.0.0.9", "realuser", "correct-horse-battery") {
		t.Fatal("initial verification failed")
	}

	// Now occupy the entire ceiling and keep it occupied.
	if r, _ := globalAuthCostGate.Admit("holder"); r != authcost.Admitted {
		t.Fatal("could not occupy the ceiling")
	}
	defer globalAuthCostGate.Release("holder")

	for i := 0; i < 50; i++ {
		if !c.VerifyAuthFrom("10.0.0.9", "realuser", "correct-horse-battery") {
			t.Fatalf("cached verification %d was denied while the governor was saturated — a warm cache must not be throttled", i)
		}
	}
	if got := authCostHealthStatus().Refused; got != 0 {
		t.Fatalf("Refused = %d, want 0: cache hits must not reach the governor at all", got)
	}
}

// CONTROL. The governor must not change any VERDICT. Correct credentials still
// authenticate; wrong ones still do not.
func TestChaos57_VerdictsAreUnchanged(t *testing.T) {
	installTestGate(t, 4, 4)
	c := newAuthTestConfig(t, "realuser", "correct-horse-battery")

	for _, tc := range []struct {
		user, pass string
		want       bool
	}{
		{"realuser", "correct-horse-battery", true},
		{"realuser", "wrong", false},
		{"nosuchuser", "correct-horse-battery", false},
		{"", "", false},
	} {
		if got := c.VerifyAuthFrom("10.0.0.9", tc.user, tc.pass); got != tc.want {
			t.Errorf("VerifyAuthFrom(%q,%q) = %v, want %v", tc.user, tc.pass, got, tc.want)
		}
	}
}

// CONTROL. An external provider (LDAP bind / OIDC introspection) runs no
// bcrypt; charging it a verification slot would bound the wrong resource and
// let a slow directory starve local authentication. It must bypass the
// governor entirely.
func TestChaos57_ExternalProvidersBypassTheGovernor(t *testing.T) {
	installTestGate(t, 1, 1)
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	c.SetProvider(&chaos57StubProvider{ok: true})

	if r, _ := globalAuthCostGate.Admit("holder"); r != authcost.Admitted {
		t.Fatal("could not occupy the ceiling")
	}
	defer globalAuthCostGate.Release("holder")

	if !c.VerifyAuthFrom("10.0.0.9", "u", "p") {
		t.Fatal("an external provider was denied by the bcrypt governor")
	}
	if got := authCostHealthStatus().Refused; got != 0 {
		t.Fatalf("Refused = %d, want 0", got)
	}
}

// ── Fair cache eviction ─────────────────────────────────────────────────────

// DEFECT GATE. Pre-fix the cache evicted "one arbitrary entry" — a Go map
// range that stops at the first key, i.e. a uniformly random LIVE entry. A
// flood of distinct passwords under a known username therefore displaced other
// clients' cached positives, and the victim then paid a full ~80 ms bcrypt on
// every subsequent request. Measured pre-fix: the honest entry survived a
// flood of 1x the cache capacity and was reliably gone by 2x.
func TestChaos57_FloodCannotDisplaceAnHonestClientsCachedResult(t *testing.T) {
	var store authCacheStore
	store.entries = map[string]*authCacheEntry{}
	store.buckets = map[string]*authCacheBucket{}

	const honestClient = "10.0.0.7"
	store.set(honestClient, "realuser", "correct-horse-battery", true)

	// Ten times the capacity, from one flooding source.
	for i := 0; i < maxAuthCacheSize*10; i++ {
		store.set("203.0.113.5", "realuser", fmt.Sprintf("flood-%d", i), false)
	}

	if _, hit := store.get("realuser", "correct-horse-battery"); !hit {
		t.Fatalf("the honest client's cached result was evicted by a flood from a different source (%d evictions) — the attacker's CPU amplification now lands on legitimate traffic", store.Evictions())
	}
	if store.Evictions() == 0 {
		t.Fatal("no evictions occurred: the flood did not actually exercise the cap, so this gate proved nothing")
	}
}

// CONTROL for the gate above. The flooder must evict ITSELF: a policy that
// simply never evicted would pass the displacement gate while turning the
// cache into an unbounded map — the memory-exhaustion defect in place of the
// CPU one.
func TestChaos57_CacheStaysBounded(t *testing.T) {
	var store authCacheStore
	store.entries = map[string]*authCacheEntry{}
	store.buckets = map[string]*authCacheBucket{}

	for i := 0; i < maxAuthCacheSize*3; i++ {
		store.set("203.0.113.5", "realuser", fmt.Sprintf("flood-%d", i), false)
	}
	store.mu.Lock()
	size := len(store.entries)
	buckets := len(store.buckets)
	backing := 0
	for _, b := range store.buckets {
		backing += cap(b.keys)
	}
	store.mu.Unlock()

	if size > maxAuthCacheSize {
		t.Fatalf("cache holds %d entries, cap is %d", size, maxAuthCacheSize)
	}
	if buckets > 4 {
		t.Fatalf("bucket index holds %d clients for a single flooding source", buckets)
	}
	// The per-client backing slice must be compacted, not grown with total
	// request count — the window-vs-length trap internal/authstate documents.
	if backing > 8*maxAuthCacheSize {
		t.Fatalf("per-client backing slices total %d capacity for a %d-entry cache — the key list is growing with request count", backing, maxAuthCacheSize)
	}
}

// Eviction must be DETERMINISTIC: the victim may never depend on Go's map
// iteration order, or the policy is untestable and an operator can never
// reproduce an incident.
func TestChaos57_EvictionIsDeterministic(t *testing.T) {
	build := func() string {
		var store authCacheStore
		store.entries = map[string]*authCacheEntry{}
		store.buckets = map[string]*authCacheBucket{}
		for i := 0; i < maxAuthCacheSize; i++ {
			client := fmt.Sprintf("client-%d", i%3) // client-0 ends up largest
			store.set(client, "realuser", fmt.Sprintf("p-%d", i), false)
		}
		store.set("newcomer", "realuser", "trigger", false)
		store.mu.Lock()
		defer store.mu.Unlock()
		var live []string
		for _, e := range store.entries {
			live = append(live, e.client)
		}
		counts := map[string]int{}
		for _, c := range live {
			counts[c]++
		}
		return fmt.Sprintf("%d/%d/%d/%d", counts["client-0"], counts["client-1"], counts["client-2"], counts["newcomer"])
	}
	first := build()
	for i := 0; i < 5; i++ {
		if got := build(); got != first {
			t.Fatalf("eviction outcome varied across runs: %q vs %q — the victim depends on map order", first, got)
		}
	}
}

// ── Observability ───────────────────────────────────────────────────────────

// A fail-closed refusal that nobody can see is the silent-failure class this
// review series exists to remove. Every surface must carry it.
func TestChaos57_RefusalIsVisibleOnEverySurface(t *testing.T) {
	installTestGate(t, 1, 1)
	c := newAuthTestConfig(t, "realuser", "correct-horse-battery")

	if r, _ := globalAuthCostGate.Admit("holder"); r != authcost.Admitted {
		t.Fatal("could not occupy the ceiling")
	}
	c.VerifyAuthFrom("10.0.0.9", "realuser", "some-password")
	globalAuthCostGate.Release("holder")

	s := authCostHealthStatus()
	if s.Refused != 1 {
		t.Fatalf("Refused = %d, want 1", s.Refused)
	}
	if !s.Refusing {
		t.Fatal("status does not report a live refusal episode")
	}
	if s.LastReason == "" || s.LastReason == "admitted" {
		t.Fatalf("LastReason = %q, want a refusal classification", s.LastReason)
	}

	row := checkCredentialVerification()
	if row.Code != "credential_verification" {
		t.Fatalf("contract row code = %q", row.Code)
	}
	if row.Status == diagOK {
		t.Fatal("contract row reports OK while authentication is being refused")
	}
	if row.OperatorAction == "" {
		t.Fatal("contract row carries no operator action")
	}
	// The row is a VIEWER-role surface: it must carry counts, never a client
	// identifier.
	if strings.Contains(row.Message, "10.0.0.9") {
		t.Fatalf("contract row leaks a client address: %q", row.Message)
	}
}

// Recovery is reported only on OBSERVED evidence — a fast-path admission —
// never on elapsed time and never on a merely-queued admission. A gate that
// cleared on silence would clear in the middle of an incident, because a flood
// that stops SENDING looks identical to capacity returning.
func TestChaos57_RecoveryRequiresObservedCapacity(t *testing.T) {
	installTestGate(t, 1, 1)
	c := newAuthTestConfig(t, "realuser", "correct-horse-battery")

	if r, _ := globalAuthCostGate.Admit("holder"); r != authcost.Admitted {
		t.Fatal("could not occupy the ceiling")
	}
	c.VerifyAuthFrom("10.0.0.9", "realuser", "some-password")
	if !authCostHealthStatus().Refusing {
		t.Fatal("expected a live refusal episode")
	}

	// Time passing must not clear it.
	time.Sleep(30 * time.Millisecond)
	if !authCostHealthStatus().Refusing {
		t.Fatal("the episode cleared on elapsed time alone")
	}

	// Nor does a fast-path admission WHILE refusals are still happening — see
	// the dedicated gate below.
	globalAuthCostGate.Release("holder")
	if !c.VerifyAuthFrom("10.0.0.9", "realuser", "correct-horse-battery") {
		t.Fatal("verification failed once capacity returned")
	}
	if !authCostHealthStatus().Refusing {
		t.Fatal("the episode cleared on an admission taken moments after a refusal")
	}

	// Both halves of the evidence: an admission AND a quiet period since the
	// last refusal. Backdating lastRefusal is how the quiet period is driven
	// deterministically, the same way the alert gate backdates firstRefusal.
	authCostHealth.mu.Lock()
	authCostHealth.lastRefusal = time.Now().Add(-2 * authCostRecoveryQuiet)
	authCostHealth.mu.Unlock()
	if !c.VerifyAuthFrom("10.0.0.9", "realuser", "another-password") {
		// wrong password, but it is still an ADMITTED verification, which is
		// what recovery is evidence of — the verdict is irrelevant here.
		_ = false
	}
	if authCostHealthStatus().Refusing {
		t.Fatal("the episode did not clear on an admission after a quiet period")
	}
}

// DEFECT GATE (Codex review, PR #1328 — P1).
//
// A fast-path admission proves a slot was free AT THAT INSTANT. It does not
// prove refusals have stopped, and during a sustained flood the two coexist:
// every in-flight bcrypt eventually releases its slot, so some arrival wins the
// fast path roughly once per comparison while its siblings keep being refused.
//
// Clearing the episode on that alone made it restart every ~80 ms, so it could
// never reach authCostDegradedAfter. The consequences were the whole
// observability plane failing at its one job: the contract row flapping between
// "refusing" and "recovered", an AUTH_VERIFY_RECOVERED line per comparison, and
// `auth_verify_saturated` NEVER firing for the primary attack.
func TestChaos57_RefusalEpisodeSurvivesInterleavedFastAdmissions(t *testing.T) {
	installTestGate(t, 2, 2)
	c := newAuthTestConfig(t, "realuser", "correct-horse-battery")

	// Interleave, as a flood does: a refusal, then an admission that finds a
	// slot free, repeatedly. The episode must persist across all of it.
	for i := 0; i < 5; i++ {
		// Occupy the ceiling so the next verification is refused.
		var held []string
		for globalAuthCostGate.Stats().InFlight < 2 {
			k := fmt.Sprintf("holder-%d-%d", i, len(held))
			if r, _ := globalAuthCostGate.Admit(k); r != authcost.Admitted {
				t.Fatalf("could not pre-fill the ceiling")
			}
			held = append(held, k)
		}
		c.VerifyAuthFrom("10.0.0.9", "realuser", fmt.Sprintf("wrong-%d", i)) // refused
		for _, k := range held {
			globalAuthCostGate.Release(k)
		}

		// Now a fast-path admission succeeds, exactly as it would between two
		// refusals during a flood.
		c.VerifyAuthFrom("10.0.0.9", "realuser", fmt.Sprintf("admitted-%d", i))

		if !authCostHealthStatus().Refusing {
			t.Fatalf("round %d: the episode was cleared by an admission taken between refusals — "+
				"under a sustained flood this restarts the episode every comparison, so it can never "+
				"reach the degradation threshold and auth_verify_saturated never fires", i)
		}
	}

	// And the episode must still be able to age into DEGRADED, which is the
	// state the alert keys on.
	authCostHealth.mu.Lock()
	authCostHealth.firstRefusal = time.Now().Add(-2 * authCostDegradedAfter)
	authCostHealth.mu.Unlock()
	if !authCostHealthStatus().Degraded {
		t.Fatal("a persistent episode never reaches Degraded, so the alert can never fire")
	}
}

// The refusal counters must be exported. An incident that is only visible by
// reading Go structs is not observable.
func TestChaos57_MetricsCarryTheGovernor(t *testing.T) {
	installTestGate(t, 1, 1)
	c := newAuthTestConfig(t, "realuser", "correct-horse-battery")
	if r, _ := globalAuthCostGate.Admit("holder"); r != authcost.Admitted {
		t.Fatal("could not occupy the ceiling")
	}
	c.VerifyAuthFrom("10.0.0.9", "realuser", "some-password")
	globalAuthCostGate.Release("holder")

	body := renderMetricsForTest(t)
	for _, want := range []string{
		"culvert_auth_verify_refused_total{reason=\"per_client\"}",
		"culvert_auth_verify_refused_total{reason=\"queue_full\"}",
		"culvert_auth_verify_refused_total{reason=\"timeout\"}",
		"culvert_auth_verify_inflight",
		"culvert_auth_verify_max_concurrent",
		"culvert_auth_verify_saturated",
		"culvert_auth_verify_waited_total",
		"culvert_auth_cache_evictions_total",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics is missing %s", want)
		}
	}
}

// ── The alert ───────────────────────────────────────────────────────────────

// The alert fires once per EPISODE, not once per denied request: a credential
// flood denies thousands of requests, and one alert per denial would flood the
// webhook retry queue and evict real threat alerts (the WK-12/RS-5 defect).
func TestChaos57_AlertFiresOncePerEpisode(t *testing.T) {
	installTestGate(t, 1, 1)

	var mu sync.Mutex
	var fired []string
	prev := fireAuthCostAlert
	fireAuthCostAlert = func(detail string) {
		mu.Lock()
		fired = append(fired, detail)
		mu.Unlock()
	}
	t.Cleanup(func() { fireAuthCostAlert = prev })

	// Backdate the episode start so the degradation threshold is already met,
	// then drive many refusals.
	noteAuthCostRefused(authcost.RefusedPerClient)
	authCostHealth.mu.Lock()
	authCostHealth.firstRefusal = time.Now().Add(-2 * authCostDegradedAfter)
	authCostHealth.mu.Unlock()

	for i := 0; i < 200; i++ {
		noteAuthCostRefused(authcost.RefusedPerClient)
	}

	mu.Lock()
	n := len(fired)
	detail := ""
	if n > 0 {
		detail = fired[0]
	}
	mu.Unlock()

	if n != 1 {
		t.Fatalf("alert fired %d times for one episode, want 1", n)
	}
	if !strings.Contains(detail, "failing closed") {
		t.Fatalf("alert detail does not state the posture: %q", detail)
	}
	// The detail reaches Dispatch's dedup key (event + Detail), so it must not
	// carry a per-request-distinct value.
	if strings.Contains(detail, "10.0.0.") {
		t.Fatalf("alert detail carries a client address, which would defeat dedup: %q", detail)
	}
}

// ── Client-key derivation ───────────────────────────────────────────────────

// The fairness key must not be mintable at will. IPv6 collapses to its /64
// because one host legitimately owns a whole /64; IPv4 stays raw because a /24
// is a network of distinct devices.
func TestChaos57_ClientFairnessKeyShape(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"10.0.0.1", "10.0.0.1"},
		{"2001:db8::1", "2001:db8::/64"},
		{"2001:db8::dead:beef", "2001:db8::/64"},
		{"not-an-ip", ""},
		{"", ""},
	} {
		if got := authstate.ClientKey(tc.in); got != tc.want {
			t.Errorf("authstate.ClientKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// A single IPv6 host must not be able to present thousands of budgets.
	if a, b := authstate.ClientKey("2001:db8::1"), authstate.ClientKey("2001:db8::2"); a != b {
		t.Fatalf("two addresses in one /64 produced distinct keys (%q, %q) — one host can mint unlimited budgets", a, b)
	}
}

// chaos57StubProvider is a minimal AuthProvider for the bypass control above.
type chaos57StubProvider struct{ ok bool }

func (s *chaos57StubProvider) Verify(string, string) bool { return s.ok }
func (s *chaos57StubProvider) Name() string               { return "chaos57-stub" }

// ── Cache-key injectivity ───────────────────────────────────────────────────

// DEFECT GATE, raised against THIS change during self-review.
//
// CHAOS-57 moves the cache lookup ahead of the username comparison, so that a
// client riding a warm cache never consumes a verification slot. That is
// correct and necessary — but the pre-existing key derivation hashed
// `user + ":" + pass`, which is not injective once either field can contain
// the separator:
//
//	("admin",   "a:b")  ->  "admin:a:b"
//	("admin:a", "b")    ->  "admin:a:b"
//
// While the cache was only ever consulted AFTER the username had been
// confirmed equal to the configured one, every reachable key shared the same
// prefix and the ambiguity was unreachable. Moving the lookup earlier makes it
// reachable with a CALLER-CHOSEN username, turning it into an authentication
// BYPASS: with a colon anywhere in the configured password, presenting a
// re-split of it hits the cached positive and authenticates.
//
// This is the end-to-end gate. It was verified failing against the
// concatenation-based key.
func TestChaos57_ReSplitCredentialCannotAuthenticate(t *testing.T) {
	installTestGate(t, 4, 4)
	c := newAuthTestConfig(t, "admin", "a:b") // a colon in the password

	if !c.VerifyAuthFrom("10.0.0.1", "admin", "a:b") {
		t.Fatal("the legitimate credential was rejected")
	}
	// Every re-split of the same concatenation must be rejected.
	for _, tc := range []struct{ user, pass string }{
		{"admin:a", "b"},
		{"admin:a:b", ""},
		{"", "admin:a:b"},
	} {
		if c.VerifyAuthFrom("10.0.0.2", tc.user, tc.pass) {
			t.Fatalf("AUTHENTICATION BYPASS: (%q, %q) authenticated via a cache-key collision with the configured credential", tc.user, tc.pass)
		}
	}
}

// The unit half: no two distinct (user, pass) pairs may share a key, however
// the separator is distributed between them.
func TestChaos57_CacheKeyIsInjective(t *testing.T) {
	pairs := []struct{ user, pass string }{
		{"admin", "a:b"},
		{"admin:a", "b"},
		{"admin:a:b", ""},
		{"", "admin:a:b"},
		{"admin", ""},
		{"", "admin"},
		{"ad", "min"},
		{"admin", "b:a"},
	}
	seen := map[string]string{}
	for _, p := range pairs {
		k := cacheKey(p.user, p.pass)
		if prev, dup := seen[k]; dup {
			t.Fatalf("cacheKey collision: (%q,%q) and %s share a key", p.user, p.pass, prev)
		}
		seen[k] = fmt.Sprintf("(%q,%q)", p.user, p.pass)
	}
	// And it must still be deterministic within a process — the same credential
	// has to land on the same key, or the cache never hits and every request
	// pays a full bcrypt. Bound to separate variables rather than compared
	// inline: staticcheck's SA4000 rightly rejects two syntactically identical
	// operands, and the property under test is that two SEPARATE derivations of
	// the same input agree.
	first := cacheKey("admin", "a:b")
	second := cacheKey("admin", "a:b")
	if first != second {
		t.Fatalf("cacheKey is not deterministic: %q vs %q", first, second)
	}
}

// ── One workstation's parallel connections ──────────────────────────────────

// DEFECT GATE, raised against this PR's own first shape and reproduced
// end-to-end through the real authentication path.
//
// The per-client rule originally REFUSED a client already at its cap, on the
// spot. Measured on the real path: a single workstation opening its normal
// parallel connection pool — six requests whose cached results expired
// together — had FIVE of six VALID credentials denied, with no attacker
// anywhere. A governor built to stop an attacker denying service was denying
// it on its own, which is precisely the self-inflicted outage the CONTROL
// gates in this file exist to catch.
//
// A client at its cap now WAITS for its own earlier verification instead. The
// gate uses a long wait budget deliberately: the property under test is "none
// of them is refused", and tying it to how long bcrypt happens to take on this
// build would make it fail under -race (where bcrypt is several times slower)
// for a reason that has nothing to do with the property. The BUDGET's own
// behaviour is gated separately in internal/authcost.
func TestChaos57_OneWorkstationsParallelRequestsAreNotDenied(t *testing.T) {
	resetAuthCostHealthForTest()
	t.Cleanup(resetAuthCostHealthForTest)
	restore := swapAuthCostGate(authcost.New(2, 1, 5*time.Minute))
	t.Cleanup(restore)

	c := newAuthTestConfig(t, "realuser", "correct-horse-battery")

	const n = 6 // a browser's default parallel connection pool
	var wg sync.WaitGroup
	ok := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Distinct passwords would be distinct credentials; the same one is
			// the realistic case — every connection presents the SAME stored
			// credential, and they race to be the one that warms the cache.
			ok[i] = c.VerifyAuthFrom("10.0.0.9", "realuser", "correct-horse-battery")
		}(i)
	}
	wg.Wait()

	denied := 0
	for _, v := range ok {
		if !v {
			denied++
		}
	}
	s := authCostHealthStatus()
	if denied != 0 {
		t.Fatalf("%d of %d VALID concurrent credentials from ONE workstation were denied (per_client=%d queue_full=%d timeout=%d)",
			denied, n, s.RefusedPerClient, s.RefusedQueueFull, s.RefusedTimeout)
	}
	if s.Refused != 0 {
		t.Fatalf("Refused = %d, want 0", s.Refused)
	}
}
