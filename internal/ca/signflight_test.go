package ca

import (
	"crypto/tls"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// A deterministic barrier over the signing path.
//
// SignLatencyObserver is a production seam already on the leader's branch and
// nowhere else, so a test can park the leader INSIDE its flight without any
// sleep, timing assumption or scheduler hint. Every gate below is therefore
// deterministic under -race, under load, and at any GOMAXPROCS.
// ─────────────────────────────────────────────────────────────────────────────

type signBarrier struct {
	signs   atomic.Int64
	release chan struct{}
	once    sync.Once
	onFirst func() // optional: runs on the first sign, after signs is charged
}

func newSignBarrier(t *testing.T) *signBarrier {
	t.Helper()
	b := &signBarrier{release: make(chan struct{})}
	prev := SignLatencyObserver
	SignLatencyObserver = func(float64) {
		b.signs.Add(1)
		first := false
		b.once.Do(func() { first = true })
		if !first {
			return
		}
		if b.onFirst != nil {
			b.onFirst()
		}
		<-b.release // park the leader inside its flight
	}
	t.Cleanup(func() {
		SignLatencyObserver = prev
		b.Free()
	})
	return b
}

func (b *signBarrier) Free() {
	select {
	case <-b.release:
	default:
		close(b.release)
	}
}

func readyManager(t *testing.T) *Manager {
	t.Helper()
	cm := New()
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	if _, err := cm.sharedLeafKey(); err != nil { // warm, so the gate measures signing only
		t.Fatalf("sharedLeafKey: %v", err)
	}
	return cm
}

// waitFor spins (with Gosched, no sleep) until cond holds. Every caller's
// condition is reached by the code under test without any further input, so a
// failure here is a real hang, not a slow machine.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		runtime.Gosched()
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Defect gates. Each fails against the pre-single-flight tree.
// ─────────────────────────────────────────────────────────────────────────────

// TestSignFlight_ConcurrentMissesForOneHostSignOnce is THE gate. Pre-fix, every
// concurrent miss for one host started its own 144us P-256 sign; the followers'
// certificates were then thrown away by whichever writer reached the cache last.
func TestSignFlight_ConcurrentMissesForOneHostSignOnce(t *testing.T) {
	const followers = 16
	cm := readyManager(t)
	b := newSignBarrier(t)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: "hot.example.com"}); err != nil {
			t.Errorf("leader GetCert: %v", err)
		}
	}()
	waitFor(t, "the leader to enter its flight", func() bool { return b.signs.Load() >= 1 })

	certs := make([]*tls.Certificate, followers)
	var returned atomic.Int64
	for i := range followers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer returned.Add(1)
			c, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: "hot.example.com"})
			if err != nil {
				t.Errorf("follower GetCert: %v", err)
				return
			}
			certs[i] = c
		}()
	}
	// Post-fix every follower PARKS on the leader's flight (joined == N, none
	// returned). Pre-fix none of them can park, so they sign or hit and RETURN.
	// Counting both accounts for every follower on either tree, so this loop
	// terminates promptly on both and the assertion below — not a timeout —
	// is what reports the defect.
	waitFor(t, "every follower to park or return", func() bool {
		return cm.SignFlightsJoined()+returned.Load() >= followers
	})
	b.Free()
	wg.Wait()

	if got := b.signs.Load(); got != 1 {
		t.Fatalf("%d concurrent misses for one host performed %d signs, want exactly 1 "+
			"(each duplicate is ~144us of P-256 and ~19.6KB of garbage for a certificate that is discarded)", followers+1, got)
	}
	if got := cm.SignFlightsJoined(); got != followers {
		t.Fatalf("SignFlightsJoined = %d, want %d", got, followers)
	}
}

// TestSignFlight_FollowersGetTheLeadersCertificate: a collapsed miss must hand
// back the very certificate the leader signed and cached. Anything else would
// make the collapsing a correctness change rather than a cost change.
func TestSignFlight_FollowersGetTheLeadersCertificate(t *testing.T) {
	const followers = 8
	cm := readyManager(t)
	b := newSignBarrier(t)

	var leaderCert atomic.Pointer[tls.Certificate]
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: "one.example.com"})
		if err != nil {
			t.Errorf("leader: %v", err)
			return
		}
		leaderCert.Store(c)
	}()
	waitFor(t, "the leader to enter its flight", func() bool { return b.signs.Load() >= 1 })

	got := make([]*tls.Certificate, followers)
	var returned atomic.Int64
	for i := range followers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer returned.Add(1)
			c, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: "one.example.com"})
			if err != nil {
				t.Errorf("follower %d: %v", i, err)
				return
			}
			got[i] = c
		}()
	}
	waitFor(t, "every follower to park or return", func() bool {
		return cm.SignFlightsJoined()+returned.Load() >= followers
	})
	b.Free()
	wg.Wait()

	want := leaderCert.Load()
	if want == nil {
		t.Fatal("leader produced no certificate")
	}
	for i, c := range got {
		if c != want {
			t.Fatalf("follower %d received a different *tls.Certificate than the leader signed", i)
		}
	}
	if want.Leaf == nil || want.Leaf.Subject.CommonName != "one.example.com" {
		t.Fatalf("leaf CommonName = %v, want one.example.com", want.Leaf)
	}
	cached, ok := cm.cachedLeaf("one.example.com", time.Now())
	if !ok || cached != want {
		t.Fatal("the leader's certificate is not the one left in the cache")
	}
}

// TestSignFlight_DistinctHostsAreNotCollapsed is the CONTROL, and it is the
// most important test in this file: a "single flight" keyed on nothing at all
// would pass every gate above while serving one host's certificate for every
// other host — a catastrophic MITM-identity failure dressed as a speed-up.
func TestSignFlight_DistinctHostsAreNotCollapsed(t *testing.T) {
	const hosts = 12
	cm := readyManager(t)
	var signs atomic.Int64
	prev := SignLatencyObserver
	SignLatencyObserver = func(float64) { signs.Add(1) }
	t.Cleanup(func() { SignLatencyObserver = prev })

	var wg sync.WaitGroup
	got := make([]*tls.Certificate, hosts)
	for i := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("h%d.example.com", i)
			c, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: name})
			if err != nil {
				t.Errorf("%s: %v", name, err)
				return
			}
			got[i] = c
		}()
	}
	wg.Wait()

	if n := signs.Load(); n != hosts {
		t.Fatalf("signs = %d for %d distinct hosts, want %d — distinct hosts must never share a flight", n, hosts, hosts)
	}
	if n := cm.SignFlightsJoined(); n != 0 {
		t.Fatalf("SignFlightsJoined = %d for distinct hosts, want 0", n)
	}
	for i, c := range got {
		want := fmt.Sprintf("h%d.example.com", i)
		if c == nil || c.Leaf == nil || c.Leaf.Subject.CommonName != want {
			t.Fatalf("host %d got a certificate for %v, want %s", i, c.Leaf, want)
		}
	}
}

// TestSignFlight_LeaderErrorReachesFollowers: a refusal is fail-closed for the
// whole herd, and it costs ONE refused sign rather than N. The followers must
// see the leader's error verbatim, not a nil certificate with a nil error
// (which crypto/tls reports as an opaque "no certificates configured").
func TestSignFlight_LeaderErrorReachesFollowers(t *testing.T) {
	const followers = 6
	cm := readyManager(t)

	// Expire the Root CA so signLeaf refuses (CHAOS-28 fail-closed path).
	cm.mu.Lock()
	cm.caCert.NotBefore = time.Now().Add(-48 * time.Hour)
	cm.caCert.NotAfter = time.Now().Add(-24 * time.Hour)
	cm.mu.Unlock()

	var wg sync.WaitGroup
	errs := make([]error, followers+1)
	for i := range followers + 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = cm.GetCert(&tls.ClientHelloInfo{ServerName: "expired.example.com"})
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if !errors.Is(err, ErrCAUnusable) {
			t.Fatalf("caller %d error = %v, want ErrCAUnusable (fail closed for every caller)", i, err)
		}
	}
	if _, ok := cm.cachedLeaf("expired.example.com", time.Now()); ok {
		t.Fatal("a refused sign must not populate the cache")
	}
}

// TestSignFlight_PanickingLeaderDoesNotStrandFollowers pins the invariant this
// tree learned inside CHAOS-60's own fix: a leader that dies without publishing
// leaves every follower blocked forever, turning a bounded CPU cost into a
// permanent handshake hang — strictly worse than the defect being fixed.
func TestSignFlight_PanickingLeaderDoesNotStrandFollowers(t *testing.T) {
	const followers = 4
	cm := readyManager(t)

	var entered atomic.Int64
	prev := SignLatencyObserver
	SignLatencyObserver = func(float64) {
		entered.Add(1)
		panic("injected: signing path died")
	}
	t.Cleanup(func() { SignLatencyObserver = prev })

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = recover() }()
		_, _ = cm.GetCert(&tls.ClientHelloInfo{ServerName: "panic.example.com"})
	}()
	waitFor(t, "the leader to die", func() bool { return entered.Load() >= 1 })
	wg.Wait()

	// The flight must have been published and removed, so followers arriving
	// after the panic neither hang nor inherit a half-built result.
	errs := make([]error, followers)
	var wg2 sync.WaitGroup
	for i := range followers {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			defer func() { _ = recover() }()
			_, errs[i] = cm.GetCert(&tls.ClientHelloInfo{ServerName: "panic.example.com"})
		}()
	}
	wg2.Wait() // a hang here IS the defect

	cm.flightMu.Lock()
	n := len(cm.flights)
	cm.flightMu.Unlock()
	if n != 0 {
		t.Fatalf("flights left registered after a panicking leader: %d", n)
	}
}

// TestSignFlight_AbandonedLeaderReportsFailClosed drives the publish-on-panic
// path directly and pins that a follower parked on the doomed flight is woken
// with ErrSignAbandoned rather than (nil, nil).
func TestSignFlight_AbandonedLeaderReportsFailClosed(t *testing.T) {
	cm := readyManager(t)
	joined := make(chan struct{})

	var entered atomic.Int64
	prev := SignLatencyObserver
	SignLatencyObserver = func(float64) {
		entered.Add(1)
		<-joined // hold the flight open until a follower is parked on it
		panic("injected: signing path died mid-flight")
	}
	t.Cleanup(func() { SignLatencyObserver = prev })

	go func() {
		defer func() { _ = recover() }()
		_, _ = cm.GetCert(&tls.ClientHelloInfo{ServerName: "abandon.example.com"})
	}()
	waitFor(t, "the leader to enter its flight", func() bool { return entered.Load() >= 1 })

	type res struct {
		cert *tls.Certificate
		err  error
	}
	out := make(chan res, 1)
	var returned atomic.Int64
	go func() {
		// A tree with no flight to park on runs the observer itself and panics;
		// recovering keeps this gate fast and specific instead of timing out.
		defer func() {
			if p := recover(); p != nil {
				out <- res{nil, fmt.Errorf("follower performed its own sign: %v", p)}
			}
		}()
		defer returned.Add(1)
		c, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: "abandon.example.com"})
		out <- res{c, err}
	}()
	// entered >= 2 is the pre-flight tree: the follower could not park, so it
	// ran the signing path itself and is now inside the observer. Without that
	// arm this gate would deadlock (the follower waits on joined, and joined
	// closes only once the follower is accounted for) and report a timeout
	// instead of the defect.
	waitFor(t, "the follower to park, return, or sign on its own", func() bool {
		return cm.SignFlightsJoined() >= 1 || returned.Load() >= 1 || entered.Load() >= 2
	})
	close(joined)

	r := <-out // a hang here IS the defect
	if !errors.Is(r.err, ErrSignAbandoned) {
		t.Fatalf("follower of an abandoned flight got (%v, %v), want ErrSignAbandoned", r.cert, r.err)
	}
	if r.cert != nil {
		t.Fatal("an abandoned flight must not hand back a certificate")
	}
}

// TestSignFlight_CacheIsRecheckedBeforeOpeningAFlight pins invariant 3: the
// caller's cache probe is already stale by the time it reaches signOnce if a
// leader finished in between, and opening a new flight there would sign again
// for a certificate that is already cached — defeating the collapsing during
// exactly the cold-cache burst it exists for (the CHAOS-65 finding).
func TestSignFlight_CacheIsRecheckedBeforeOpeningAFlight(t *testing.T) {
	cm := readyManager(t)
	var signs atomic.Int64
	prev := SignLatencyObserver
	SignLatencyObserver = func(float64) { signs.Add(1) }
	t.Cleanup(func() { SignLatencyObserver = prev })

	// Warm the entry, then enter signOnce as a caller whose own probe missed.
	if _, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: "warm.example.com"}); err != nil {
		t.Fatal(err)
	}
	if signs.Load() != 1 {
		t.Fatalf("setup signs = %d, want 1", signs.Load())
	}
	cert, err := cm.signOnce("warm.example.com")
	if err != nil {
		t.Fatalf("signOnce: %v", err)
	}
	if signs.Load() != 1 {
		t.Fatalf("signOnce re-signed a cached host: signs = %d, want 1", signs.Load())
	}
	cached, _ := cm.cachedLeaf("warm.example.com", time.Now())
	if cert != cached {
		t.Fatal("the re-check returned something other than the cached certificate")
	}
}

// TestSignFlight_AccountingIsUnchanged: the collapsing must not silently
// redefine the leaf-cache hit ratio an operator alerts on. hits + misses still
// equals the number of GetCert calls, and a follower is still a miss — one
// served without signing.
func TestSignFlight_AccountingIsUnchanged(t *testing.T) {
	const followers = 5
	cm := readyManager(t)
	b := newSignBarrier(t)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = cm.GetCert(&tls.ClientHelloInfo{ServerName: "acct.example.com"})
	}()
	waitFor(t, "the leader to enter its flight", func() bool { return b.signs.Load() >= 1 })
	var returned atomic.Int64
	for range followers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer returned.Add(1)
			_, _ = cm.GetCert(&tls.ClientHelloInfo{ServerName: "acct.example.com"})
		}()
	}
	waitFor(t, "every follower to park or return", func() bool {
		return cm.SignFlightsJoined()+returned.Load() >= followers
	})
	b.Free()
	wg.Wait()

	// One more call, now a plain hit.
	if _, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: "acct.example.com"}); err != nil {
		t.Fatal(err)
	}
	hits, misses, _ := cm.CacheStats()
	const calls = followers + 2
	if hits+misses != calls {
		t.Fatalf("hits(%d)+misses(%d) = %d, want %d — every GetCert call must land in exactly one bucket", hits, misses, hits+misses, calls)
	}
	if misses != followers+1 {
		t.Fatalf("misses = %d, want %d — a collapsed caller still missed the cache", misses, followers+1)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
}

// TestSignFlight_ConcurrentWithCacheClearingMutators runs the real hot path
// against the mutators that replace the cache wholesale. Its value is under
// -race: it is the gate that catches a flight map read outside flightMu, or a
// lock order taken the other way round.
func TestSignFlight_ConcurrentWithCacheClearingMutators(t *testing.T) {
	cm := readyManager(t)
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				name := fmt.Sprintf("r%d.example.com", (w+i)%6)
				if _, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: name}); err != nil {
					t.Errorf("GetCert(%s): %v", name, err)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 200 {
			cm.ClearCache()
			_, _, _ = cm.CacheStats()
			runtime.Gosched()
		}
	}()
	time.AfterFunc(150*time.Millisecond, func() { close(stop) })
	wg.Wait()

	cm.flightMu.Lock()
	n := len(cm.flights)
	cm.flightMu.Unlock()
	if n != 0 {
		t.Fatalf("flights leaked: %d still registered after every caller returned", n)
	}
}
