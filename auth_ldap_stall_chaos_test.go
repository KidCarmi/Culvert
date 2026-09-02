package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// CHAOS-57 — the directory that ACCEPTS and then STOPS ANSWERING.
//
// CHAOS-47 gave the identity backends a fail-closed posture and a provider-wide
// cooldown so a DOWN directory costs one probe per cooldown instead of a full
// dial timeout per request. That machinery is armed by an error that RETURNS.
// The fault in this file never returns: a directory that completes the TCP
// handshake and then goes silent — an overloaded server, a firewall that drops
// established flows, a half-open socket after a peer reboot, a hung VM — left
// go-ldap waiting on a response that never came, because the library's default
// requestTimeout is 0 and that arms NO timer at all.
//
// The consequence is the one the cooldown exists to prevent, in its worst form:
// every authenticating request pinned a goroutine, a socket, an FD and a per-IP
// connection slot FOREVER, and the gate could not arm because nothing ever
// reported a failure. FD exhaustion is the recorded terminal state of PX-6 and
// WK-11, and CHAOS-54 measured what FD exhaustion then does to the SOCKS5
// accept loop — so this fault feeds a known amplifier.
//
// The fix is two layers that are NOT redundant, and the second gate below is
// what proves the second layer is load-bearing rather than belt-and-braces.

// ── Fault injectors ──────────────────────────────────────────────────────────

// blackHoleDirectory accepts TCP connections and then never writes a byte.
// This is the plain "accepted, then stopped answering" fault.
func blackHoleDirectory(t *testing.T) string {
	t.Helper()
	return stallingDirectory(t, func(c net.Conn) { io.Copy(io.Discard, c) }) //nolint:errcheck // fault injector
}

// startTLSSuccess is a verbatim RFC 4511 ExtendedResponse carrying
// resultCode=success with an empty matchedDN and diagnosticMessage, for
// messageID 1 — StartTLS is always the first message on a fresh connection:
//
//	30 0C            LDAPMessage SEQUENCE, len 12
//	  02 01 01       messageID INTEGER 1
//	  78 07          [APPLICATION 24] ExtendedResponse, len 7
//	    0A 01 00     resultCode ENUMERATED success
//	    04 00        matchedDN ""
//	    04 00        diagnosticMessage ""
var startTLSSuccess = []byte{0x30, 0x0C, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}

// startTLSAckThenStallDirectory answers the StartTLS extended request with
// success and then never speaks TLS. This is the fault that go-ldap's own
// request timer structurally cannot bound, because the handshake it hangs in
// runs on the raw socket outside the library's message loop.
func startTLSAckThenStallDirectory(t *testing.T) string {
	t.Helper()
	return stallingDirectory(t, func(c net.Conn) {
		buf := make([]byte, 512)
		if _, err := c.Read(buf); err != nil { // the StartTLS extended request
			return
		}
		if _, err := c.Write(startTLSSuccess); err != nil {
			return
		}
		io.Copy(io.Discard, c) //nolint:errcheck // never negotiate TLS
	})
}

func stallingDirectory(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		ln.Close() //nolint:errcheck // test teardown
		mu.Lock()
		for _, c := range conns {
			c.Close() //nolint:errcheck // test teardown
		}
		mu.Unlock()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go handle(c)
		}
	}()
	return "ldap://" + ln.Addr().String()
}

// withLDAPBudget drives the production round-trip envelope down so the gates
// assert the CONTRACT (the call returns inside its budget) without sleeping for
// the production value.
func withLDAPBudget(t *testing.T, d time.Duration) {
	t.Helper()
	prev := ldapRoundTripBudget
	ldapRoundTripBudget = d
	t.Cleanup(func() { ldapRoundTripBudget = prev })
}

func stalledDirectoryAuth(t *testing.T, url string, startTLS bool) *LDAPAuth {
	t.Helper()
	a, err := NewLDAPAuth(LDAPConfig{
		URL:          url,
		BaseDN:       "dc=corp,dc=com",
		UserFilter:   "(uid=%s)",
		BindDN:       "cn=svc,dc=corp,dc=com",
		BindPassword: "svcpass",
		StartTLS:     startTLS,
		// A stalled directory must never be rescued by the cache; every gate
		// here has to reach the network.
		TLSSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("NewLDAPAuth: %v", err)
	}
	return a
}

// verifyWithin runs one authentication and reports how long it took, failing
// the test if it has not returned by limit.
func verifyWithin(t *testing.T, a *LDAPAuth, limit time.Duration) (bool, time.Duration) {
	t.Helper()
	type res struct {
		ok  bool
		dur time.Duration
	}
	done := make(chan res, 1)
	start := time.Now()
	go func() {
		ok := a.Verify("alice", "hunter2")
		done <- res{ok, time.Since(start)}
	}()
	select {
	case r := <-done:
		return r.ok, r.dur
	case <-time.After(limit):
		t.Fatalf("Verify did not return within %s against a stalled directory — "+
			"the request goroutine, its socket and its FD are pinned for the life of the process", limit)
		return false, 0
	}
}

// ── Defect gates ─────────────────────────────────────────────────────────────

// A directory that accepts and then goes silent must not hold the request
// goroutine. Verified failing against the pre-fix tree, where Verify was still
// blocked when the test gave up.
func TestChaos57_StalledDirectoryReleasesTheRequestGoroutine(t *testing.T) {
	withLDAPBudget(t, 1500*time.Millisecond)
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	a := stalledDirectoryAuth(t, blackHoleDirectory(t), false)
	ok, dur := verifyWithin(t, a, 8*time.Second)

	if ok {
		t.Fatal("a directory that never answered authenticated the user — the posture must be fail CLOSED")
	}
	if dur > 4*ldapRoundTripBudget {
		t.Errorf("Verify took %s against a %s budget — the envelope is not being enforced", dur, ldapRoundTripBudget)
	}
}

// The second half of the defect, and the more important one: because verify()
// never returned, CHAOS-47's provider-wide cooldown could never arm. The
// mitigation designed for an unreachable directory was structurally blind to
// the fault class that hangs. Bounding the round trip is what makes it visible.
func TestChaos57_StalledDirectoryArmsTheUnreachableCooldown(t *testing.T) {
	withLDAPBudget(t, 1500*time.Millisecond)
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	a := stalledDirectoryAuth(t, blackHoleDirectory(t), false)
	verifyWithin(t, a, 8*time.Second)

	if !a.gate.gated() {
		t.Error("a stalled directory did not arm the CHAOS-47 cooldown — every subsequent request " +
			"would dial it again and pin another goroutine")
	}
	if snap := authBackendHealthStatus(); snap.Unavailable == 0 || !snap.Degraded {
		t.Errorf("a stalled directory is invisible on the identity_backend health plane: %+v", snap)
	}
}

// Once armed, the cooldown must deny WITHOUT dialing — otherwise a stalled
// directory still costs a full budget per request. This is what turns an
// unbounded leak into a bounded, self-limiting outage.
func TestChaos57_ArmedCooldownDeniesAStalledDirectoryWithoutDialing(t *testing.T) {
	withLDAPBudget(t, 1500*time.Millisecond)
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	a := stalledDirectoryAuth(t, blackHoleDirectory(t), false)
	verifyWithin(t, a, 8*time.Second)
	if !a.gate.gated() {
		t.Fatal("precondition: the first stall must arm the gate")
	}

	// A different credential, so the cache cannot be what makes this fast.
	start := time.Now()
	if a.Verify("bob", "different-password") {
		t.Fatal("gated directory authenticated a user")
	}
	if dur := time.Since(start); dur > ldapRoundTripBudget/2 {
		t.Errorf("gated request took %s — it reached the network instead of being denied by the cooldown", dur)
	}
}

// The StartTLS handshake is the fault the per-message timer cannot reach, so
// this gate is what proves the second layer (the connection watchdog) is
// load-bearing. Remove armLDAPConnWatchdog and this test hangs.
func TestChaos57_StartTLSHandshakeStallIsBounded(t *testing.T) {
	withLDAPBudget(t, 1500*time.Millisecond)
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	a := stalledDirectoryAuth(t, startTLSAckThenStallDirectory(t), true)
	ok, dur := verifyWithin(t, a, 8*time.Second)

	if ok {
		t.Fatal("a directory that never completed the TLS handshake authenticated the user")
	}
	if dur > 4*ldapRoundTripBudget {
		t.Errorf("StartTLS stall took %s against a %s budget — the watchdog did not fire", dur, ldapRoundTripBudget)
	}
}

// The admin directory test carries the same StartTLS exposure. It already set a
// per-message timeout, which is exactly why the gap was easy to miss: the one
// stage that timer cannot bound is the one this endpoint runs on demand against
// an admin-supplied address.
func TestChaos57_AdminDirectoryTestIsBoundedOnAStartTLSStall(t *testing.T) {
	prev := ldapTestTotalBudget
	ldapTestTotalBudget = 1500 * time.Millisecond
	t.Cleanup(func() { ldapTestTotalBudget = prev })

	url := startTLSAckThenStallDirectory(t)
	done := make(chan *ldapTestReport, 1)
	go func() {
		done <- runLDAPDirectoryTest(&LDAPProfileConfig{
			URL:           url,
			StartTLS:      true,
			TLSSkipVerify: true,
			BaseDN:        "dc=corp,dc=com",
			UserFilter:    "(uid=%s)",
		}, "", "")
	}()

	select {
	case rep := <-done:
		if rep.OK {
			t.Error("a directory that never completed the TLS handshake reported a healthy test")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("runLDAPDirectoryTest did not return — the admin handler goroutine is pinned by a stalled directory")
	}
}

// Concurrency is where the pre-fix behaviour became an outage rather than a
// slow request: N authenticating clients meant N permanently blocked
// goroutines and N leaked sockets. The bound has to reclaim all of them.
func TestChaos57_ConcurrentStallsDoNotAccumulateGoroutines(t *testing.T) {
	withLDAPBudget(t, 1500*time.Millisecond)
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	a := stalledDirectoryAuth(t, blackHoleDirectory(t), false)

	const n = 12
	baseline := runtime.NumGoroutine()
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Distinct credentials so nothing is served from the cache and
			// every call has to reach the stalled directory.
			a.Verify("user", fmt.Sprintf("pw-%d", i))
		}(i)
	}

	waited := make(chan struct{})
	go func() { wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(20 * time.Second):
		t.Fatalf("%d concurrent authentications against a stalled directory never all returned", n)
	}

	// Give the library's own reader/message goroutines a moment to unwind
	// after their connections were closed, then require the process to have
	// come back down.
	//
	// The threshold is measured, not guessed. Mid-flight, these 12 stalled
	// authentications hold +60 goroutines — five per call: the caller, plus
	// go-ldap's reader, message loop and timers. After the fix they settle to
	// delta 0. So requiring "< baseline+n" leaves 48 goroutines of headroom
	// before a real leak could hide under it, while tolerating the handful of
	// unrelated stragglers a shuffled full-suite run can leave behind.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() < baseline+n {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("goroutines did not return to baseline after %d stalled authentications: baseline=%d now=%d",
		n, baseline, runtime.NumGoroutine())
}

// ── Permanent defect proof ───────────────────────────────────────────────────

// This asserts a fact about go-ldap, not about Culvert: SetTimeout does NOT
// bound the post-StartTLS TLS handshake. The connection watchdog exists only
// because of it, so if a future go-ldap release fixes this, the build says so
// rather than leaving a backstop that silently guards nothing — the same role
// BareGracefulStopIsUnboundedOnAWedgedStream plays for CHAOS-56.
func TestChaos57_SetTimeoutDoesNotBoundStartTLSHandshake(t *testing.T) {
	url := startTLSAckThenStallDirectory(t)
	conn, err := ldap.DialURL(url, ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test teardown
	conn.SetTimeout(300 * time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- conn.StartTLS(ldapTLSConfig(url, true)) }()

	select {
	case err := <-done:
		t.Fatalf("go-ldap now bounds the StartTLS handshake with SetTimeout (returned %v). "+
			"Re-evaluate armLDAPConnWatchdog: the layer it exists for may have moved into the library, "+
			"and a backstop nobody has re-checked is worse than none.", err)
	case <-time.After(2 * time.Second):
		// Still blocked at ~7x the request timeout: the handshake is outside it.
	}
}

// ── Controls ─────────────────────────────────────────────────────────────────
//
// A bound that fires on a HEALTHY directory would pass every gate above while
// being far worse than the defect: it would deny valid credentials on a working
// directory. These two pin the other direction.

// promptDirectory answers each request immediately and correctly for its
// protocol op: a BindResponse to a BindRequest, a SearchResultDone (zero
// entries) to a SearchRequest. The whole flow therefore completes with an
// AUTHORITATIVE "no such user" — a healthy directory saying no.
//
//	30 LL 02 01 <id> <op> …   request framing; <op> 0x60 = bind, 0x63 = search
//	reply 0x61 = BindResponse, 0x65 = SearchResultDone, resultCode=success
func promptDirectory(t *testing.T) string {
	t.Helper()
	return stallingDirectory(t, func(c net.Conn) {
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if err != nil || n < 6 {
				return
			}
			msgID, replyTag := buf[4], byte(0x61)
			if buf[5] == 0x63 {
				replyTag = 0x65
			}
			resp := []byte{0x30, 0x0C, 0x02, 0x01, msgID, replyTag, 0x07, 0x0A, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
			if _, err := c.Write(resp); err != nil {
				return
			}
		}
	})
}

// A directory that answers promptly must complete well inside the envelope and
// must NOT be treated as an outage. A bound that clipped a healthy round trip,
// or armed the cooldown on one, would pass every defect gate above while
// denying valid credentials against a working directory — strictly worse than
// the defect it replaced.
func TestChaos57_PromptDirectoryIsNeitherClippedNorGated(t *testing.T) {
	withLDAPBudget(t, 3*time.Second)
	resetAuthBackendHealthForTest()
	t.Cleanup(resetAuthBackendHealthForTest)

	a := stalledDirectoryAuth(t, promptDirectory(t), false)
	start := time.Now()
	ok := a.Verify("alice", "hunter2")
	dur := time.Since(start)

	if ok {
		t.Fatal("precondition: the stub answers with zero entries, so this must be a deny")
	}
	if dur >= ldapRoundTripBudget/2 {
		t.Errorf("a directory that answered immediately took %s (budget %s) — the round trip is being clipped, "+
			"not bounded", dur, ldapRoundTripBudget)
	}
	if a.gate.gated() {
		t.Error("a healthy directory's authoritative deny armed the unreachable cooldown — " +
			"the bound is manufacturing an outage that does not exist")
	}
}

// The watchdog must not close a connection whose operations completed. If it
// did, the gates above would pass while every real authentication broke.
func TestChaos57_WatchdogStopsWhenTheRoundTripCompletes(t *testing.T) {
	url := blackHoleDirectory(t)
	conn, err := ldap.DialURL(url, ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close() //nolint:errcheck // test teardown

	stop := armLDAPConnWatchdog(conn, 200*time.Millisecond, "control")
	stop()
	time.Sleep(600 * time.Millisecond)

	if conn.IsClosing() {
		t.Error("a cancelled watchdog still closed the connection — every completed authentication " +
			"would race a close it did not need")
	}
}
