package upstreamclient

// sendfacts_test.go — gates for send-state evidence across a RETRY LOOP
// (First Controlled Canary review, blockers #6/#8; Codex round 15).
//
// The invariant:
//
//	if Culvert cannot know whether an invocation reached the peer,
//	the uncertainty stays explicit and conservative.
//
// definitely_not_sent is the strongest claim in the send-state lattice — the one an
// operator would act on by RE-RUNNING the invocation — so it may be made only from
// positive evidence covering the WHOLE Call. Call owns a retry loop, so the evidence
// has to be unanimous across legs: an initial leg can be read in full by the peer and
// then fail before a response (the classification that authorizes a re-send), and a
// later leg can fail at resolve, which sets neverSent. Reporting only the last leg's
// marker manufactures certainty about an invocation that may already have executed.

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// flakyResolver resolves successfully for the first okLookups calls and then fails
// every subsequent one. It reproduces the ordinary fault the finding turns on — a
// resolver that stops answering between two legs of one Call — without needing a real
// DNS outage. A resolve failure is marked neverSent AND preResponse by transport.go,
// so it is both retry-classified and certainty-claiming: exactly the dangerous pair.
type flakyResolver struct {
	addrs     []netip.Addr
	okLookups int64
	lookups   atomic.Int64
}

func (r *flakyResolver) LookupIP(_ context.Context, _ string) ([]netip.Addr, error) {
	if r.lookups.Add(1) > r.okLookups {
		return nil, errResolveRefusedForTest
	}
	return r.addrs, nil
}

type resolveRefusedError struct{}

func (resolveRefusedError) Error() string { return "resolver refused" }

var errResolveRefusedForTest = resolveRefusedError{}

// callAmbiguousWithFlakyResolver drives ONE idempotent Call, under retry-ENABLED
// limits, against the ambiguous peer (which reads the whole request and drops) with a
// resolver that stops answering after okLookups. It returns how many physical
// requests the peer actually received and the Call's error.
//
// Both gates below share this one fixture; only okLookups differs. That is what makes
// the control a real control: the negative gate cannot be passing because the harness
// never reaches a never-sent leg at all.
func callAmbiguousWithFlakyResolver(t *testing.T, okLookups int64) (int64, error) {
	t.Helper()
	restore := ssrf.AllowLoopbackForTest()
	defer restore()

	srv, pin, received := ambiguousPeer(t)
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "https://")
	ipStr, portStr, _ := net.SplitHostPort(host)
	addr, _ := netip.ParseAddr(ipStr)

	res := &flakyResolver{addrs: []netip.Addr{addr}, okLookups: okLookups}
	c := newClientWithLimits(t, res, DefaultLimits())

	// A NAME, not an IP literal: destination.Resolve short-circuits a literal, so an
	// IP endpoint never consults the resolver and the flake could not fire. The dial
	// is pinned to whatever the resolver answered, and identity is the SPKI pin, so
	// the name never has to exist.
	_, err := c.Call(context.Background(),
		Target{ServerID: "s1", Endpoint: "https://upstream.invalid:" + portStr, PinnedIdentity: pin},
		"tools/call", nil, CallOptions{Idempotent: true, WireID: "call-1"})
	if err == nil {
		t.Fatal("expected the Call to fail")
	}
	t.Logf("legs resolved=%d peer received=%d", res.lookups.Load(), received.Load())
	return received.Load(), err
}

// TestCallFacts_ALaterNeverSentLegDoesNotEraseAnEarlierAmbiguousSend is the primary
// gate. Leg 1 reaches the peer and fails before a response; a later leg fails at
// resolve and is provably never sent. The Call as a whole is NOT never-sent, because
// one of its legs demonstrably put an invocation on the wire.
//
// Before the fix this reported SendNeverStarted()==true, which the executor records
// as definitely_not_sent — uncertainty converted into executed=false for an
// invocation the peer may already have acted on.
func TestCallFacts_ALaterNeverSentLegDoesNotEraseAnEarlierAmbiguousSend(t *testing.T) {
	received, err := callAmbiguousWithFlakyResolver(t, 1)

	// The premise: a real physical send happened on the first leg. Without this the
	// assertion below would be vacuous.
	if received < 1 {
		t.Fatalf("premise: the peer must have received at least one invocation, got %d", received)
	}
	if SendNeverStarted(err) {
		t.Fatal("a Call whose earlier leg reached the peer must NEVER report never-sent: " +
			"that converts uncertainty into definitely_not_sent for an invocation that may have executed")
	}
}

// TestCallFacts_AnAllLegsNeverSentCallStillReportsNeverSent is the POSITIVE CONTROL
// on the same fixture. With the resolver refusing from the very first lookup, no leg
// ever sends anything, the peer receives nothing, and the strong claim is TRUE and
// must still be made.
//
// Without this control the gate above could be satisfied by simply never reporting
// never-sent — which would silently retire definitely_not_sent from the lattice and
// send provably-undelivered attempts to witness reconciliation that has nothing to
// establish.
func TestCallFacts_AnAllLegsNeverSentCallStillReportsNeverSent(t *testing.T) {
	received, err := callAmbiguousWithFlakyResolver(t, 0)

	if received != 0 {
		t.Fatalf("premise: no leg should have reached the peer, got %d", received)
	}
	if !SendNeverStarted(err) {
		t.Fatal("a Call in which EVERY leg provably sent nothing must still report never-sent")
	}
}

// TestFoldLegFacts_DirectionsAreOppositeAndConservative pins the fold semantics
// directly, independent of any transport shape: receipt is a disjunction (monotonic
// knowledge — no later leg can un-prove that the peer answered) and never-sent is a
// conjunction (unanimity required for the strongest claim).
func TestFoldLegFacts_DirectionsAreOppositeAndConservative(t *testing.T) {
	seed := legFacts{neverSent: true} // the vacuous truth Call starts from

	t.Run("one non-never-sent leg defeats the whole-call claim", func(t *testing.T) {
		got := foldLegFacts(foldLegFacts(seed, legFacts{preResponse: true}), legFacts{neverSent: true})
		if got.neverSent {
			t.Fatal("never-sent must be a CONJUNCTION: one leg that may have sent defeats it")
		}
	})

	t.Run("unanimous never-sent legs keep the claim", func(t *testing.T) {
		got := foldLegFacts(foldLegFacts(seed, legFacts{neverSent: true}), legFacts{neverSent: true})
		if !got.neverSent {
			t.Fatal("unanimous never-sent legs must keep the claim")
		}
	})

	t.Run("an observed response survives a later unobserved leg", func(t *testing.T) {
		got := foldLegFacts(foldLegFacts(seed, legFacts{responseObserved: true}), legFacts{neverSent: true})
		if !got.responseObserved {
			t.Fatal("receipt must be a DISJUNCTION: a later leg cannot un-prove that the peer answered")
		}
		if got.neverSent {
			t.Fatal("a leg that observed a response cannot leave the call claiming never-sent")
		}
	})
}
