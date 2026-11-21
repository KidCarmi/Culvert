package main

// autoexclude_setup_deadline_learn_test.go — negative control for the client-leg
// failure mode CHAOS-125 made reachable.
//
// CHAOS-125 (proxy_tunnel.go) armed sslInspectSetupTimeout on the hijacked CLIENT
// leg, because net/http's Hijack clears the listener's ReadTimeout and nothing
// else bounded the forged-leaf handshake. That closed a resource-exhaustion hole,
// but it also created a NEW error that reaches the auto-exclusion learner: before
// it, a client that completed CONNECT to an inspect-marked host and then stalled
// mid-handshake hung forever and produced no error at all, so
// handleTunnelInspect's client-handshake failure site — which calls
// maybeFailOpenClient — was simply never reached for that client. Now the window
// expires and the site runs with an "i/o timeout".
//
// That matters because the same round REFUSED to consult the learner on its two
// sibling client-leg failures, and said why: "learning an auto-exclusion from a
// client-side stall would let anything able to open a CONNECT and go quiet TEACH
// the gateway to stop inspecting the host on the next connection"
// (recordInspectClientHelloFailure, refuseNonTLSInspectClient). The strip path's
// client-handshake site still consults it, so the only thing standing between a
// deliberate stall and a learned inspection bypass is that
// classifyClientInspectFailure's substring set happens not to match a timeout.
//
// Nothing pinned that. TestClassifyClientInspectFailure's negative controls are
// "connection reset by peer", "access denied" and "handshake failure" — all
// pre-CHAOS-125 shapes, none of them a deadline expiry. Widening the classifier
// (adding "timeout", or a generic "handshake" catch-all) would therefore convert
// a client-chosen stall into a per-host inspection opt-out, with the only visible
// trace an autoexclude audit entry, and ship green.
//
// The error values below are MEASURED, not guessed: a tls.Server handshake on a
// conn whose deadline expires before the ClientHello arrives returns the
// underlying read's *net.OpError wrapping os.ErrDeadlineExceeded, whose text is
// "read tcp <local>-><remote>: i/o timeout".

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/KidCarmi/Culvert/internal/autoexclude"
)

// setupDeadlineErrs are the error values the CHAOS-125 setup window produces on
// the client leg, in the shapes the handshake actually returns them.
func setupDeadlineErrs() map[string]error {
	opErr := &net.OpError{
		Op:     "read",
		Net:    "tcp",
		Source: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 3128},
		Addr:   &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 51000},
		Err:    os.ErrDeadlineExceeded,
	}
	return map[string]error{
		"net.OpError wrapping os.ErrDeadlineExceeded": opErr,
		"wrapped once":                fmt.Errorf("tls: %w", opErr),
		"bare os.ErrDeadlineExceeded": os.ErrDeadlineExceeded,
		"context deadline":            context.DeadlineExceeded,
		"bare i/o timeout text":       errors.New("read tcp 10.0.0.1:3128->203.0.113.7:51000: i/o timeout"),
	}
}

// TestClassifyClientInspectFailure_SetupDeadlineIsNotAPinningSignal pins that no
// shape of the CHAOS-125 setup-window expiry is learnable. The positive control
// in the same test keeps it from passing vacuously: if the classifier ever stops
// recognising a real pinning alert, this fails too rather than going quiet.
func TestClassifyClientInspectFailure_SetupDeadlineIsNotAPinningSignal(t *testing.T) {
	for name, err := range setupDeadlineErrs() {
		t.Run(name, func(t *testing.T) {
			if r, ok := classifyClientInspectFailure(err); ok {
				t.Fatalf("a setup-window timeout must not be a pinning signal; got (%q, %v) for %v", r, ok, err)
			}
		})
	}
	// Positive control: the classifier still recognises what it is FOR.
	if r, ok := classifyClientInspectFailure(errors.New("remote error: tls: bad certificate")); !ok || r != autoExReasonClientPinned {
		t.Fatalf("positive control: bad-certificate alert should be client_pinned, got (%q,%v)", r, ok)
	}
	// Being a DEADLINE error is what makes these one class rather than five
	// strings; assert the premise so a future reader can tell the fixtures are
	// the real shape. errors.Is is the right predicate and os.IsTimeout is not:
	// os.IsTimeout unwraps only *PathError/*LinkError/*SyscallError, so it
	// reports false for the fmt.Errorf("%w") form the handshake can return.
	for name, err := range setupDeadlineErrs() {
		if name == "bare i/o timeout text" {
			continue // a text-only stand-in, deliberately carrying no sentinel
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s carries no deadline sentinel; the fixture no longer models the setup window", name)
		}
	}
}

// TestMaybeFailOpenClient_SetupDeadlineNeverLearns is the end-to-end control at
// the entry point handleTunnelInspect actually calls, under the only profile that
// can learn at all (fail-open) and the weakest possible promotion bar
// (ConfirmN=1, plus an AUTHENTICATED identity so ADR-0008's evidence gate cannot
// be what saves us). A stall must leave the exclusion cache empty; the same
// session shape with a genuine pinning alert must populate it.
func TestMaybeFailOpenClient_SetupDeadlineNeverLearns(t *testing.T) {
	swapAutoExclude(t, autoexclude.Config{ConfirmN: 1})
	swapProfiles(t)
	fo, scope := bindFailOpenProfile(t, "sd", "fail-open")
	gen := scopeGen(t, "sd")
	id := ProxyIdentity{ClientIP: "203.0.113.7", Identity: "stalling-user"}

	for name, err := range setupDeadlineErrs() {
		host := "stall.example"
		if learned := maybeFailOpenClient(host, fo, id, err); learned != "" {
			t.Fatalf("%s: a client stall must not learn; got reason %q", name, learned)
		}
		if _, ok := autoExclude().Contains(scope, gen, host); ok {
			t.Fatalf("%s: a client stall promoted an auto-exclusion — an inspect-marked host "+
				"is now bypassed because a client went quiet", name)
		}
	}

	// Positive control: the harness CAN learn, so the assertions above are real.
	if learned := maybeFailOpenClient("pinned.example", fo, id, errors.New("remote error: tls: bad certificate")); learned != autoExReasonClientPinned {
		t.Fatalf("positive control: pinning alert should learn client_pinned, got %q", learned)
	}
	if _, ok := autoExclude().Contains(scope, gen, "pinned.example"); !ok {
		t.Fatal("positive control: pinning rejection under fail-open must populate the cache")
	}
}
