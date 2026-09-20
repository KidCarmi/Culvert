package main

// mcp_canary_physical_effect_test.go — composition-layer gates for the First
// Controlled Canary physical-effect contract (review blockers #6/#8).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/upstreamclient"
)

// TestCanaryPath_ProductionUpstreamClientIsRetryFree is the blocker-#6 closure gate
// at the composition layer. Transport SUPPORT for retry-freedom is not enough: the
// client the live tier actually uses must be constructed retry-free, or one
// accepted reservation can still cause several physical tool invocations.
func TestCanaryPath_ProductionUpstreamClientIsRetryFree(t *testing.T) {
	lim, err := upstreamclient.RetryFreeLimits(upstreamclient.LimitConfig{})
	if err != nil {
		t.Fatalf("RetryFreeLimits: %v", err)
	}
	if !lim.RetriesDisabled() {
		t.Fatal("the First-Canary limits must disable transport retries")
	}
	if got := lim.MaxReadRetries(); got != 0 {
		t.Fatalf("retry-free limits must carry a zero retry budget, got %d", got)
	}
	// The production client must construct successfully from exactly these limits —
	// a construction failure here would silently push the live tier back onto the
	// defaults.
	if _, err := newProductionUpstreamClient(); err != nil {
		t.Fatalf("production upstream client must construct: %v", err)
	}
}

// TestNonCanaryBehaviorUnchanged is the CONTROL for blocker #6: making the Canary
// path retry-free must not remove retries from anything else. If this ever fails,
// the change stopped being scoped to the Canary.
func TestNonCanaryBehaviorUnchanged(t *testing.T) {
	def := upstreamclient.DefaultLimits()
	if def.RetriesDisabled() {
		t.Fatal("default limits must still retry — non-Canary behavior is unchanged")
	}
	if def.MaxReadRetries() == 0 {
		t.Fatal("default limits must still carry a non-zero retry budget")
	}
}

// TestCanaryGate_MintsReservationIdentity pins that a granted admission names both
// the slot that paid for the effect and the activation generation it belongs to.
// Without them a physical effect cannot be attributed to an authorized reservation,
// and an orphan from a superseded generation cannot be recognized after a restart.
func TestCanaryGate_MintsReservationIdentity(t *testing.T) {
	seen := make(map[string]struct{}, 256)
	for i := 0; i < 256; i++ {
		id, err := newCanaryReservationID()
		if err != nil {
			t.Fatalf("newCanaryReservationID: %v", err)
		}
		if len(id) != 4+2*canaryReservationIDBytes {
			t.Fatalf("unbounded reservation id: %q", id)
		}
		if id[:4] != "rsv_" {
			t.Fatalf("reservation id must be self-describing, got %q", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("reservation id collision at %d: %q", i, id)
		}
		seen[id] = struct{}{}
	}
}

// ── the production constructor must BE the shape, not merely resemble one ───────────────────

// TestCanaryPath_ProductionUpstreamClientIsBuiltFromRetryFreeLimits closes a vacuity in the gate
// above, found while verifying blocker #11's runtime invariant.
//
// THE GAP. TestCanaryPath_ProductionUpstreamClientIsRetryFree asserts two things: that
// RetryFreeLimits returns retry-free limits, and that newProductionUpstreamClient constructs
// without error. Neither reaches the property its own doc comment names — that the client the
// live tier actually uses is built retry-free. Swapping RetryFreeLimits for NewLimits inside
// newProductionUpstreamClient reintroduces both transport retries AND redirects, and the gate
// still passes; so does every other test in the canary and peer-freshness families (measured).
// The E2E proofs cannot catch it either, because realUpstreamFor rebuilds the shape locally with
// its own RetryFreeLimits call — they prove properties of a REPLICA of the production client, not
// of the production constructor.
//
// WHY IT IS LOAD-BEARING, AND FOR TWO BLOCKERS. Blocker #6 is "one accepted reservation, at most
// one physical invocation" — retries and redirects each defeat it, and upstreamclient's own
// limits.go records that a redirect is "a retry by another name" (a 307/308 replays the POST body
// carrying the SAME AttemptID, so no witness could tell the two invocations apart). Blocker #11's
// runtime half then RESTS on that: the claim that nothing unbounded sits between the last
// peer-freshness re-ask and the first request byte holds because there is exactly ONE physical
// send. PreSend is re-asked per leg and the TLS dialer site reaches every leg — but a redirect to
// the SAME approved host can reuse a pooled connection, so it would not re-enter the dialer, and
// the peer chooses when its 3xx arrives. With redirects forced off that is unreachable; without
// that forcing it is the peer's to trigger.
//
// WHAT THIS PINS, structurally rather than behaviourally: production code cannot be driven
// against the controlled peer (DefaultGatewayPolicy refuses loopback, which is why the E2E relaxes
// exactly that knob), so behaviour cannot reach this constructor. The chain each link of which is
// gated elsewhere: this wall pins that the production constructor takes its limits from
// RetryFreeLimits; RetryFreeLimits FORCES MaxRedirects=0 and RetryDisabled (gated above and in
// internal/mcp/upstreamclient/limits.go); and the client honours both (internal/mcp/upstreamclient
// /retryfree_test.go and the HTTPS E2E).
func TestCanaryPath_ProductionUpstreamClientIsBuiltFromRetryFreeLimits(t *testing.T) {
	body := productionUpstreamClientBody(t)
	if !limitsAreRetryFree(body) {
		t.Fatal("newProductionUpstreamClient must take its limits from upstreamclient.RetryFreeLimits " +
			"and from nothing else. A client built from NewLimits/DefaultLimits carries transport " +
			"retries AND redirects, so one accepted reservation can cause several physical tool " +
			"invocations (blocker #6) and a peer-chosen 3xx can put a second send after the last " +
			"peer-freshness re-ask on a pooled connection (blocker #11).")
	}
}

// TestCanaryPath_RetryFreeWallIsNotVacuous is the CONTROL for the wall above.
//
// A selector that matched nothing would pass forever, which is the failure mode the wall exists to
// remove. It requires the same predicate to REJECT each way the production constructor could stop
// being retry-free — so a typo in the matcher, or a rename in upstreamclient, fails the build here
// rather than silently retiring the gate.
func TestCanaryPath_RetryFreeWallIsNotVacuous(t *testing.T) {
	for _, bad := range []struct{ name, src string }{
		{"NewLimits", "lim, err := upstreamclient.NewLimits(upstreamclient.LimitConfig{})"},
		{"DefaultLimits", "lim := upstreamclient.DefaultLimits()"},
		{"no limits call at all", "lim := someOtherLimits()"},
	} {
		if limitsAreRetryFree(bad.src) {
			t.Fatalf("the retry-free wall must reject %s; it accepted %q", bad.name, bad.src)
		}
	}
	// And it must ACCEPT the real thing, or the gate above is unfalsifiable in the other direction.
	if !limitsAreRetryFree("lim, lerr := upstreamclient.RetryFreeLimits(upstreamclient.LimitConfig{})") {
		t.Fatal("the retry-free wall must accept the production form")
	}
}

// limitsAreRetryFree reports whether src takes its upstream limits from RetryFreeLimits and from
// no other limits constructor. Both halves matter: a body that called RetryFreeLimits and then
// overwrote lim from NewLimits would satisfy a presence-only check.
func limitsAreRetryFree(src string) bool {
	if !strings.Contains(src, "upstreamclient.RetryFreeLimits(") {
		return false
	}
	for _, other := range []string{"upstreamclient.NewLimits(", "upstreamclient.DefaultLimits("} {
		if strings.Contains(src, other) {
			return false
		}
	}
	return true
}

// productionUpstreamClientBody returns the source text of newProductionUpstreamClient, located by
// parsing the file rather than by matching line numbers, so moving the function does not retire
// the wall.
func productionUpstreamClientBody(t *testing.T) string {
	t.Helper()
	const path = "mcp_live_production_deps.go"
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "newProductionUpstreamClient" || fn.Body == nil {
			continue
		}
		return string(src[fset.Position(fn.Body.Pos()).Offset:fset.Position(fn.Body.End()).Offset])
	}
	t.Fatal("newProductionUpstreamClient not found in " + path + " — if it was renamed or moved, " +
		"point this wall at its new home rather than deleting it: it is the only gate connecting " +
		"the live tier's client to the retry-free (and therefore redirect-free) shape.")
	return ""
}
