package protocol

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func TestVersionAllowlist(t *testing.T) {
	if !IsSupported(VersionPrimary) || !IsSupported(VersionFloor) {
		t.Fatal("primary/floor must be supported")
	}
	for _, v := range []Version{"2024-11-05", "2025-03-26", "2026-07-28", "9999-99-99", "", "2025-11-25 "} {
		if IsSupported(v) {
			t.Fatalf("version %q must not be supported", v)
		}
	}
	for _, v := range []Version{"2024-11-05", "2025-03-26", "2026-07-28"} {
		if !IsExplicitlyRejected(v) {
			t.Fatalf("version %q must be explicitly rejected", v)
		}
	}
}

func TestNegotiation(t *testing.T) {
	// A supported requested version is accepted as-is.
	for _, v := range []Version{VersionPrimary, VersionFloor} {
		n := Negotiate(v)
		if !n.Accepted || n.CounterOffered || n.Selected != v {
			t.Fatalf("negotiate(%q) = %+v", v, n)
		}
	}
	// An unsupported/rejected version yields a counter-offer of the primary — never
	// a silent adoption of the requested version.
	for _, v := range []Version{"2025-03-26", "2024-11-05", "2026-07-28", "garbage"} {
		n := Negotiate(v)
		if n.Accepted || !n.CounterOffered || n.Selected != VersionPrimary {
			t.Fatalf("negotiate(%q) = %+v, want counter-offer of primary", v, n)
		}
	}
}

func TestAdapterEquivalence(t *testing.T) {
	// The per-version adapters must be equivalence-proven: for the same input they
	// produce the same normalized message (downstream never branches on version).
	lim := limits.DefaultGateway()
	corpus := []string{
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":"x","result":{"ok":true}}`,
		`{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"m"}}`,
	}
	ap, ok := AdapterFor(VersionPrimary)
	if !ok {
		t.Fatal("no primary adapter")
	}
	af, ok := AdapterFor(VersionFloor)
	if !ok {
		t.Fatal("no floor adapter")
	}
	for _, in := range corpus {
		msg, err := jsonrpc.Decode([]byte(in), lim)
		if err != nil {
			t.Fatalf("decode %q: %v", in, err)
		}
		np, errp := ap.Normalize(msg)
		nf, errf := af.Normalize(msg)
		if errp != nil || errf != nil {
			t.Fatalf("normalize errors: %v / %v", errp, errf)
		}
		if np.Class != nf.Class || np.Method != nf.Method || np.ID != nf.ID {
			t.Fatalf("adapter divergence on %q: %+v vs %+v", in, np, nf)
		}
	}
	if _, ok := AdapterFor("2025-03-26"); ok {
		t.Fatal("no adapter may exist for an unsupported version")
	}
}

func TestLifecycleStateMachine(t *testing.T) {
	// New: only initialize.
	if !LifecycleAdmits(StateNew, "initialize") || LifecycleAdmits(StateNew, "ping") || LifecycleAdmits(StateNew, "tools/call") {
		t.Fatal("StateNew must admit only initialize")
	}
	if LifecycleNext(StateNew, "initialize") != StateInitializing {
		t.Fatal("initialize must advance New -> Initializing")
	}
	// Initializing: notifications/initialized + ping.
	if !LifecycleAdmits(StateInitializing, "notifications/initialized") || !LifecycleAdmits(StateInitializing, "ping") {
		t.Fatal("StateInitializing admits initialized+ping")
	}
	if LifecycleAdmits(StateInitializing, "tools/call") {
		t.Fatal("tools/call not allowed before initialized")
	}
	if LifecycleNext(StateInitializing, "notifications/initialized") != StateInitialized {
		t.Fatal("initialized must advance to StateInitialized")
	}
	// Initialized: everything except the one-time handshake pair.
	if !LifecycleAdmits(StateInitialized, "tools/call") || LifecycleAdmits(StateInitialized, "initialize") || LifecycleAdmits(StateInitialized, "notifications/initialized") {
		t.Fatal("StateInitialized handshake gating wrong")
	}
	// Closed: nothing.
	if LifecycleAdmits(StateClosed, "ping") || LifecycleAdmits(StateClosed, "initialize") {
		t.Fatal("StateClosed admits nothing")
	}
}

func TestTransportDecisions(t *testing.T) {
	cases := []struct {
		cond    TransportCondition
		status  int
		counter bool
	}{
		{CondSessionlessMissingVersion, 400, false},
		{CondInvalidVersionHeader, 400, false},
		{CondMissingSessionID, 400, false},
		{CondUnknownOrTerminatedSession, 404, false},
		{CondDeleteUnsupported, 405, false},
		{CondGetWithoutNegotiatedContext, 405, false},
		{CondInitializeVersionUnsupported, 200, true},
	}
	for _, c := range cases {
		d := DecideTransport(c.cond)
		if d.Status != c.status || d.CounterOffer != c.counter {
			t.Fatalf("cond %d = status %d counter %v, want %d/%v", c.cond, d.Status, d.CounterOffer, c.status, c.counter)
		}
		// The no-pre-negotiation-stream invariant: EVERY decision retains zero streams.
		if d.RetainStream {
			t.Fatalf("cond %d retained a stream", c.cond)
		}
	}
}

// ValidateRegistry uses ReasonInvalidLifecycle for a broken row; ensure the error
// model wiring is intact (a smoke test of the shared reason contract).
func TestRegistryValidateReasonWiring(t *testing.T) {
	if err := ValidateRegistry(); err != nil && mcperr.ReasonOf(err) == mcperr.ReasonNone {
		t.Fatal("registry error must carry a reason")
	}
}
