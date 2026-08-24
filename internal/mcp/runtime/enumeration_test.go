package runtime

import (
	"context"
	"testing"
)

// OVN-08. Registered server ids must not be enumerable by an UNAUTHENTICATED
// caller.
//
// The previous round closed this for a caller presenting NO credential. It stayed
// open for a caller presenting a syntactically well-formed but invalid one —
// `Authorization: Bearer anything` — because step 8 consulted the registry BEFORE
// the token was validated, answering 404 for an unknown server and proceeding for
// a registered one. A garbage token passes the syntactic pre-check, so the oracle
// was effectively unauthenticated, and it is tenant-blind by construction (no
// identity exists yet), so it disclosed the inventory of EVERY tenant.
//
// The pre-auth lookup was redundant for correctness: identity.Resolve performs the
// identical existence + Usable() check, with the same reason, after the token is
// validated. Removing it loses no enforcement.
func TestEnumeration_InvalidCredentialCannotDistinguishRegisteredServers(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))

	// A well-formed JWT signed by a key the resolver does not know: it passes the
	// syntactic pre-check and fails validation.
	bogus := gwToken(newESKey(t, "k1"))

	known := gwRequest(bogus, initializeBody(1))
	unknown := gwRequest(bogus, initializeBody(1))
	unknown.ServerID = "srv-does-not-exist"
	unknown.Path = "/mcp/gateway/srv-does-not-exist"

	a := p.Process(context.Background(), known, fixedClock())
	b := p.Process(context.Background(), unknown, fixedClock())

	if a.Status != b.Status || a.Reason != b.Reason {
		t.Fatalf("server-existence oracle for an invalid credential: registered=%d/%v unknown=%d/%v",
			a.Status, a.Reason, b.Status, b.Reason)
	}
	if a.Disposition != DispRejected {
		t.Fatalf("an invalid credential must be rejected, got %v", a.Disposition)
	}
}

// Removing the pre-auth lookup must NOT weaken the fail-closed rule: an
// AUTHENTICATED request for a server that is not registered (or not enabled) is
// still refused — identity.Resolve enforces it. MCP-SERVER-002/003.
func TestEnumeration_UnknownServerStillFailsClosedForAValidCredential(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))

	req := gwRequest(gwToken(k), initializeBody(1))
	req.ServerID = "srv-does-not-exist"
	req.Path = "/mcp/gateway/srv-does-not-exist"

	out := p.Process(context.Background(), req, fixedClock())
	if out.Disposition != DispRejected {
		t.Fatalf("an unregistered server must be refused even with a valid token, got %v (status %d)",
			out.Disposition, out.Status)
	}
	if p.sessions.SessionCount() != 0 {
		t.Fatalf("a refused request left %d session(s) behind", p.sessions.SessionCount())
	}
}

// A malformed or foreign path is still a pure syntactic rejection, and consults no
// registry — so it discloses nothing about what is registered.
func TestEnumeration_ForeignPathIsRejectedWithoutTheRegistry(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	deps.Registry = nil // no registry at all: the path check must not need one
	p := newGatewayPipeline(t, deps)

	req := gwRequest(gwToken(k), initializeBody(1))
	req.ServerID = ""
	req.Path = "/not/the/gateway/space"
	if out := p.Process(context.Background(), req, fixedClock()); out.Disposition != DispRejected {
		t.Fatalf("a foreign path must be rejected, got %v", out.Disposition)
	}
}

// The observation record must not carry an attacker-supplied server id that was
// never confirmed to be registered: it is an unbounded, caller-controlled string
// reaching a telemetry field.
func TestEnumeration_UnverifiedServerIDNeverReachesTheRecord(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))

	req := gwRequest(gwToken(newESKey(t, "k1")), initializeBody(1)) // invalid token
	req.ServerID = "srv-attacker-chosen"
	req.Path = "/mcp/gateway/srv-attacker-chosen"

	out := p.Process(context.Background(), req, fixedClock())
	if out.Record.ServerID != "" {
		t.Fatalf("observation recorded an unverified, caller-supplied server id %q", out.Record.ServerID)
	}
}
