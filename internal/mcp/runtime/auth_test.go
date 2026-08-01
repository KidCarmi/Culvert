package runtime

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

func TestParseCredential_Rules(t *testing.T) {
	tok := "aaa.bbb.ccc"
	tests := []struct {
		name string
		req  Request
		want mcperr.Reason
	}{
		{"query bearer forbidden", Request{BearerInQuery: true, AuthorizationHeaders: []string{"Bearer " + tok}}, mcperr.ReasonCredentialInQuery},
		{"duplicate headers", Request{AuthorizationHeaders: []string{"Bearer a.b.c", "Bearer d.e.f"}}, mcperr.ReasonCredentialMissing},
		{"absent", Request{}, mcperr.ReasonCredentialMissing},
		{"malformed scheme", Request{AuthorizationHeaders: []string{"Basic Zm9v"}}, mcperr.ReasonUnsupportedTokenType},
		{"no token", Request{AuthorizationHeaders: []string{"Bearer "}}, mcperr.ReasonCredentialMissing},
		{"bare token no scheme", Request{AuthorizationHeaders: []string{tok}}, mcperr.ReasonCredentialMissing},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCredential(tc.req)
			if got := mcperr.ReasonOf(err); got != tc.want {
				t.Fatalf("reason = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseCredential_QueryBeforeValidation(t *testing.T) {
	// A valid header AND a query credential must still reject as credential_in_query:
	// the forbidden location is checked first.
	req := Request{BearerInQuery: true, AuthorizationHeaders: []string{"Bearer a.b.c"}}
	_, err := parseCredential(req)
	if mcperr.ReasonOf(err) != mcperr.ReasonCredentialInQuery {
		t.Fatalf("reason = %v", mcperr.ReasonOf(err))
	}
}

func TestGuessTokenType(t *testing.T) {
	// A three-nonempty-segment token is a JWT; anything else opaque.
	if got := guessTokenType("a.b.c"); got != 0 { // authn.TokenJWT == 0
		t.Fatalf("compact jwt guessed as %v", got)
	}
	if got := guessTokenType("opaque-token"); got == 0 {
		t.Fatalf("opaque token guessed as JWT")
	}
	if got := guessTokenType("a.b"); got == 0 {
		t.Fatalf("two-segment token guessed as JWT")
	}
}

func TestPipeline_AuthMissingRejected(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	req := gwRequest(gwToken(k), initializeBody(1))
	req.AuthorizationHeaders = nil // no credential
	out := p.Process(req, fixedClock())
	if out.Status != 401 || out.Reason != mcperr.ReasonCredentialMissing {
		t.Fatalf("missing auth: status=%d reason=%v", out.Status, out.Reason)
	}
}

func TestPipeline_QueryBearerRejected(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	req := gwRequest(gwToken(k), initializeBody(1))
	req.BearerInQuery = true
	out := p.Process(req, fixedClock())
	if out.Reason != mcperr.ReasonCredentialInQuery {
		t.Fatalf("query bearer: reason=%v", out.Reason)
	}
	if out.Status != 400 {
		t.Fatalf("query bearer status=%d, want 400", out.Status)
	}
}

func TestPipeline_ImmutableIdentityBinding(t *testing.T) {
	k := newESKey(t, "k1")
	p := newGatewayPipeline(t, testDeps(t, k, nil))
	tok := gwToken(k)
	sid := doInit(t, p, tok)

	// A DIFFERENT identity (different subject) on the same session must be rejected;
	// the original binding is retained.
	other := mintJWT(
		map[string]any{"alg": "ES256", "kid": k.kid},
		map[string]any{
			"iss": testIssuer, "sub": "user-2", "client_id": testClientG,
			"aud": gwResource, "scope": gwScope, "tenant": testTenant,
			"iat": fixedClock().Unix(), "exp": fixedClock().Add(600e9).Unix(),
		}, k)
	out := p.Process(withSession(gwRequest(other, pingBody(9)), sid), fixedClock())
	if out.Reason != mcperr.ReasonSessionIdentityRebind {
		t.Fatalf("rebind: reason=%v, want session_identity_rebind", out.Reason)
	}
	if out.Status != 409 {
		t.Fatalf("rebind status=%d, want 409", out.Status)
	}
	// The original identity still works on the same session (binding retained).
	ok := p.Process(withSession(gwRequest(tok, pingBody(10)), sid), fixedClock())
	if ok.Disposition != DispKernelTerminal {
		t.Fatalf("original identity broke after rejected rebind: %v", ok.Reason)
	}
	if p.bindings.Len() != 1 {
		t.Fatalf("binding count = %d, want 1", p.bindings.Len())
	}
}

func TestPipeline_ManagementRejectsServerPath(t *testing.T) {
	k := newESKey(t, "k1")
	// Management pipeline must not carry gateway server authority.
	ctr := &counters{}
	deps := testDeps(t, k, nil)
	p, err := newPipeline(mgmtListenerConfig(t), deps, "test-mgmt", ctr, 1)
	if err != nil {
		t.Fatalf("newPipeline mgmt: %v", err)
	}
	req := Request{
		HTTPMethod: "POST", Capability: 1 /*Management*/, Host: mgmtHost,
		Path: mgmtResource, ServerID: "srv-1", // a server id on a management request
		AuthorizationHeaders: []string{"Bearer " + mgmtToken(k)},
		Body:                 initializeBody(1),
	}
	out := p.Process(req, fixedClock())
	if out.Status != 404 || out.Reason != mcperr.ReasonAdmissionRejected {
		t.Fatalf("mgmt server path: status=%d reason=%v", out.Status, out.Reason)
	}
}
