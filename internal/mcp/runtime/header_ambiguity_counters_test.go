package runtime

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The duplicate-singleton-header refusal is a CLASSIFIED denial, and the earlier
// fix that made it visible charged every occurrence to authFailures. The guarded
// singleton set spans five headers, and only two of them carry a credential —
// so a client (or a middlebox) duplicating Mcp-Protocol-Version, Mcp-Session-Id or
// Origin moved culvert_mcp_auth_failures_total, the one series an operator reads to
// answer "are credentials being attacked?". Ordinary protocol traffic and a
// credential-stuffing spike became indistinguishable on it.
//
// The split below is the contract: EVERY ambiguous header is counted (so header
// confusion stays visible and the original fix is not undone), the durable denial
// record is written for every one of them, and authFailures moves only for the
// credential-bearing subset.

func dupHeaderRequest(name, a, b string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://"+gwHost+gwResource, http.NoBody)
	r.Host = gwHost
	r.Header.Add(name, a)
	r.Header.Add(name, b)
	return r
}

func TestHeaderAmbiguity_NonCredentialHeaderIsNotAnAuthFailure(t *testing.T) {
	for _, name := range []string{"Mcp-Protocol-Version", "Mcp-Session-Id", "Origin"} {
		t.Run(name, func(t *testing.T) {
			k := newESKey(t, "k1")
			l, err := newListener(gwListenerConfig(t), testDeps(t, k, NewBoundedSink(8)), "amb-"+name, 1)
			if err != nil {
				t.Fatalf("newListener: %v", err)
			}
			before := l.ctr.snapshot("gateway", "amb")
			rec := httptest.NewRecorder()
			l.ServeHTTP(rec, dupHeaderRequest(name, "one", "two"))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 — the refusal itself must not regress", rec.Code)
			}
			after := l.ctr.snapshot("gateway", "amb")
			if got := after.AmbiguousHeaders - before.AmbiguousHeaders; got != 1 {
				t.Fatalf("ambiguousHeaders delta = %d, want 1 — a duplicated %s must stay "+
					"visible as header confusion, not be silently absorbed by the split", got, name)
			}
			if got := after.AuthFailures - before.AuthFailures; got != 0 {
				t.Fatalf("authFailures delta = %d, want 0 — %s carries no credential, so "+
					"duplicating it must not read as a credential attack", got, name)
			}
			if got := after.RequestsRejected - before.RequestsRejected; got != 1 {
				t.Fatalf("requestsRejected delta = %d, want 1", got)
			}
		})
	}
}

func TestHeaderAmbiguity_CredentialHeaderIsStillAnAuthFailure(t *testing.T) {
	for _, name := range []string{"Authorization", "DPoP"} {
		t.Run(name, func(t *testing.T) {
			k := newESKey(t, "k1")
			l, err := newListener(gwListenerConfig(t), testDeps(t, k, NewBoundedSink(8)), "cred-"+name, 1)
			if err != nil {
				t.Fatalf("newListener: %v", err)
			}
			before := l.ctr.snapshot("gateway", "cred")
			rec := httptest.NewRecorder()
			l.ServeHTTP(rec, dupHeaderRequest(name, "one", "two"))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			after := l.ctr.snapshot("gateway", "cred")
			if got := after.AuthFailures - before.AuthFailures; got != 1 {
				t.Fatalf("authFailures delta = %d, want 1 — duplicating %s IS a credential "+
					"attack and must remain on the authentication series", got, name)
			}
			if got := after.AmbiguousHeaders - before.AmbiguousHeaders; got != 1 {
				t.Fatalf("ambiguousHeaders delta = %d, want 1 — the credential case is header "+
					"confusion too and is counted on both series, not moved off the ambiguity one", got)
			}
		})
	}
}

// culvert_mcp_requests_total is documented as "requests received". It was
// incremented only inside pipeline.Process, while three transport-level branches
// (connection budget, queue admission, header extraction) reject and return before
// the pipeline is ever entered — each still moving requestsRejected. Under an
// ambiguous-header flood the rejected counter could therefore exceed the total,
// inverting every rejection-rate panel and alert built on the pair.
func TestHeaderAmbiguity_RejectedRequestIsStillCountedAsReceived(t *testing.T) {
	k := newESKey(t, "k1")
	l, err := newListener(gwListenerConfig(t), testDeps(t, k, NewBoundedSink(8)), "total-gw", 1)
	if err != nil {
		t.Fatalf("newListener: %v", err)
	}
	const n = 5
	for i := 0; i < n; i++ {
		l.ServeHTTP(httptest.NewRecorder(), dupHeaderRequest("Authorization", "Bearer a", "Bearer b"))
	}
	snap := l.ctr.snapshot("gateway", "total")
	if snap.RequestsTotal != n {
		t.Fatalf("requestsTotal = %d, want %d — a request refused before the pipeline was "+
			"never counted as received", snap.RequestsTotal, n)
	}
	if snap.RequestsRejected > snap.RequestsTotal {
		t.Fatalf("requestsRejected (%d) exceeds requestsTotal (%d): the rejection rate "+
			"derived from this pair is not a rate", snap.RequestsRejected, snap.RequestsTotal)
	}
}

// The counter must not double-count a request that DOES reach the pipeline: the
// increment moved from pipeline.Process to the transport entrypoint, and leaving
// both in place would have inflated the total for every ordinary request.
func TestHeaderAmbiguity_AcceptedRequestIsCountedExactlyOnce(t *testing.T) {
	k := newESKey(t, "k1")
	l, err := newListener(gwListenerConfig(t), testDeps(t, k, NewBoundedSink(8)), "once-gw", 1)
	if err != nil {
		t.Fatalf("newListener: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "https://"+gwHost+gwResource, http.NoBody)
	r.Host = gwHost
	r.Header.Set("Authorization", "Bearer "+gwToken(k))
	l.ServeHTTP(httptest.NewRecorder(), r)
	if snap := l.ctr.snapshot("gateway", "once"); snap.RequestsTotal != 1 {
		t.Fatalf("requestsTotal = %d after one request, want 1", snap.RequestsTotal)
	}
}
