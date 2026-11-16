package main

// idp_fetch_conn_release_test.go — a one-shot IdP document fetch must not leave
// its connection behind.
//
// fetchOIDCDiscoveryOverNetwork and fetchSAMLMetadataOverNetwork each build a
// fresh http.Transport per call and drop it on return. A zero-value Transport
// keeps connections alive and has NO idle timeout, and nothing can ever reuse
// or close a pool nobody holds a reference to: each successful fetch therefore
// parked one TCP connection, its file descriptor and the transport's read and
// write loop goroutines until the IdP chose to hang up. Against an IdP (or a
// load balancer in front of one) that does not time idle connections out, that
// is for the life of the process, once per provider compile.
//
// The gates count connections on the SERVER side, where the leak is visible
// without reaching into net/http internals, and wait for a positive condition
// (every connection closed) rather than asserting on elapsed time. The test
// server never closes an idle connection on its own, which is exactly the peer
// that makes the pre-fix tree fail.

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// connLedger counts a test server's connections by lifecycle.
type connLedger struct {
	mu     sync.Mutex
	opened int
	open   map[net.Conn]struct{}
}

func (l *connLedger) track(c net.Conn, s http.ConnState) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch s {
	case http.StateNew:
		l.opened++
		l.open[c] = struct{}{}
	case http.StateClosed, http.StateHijacked:
		delete(l.open, c)
	}
}

func (l *connLedger) counts() (opened, stillOpen int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.opened, len(l.open)
}

// newLedgerServer starts a keep-alive HTTP/1.1 server with no idle timeout that
// answers every request with body.
func newLedgerServer(t *testing.T, body string) (*httptest.Server, *connLedger) {
	t.Helper()
	ledger := &connLedger{open: map[net.Conn]struct{}{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	srv.Config.ConnState = ledger.track
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, ledger
}

// waitAllConnsClosed waits for the server to observe every connection it
// accepted as closed. It returns the number still open when the wait ended.
func waitAllConnsClosed(l *connLedger) int {
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, open := l.counts()
		if open == 0 || time.Now().After(deadline) {
			return open
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestIdPDocumentFetch_ReleasesItsConnection(t *testing.T) {
	const fetches = 8

	cases := []struct {
		name  string
		fetch func(url string) ([]byte, error)
	}{
		{"oidc-discovery", func(u string) ([]byte, error) { return fetchOIDCDiscoveryOverNetwork(idpRemoteURL(u)) }},
		{"saml-metadata", func(u string) ([]byte, error) { return fetchSAMLMetadataOverNetwork(idpRemoteURL(u)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chaos87Env(t)
			const doc = `{"document":"served"}`
			srv, ledger := newLedgerServer(t, doc)

			for i := 0; i < fetches; i++ {
				got, err := tc.fetch(srv.URL + "/document")
				if err != nil {
					t.Fatalf("fetch %d: %v", i, err)
				}
				// CONTROL: the fix must not change what a fetch returns.
				if string(got) != doc {
					t.Fatalf("fetch %d returned %q, want %q", i, got, doc)
				}
			}

			opened, _ := ledger.counts()
			if opened != fetches {
				// Each call owns its transport, so nothing was ever reused: this
				// pins that the fix gives up no connection reuse that existed.
				t.Fatalf("server accepted %d connections for %d fetches, want one each", opened, fetches)
			}
			if open := waitAllConnsClosed(ledger); open != 0 {
				t.Fatalf("%d of %d fetch connections are still open after the fetches returned: "+
					"each one pins a file descriptor and two transport goroutines until the IdP hangs up", open, fetches)
			}
		})
	}
}
