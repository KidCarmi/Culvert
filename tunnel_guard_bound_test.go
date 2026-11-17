package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// The data-plane tunnel paths bound their upstream dial at 10 s but ran the
// pre-flight SSRF guard in front of it with no bound at all, so a resolver that
// stopped answering held each request goroutine — and its client connection and
// connection-limiter slot — for the OS resolver budget, even after the client
// hung up. These tests pin the wiring at every such call site. They assert on
// WHY the resolver's context ended (its cancellation cause), not on elapsed
// time; the release channel only keeps a regression from hanging the package.

type wedgedGuardResolver struct {
	entered chan struct{}
	exited  chan struct{} // one send per lookup, after cause is recorded
	release chan struct{}
	cause   atomic.Pointer[error]
}

func installWedgedGuardResolver(t *testing.T) *wedgedGuardResolver {
	t.Helper()
	w := &wedgedGuardResolver{entered: make(chan struct{}, 8), exited: make(chan struct{}, 8), release: make(chan struct{})}
	restore := ssrf.SetLookupHostForTest(func(ctx context.Context, _ string) ([]string, error) {
		w.entered <- struct{}{}
		defer func() { w.exited <- struct{}{} }()
		select {
		case <-ctx.Done():
			c := context.Cause(ctx)
			w.cause.Store(&c)
			return nil, ctx.Err()
		case <-w.release:
			return nil, errors.New("released by test: the guard's lookup context never ended")
		}
	})
	t.Cleanup(restore)
	return w
}

// observedCause waits for the lookup to exit, then reports why its context
// ended. The guard shares one lookup per host across concurrent callers
// (ssrf miss-path single-flight), so the lookup runs on its own goroutine: its
// context is cancelled before the guard returns, but the resolver observes
// that asynchronously.
func (w *wedgedGuardResolver) observedCause() error {
	select {
	case <-w.exited:
	case <-time.After(5 * time.Second):
		return errors.New("the guard's lookup never exited: its context was not cancelled")
	}
	if p := w.cause.Load(); p != nil {
		return *p
	}
	return nil
}

// waitOrRelease waits for the handler; if the guard is still parked after the
// grace period it releases the resolver so the test FAILS rather than hangs.
func (w *wedgedGuardResolver) waitOrRelease(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		close(w.release)
		<-done
		t.Fatal("pre-flight SSRF guard stayed parked on a wedged resolver: its lookup is not bounded by the request")
	}
}

var tunnelGuardSites = []struct {
	name string
	run  func(w http.ResponseWriter, r *http.Request)
}{
	{"connect-bypass", func(w http.ResponseWriter, r *http.Request) {
		handleTunnelBypass(w, r, nil, ProxyIdentity{}, "", nil)
	}},
	{"connect-inspect", func(w http.ResponseWriter, r *http.Request) {
		handleTunnelInspect(w, r, sslResolution{}, nil, ProxyIdentity{})
	}},
	{"websocket", func(w http.ResponseWriter, r *http.Request) {
		dialWebSocketUpstream(w, r)
	}},
}

func TestTunnelGuard_ClientAbortReleasesWedgedLookup(t *testing.T) {
	for _, site := range tunnelGuardSites {
		t.Run(site.name, func(t *testing.T) {
			setupProxyTest(t)
			w := installWedgedGuardResolver(t)

			ctx, hangUp := context.WithCancel(context.Background())
			defer hangUp()
			req := httptest.NewRequestWithContext(ctx, http.MethodConnect, "http://wedged-"+site.name+".example.test:443", http.NoBody)
			req.Host = "wedged-" + site.name + ".example.test:443"
			rec := httptest.NewRecorder()

			done := make(chan struct{})
			go func() { defer close(done); site.run(rec, req) }()
			<-w.entered
			hangUp() // the client goes away while the resolver is silent
			w.waitOrRelease(t, done)

			if got := w.observedCause(); !errors.Is(got, context.Canceled) {
				t.Fatalf("guard lookup ended with cause %v, want the client's cancellation", got)
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (an undetermined destination still fails closed)", rec.Code)
			}
		})
	}
}

func TestTunnelGuard_BudgetBoundsWedgedLookup(t *testing.T) {
	shrinkTunnelGuardBudget(t)
	for _, site := range tunnelGuardSites {
		t.Run(site.name, func(t *testing.T) {
			setupProxyTest(t)
			w := installWedgedGuardResolver(t)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodConnect, "http://slow-"+site.name+".example.test:443", http.NoBody)
			req.Host = "slow-" + site.name + ".example.test:443"
			rec := httptest.NewRecorder()

			done := make(chan struct{})
			go func() { defer close(done); site.run(rec, req) }()
			w.waitOrRelease(t, done)

			if got := w.observedCause(); !errors.Is(got, ssrf.ErrLookupBudget) {
				t.Fatalf("guard lookup ended with cause %v, want ssrf.ErrLookupBudget", got)
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (fail closed)", rec.Code)
			}
		})
	}
}

// SOCKS5 has no request context at all, so the budget is the only bound.
func TestTunnelGuard_SOCKS5BudgetBoundsWedgedLookup(t *testing.T) {
	setupProxyTest(t)
	shrinkTunnelGuardBudget(t)
	w := installWedgedGuardResolver(t)
	ln := startSOCKS5Listener(t)

	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		t.Fatal(err)
	}
	const host = "slow-socks5.example.test"
	req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
	req = binary.BigEndian.AppendUint16(req, 443)
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}

	reply := make([]byte, 10)
	done := make(chan struct{})
	var readErr error
	go func() { defer close(done); _, readErr = io.ReadFull(conn, reply) }()
	w.waitOrRelease(t, done)
	if readErr != nil {
		t.Fatalf("reading SOCKS5 reply: %v", readErr)
	}
	if reply[1] != 0x02 {
		t.Fatalf("SOCKS5 reply = 0x%02x, want 0x02 (fail closed)", reply[1])
	}
	if got := w.observedCause(); !errors.Is(got, ssrf.ErrLookupBudget) {
		t.Fatalf("guard lookup ended with cause %v, want ssrf.ErrLookupBudget", got)
	}
}

func shrinkTunnelGuardBudget(t *testing.T) {
	t.Helper()
	prev := tunnelGuardBudget
	tunnelGuardBudget = 20 * time.Millisecond
	t.Cleanup(func() { tunnelGuardBudget = prev })
}
