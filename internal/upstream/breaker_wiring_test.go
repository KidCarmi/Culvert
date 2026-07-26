package upstream

// breaker_wiring_test.go — CHAOS-11 regression pins.
//
// Before the attribution wiring, CircuitBreaker.RecordFailure/RecordSuccess
// had no production caller: the breaker never tripped on real request
// failures, and the all-upstreams-down → direct fail-open was silent (no
// log, no alert, no counter). These tests pin:
//
//  1. ProxyFunc fills the request's Attribution slot and Record() drives the
//     selected proxy's breaker (failures trip it, success closes it,
//     client-side cancellation is not charged).
//  2. Next() counts direct fallbacks and fires the upstream_pool_down alert
//     exactly once per transition into the fallback state.
//  3. Everything is nil-safe (no slot, no proxy selected, nil receiver) so
//     the disabled-pool path stays byte-identical.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
)

func newAttribPool(t *testing.T, threshold int, timeout time.Duration, urls ...string) *Pool {
	t.Helper()
	entries := make([]Entry, len(urls))
	for i, u := range urls {
		entries[i] = Entry{URL: u}
	}
	p := &Pool{}
	p.Configure(entries, threshold, timeout)
	if len(p.proxies) != len(urls) {
		t.Fatalf("configured %d proxies, want %d", len(p.proxies), len(urls))
	}
	return p
}

func attribRequest(t *testing.T) (*http.Request, *Attribution) {
	t.Helper()
	ctx, att := WithAttribution(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://origin.test/", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	return req, att
}

func TestAttribution_FailuresTripBreakerAndSuccessCloses(t *testing.T) {
	pool := newAttribPool(t, 2, time.Minute, "http://parent.test:3128")
	fn := pool.ProxyFunc()

	// Two attributed failures → breaker opens → pool falls back to direct.
	for i := 0; i < 2; i++ {
		req, att := attribRequest(t)
		u, err := fn(req)
		if err != nil || u == nil {
			t.Fatalf("request %d: ProxyFunc = (%v, %v), want proxy URL", i, u, err)
		}
		att.Record(fmt.Errorf("connect: connection refused"))
	}
	if st := pool.proxies[0].CB.State(); st != "open" {
		t.Fatalf("breaker state after threshold failures = %q, want open", st)
	}
	if up := pool.Next(); up != nil {
		t.Fatalf("Next() with open breaker = %v, want nil (direct fallback)", up.URL)
	}

	// The breaker recovers via RecordSuccess (half-open probe outcome path):
	// an attributed success closes the circuit and the pool serves it again.
	pool.proxies[0].CB.RecordSuccess()
	req, att := attribRequest(t)
	if u, _ := fn(req); u == nil {
		t.Fatal("ProxyFunc after recovery = nil, want proxy URL")
	}
	att.Record(nil)
	if st := pool.proxies[0].CB.State(); st != "closed" {
		t.Fatalf("breaker state after attributed success = %q, want closed", st)
	}
	if got := pool.proxies[0].CB.Failures(); got != 0 {
		t.Fatalf("failure count after success = %d, want 0", got)
	}
}

func TestAttribution_ClientCancelNotCharged(t *testing.T) {
	pool := newAttribPool(t, 1, time.Minute, "http://parent.test:3128")
	fn := pool.ProxyFunc()

	req, att := attribRequest(t)
	if u, _ := fn(req); u == nil {
		t.Fatal("ProxyFunc = nil, want proxy URL")
	}
	// The stdlib wraps a client abort as *url.Error{Err: context.Canceled};
	// errors.Is unwrap must keep it off the breaker even at threshold 1.
	att.Record(fmt.Errorf("Get \"http://origin.test/\": %w", context.Canceled))
	if st := pool.proxies[0].CB.State(); st != "closed" {
		t.Fatalf("breaker state after client cancel = %q, want closed (not charged)", st)
	}
	if got := pool.proxies[0].CB.Failures(); got != 0 {
		t.Fatalf("failure count after client cancel = %d, want 0", got)
	}

	// DeadlineExceeded IS charged (slow parent = failing parent).
	req2, att2 := attribRequest(t)
	if u, _ := fn(req2); u == nil {
		t.Fatal("ProxyFunc = nil, want proxy URL")
	}
	att2.Record(fmt.Errorf("Get \"http://origin.test/\": %w", context.DeadlineExceeded))
	if st := pool.proxies[0].CB.State(); st != "open" {
		t.Fatalf("breaker state after deadline-exceeded = %q, want open", st)
	}
}

func TestAttribution_NilSafety(t *testing.T) {
	// Nil receiver: the disabled-pool path calls Record on a nil *Attribution.
	var att *Attribution
	att.Record(errors.New("boom")) // must not panic

	// Slot created but no proxy selected (direct fallback): Record no-ops.
	_, att2 := WithAttribution(context.Background())
	att2.Record(errors.New("boom")) // must not panic

	// ProxyFunc with a nil request (legacy call shape) and with a request
	// carrying no attribution slot: both must work.
	pool := newAttribPool(t, 2, time.Minute, "http://parent.test:3128")
	fn := pool.ProxyFunc()
	if u, err := fn(nil); err != nil || u == nil {
		t.Fatalf("ProxyFunc(nil) = (%v, %v), want proxy URL", u, err)
	}
	plain, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://origin.test/", http.NoBody)
	if u, err := fn(plain); err != nil || u == nil {
		t.Fatalf("ProxyFunc(no-slot request) = (%v, %v), want proxy URL", u, err)
	}
}

func TestNext_DirectFallbackCountsAndAlertsOncePerTransition(t *testing.T) {
	fired := make(chan string, 8)
	alerts.SetSink(func(event string, _ alerts.Payload) { fired <- event })
	defer alerts.SetSink(func(string, alerts.Payload) {})

	pool := newAttribPool(t, 1, time.Minute, "http://parent.test:3128")

	// Healthy pool: no fallback recorded.
	if up := pool.Next(); up == nil {
		t.Fatal("Next() on healthy pool = nil, want proxy")
	}
	if active, total := pool.DirectFallback(); active || total != 0 {
		t.Fatalf("DirectFallback() on healthy pool = (%v, %d), want (false, 0)", active, total)
	}

	// Trip the only parent: every Next() is a counted fallback, but the
	// alert fires only on the first (transition into the fallback state).
	pool.proxies[0].CB.RecordFailure()
	for i := 0; i < 3; i++ {
		if up := pool.Next(); up != nil {
			t.Fatalf("Next() with tripped pool = %v, want nil", up.URL)
		}
	}
	if active, total := pool.DirectFallback(); !active || total != 3 {
		t.Fatalf("DirectFallback() = (%v, %d), want (true, 3)", active, total)
	}
	select {
	case ev := <-fired:
		if ev != "upstream_pool_down" {
			t.Fatalf("alert event = %q, want upstream_pool_down", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no upstream_pool_down alert fired on fallback transition")
	}
	select {
	case ev := <-fired:
		t.Fatalf("second alert %q fired while still in fallback — want once per transition", ev)
	case <-time.After(50 * time.Millisecond):
	}

	// Recovery: a usable parent clears the state; re-entering fallback
	// alerts again (new transition).
	pool.proxies[0].CB.RecordSuccess()
	if up := pool.Next(); up == nil {
		t.Fatal("Next() after recovery = nil, want proxy")
	}
	if active, _ := pool.DirectFallback(); active {
		t.Fatal("DirectFallback() active after recovery, want cleared")
	}
	pool.proxies[0].CB.RecordFailure()
	if up := pool.Next(); up != nil {
		t.Fatal("Next() after re-trip should fall back to direct")
	}
	select {
	case ev := <-fired:
		if ev != "upstream_pool_down" {
			t.Fatalf("alert event = %q, want upstream_pool_down", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no alert on re-entering fallback (second transition)")
	}
}

func TestNext_EmptyPoolIsNotAFallback(t *testing.T) {
	// Direct egress with NO pool configured is the normal operating mode —
	// it must never count as a fail-open fallback or fire alerts.
	p := &Pool{}
	if up := p.Next(); up != nil {
		t.Fatalf("Next() on empty pool = %v, want nil", up.URL)
	}
	if active, total := p.DirectFallback(); active || total != 0 {
		t.Fatalf("DirectFallback() on empty pool = (%v, %d), want (false, 0)", active, total)
	}
}
