package main

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"
)

// errSOCKS5ClientGone is the cancellation cause attached to a SOCKS5 session's
// connect context when the client closes (or resets) its connection while the
// pre-flight SSRF guard or the upstream dial is still running.
var errSOCKS5ClientGone = errors.New("socks5: client closed the connection before the tunnel was established")

// socks5ExpiredDeadline is a read deadline in the past. Setting it makes a
// blocked Read return immediately — the same technique net/http uses to stop
// its background connection reader.
var socks5ExpiredDeadline = time.Unix(1, 0)

// socks5HangupWatch gives the SOCKS5 connect phase what an HTTP CONNECT gets
// from r.Context(): a context that ends when the client goes away.
//
// Between parsing the CONNECT request and writing the reply, a compliant client
// sends nothing — so a background Read on the client connection that returns
// EOF or an error means the client has hung up. Without this, the guard's DNS
// lookup (up to tunnelGuardBudget, 10 s) and then the upstream dial (10 s) ran
// under context.Background(), holding the handler goroutine, the client
// descriptor and the client's per-IP connection-limiter slot for up to ~20 s
// after the client had already left.
//
// A client that DOES send early ("optimistic") data is alive by definition.
// The watcher keeps the single byte it read, stops watching, and stop() hands
// that byte back so it is forwarded to the destination ahead of the relay —
// no client byte is ever dropped. Such a client simply loses hang-up detection
// for the rest of the connect phase, which is the prior behaviour.
type socks5HangupWatch struct {
	conn    net.Conn
	cancel  context.CancelCauseFunc
	stopped atomic.Bool
	done    chan struct{}
	buf     [1]byte
	n       int // written by run before close(done); read by stop after <-done
}

// watchSOCKS5Hangup starts watching conn and returns the connect-phase context.
// readDeadline is the connection's current read deadline: it is re-applied up
// front (proving the conn honours deadlines, so stop can always unblock the
// watcher) and restored by stop. When the conn rejects deadlines the watcher is
// not started and the returned watch is inert — the connect phase then runs
// uncancellable, exactly as before, rather than risking a reader that cannot be
// stopped racing the relay for client bytes.
func watchSOCKS5Hangup(conn net.Conn, readDeadline time.Time) (context.Context, *socks5HangupWatch) {
	ctx, cancel := context.WithCancelCause(context.Background())
	w := &socks5HangupWatch{conn: conn, cancel: cancel, done: make(chan struct{})}
	if err := conn.SetReadDeadline(readDeadline); err != nil {
		close(w.done)
		w.stopped.Store(true)
		return ctx, w
	}
	go w.run()
	return ctx, w
}

func (w *socks5HangupWatch) run() {
	defer close(w.done)
	defer recoverGoroutine("socks5-hangup-watch")
	n, err := w.conn.Read(w.buf[:])
	w.n = n
	if n > 0 {
		return // optimistic data: the client is alive; stop keeps the byte
	}
	// EOF, reset, or the negotiation deadline expiring (after which the reply
	// write would fail too) all mean nobody will receive the reply. An error
	// caused by stop's expired deadline is not a hang-up.
	if err != nil && !w.stopped.Load() {
		w.cancel(errSOCKS5ClientGone)
	}
}

// stop ends the watch, restores readDeadline, and returns the byte the client
// sent early, if any (nil otherwise). It must be called before anything else
// reads conn, and it always returns: the expired deadline unblocks the Read.
// The connect context is cancelled on return; callers must not use it after.
func (w *socks5HangupWatch) stop(readDeadline time.Time) []byte {
	if w.stopped.Swap(true) {
		// Inert watch (deadline unsupported): nothing to stop or restore.
		<-w.done
		w.cancel(nil)
		return nil
	}
	_ = w.conn.SetReadDeadline(socks5ExpiredDeadline)
	<-w.done
	_ = w.conn.SetReadDeadline(readDeadline)
	w.cancel(nil)
	if w.n > 0 {
		return []byte{w.buf[0]}
	}
	return nil
}

// clientGone reports whether ctx ended because the SOCKS5 client hung up.
func socks5ClientGone(ctx context.Context) bool {
	return errors.Is(context.Cause(ctx), errSOCKS5ClientGone)
}
