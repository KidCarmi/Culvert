package main

// proxy_tunnel_drain.go — CHAOS-57: the shutdown drain's registry of live
// HIJACKED tunnels, and the force-close backstop that ends them deterministically.
//
// THE GAP THIS CLOSES (register row PX-8). `drainActiveTunnels` (main_shutdown.go,
// order 100) waits on ONE number: `activeConns` (geoip.go). Four of Culvert's seven
// hijacked-tunnel classes never touched that number, so the drain could not see them:
//
//	counted   CONNECT bypass ................ handleTunnelBypass
//	counted   CONNECT inspect (strip, H1) ... handleTunnelInspect
//	counted   CONNECT inspect (native ALPN) . handleTunnelInspectNative
//	INVISIBLE CONNECT inspect non-TLS fallback (strip path)
//	INVISIBLE CONNECT inspect non-TLS fallback (native path)
//	INVISIBLE WebSocket .................... handleWebSocket
//	INVISIBLE SOCKS5 ....................... socks5Relay
//
// A hijacked conn is invisible to `http.Server.Shutdown` by construction (net/http
// stops tracking a conn the moment it is hijacked), and the SOCKS5 listener's `Stop`
// waits only for the ACCEPT LOOP — each session runs in a detached
// `go handleSOCKS5(conn)`. So for those four classes NOTHING in the shutdown sequence
// waited, and nothing closed them: they ran until the process exited and the kernel
// reset them. Three consequences, all silent:
//
//  1. OPPOSITE POSTURES FOR ONE FAULT CLASS. A CONNECT tunnel gets a 15 s grace on
//     SIGTERM; a WebSocket or an SSH-over-SOCKS5 session on the same node, at the same
//     instant, gets none. Same event, same customer, two behaviours, decided by which
//     `recordActiveConn` call site the code path happened to pass through. That is the
//     CHAOS-28 §16.3 theme (one fault, two postures) in the data plane.
//
//  2. THE ACCOUNTING FOR EVERY SEVERED TUNNEL IS LOST. `recordTunnelClose*` — the
//     TUNNEL_CLOSED request-log entry carrying BytesSent/BytesRecv/DurationMs, and the
//     `recordTunnelBytes` fold into the global byte counters — runs AFTER both relay
//     goroutines drain. A tunnel killed by process exit never reaches it. So every
//     graceful shutdown drops the byte accounting for every in-flight WebSocket and
//     SOCKS5 session, and on a rolling fleet upgrade that is systematic, not
//     incidental: the bytes are missing from the request log, the JSONL export, the
//     SIEM feed and the dashboard totals, with no counter saying so.
//
//  3. THE DRAIN'S OWN LOG LINE UNDERCOUNTS. "Draining %d active tunnel(s)" is the
//     operator's evidence that a node left cleanly. With four classes uncounted it
//     reports 0 — and returns immediately — on a node severing hundreds of live
//     sessions. `activeConns` is also the dashboard's `activeConns` field, so an
//     operator sizing FD/connection budgets from it is reading a number that excludes
//     SOCKS5 and WebSocket entirely.
//
// WHY COUNTING ALONE WOULD HAVE BEEN THE WRONG FIX. Adding `recordActiveConn` to the
// four blind sites makes the drain WAIT on them — but nothing would END that wait.
// Long-lived is what WebSocket and SOCKS5 are FOR (SSH sessions, IMAP IDLE, push
// channels): they do not go quiet inside 15 s, so the drain would hit its deadline on
// EVERY shutdown of a node with any such session, turning an instant shutdown into a
// guaranteed 15 s one across a rolling fleet upgrade — and then sever them anyway. The
// operator would have bought delay and nothing else. The wait is only worth its cost if
// it ends in a DETERMINISTIC teardown, which is the same argument PR3d already made for
// inspected H2 (`forceCloseH2InspectTunnels`). So the registry holds the conns, and the
// drain deadline hard-closes them: each relay's `io.Copy` returns, its parent runs
// `recordTunnelClose*`, and the accounting lands in the request-log queue while the
// FLUSH hooks (order ≥ 110) are still ahead of us. Force-closing is never worse than
// the SIGKILL it replaces — that abandons the same conns AND the accounting.
//
// This registry deliberately does NOT cover inspected H2. That path negotiates a
// graceful GOAWAY first and owns its own registry + backstop (proxy_tunnel_h2_drain.go);
// duplicating it here would double-count `activeConns` and force-close a conn that is
// mid-graceful-shutdown.

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// tunnelClass identifies a hijacked-tunnel class for the drain registry and the
// per-class `culvert_tunnels_active` gauge. The gauge exists because `activeConns`
// conflates every class into one number: an operator who sees the drain time out
// needs to know WHICH kind of session is holding the node, since the remedies differ
// (a stuck SSH-over-SOCKS5 session is a user to notify; a pinned inspect tunnel is a
// policy question).
type tunnelClass int

const (
	tunnelClassConnectBypass tunnelClass = iota
	tunnelClassConnectInspect
	tunnelClassInspectFallback
	tunnelClassWebSocket
	tunnelClassSOCKS5
	tunnelClassCount
)

// tunnelClassNames are the `class` label values. Stable strings — they are a
// monitoring contract; renaming one silently breaks an operator's dashboard.
var tunnelClassNames = [tunnelClassCount]string{
	tunnelClassConnectBypass:   "connect_bypass",
	tunnelClassConnectInspect:  "connect_inspect",
	tunnelClassInspectFallback: "inspect_fallback",
	tunnelClassWebSocket:       "websocket",
	tunnelClassSOCKS5:          "socks5",
}

func (c tunnelClass) String() string {
	if c < 0 || c >= tunnelClassCount {
		return "unknown"
	}
	return tunnelClassNames[c]
}

// tunnelDrainEntry is one registered tunnel. The KEY of the registry map is the
// *entry pointer, never a conn: two tunnels can legitimately hold the same conn value
// (the strip-path fallback registers rawClient on one side and the inspect path
// registers the tls.Conn wrapping it), and a conn-keyed map would have one release
// silently evict the other's registration — a leak in the direction that matters, since
// the surviving tunnel would then never be force-closed.
type tunnelDrainEntry struct {
	class    tunnelClass
	conns    []net.Conn
	released sync.Once
}

var (
	// tunnelDrainConns is the live registry: *tunnelDrainEntry -> struct{}.
	tunnelDrainConns sync.Map

	// tunnelClassActive is the per-class gauge feeding `culvert_tunnels_active`.
	tunnelClassActive [tunnelClassCount]int64

	// statTunnelForced counts conns hard-closed by the drain-deadline backstop.
	statTunnelForced int64
)

// registerDrainableTunnel records a live hijacked tunnel and returns its release
// function. It OWNS the `activeConns` accounting for its class, so a caller must not
// also call `recordActiveConn` — the drain would then wait for a count that never
// reaches zero, spending the whole window on every shutdown forever after.
//
// Callers use it as a single deferred statement immediately after the tunnel is
// established, with nothing between the register and the defer:
//
//	defer registerDrainableTunnel(tunnelClassWebSocket, clientConn, destConn)()
//
// The release is idempotent (sync.Once), so an extra call cannot drive the gauge
// negative; nil conns are dropped at registration so the backstop never nil-derefs.
func registerDrainableTunnel(class tunnelClass, conns ...net.Conn) func() {
	live := make([]net.Conn, 0, len(conns))
	for _, c := range conns {
		if c != nil {
			live = append(live, c)
		}
	}
	e := &tunnelDrainEntry{class: class, conns: live}
	tunnelDrainConns.Store(e, struct{}{})
	if class >= 0 && class < tunnelClassCount {
		atomic.AddInt64(&tunnelClassActive[class], 1)
	}
	recordActiveConn(1)
	return func() {
		e.released.Do(func() {
			tunnelDrainConns.Delete(e)
			if class >= 0 && class < tunnelClassCount {
				atomic.AddInt64(&tunnelClassActive[class], -1)
			}
			recordActiveConn(-1)
		})
	}
}

// forceCloseDrainableTunnels is the drain-deadline backstop: it hard-closes both legs
// of every still-registered tunnel so a long-lived session cannot pin a departing node
// past the drain window, and so the severed relays reach their TUNNEL_CLOSED accounting
// before the flush hooks run. Returns the number of TUNNELS closed (not conns) and a
// per-class breakdown for the operator log line.
//
// Closing the conn — rather than cancelling a context — is what unblocks the relay
// deterministically: `idleCopyCounted` sits in `io.CopyBuffer`, which only returns on a
// read/write error, and the peer direction may be parked in a deadline-less Write that
// nothing but a close can end (the same reason every relay's panic path closes BOTH
// legs). Registry entries are left in place: the relay's own release removes them, and
// deleting here would race a concurrent release into double-decrementing the gauge.
// A double Close is a harmless already-closed error.
func forceCloseDrainableTunnels() (int, string) {
	var perClass [tunnelClassCount]int
	n := 0
	tunnelDrainConns.Range(func(k, _ any) bool {
		e, ok := k.(*tunnelDrainEntry)
		if !ok {
			return true
		}
		for _, c := range e.conns {
			_ = c.Close() //nolint:errcheck // backstop: force-unblock a laggard relay at the deadline
		}
		if e.class >= 0 && e.class < tunnelClassCount {
			perClass[e.class]++
		}
		n++
		return true
	})
	if n > 0 {
		atomic.AddInt64(&statTunnelForced, int64(n))
	}
	return n, formatTunnelClassBreakdown(perClass)
}

// formatTunnelClassBreakdown renders a stable, comma-separated "class=n" list of the
// non-zero classes. Split out so the log-line shape is testable without driving the
// process-global registry.
func formatTunnelClassBreakdown(perClass [tunnelClassCount]int) string {
	var b strings.Builder
	for i := tunnelClass(0); i < tunnelClassCount; i++ {
		if perClass[i] == 0 {
			continue
		}
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		b.WriteString(tunnelClassNames[i])
		b.WriteByte('=')
		b.WriteString(strconv.Itoa(perClass[i]))
	}
	if b.Len() == 0 {
		return "none"
	}
	return b.String()
}

// tunnelForceCloseSettle bounds how long the drain lingers AFTER force-closing so the
// severed relays can hand their TUNNEL_CLOSED entries to the request-log queue before
// the FLUSH hooks (order ≥ 110) run. Without it the ordering is only probabilistic —
// the relays need microseconds and the intervening hooks take milliseconds, so it
// "works" — and this file exists because probabilistic shutdown ordering is exactly
// what CHAOS-56 removed everywhere else.
//
// It is a CEILING, not a budget: it is clamped to whatever the drain phase has left, so
// a settle can never overrun the phase deadline or borrow from the flush reserve. When
// the budget is already gone the settle is SKIPPED, and the accounting for those
// tunnels is lost exactly as it was before this change — never worse.
const tunnelForceCloseSettle = 2 * time.Second

// settleAfterForceClose waits for `activeConns` to reach zero, bounded by
// tunnelForceCloseSettle and by whatever ctx has left, and reports how many tunnels
// were still outstanding when it gave up.
//
// It can legitimately time out: `activeConns` is a SUPERSET of what either backstop can
// force-close (a native-ALPN inspect tunnel mid-handshake is counted but held by
// neither registry), so this is a best-effort settle, never a guarantee that every
// tunnel drained. It never blocks longer than its own ceiling.
func settleAfterForceClose(ctx context.Context) int64 {
	if remaining := getActiveConns(); remaining <= 0 {
		return 0
	}
	budget := tunnelForceCloseSettle
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < budget {
			budget = left
		}
	}
	if budget <= 0 {
		return getActiveConns()
	}
	timer := time.NewTimer(budget)
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return getActiveConns()
		case <-timer.C:
			return getActiveConns()
		case <-tick.C:
			if getActiveConns() <= 0 {
				return 0
			}
		}
	}
}

// resetTunnelDrainRegistryForTest clears the process-global registry and gauges so a
// test that leaves a registration behind cannot poison a later one (the PR3d
// fence-pollution class). Test-only; never called from production code.
func resetTunnelDrainRegistryForTest() {
	tunnelDrainConns.Range(func(k, _ any) bool {
		tunnelDrainConns.Delete(k)
		return true
	})
	for i := range tunnelClassActive {
		atomic.StoreInt64(&tunnelClassActive[i], 0)
	}
	atomic.StoreInt64(&statTunnelForced, 0)
	atomic.StoreInt64(&activeConns, 0)
}
