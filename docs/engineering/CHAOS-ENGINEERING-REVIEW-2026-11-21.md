# Chaos engineering review — 2026-11-21

Reviewer: Culvert Chaos Engineer (automated round). Base revision `0fe4578`
(`origin/main`), clean worktree at branch point.
[CHAOS-ENGINEERING-REVIEW.md](../../roadmap/CHAOS-ENGINEERING-REVIEW.md) stays
the index; this is the dated record for the round it registers.

Id claimed: **CHAOS-125**, in a committed placeholder row as commit one, before
any code, and checked against `origin/main` rather than the working tree per the
register's 2026-09-25 amendment. `CHAOS-124` was the highest id anywhere on
`origin/main` at `0fe4578`, and no open PR held a chaos id (#1977, #1705, #1549,
#1548, #1536, #1528, #1526). The round was claimed on 2026-11-20 and recorded
the following day.

Scope: **the inspected tunnel's SETUP WINDOW** — the interval between the
`200 Connection Established` an SSL-inspect rule sends and the established
tunnel its enforcement loop owns. This round **closes `CHAOS-32`**, found on
2026-07-07, sized "S", listed twelfth in that round's ranked improvements, never
implemented, and since **duplicated into the native-ALPN leg that did not exist
when it was written**.

---

## 1. Executive summary

An inspected tunnel's life has three phases. Culvert bounds the first and the
third explicitly, and said so in its own comments; the one in the middle was
bounded by nothing at all, on both dispatches.

- The **bypass relay** registers with the shutdown drain immediately after its
  own 200 (`proxy_tunnel.go:617`, `tunnelClassConnectBypass`) and is reaped by
  `tunnelIdleTimeout` — whose doc comment states the exact failure mode this
  round found one layer up: "Half-open peers that keep ACKing TCP keepalives but
  never send data previously pinned 2 goroutines + 2 FDs indefinitely; a flood of
  such connections exhausts the process."
- The **inner enforcement loop** arms a read deadline per iteration
  (`proxy_tunnel.go:1212`) "so a slow client cannot hold the connection open
  indefinitely by trickling bytes".
- Between them: the origin TLS handshake, the client first-byte peek, the native
  leg's two ClientHello record peeks, and the forged-leaf client handshake. **No
  deadline on either leg, on either dispatch.**

**CHAOS-125a (HIGH) — the bound the window looks like it has is deleted before
the window opens.** The proxy listener sets `ReadTimeout: 30 * time.Second`
(`main.go:1220`). `net/http`'s `hijackLocked` calls `rwc.SetDeadline(time.Time{})`
on the way out (`$GOROOT/src/net/http/server.go:326`, go1.27.4), so the socket
the inspect path takes ownership of carries **no deadline of any kind**.
`r.Context()` is not a substitute: the server cancels it when the handler
*returns*, not when a hijacked client goes quiet, and `http.Server.Shutdown`
explicitly neither closes nor waits for hijacked connections. So
`peekBuf.Peek(1)` (`proxy_tunnel.go:1043`, `proxy_tunnel_h2.go:190`),
`peekClientALPN`'s `Peek(5)` / `Peek(5+recLen)` (`proxy_tunnel_h2.go:311,316`)
and `clientTLS.HandshakeContext(r.Context())` (`proxy_tunnel.go:1074`,
`proxy_tunnel_h2.go:232`) all block for as long as the client cares to stay
silent.

Measured on this tree, before the fix, with the production code path and the real
listener (`inspect_setup_window_chaos125_test.go`, control runs recorded in §11):

| probe | observed |
|---|---|
| strip leg, client silent after the 200 | client leg held **8.0 s**, then **15.0 s** — in both cases the probe's own patience, not the code's; origin leg never released |
| native leg, same | client leg held **8.0 s / 15.0 s**; origin leg never released |
| blackholing origin (accepts TCP, never speaks TLS), strip leg | handler and client leg held **15.0 s**, no 502 |
| 100 silent admitted clients, held 10 s | **+400 FDs, +200 goroutines** in the single-process harness |

The 4.0 FDs and 2.0 goroutines per connection in that last row are the harness's
total, which hosts the client and the origin in the same process. The gateway's
own share is **2 sockets and 1 handler goroutine per connection** by
construction: the hijacked client socket plus the origin socket — and on the
strip leg that origin socket is a **completed TLS session**, so the attacker also
spends Culvert's handshake CPU and an origin connection slot, not just a file
descriptor. There is no timer at any length in the path; the numbers above are
floors, not measurements of a bound.

**Nothing capped the concurrency of this state and nothing counted it.**
`registerDrainableTunnel` — which owns the `activeConns` increment and hands the
drain the force-close handles — is only reached *after* both handshakes
(`proxy_tunnel.go:1094`, `proxy_tunnel_h2.go:258`), so a connection in the setup
window appeared in no gauge and no registry. The per-IP connection limiter is
`0 = off` in the default configuration (`connlimit_startup_config.go:13`, the
default CHAOS-112 recorded), so one source IP could hold as many as it liked.

**CHAOS-125b (MED) — the window was also SILENT, and the native leg was
completely silent.** The strip leg's peek failure logged one line and recorded
nothing: no metric, no coverage, no drill-down row. The native leg's
`if ferr != nil` branch closed both legs and returned with **no log line, no
metric and no row at all** — so the native leg's share of this stall, and every
ordinary client that disconnects between the 200 and its ClientHello, left no
trace anywhere in the product. The taxonomy cell for it already existed and had
never been written by anything: `classifyClientFailure` maps `"i/o timeout"` to
(`client_hello`, `timeout`) at `decryption_observability.go:414`.

**The house already had the pattern.** `handleSOCKS5` arms a single 30 s
negotiation deadline on accept (`socks5.go:443`) and clears it at the moment it
starts streaming (`socks5.go:578`). That is this fix, in another listener, in
code older than this review series. The CONNECT-inspect path simply never got
it — and when the native-ALPN dispatch was added, the gap was copied rather than
noticed.

**Shipped:** one named budget (`sslInspectSetupTimeout`, 30 s — the listener's
own `ReadTimeout`, restored to the socket for the window `Hijack` cleared it
for), armed on the origin leg at the dial (one site, before the native/strip
split, so both dispatches inherit it) and on the client leg at the hijack, and
cleared on **both** legs the moment the tunnel is established. Acquiring the
hijacked leg and arming it are now one function (`adoptHijackedInspectLeg`), so a
third dispatch cannot take the buffered reader without the deadline. The
client-leg setup failure is recorded through the existing ADR-0011 taxonomy by a
shared recorder, with **no new vocabulary** and deliberately **no fail-open
learn**.

---

## 2. Failure scenarios

**S1 — handshake-slowloris against an inspect rule (the primary).** A client
completes CONNECT to any host an inspect rule matches, reads the 200, and sends
nothing. *Before:* two sockets and a goroutine per connection held until the
process dies, uncapped, uncounted, with the strip leg's origin TLS session held
open too. At a default `ulimit -n` of 1024 a few hundred such connections stop
the listener accepting; the gateway stops forwarding traffic for everybody.
*After:* both legs released after one 30 s budget, recorded as
(`client_hello`, `timeout`).

**S2 — the same, one byte in.** The client sends `0x16` and stops, so the
first-byte peek succeeds and the stall lands in the forged-leaf handshake (strip
leg) or in `peekClientALPN`'s record peek (native leg). Same cost before, same
bound now — the window covers the whole phase, not one call in it.

**S3 — a declared-but-undelivered ClientHello record (native leg).** The client
writes a 5-byte header declaring a record length and then sends fewer bytes.
`Peek(5+recLen)` with `recLen > 4091` returns `ErrBufferFull` immediately (the
hijacked `bufio.Reader` is the server's 4 KiB buffer), so there is no memory
amplification here — but for any `recLen` inside the buffer the read blocked
exactly as in S1. Bounded now.

**S4 — a blackholing origin.** An origin that completes the TCP handshake and
then never speaks TLS. The dialer's `Timeout: 10 * time.Second` covers the dial
only, and `HandshakeContext`'s context is `r.Context()`, which nothing cancels
here. *Before:* the handler goroutine and the client's own connection were held
indefinitely, and the client never got its 502. *After:* the handshake fails
inside the window, the client gets `HTTP/1.1 502`, and the failure records
through `originInspectFailureOutcome` as it always did.

**S5 — mass reconnect storm meeting S1 (the compounding case).** A reconnect
storm after a fleet-wide event is the condition under which half-open and
abandoned connections are *normal*, not adversarial: a laptop that suspends
between the 200 and its ClientHello left the same pinned pair behind. S1's cost
therefore accrued without an attacker, and because nothing counted the state the
only visible symptom was the gateway running out of descriptors.

---

## 3. Risk matrix

| id | severity | likelihood | domain | before | after |
|---|---|---|---|---|---|
| 125a | HIGH | high (needs only a client allowed to CONNECT; happens accidentally on suspend/reconnect) | HTTPS proxy / data plane | 2 FDs + 1 goroutine + an origin TLS session per connection, unbounded, uncapped, uncounted | released within one 30 s budget per leg |
| 125b | MED | certain (every client that leaves in the window) | observability | strip leg: a log line only; native leg: nothing at all | ADR-0011 (`client_hello`, `timeout`) + `DECRYPT_FAILED` row on both |
| 125c (S4) | MED | medium (a blackholing origin is an ordinary network fault) | upstream / TLS | handler + client leg pinned, no 502 | handshake fails in-window, client gets its 502 |

Severity note: CHAOS-32 rated this **MED** in 2026-07-07. It is rated HIGH here
on two grounds that round did not have. The native-ALPN dispatch has since
doubled the reachable surface and made the window *longer* (it peeks before the
origin handshake, so a silent client pins a dialled origin socket as well). And
the per-IP limiter that would have blunted it is off by default — a fact
established by CHAOS-112 after CHAOS-32 was written.

---

## 4. Recovery assessment

**Automatic recovery, before:** none. No timer, no registry, no counter. The
only recovery was a process restart, and a restart under this condition is the
customer's outage, not a repair.

**Automatic recovery, after:** deterministic and local. Each leg carries one
absolute deadline; its expiry closes both legs, records the failure and returns
the goroutine. No retry, no backoff, no hidden state — the connection is gone
and the client's next attempt is a fresh one, which is the correct shape for a
phase that has no partial result worth preserving.

**Manual recovery:** unchanged and no longer the only option. An operator who
wants the symptom capped *below* the budget has `MaxConnsPerIP` (now meaningful,
because the state it caps is finite in time).

**Fail direction:** this is fail-closed in the inspection sense — the refused
connection is never relayed, never bypassed, and never learns an auto-exclusion.
The client is disconnected rather than served uninspected, which is the posture
SEC-INSPECT-PLAINTEXT-1 fixed for the plaintext case and the same choice here.

---

## 5. Operational impact

Before, an operator's first and only signal was descriptor exhaustion across the
whole listener, with no series to correlate and no row naming the hosts or
clients involved. After, the stall is an ordinary `DECRYPT_FAILED` row with a
dec block in the Decryption Health drill-down, and it moves the existing
`culvert_decrypt_failures_total` taxonomy counter in the (`client_hello`,
`timeout`) cell. A burst of that cell is now the signature of this condition —
and it reads the same whether the cause is an attack, a captive portal or a
fleet of suspending laptops, which is honest: the gateway cannot tell those
apart and should not pretend to.

No alert was added. A client-side stall on a single tunnel is not an incident,
and a threshold that fires on the normal background rate of clients leaving
mid-handshake would be noise. The metric and the row are the surfaces; a
deployment that wants paging writes a rate rule on the cell it now has.

No configuration surface was added: GUI/API parity is not owed here, and the
reason is recorded in the code comment — this is a security boundary with a
budget two orders of magnitude longer than any real handshake, not an operator
setting. That matches the recorded startup-only/trust-boundary exception class
in [conventions](../agent-context/conventions.md), and it is the same decision
`tunnelIdleTimeout` and the SOCKS5 negotiation deadline already carry.

---

## 6. Security impact

**The window was a denial-of-service lever against the gateway's primary
function,** available to anything permitted to open a CONNECT to an
inspect-marked host, costing the attacker one idle socket per two of Culvert's
and zero bandwidth after the CONNECT line. That is the cheapest ratio in the data
path.

**Two things it was NOT, and the fix keeps them that way.** It never produced
uninspected traffic: the refusal closes both legs rather than relaying, so the
SEC-INSPECT-PLAINTEXT-1 posture is untouched. And the new recorder deliberately
does **not** consult `maybeFailOpenClient`: a client-side stall must never teach
an auto-exclusion, or anything able to open a CONNECT and go quiet could *teach
the gateway to stop inspecting a host* on the next connection — a bypass
manufactured out of a timeout. Both chaos gates assert `autoExclude().Len() == 0`
after the reap for exactly this reason.

**One residual asymmetry, stated rather than fixed:** a client whose ClientHello
genuinely takes longer than 30 s to arrive is now disconnected. That is the
intended trade (it is indistinguishable from the attack at the protocol level),
and 30 s is ~3 orders of magnitude above a real handshake on any link a gateway
serves.

---

## 7. Data-integrity impact

None. The window holds no durable state: no file is written, no configuration
version is created, no roster or policy mutation is in flight, and the audit ring
is untouched. The one persisted artifact is the new `DECRYPT_FAILED` log row,
which is append-only through `persistLogEntry` and carries no raw error string
(the ADR-0011 builders record the categorical result only).

---

## 8. Monitoring, logging and alert quality

- **Metric:** no new series. The existing decryption-failure taxonomy counter
  gains traffic in a cell that previously could not be reached, which is a
  strictly better outcome than a bespoke gauge nobody has a dashboard for.
- **Logging:** the native leg gains the log line it never had
  (`SSL_INSPECT(native) client-hello peek %q: %v`), with `sanitizeLog` + `%q` on
  the host per CWE-117. Both legs now log through the same shared recorder, so
  they cannot drift again.
- **Row:** a `DECRYPT_FAILED` entry with a dec block, at level ERROR, method
  CONNECT, `ssl_action=inspect` — the shape the Decryption Health drill-down
  filters on, asserted by the new gates.
- **Alert:** none, for the reason in §5.
- **What is still not visible:** a connection *currently inside* the setup window
  is still in no gauge. The fix bounds the state rather than counting it; see
  §10.

---

## 9. Suggested improvements, in priority order

1. **Shipped here:** bound the window on both legs of both dispatches; record
   the client-leg failure; make acquisition and arming one function.
2. **Count the window (not shipped).** A gauge of connections between the 200
   and `registerDrainableTunnel` would make the state observable while it is
   held, not only when it ends. It needs an owner decision on whether the
   pre-established phase joins `activeConns` (which would change what the drain
   waits for) or gets its own series. Recorded for the round that takes the
   drain's accounting contract.
3. **Audit the remaining hijack sites for the same class.** This round checked
   all four in the tree: the two inspect dispatches (fixed), the CONNECT bypass
   (`proxy_tunnel.go:601` — registers with the drain immediately and is
   idle-bounded) and the WebSocket relay (`proxy_tunnel.go:212` — same). The
   SOCKS5 listener already carries the pattern. No further site is open **in this
   tree**, which is the point: the next *new* hijack is the risk, and
   `adoptHijackedInspectLeg` is the structural answer for the inspect family
   only.
4. **Revisit the `MaxConnsPerIP = 0` default** (CHAOS-112's open item, not this
   round's to change). Every per-connection bound in the data path is a product
   of time × concurrency, and Culvert bounds the first factor well and the second
   not at all by default.

---

## 10. Residual risk

**The budget is per leg, not per tunnel.** Each leg's absolute deadline is armed
when that leg becomes the handler's to hold — the origin leg at the dial, the
client leg at the hijack — so a pathological tunnel can consume one budget on
each, i.e. up to 60 s of setup rather than 30. This was chosen over threading a
single deadline through `handleInspectNativeALPN`'s already eight-parameter
signature. Bounded either way, which is the property that was missing; the
tighter variant is an owner call, not a correctness fix.

**A connection inside the window is still uncounted.** See §9.2. An operator
watching a storm sees the *outcomes* (the taxonomy cell) rather than the
*occupancy*.

**30 s is not configurable.** Deliberate, with the reason in the code comment.
An operator who needs tighter has `MaxConnsPerIP`; one who needs looser has a
client that cannot complete a TLS handshake in half a minute, which is a client
problem.

**A slow-but-progressing ClientHello is not distinguished from a stalled one.**
The window is an absolute deadline, not an inactivity timer, because unlike the
body paths (which re-arm on progress via `h2StallReader` /
`stallDetectReadCloser`) a handshake has no legitimate reason to take longer than
its budget. The consequence is that a client trickling a valid ClientHello over
31 s is dropped. Accepted.

**The clear is the dangerous half, and it is tested rather than argued.** The
armed deadline is a WRITE deadline too; left on, it would abort a healthy
inspected tunnel's response delivery one window after setup — a bound turned
into an outage. Both dispatches clear both legs before their enforcement loop
starts, and
`TestChaos125_EstablishedInspectedTunnelOutlivesTheSetupWindow` serves two
requests across two idle windows to pin it. That gate passes on the *unfixed*
tree too (there was no deadline to leave behind), so it is a guard against this
round's own failure mode, not a reproduction — stated here so a later reader does
not mistake it for one.

**Sidecar/CDR and H2 inner-stream phases are out of scope** and already owned:
per-stream stalls are `h2StreamStallTimeout`, the scan window is CHAOS-106/115.

---

## 11. Tests

Five new cases in `inspect_setup_window_chaos125_test.go` (root, because the
production wiring under test is main's), plus two shared helpers
(`shortenInspectSetupWindow`, `inspectProbeOriginListener`) and a probe
(`silentInspectClientProbe`) that drives the real listener end to end — real
CONNECT, real policy match, real CA, real hijack.

| test | pins |
|---|---|
| `TestChaos125_SilentClientOnStripInspectLegIsReaped` | both legs released inside the window; the release is not premature (≥ half the budget); the (`client_hello`, `timeout`) row exists; no auto-exclusion learned |
| `TestChaos125_SilentClientOnNativeInspectLegIsReaped` | the same for the native dispatch, against a PLAIN TCP origin — the extra reachability that leg added |
| `TestChaos125_StalledOriginHandshakeDoesNotPinTheClientLeg` | a blackholing origin's handshake fails in-window and the client gets its 502 |
| `TestChaos125_EstablishedInspectedTunnelOutlivesTheSetupWindow` | the regression guard: two requests across two idle windows on an established tunnel (no left-over write deadline) |

**Negative control (the measurement).** With the arming disabled and everything
else identical — including the new helpers, so the only variable is the
deadline — the three reproduction gates fail, each holding for 15.0 s, the
probe's own patience:

```
--- FAIL: TestChaos125_SilentClientOnStripInspectLegIsReaped (20.01s)
    the gateway held a silent admitted client's leg for 15.000316333s with no
    sign of releasing it: the setup window (600ms) did not bound the first-byte peek
--- FAIL: TestChaos125_SilentClientOnNativeInspectLegIsReaped (20.02s)
    ... did not bound the native leg's peeks
--- FAIL: TestChaos125_StalledOriginHandshakeDoesNotPinTheClientLeg (15.02s)
    a blackholing origin's TLS handshake pinned the inspect handler and the
    client leg for 15.014709172s ...
```

The fourth gate passes in the control, as §10 records.

### Checks run, at the branch tip

| check | command | result |
|---|---|---|
| build | `go build ./...` | pass |
| vet | `go vet ./` | pass |
| root package, full | `go test ./ -count=1` | **pass** (470 s) |
| internal + cmd, full | `go test ./internal/... ./cmd/... -count=1` | **pass** |
| focused, race | `go test -race ./ -run 'TestChaos125_\|MITM\|Inspect\|Native\|H2\|Tunnel\|CONNECT\|Drain'` | pass |
| chaos gates | `go test ./ -run 'TestChaos125_' -count=1` | pass |
| chaos gates, control | arming disabled | **3 of 4 fail as designed** |
| lint, gate command | `golangci-lint run --new-from-rev origin/main` (v2.15.0, installed with the `go.mod` toolchain go1.27.4) | **0 issues** |
| lint, full tree vs base | `golangci-lint run` on the working tree and on the stashed base | **identical totals (175)** — the conventions' required second pass caught a real regression this way: `handleInspectNativeALPN` crossed `funlen` (51 > 50), which `--new-from-rev` cannot see because the linter attributes to the declaration line. Fixed by extracting the two shared helpers, not by suppressing. |
| product contracts | `go run ./cmd/contractcheck impact -base origin/main` | SWG-001, SWG-002, TLS-001, TLS-002, TLS-900 touched; **no contract amended or retired** (the fix adds a bound, it does not change an asserted behavior) — all five named tests run and pass |
| guidance checker | `python3 docs/agent-context/check.py` | pass (exit 0) |

Not run, and why: the sharded `-race -cover` aggregate and the hosted Fast PR
Gate run on the pushed SHA, not here; the `benchgate`-tagged residency
benchmarks are outside this change's paths (no allocation or buffer behavior was
touched). A passing local check is not a passing merge gate.

---

## 12. Suggested PR

Title: `fix(inspect): bound the inspected tunnel's setup window (CHAOS-125, closes CHAOS-32)`

Contents: the two production files (`proxy_tunnel.go`, `proxy_tunnel_h2.go`), the
new chaos gates, the register's claim row, and this record. No behavior outside
the setup window changes; no configuration surface, metric name, alert type,
persisted shape or wire format is added or altered.
