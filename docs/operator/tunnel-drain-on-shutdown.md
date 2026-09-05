# Tunnel drain on shutdown

*What happens to in-flight tunnels when a Culvert node is stopped, restarted or
upgraded — and how to tell whether it left cleanly.*

Related: `graceful-shutdown.md` (the bounded shutdown sequence),
`socks5-listener-health.md`, `roadmap/CHAOS-ENGINEERING-REVIEW.md` §24–§25.

---

## 1. What a tunnel is here

Culvert forwards most traffic request-by-request, but seven kinds of connection
are **hijacked**: the proxy takes the raw socket and relays bytes until one side
goes away. These are the sessions that survive across many minutes or hours, and
they are the ones a restart can interrupt.

| class (metric label) | what it is |
|---|---|
| `connect_bypass` | `CONNECT` tunnel on a rule that does not inspect |
| `connect_inspect` | `CONNECT` tunnel under SSL inspection (both the strip and native-ALPN paths) |
| `inspect_fallback` | a non-TLS protocol (SSH, RDP, …) found inside a `CONNECT` on an inspect rule, relayed raw |
| `websocket` | a `101 Switching Protocols` upgrade proxied end to end |
| `socks5` | a SOCKS5 session |

Inspected HTTP/2 tunnels are a subset of `connect_inspect` and carry their own
`culvert_h2_inspect_*` series, because only they can be signalled with a
graceful HTTP/2 `GOAWAY`.

## 2. What happens on SIGTERM

The shutdown sequence stops accepting first, then drains:

1. **order 80** — the SOCKS5 listener stops accepting.
2. **order 90** — the proxy HTTP listener stops accepting.
3. **order 94 — the establishment fence.** New long-lived tunnels are refused
   from here on. In practice this affects SOCKS5: a session accepted just before
   the listener closed can still be negotiating or dialling, and if it were
   allowed to establish now it would do so *behind* the drain and be reset at
   process exit with no record. Such a client gets a SOCKS5 `0x01` (general
   server failure) and a `SOCKS5 SHUTTING_DOWN` log line, so it can retry —
   against another node, on a fleet — instead of receiving a success reply and a
   tunnel that dies seconds later. Counted by
   `culvert_tunnel_fence_refused_total`. A handful of these during a restart is
   expected and healthy; the alternative is a silently orphaned tunnel.
4. **order 95** — inspected-H2 tunnels are sent a `GOAWAY` (in-flight streams
   may finish; no new ones start).
5. **order 100 — the drain.** It waits for every live tunnel of every class to
   end on its own, up to **15 s** *or* whatever the shutdown phase has left,
   whichever is shorter.
6. **At the drain deadline**, any tunnel still live is **force-closed**. Its
   relay unblocks, and its `TUNNEL_CLOSED` accounting entry (bytes each way,
   duration, matched rule, identity) is written.
7. **order ≥ 110** — the flush hooks close the syslog socket, the category
   store, the request log, the audit log and the process log.

A force-close is a clean, deliberate teardown — not a failure. It is what
replaces the container's `SIGKILL` resetting the socket with nothing recorded.

**Clients see a closed connection either way.** Culvert cannot migrate a live
tunnel to another node. If you need zero interruption for long-lived sessions,
drain the node at your load balancer and let the sessions age out **before**
sending SIGTERM.

## 3. Reading the shutdown log

On a node with nothing in flight, the drain is silent and instant.

Otherwise you get one opening line and one closing line:

```
Draining 42 active tunnel(s) (3 inspected H2)…
All tunnels drained
```

That is the clean case: every session ended by itself inside the window.

```
Draining 42 active tunnel(s) (3 inspected H2)…
Drain timeout: 0 tunnel(s) still active (force-closed 3 inspected H2, 11 hijacked [websocket=4, socks5=7])
```

The window expired with 11 sessions still open, so they were force-closed. The
`[class=n]` breakdown is the actionable part — it says **which** kind of session
held the node, and those have different owners (a SOCKS5 count is usually
someone's SSH or database tunnel; a `websocket` count is an application).

```
Drain budget exhausted: 6 tunnel(s) still active (force-closed 0 inspected H2, 6 hijacked [socks5=6])
```

The **phase** budget ran out before the 15 s window did — the shutdown as a
whole is running late, usually because an earlier hook was slow. The tunnels are
still force-closed, but the brief settle that lets their accounting reach the
request log is skipped, so those six sessions will have no `TUNNEL_CLOSED`
entry. Investigate the slow hook, not the tunnels (see `graceful-shutdown.md`).

## 4. Metrics

```
culvert_tunnels_active{class="connect_bypass"}     gauge
culvert_tunnels_active{class="connect_inspect"}    gauge
culvert_tunnels_active{class="inspect_fallback"}   gauge
culvert_tunnels_active{class="websocket"}          gauge
culvert_tunnels_active{class="socks5"}             gauge
culvert_tunnel_drain_forced_total                  counter
culvert_tunnel_fence_refused_total                 counter
```

**Use `culvert_tunnels_active` for capacity, not for alerting.** Each tunnel
holds two file descriptors, two goroutines and a pooled 128 KB relay buffer for
its whole lifetime, so the sum across classes is the right input when sizing a
node's FD limit or the per-IP connection cap. A high steady value is normal for
a gateway that carries SSH or WebSocket traffic.

**`culvert_tunnel_drain_forced_total` is an operational signal, not an error
counter.** It increments only during shutdown. A persistently non-zero rate
across a fleet upgrade means the 15 s window is shorter than this deployment's
session mix — the sessions were ended deterministically and accounted for, which
is the intended behaviour. It is worth knowing because it tells you how many
users saw a reset connection on the last maintenance window.

A useful panel is the per-class gauge over time with upgrade windows annotated:
the drop to zero is the restart, and the height just before it is how many
sessions the restart cost.

## 5. Frequently asked

**Why did my restart suddenly take 15 seconds?**
Because there were live WebSocket or SOCKS5 sessions and the node waited for
them. Before CHAOS-57 those classes were invisible to the drain, so the node
returned instantly and reset them without recording anything. The wait is the
grace they always should have had; the force-close at the end bounds it.

**Can I shorten or disable the window?**
Not at runtime — it is a compile-time bound (`tunnelDrainWindow`, 15 s), and it
is already clamped by the shutdown phase budget, so it can never be the thing
that makes a shutdown exceed its envelope. If your maintenance windows cannot
absorb it, drain at the load balancer first.

**Why is `culvert_tunnels_active{class="connect_inspect"}` higher than
`culvert_h2_inspect_active`?**
Expected. `connect_inspect` counts every inspected CONNECT tunnel;
`culvert_h2_inspect_active` counts only the subset that negotiated HTTP/2 and
can therefore be sent a graceful `GOAWAY`.

**A tunnel was force-closed — did the traffic get scanned?**
Yes, up to the point of the close. Force-closing is a teardown, not a policy
bypass: no security control is skipped, and the session's `TUNNEL_CLOSED` entry
records the bytes that did flow.

**I see `SOCKS5 SHUTTING_DOWN` lines during every restart — is something wrong?**
No. That is the establishment fence doing its job: a session that was still
negotiating or dialling when the node started draining is refused rather than
allowed to establish behind the drain, where it would be reset at process exit
with no accounting. The client gets a clean protocol-level failure and retries.
`culvert_tunnel_fence_refused_total` counts them. A large number would mean your
SOCKS5 clients reconnect very aggressively, not that the node misbehaved.
