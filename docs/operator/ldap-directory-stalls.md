# When the directory stops answering

*Applies to any node authenticating proxy traffic against LDAP or Active
Directory — the legacy `ldap:` YAML block or an LDAP IdP profile (ADR-0027).
Nodes with no directory configured never reach this path.*

Culvert's identity backends already had a posture for a directory that is
**down**: fail closed, arm a short provider-wide cooldown, deny without dialing,
and clear the moment the directory answers again (CHAOS-47). This page is about
the other fault — the directory that is **up enough to accept your connection
and then stops answering** — and what CHAOS-57 changed about it.

---

## The two faults, and why they behaved differently

| Fault | What the directory does | Before CHAOS-57 | Now |
|---|---|---|---|
| **Down** | Refuses the connection, or DNS fails | Detected on the first request, cooldown arms, subsequent requests denied without a dial | Unchanged |
| **Stalled** | Completes the TCP handshake, then goes silent | **Never detected.** The request goroutine blocked forever | Bounded at 10 s, then treated exactly like *down* |

A stall is not exotic. It is what you get from an overloaded directory, a
firewall that drops established flows without sending a reset, a half-open
socket left behind by a peer reboot, a hung VM, or a storage stall on the
directory host. In every one of those cases the TCP connection succeeds — so
the "is it reachable?" question that the dial answers is the wrong question.

The reason the stall was invisible is worth stating plainly, because it is the
general lesson: **the cooldown is armed by an error that returns.** A stalled
directory never returns one, so the mitigation designed for an unreachable
directory was structurally blind to the fault class that hangs.

---

## What it cost

Every proxied request that needed a directory decision and missed the auth cache
held, for the life of the process:

- a request goroutine,
- a socket and file descriptor to the directory,
- the client's own connection,
- a per-IP connection-limiter slot.

Nothing timed out, nothing was counted, nothing was logged, and no health
surface moved. The node stayed "green" while authentication silently stopped
completing. File-descriptor exhaustion is the terminal state, and an
FD-exhausted node is where CHAOS-54's SOCKS5 findings begin — so this fault
feeds a known amplifier rather than staying contained.

---

## The bound

One directory round trip — dial, optional StartTLS, service bind, user search,
user bind — is now bounded end to end at **10 seconds**, as a single envelope
rather than a per-step allowance.

That is deliberately the same budget this process already gives one identity
resolution against an OIDC IdP. Two identity backends answering the same
question on the same request path should not disagree about how long that
decision may take.

The bound is enforced in two layers, and they are **not** redundant:

1. **A per-message timeout.** Bind, search and the StartTLS response now fail
   with an ordinary network error, which the existing classifier already reads
   as *unreachable* — so a stall arms the cooldown exactly like a refused dial.
2. **A connection watchdog.** The client library runs the TLS handshake that
   follows a StartTLS acknowledgement on the raw socket, outside its own request
   timer. A directory that ACKs StartTLS and then never negotiates TLS therefore
   hangs even with layer 1 armed. Only closing the connection unblocks it.

If you are wondering whether layer 2 is real: it has a dedicated test that
asserts the library still behaves this way, so a future library upgrade that
fixes it will fail the build rather than leave a backstop quietly guarding
nothing.

---

## What you will see

A stalled directory now looks exactly like a down one, which is the point —
there is one vocabulary, not two.

**Log** — one line per rescued connection, naming the backend and the budget,
with no server-supplied text:

```
LDAP: directory "ldap:corp-ad" did not complete an operation within 10s —
closing the connection so the request goroutine is released
```

Followed by the existing backend-health line:

```
Auth: identity backend "ldap:corp-ad" UNREACHABLE (1 since boot) —
authentication is failing closed and the result is NOT cached
```

**`/api/diagnostics`** — the `identity_backend` row goes to `warn` with the
backend name and counts.

**`/metrics`** — `culvert_auth_backend_unavailable`,
`culvert_auth_backend_unavailable_total`, and
`culvert_auth_backend_gated_denials_total` climbing together is the signature:
the first stall is detected, and the cooldown then denies subsequent requests
without paying for another one.

**Alert** — `identity_backend_unreachable`, rate-limited to one per 5 minutes.

---

## What to do about it

1. **Confirm which directory.** The backend name in the log is `ldap` for the
   legacy YAML provider and `ldap:<profile-id>` for a registry profile.
2. **Reproduce it from the appliance**, not from your laptop — a stall is
   frequently path-specific. The admin **Test** button on the LDAP IdP profile
   (`POST /api/idp/test`) runs the same staged flow under its own bound and
   tells you which stage hangs.
3. **Read the stage.** A stall at *service bind* or *search* is usually the
   directory itself under load. A stall at *StartTLS* after a successful
   connection is almost always a middlebox that permits port 389 but does not
   understand the in-band TLS upgrade — switch the profile to `ldaps://`.
4. **Check the firewall's idle/established timeouts** if stalls are
   intermittent and cluster around periods of low authentication volume.

While the directory is stalled, authentication **fails closed**: users who are
not already in the auth cache are denied. That is the intended posture. The
cooldown means the outage costs one probe every 3 seconds rather than one hung
goroutine per request, so the node stays healthy and recovers on its own the
moment the directory answers again — no restart needed.

---

## Deliberately not changed

- **The budget is not configurable.** It is one constant shared with the OIDC
  path; a per-deployment knob whose only use is widening it would re-open the
  fault for whoever sets it high.
- **A slow-but-working directory is still served.** The envelope is roughly 50x
  a healthy WAN round trip, and authoritative answers are cached, so the bound
  is unreachable on a functioning deployment.
- **The posture stays fail-closed.** A directory that cannot answer does not
  become an implicit allow.
