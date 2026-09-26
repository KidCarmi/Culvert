# Destination-host bounds on the proxy data path (CHAOS-69)

**Audience:** operators running Culvert as an in-line forward proxy.
**Scope:** the bound Culvert applies to the client-supplied destination authority
on every protocol, why it exists, what it refuses, and what you will see when it
fires.

---

## 1. What changed

Culvert refuses a request whose destination is too long and answers
`400 Bad Request` (HTTP/CONNECT/WebSocket) or a SOCKS5 `0x02` failure reply.
Nothing else about the request is evaluated: it never reaches authentication,
policy, the blocklist, the threat feed, the category store, the request log or
the stats fan-out.

**Two tiers**, because one bound cannot do both jobs:

| Tier | Applied to | Limit | What it catches |
| --- | --- | --- | --- |
| **Raw pre-cap** | the authority exactly as the client sent it, before anything parses it | **1024 bytes** | the megabyte — bounds every log sink and every matcher walk before they run |
| **Canonical** | the host after IDNA normalization to its A-label form | **253 bytes** | the shape an attacker actually wants — dot-dense ASCII, which does not shrink under IDNA |

253 is the DNS limit: RFC 1035 §2.3.4 caps a wire-format name at 255 octets, which
is 253 characters in presentation form (RFC 1123 §2.1).

**The raw tier has to be generous, and that is not slack — it is correctness.** An
internationalized domain name arrives as UTF-8 and *shrinks* when converted to
A-labels. Measured against the real normalizer: `é`×40 in four labels is **323 raw
bytes and 187 canonical bytes** — an ordinary IDN. The widest legitimate case is
**883 raw bytes normalizing to 251**. A raw bound at the DNS limit would refuse all
of these with a 400, so a forward proxy would stop reaching international
destinations. The 1024-byte pre-cap clears the measured maximum with 141 bytes of
margin, and that margin is itself checked by a test that re-measures the expansion
against the shipped normalizer rather than trusting the arithmetic.

**The canonical tier is what makes the bound tight.** The raw pre-cap alone still
admits a 1000-byte dot-dense ASCII authority, which costs about 1.3 ms of matcher
walk. ASCII does not shrink under IDNA, so measuring the canonical form refuses
exactly that while the 883-byte IDN passes. With both tiers the realistic worst
case is back at the 253-byte figure (~111 µs).

---

## 2. Why the bound exists

The destination authority is chosen by the client, and before this change nothing
bounded it. `net/http` admits its 1 MiB default of request line plus headers, so
every byte of the authority reached two places:

- **two rotating log sinks** — the process log (`POLICY_*`, `INVALID_HOST`,
  `IP_BLOCKED`, `RATE_LIMITED`, …) and the durable request-log JSONL, each a
  rotating file keeping one archive. One 256 KiB authority wrote 262 228 bytes to
  the process log and a 262 143-byte `Host` field to the request log, measured on
  the default-deny path.
- **every destination matcher**, which walks the authority label by label — and
  two of those walks are **quadratic** in its length:
  - the URL-category store probes the host and then every suffix beginning just
    past a `.` against its reverse index, hashing each one;
  - the Layer-2 community category feed (`-cat-feed-db`, enabled by default in
    the shipped `docker-compose.yml`) walks parent domains and opens **one
    BadgerDB read transaction per label**.

Measured through the real request path on a 4-core box, with one ordinary
category-group rule and the Layer-2 feed present:

| Authority bytes | CPU per request |
| ---: | ---: |
| 251 | 0.45 ms |
| 4 095 | 19.6 ms |
| 16 383 | 260 ms |
| 65 535 | **3.94 s** |

The growth is quadratic, so at the 1 MiB header default a single request costs on
the order of **sixteen minutes of a core**. That time is spent inside the request
goroutine, holding the client connection, a file descriptor and a per-IP
connection-limiter slot, and it is spent **before authentication** — the gate
order is connection limit → IP filter → rate limit → authentication → policy.
All three front-door limiters ship disabled (`-rate-limit` defaults to 0), so
roughly 256 KB/s from one unauthenticated client was enough to saturate a
four-core gateway.

---

## 3. What you will see

### Metric

```
culvert_proxy_oversize_host_rejected_total
```

A counter, always emitted (there is no configuration to gate it on, so a flat
zero means *nothing has been probed*, never *the feature is off*).

**Paging rule:** this counter should be **zero** on a healthy network. A browser,
a CLI tool and an operating-system resolver cannot produce an authority this
long, so any sustained growth is either a badly broken client or a deliberate
probe. Alert on `increase(culvert_proxy_oversize_host_rejected_total[15m]) > 0`
and treat it as reconnaissance until you have identified the source.

### Log line

Rate-limited to **one line per minute**, with the cumulative count on every
line — a mitigation for a write-amplification defect must not be one itself:

```
OVERSIZE_HOST HTTP 10.4.2.19 {tier=raw bytes=1048310 limit=1024 total=4127 action=block}
```

The line names the **protocol**, the **client IP**, the **tier** that fired,
the **length**, that tier's **limit** (1024 for `raw`, 253 for `canonical`)
and the **running total**. It deliberately does **not** echo the authority, not even a
prefix: a copy of the value would reopen the amplification on the rate-limited
path, and for a name past 253 bytes the length is the only fact that
distinguishes a probe from a broken client.

`proto` is one of `HTTP`, `SOCKS5`, `api/url-lookup`, `api/policy-test`. `tier` is
`raw` (refused on the client's bytes, before normalization), `canonical`
(normalized and still longer than DNS allows) or `unnormalizable` (the host has
no canonical form at all — a malformed ACE label, say — so the DNS bound is
measured on the raw bare host instead). A run of `canonical` refusals from one
source is the dot-dense-ASCII probe shape; `unnormalizable` is the same shape
carrying a broken `xn--` label, which is a probe rather than a client mistake
once it is this long; `raw` means the authority was simply enormous.

`unnormalizable` refusals are bounded by the same 253 limit as `canonical`, and a
**short** malformed host is unaffected — it keeps the `INVALID_HOST` refusal,
which carries the authenticated identity. Only hosts past the DNS limit are
refused on length.

---

## 4. Responding to a non-zero counter

1. **Identify the source.** The log line carries the client IP. On a
   forwarded deployment that is the `realClientIP` product, so it honours
   `X-Forwarded-For` only from a configured trusted proxy.
2. **Decide whether it is a client bug.** A single source with a small steady
   count, from a host you recognise, is usually a misconfigured application
   building a URL by concatenation. The 400 tells it what to fix.
3. **If it is a probe, use the front door.** This bound makes the request cheap;
   it does not make the *arrival rate* your problem any less. Arm the per-IP
   rate limiter (`-rate-limit`) and the per-IP connection limiter, and if the
   source is external, block it at the IP filter. See
   `docs/operator/credential-verification-cost.md` §"the front door" for the
   same reasoning applied to authentication cost.
4. **Nothing needs to be cleaned up.** A refused request leaves no lockout
   entry, no log row, no top-hosts key and no cached state. The counter is
   cumulative from boot and is the only residue.

---

## 5. What is NOT affected

- **Legitimate destinations.** Every authority shape a real client produces is
  accepted: a maximum-length FQDN, an FQDN with a port, a trailing-dot FQDN, an
  IPv4 literal, a bracketed IPv6 literal with or without a port or a zone, and
  **internationalized domain names up to the widest expansion the normalizer can
  produce**. These are pinned by test, the IDN cases specifically because their
  absence let a real regression through review (see §7).
- **Admin-configured patterns.** The bound applies to request destinations, not
  to policy FQDN patterns, blocklist entries or category host patterns. An
  over-long pattern is still stored; it simply can never match, exactly as
  before.
- **Inspected inner requests.** The HTTP/1.1 and HTTP/2 inner-request loops
  attribute every inner request to the CONNECT target, which this bound already
  covered.
- **The proxy's header limit.** `MaxHeaderBytes` is unchanged. It bounds the
  whole header block rather than one field, so lowering it would cut the worst
  case by a constant while breaking clients that carry large cookie or token
  headers — the wrong instrument for a bound on one value.

### One behaviour change on the admin surfaces

**URL-category lookup** (`GET /api/url-categories/lookup`) and the **policy
tester** accept a host you type by hand, so they have to split host from port
themselves. Both now strip the port before matching — the same strip the proxy
performs on every request — which means:

- Looking up `shop.example.com:8443` reports the category of
  `shop.example.com`. Previously it reported no category at all, because the
  matcher was handed the whole string including the port.
- The policy tester's **Stage-1 auth outcome** and **Stage-2 decision** now
  agree with production for a `host:port` input. Previously a destination typed
  with an explicit port could be reported as NOT matching a scoped auth
  exemption that the live gate does apply — a narrower exemption scope than the
  appliance actually enforces. If you have audited exemption blast radius with
  the tester using `host:port` inputs, re-run those checks.

The `host` field echoed back in the response is still exactly what you typed.
The strip governs what the matchers see, not what the answer reports.

---

## 6. Why there is no configuration knob

The bound is a constant, like the admin-login username bound it mirrors. A knob
here could only ever be turned in one useful direction — wider — and widening it
re-arms a remote CPU-exhaustion vector. There is also nothing to tune toward: the
limit is fixed by the DNS wire format, not by a local policy. This is a recorded
GUI-parity deferral of the same class as `maxUsernameLen`.

---

## 7. Known residual and one thing that went wrong

The matchers themselves are still quadratic in the length of whatever host they
are handed. The bound is the only thing standing in front of them, and it has to
be, because a length guard *inside* a matcher cannot be made safe: the suffix
walk exists so that `a.b.example.com` matches a stored `example.com`, so an
over-long host still has short suffixes that may legitimately match, and skipping
the walk on length would change the verdict — **fail-open for a block rule**,
which is worse than the cost it saves.

The practical consequence for you: **any new code path that hands a
client-supplied host to the policy, blocklist or category engines must apply BOTH
tiers at its own entry point, ahead of every matcher on that path.** The four that
exist today (proxy dispatch, SOCKS5, the admin URL-lookup endpoint and the admin
policy-test endpoint) all go through shared predicates and one shared normalizer
(`canonicalDestHost`) so they cannot drift apart.

That wording is deliberately emphatic because review found the original shape
enforcing only half of it. Both admin endpoints applied the raw tier and not the
canonical one, so a **viewer-role** caller could still drive the 1 000-byte
dot-dense shape into the category fusion; and on the proxy path the canonical tier
sat behind Stage-1 authentication, which runs the same fusion for a
category-scoped auth rule and can terminate the request (407) before the bound is
reached at all — refused nothing, counted nothing. Both are fixed: the proxy gate
is hoisted ahead of authentication, and both admin endpoints apply both tiers.
Operationally this is why you may now see `tier=canonical` refusals attributed to
`api/url-lookup` and `api/policy-test`, which previously could only report
`tier=raw`.

**What went wrong in review, recorded because it is the useful part.** The first
version of this bound applied the DNS limit to the client's *raw bytes*. That is
the intuitive reading of "a hostname cannot exceed 253 characters" and it is
wrong, because the limit governs the *canonical* form and IDN shrinks on the way
there. The bound refused ordinary international destinations with a 400, and the
control test that should have caught it covered only ASCII shapes. It was found by
review (Codex, P2, PR #1446), not by the gates. The lesson worth carrying: **a
bound derived from a specification governs whichever representation the
specification is about — check which one you are measuring, and make the control
test carry an example of every representation the input can arrive in.**

See `roadmap/CHAOS-ENGINEERING-REVIEW.md` §39 for the full failure analysis,
register rows PX-21…PX-25, and the gate inventory.
