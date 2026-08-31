# Credential hashing capacity

*Applies to nodes with a **local** admin account configured (`-auth-user` /
`auth.user`). Deployments whose only credential backend is an external provider
(LDAP bind, OIDC introspection) never reach the path described here — those are
network calls, covered by [identity-backend availability](#see-also) instead.*

Culvert verifies a `Proxy-Authorization: Basic` credential with bcrypt. bcrypt is
deliberately slow — that is what makes a stolen password hash expensive to crack
— and on this node it costs roughly **70–100 ms of one CPU core per
comparison**.

That cost is paid on the proxy data path, for a request that has not been
authenticated yet, because the comparison *is* the authentication. Since
CHAOS-57 the number of comparisons that may run at once is bounded, so a flood
of bad credentials can no longer consume the whole machine. This page is what to
do when that bound starts being reached.

---

## The two ways authentication fails, and why they are different

| Signal | Meaning | Recovers by itself? | What you do |
|---|---|---|---|
| **`culvert_auth_failures`** rising | Credentials are being **rejected**. Someone is presenting the wrong password. | n/a | Investigate the source; this is a credential problem |
| **`culvert_auth_verify_saturated_total`** rising | Credentials are not being **checked at all** — every hashing slot was busy, so verification failed CLOSED for capacity. | **Yes**, the moment load drops | Find and shed the load; nobody's password is wrong |

Do not collapse these. An operator seeing only the first will go looking for a
brute-force attack against a specific account; the second says the node is at
its own CPU bound and *valid* users are being turned away as collateral.

Saturation always fails **closed**: a request that cannot be verified is denied,
never admitted. It is also never cached — once capacity returns, a valid
credential authenticates immediately, with no TTL to wait out.

---

## Where it shows up

**`/metrics`**

| Series | Type | Read it as |
|---|---|---|
| `culvert_auth_verify_hashes_total` | counter | The CPU bill. Multiply by ~0.07 s for core-seconds spent hashing. |
| `culvert_auth_verify_saturated_total` | counter | Blast radius: verifications refused for capacity. **This is the paging signal.** |
| `culvert_auth_verify_inflight` | gauge | Hashes running right now. |
| `culvert_auth_verify_slots` | gauge | The bound. `inflight` sitting at `slots` means the next arrival queues. |

**How `slots` is sized.** Credential hashing is allowed at most **half** this
host's CPUs, hard capped at 4 and floored at 1 — so a saturated gate always
leaves the proxy data path something to run on:

| CPUs | 1 | 2 | 4 | 8 | 16 | 32 |
|---|---|---|---|---|---|---|
| slots | 1 | 1 | 2 | 4 | 4 | 4 |

It is not tunable, deliberately: the only use for an operator override would be
widening the bound this exists to impose. On a **single-CPU** host the
reservation degenerates — one slot is still one core — and nothing but the Go
scheduler's preemption separates hashing from the data plane there. Give a node
that authenticates local credentials at least two CPUs.

**Log** — one line per 5 minutes while saturated, carrying the count suppressed
since the last one:

```
AUTH_VERIFY_SATURATED all 2 credential-hashing slots busy for 750ms; authentication is failing closed (suppressed=812 total=1043)
```

**Alert** — `auth_verify_saturated`, subscribable per webhook in
**Alerts → Webhooks**. Rate-limited to one per 5 minutes. Distinct from
`identity_backend_unreachable`, which says a *remote* directory is down; this one
says *this node* hit its own CPU bound, and the two call for opposite actions.

---

## Suggested alerting rule

```promql
# Verifications are being refused for capacity — valid users are affected.
rate(culvert_auth_verify_saturated_total[5m]) > 0

# Early warning: hashing is pinned at the bound but not yet refusing.
culvert_auth_verify_inflight >= culvert_auth_verify_slots
```

---

## What to do when it fires

1. **Confirm the shape.** A rising `hashes_total` with a rising
   `saturated_total` means genuinely distinct credentials are arriving — each
   one must be hashed, so they cannot be served from cache. A **flat**
   `hashes_total` with a rising `saturated_total` means something else on the
   node is holding slots; check for a stuck request.

2. **Find the source.** Saturation is not attributed per client (the counter is
   process-wide). Use the request log: `AUTH_FAIL` rows carry the client IP.
   Look for one address, or a small set, producing failures at a high rate.

3. **Shed the load.** In order of preference:
   - **IP filter** (Security → IP Filter) — block the source outright. This runs
     *before* authentication, so it costs nothing.
   - **Rate limiter** (`-rate-limit`, or Security → Rate Limiting) — off by
     default. Note it counts *requests*, not CPU: it is a useful blunt
     instrument here but was never a bound on this cost, which is why the
     admission gate exists.
   - **Connection limiter** (`-conn-limit`) — also off by default; bounds
     concurrent connections per IP.

4. **If the traffic is legitimate**, the deployment has outgrown a single local
   account. Move to an external identity provider: LDAP and OIDC verification is
   a network call, not a per-request hash on this node, and is bounded by a
   different mechanism entirely.

---

## What this does **not** protect against

The gate bounds what a credential flood can **cost this node**. It does not make
the flood expensive for the **caller** — there is no per-client lockout on the
proxy or SOCKS5 credential paths (the lockout engine guards the admin UI login
only). A distributed flood of *unique* credentials will therefore keep the gate
busy for as long as it lasts, and legitimate uncached verifications will be
refused during it — counted, alerted, and never admitted, but refused.

Step 3 above is the operator's lever until that changes. Tracked as **AU-3b** in
`roadmap/CHAOS-ENGINEERING-REVIEW.md` §25.8.

---

## See also

- `roadmap/CHAOS-ENGINEERING-REVIEW.md` §25 — the finding, the measurements and
  the design rules behind the gate.
- `docs/operator/scan-capacity-and-timeouts.md` — the same
  saturation-versus-fault distinction for the body-scanning pipeline.
- <a id="see-also"></a>The `identity_backend` row on `/api/diagnostics` — for an
  external directory that is unreachable rather than a local CPU bound.
