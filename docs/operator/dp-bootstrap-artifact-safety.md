# DP bootstrap artifact safety (SEC-BOOTSTRAP-HOST-1)

**Applies to:** Control Plane nodes that hand out one-click Data Plane
enrollment (`/api/cluster/bootstrap/…`, the **Generate enrollment token** button
in the Cluster panel).

**What changed:** the Control Plane now **refuses to render** a bootstrap script
or `docker-compose.yml` when the authority it derives from the incoming request
is not a plain `host[:port]`. Previously it rendered whatever the request said.

---

## 1. Why this matters

The bootstrap script is the one artifact this product tells an operator to
execute with root authority:

```bash
curl -fsSL -k https://cp.example.com:9090/api/cluster/bootstrap/<token> | sudo bash
```

Two of the values interpolated into that script came straight off the wire — the
request's `Host` header, and `X-Forwarded-Host` when
`proxy.trust_forwarded_headers` is enabled — and they landed inside a
**double-quoted** shell word:

```sh
CP_BASE="<derived authority>"
```

A double-quoted shell word still performs command substitution, so an authority
of `cp.example.com$(…)` produced a script that ran the attacker's command, as
root, before it did anything else.

**Go's own header validation is not a mitigation and must not be relied on as
one.** `net/http` rejects `"`, a backtick, `{` and space in a `Host` header, but
it accepts `$`, `(`, `)`, `'` and `;` — every byte a `$( … )` payload needs.
`X-Forwarded-Host` is an ordinary header and gets no host-shaped validation at
all, so on a `trust_forwarded_headers` deployment the injection was
unconstrained.

The realistic route to another person's root shell is an **intermediary**: a
caching layer or CDN in front of the admin port turns the `Host` /
`X-Forwarded-Host` into an *unkeyed* input, so a poisoned cache entry serves the
injected script to the operator who fetches it next. A reverse proxy that
*appends* to `X-Forwarded-Host` rather than replacing it gets a client's bytes
into the same place.

---

## 2. What the appliance does now

| Stage | Behaviour |
|---|---|
| Derive authority | `Host`, or `X-Forwarded-Host` when forwarded headers are trusted |
| Validate | Must be a DNS name, an IPv4 literal, or a bracketed IPv6 literal (an RFC 4007 zone id such as `fe80::1%eth0` is preserved), with an optional decimal port 1–65535 |
| On failure | **400 Bad Request**, nothing rendered, nothing written |
| Order | The enrollment token is checked **first**, so a caller with no token cannot drive the refusal path |
| Artifacts | The script single-quotes every value it interpolates; the compose document quotes its env entry |
| Sink re-check | Both renderers re-validate their inputs and refuse rather than emit a partial artifact |

The same validation guards:

- `GET /api/cluster/bootstrap/{token}` — the install script
- `GET /api/cluster/bootstrap/{token}/compose` — the compose document
- `POST /api/cluster/token` — the `bootstrap_cmd` one-liner returned to the
  admin UI (validated **before** the token is minted, so a refusal never burns a
  persisted enrollment token)

The compose document is additionally refused with **503** when the cluster CA
has no fingerprint to pin: a compose file carrying an unpinned enrollment URL
would have a fresh DP node trust whatever answers.

Both endpoints also refuse with **500** when the enrollment token *is* in the
store but is not in the format this appliance mints (base64url, `[A-Za-z0-9-_]`).
`TokenExists` compares only the token's SHA-256 hash, so a token store that was
hand-edited or restored from an incompatible format can admit a plaintext the
renderer will not interpolate — and before this check that refusal landed *after*
the 200, so the caller received an empty success and `curl … | sudo bash`
silently did nothing. 500 rather than 404 is deliberate: the token is present, so
"invalid or expired" would send you to mint another one that fails identically.
The remedy is to restore the token store from a backup taken by this version, or
revoke and re-issue the tokens.

---

## 3. Operator surface

`GET /metrics`

```
culvert_bootstrap_host_refused_total   # counter, emitted unconditionally
```

Process log, rate-limited to one line per minute (the magnitude lives in the
counter):

```
Bootstrap: refused to render the script artifact — the request's derived authority
is not a plain host[:port]; 3 refusal(s) so far. Check the reverse proxy's Host /
X-Forwarded-Host handling.
```

The caller is told only `invalid host`. The authority is never echoed back: a
misconfigured proxy and a probe look identical from here, and the response is
not the place to confirm which bytes got through.

---

## 4. If the counter is moving

`culvert_bootstrap_host_refused_total > 0` means bootstrap requests are arriving
with an authority this Control Plane cannot name itself by. Work it in this
order:

1. **Check the reverse proxy.** The usual cause is a proxy that forwards a
   client-supplied `X-Forwarded-Host`, or one that *appends* to it
   (`X-Forwarded-Host: attacker, cp.example.com`) instead of replacing it. Set
   it explicitly, e.g. nginx:

   ```nginx
   proxy_set_header Host              $host;
   proxy_set_header X-Forwarded-Host  $host;
   proxy_set_header X-Forwarded-Proto $scheme;
   ```

2. **Check whether forwarded headers should be trusted at all.**
   `proxy.trust_forwarded_headers` should be on only when every request
   reaches the admin port through a proxy you control. With it off, the
   appliance uses its own `Host` and ignores both forwarded headers.

3. **Check for a cache in front of the admin port.** The bootstrap endpoints
   must not be cached. They are token-scoped and single-purpose; a shared cache
   entry is a way for one requester's response to reach another.

4. **If none of the above applies, treat it as probing.** The bootstrap
   endpoints sit on the public allowlist because the enrollment token *is* the
   auth, so a non-zero counter with a valid token in play means somebody holds a
   token they should not. Revoke outstanding tokens
   (`Cluster → Enrollment tokens`) and issue fresh ones with a short TTL.

A legitimate deployment never trips this: every real Control Plane authority is
a hostname or an IP literal with an optional port, which is exactly what the
validator accepts.

---

## 5. What is deliberately NOT done

- **No IDNA/punycode conversion.** A non-ASCII authority is refused, not
  transliterated. Converting would mean deciding, inside a security control,
  which of two spellings of a name the operator meant.
- **The allowlist is not minimal for its own sake.** Two bytes are in it
  because refusing them would break a real deployment while buying no safety:
  the underscore (Docker Compose service names) and the IPv6 zone identifier
  (`fe80::1%eth0`, which `net.Listen` accepts as a gRPC listen address). Both
  are inert in a single-quoted shell word and in a YAML scalar. A byte is added
  here only when that argument can be made for it.
- **No sanitisation.** A bad authority is refused, never stripped down to
  something renderable. An artifact assembled from a partially-rewritten
  authority points at a host nobody chose.
- **No readiness or health impact.** A refused bootstrap render says nothing
  about whether this node is proxying traffic; failing readiness over a
  provisioning endpoint would eject a serving gateway.

## 6. Regression gates

- `internal/bootstrap/hostsafety_test.go` — the validator, both renderers, the
  structural wall on the template, and an **empirical** gate that measures which
  bytes `net/http` will actually carry in a `Host` header and requires the
  validator to refuse every one of them that is not part of a `host[:port]`. A
  future Go release that widens that set fails the build rather than quietly
  re-opening the sink.
- `bootstrap_host_injection_test.go` — the real handlers behind a real
  `net/http` server, driven with crafted `Host` and `X-Forwarded-Host` headers,
  plus the controls that a legitimate authority still gets a working artifact.
