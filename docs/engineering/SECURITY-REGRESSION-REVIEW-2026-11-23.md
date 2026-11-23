# Security Regression Review — 2026-11-23

**Scope.** `ef94311…46b4ffa` — the window since the 2026-11-21 review, whose head
was `ef94311`: 33 merged pull requests (#1992–#2064), 98 non-merge commits,
232 files, +37,063/−1,709. Reviewed at `46b4ffa`, which is also `origin/main`.

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed at `ef94311`?** Every verdict is measured against that
revision. Where a finding is pre-existing rather than newly introduced, it says
so, and says what makes it worth raising now.

**Headline.** **No CRITICAL, HIGH or MEDIUM regression was introduced.** The
window is strongly net-positive on the enforcement planes, and its two largest
behavioural changes both close real holes: a **measured** `Block`-rule bypass
via zoned IPv6 destinations (a backend was reached on an IPv6 runner with a
`Block` rule in force), and a **policy-restriction-removal** path where a rule
carrying an action this build does not dispatch was silently *dropped* at every
durable door, letting matching traffic fall through to a lower-priority `Allow`
or the default action. One LOW regression was introduced, in the shutdown
sequence: the new OTLP terminal flush hook was placed inside the flush
partition that exists as a reserve *for the durable closers*, and it takes a
second of worst-case watchdog budget from every one of them — unconditionally,
including in the shipped default where OTLP export is off (Finding A).

**The most actionable item in this report is not a regression.** A plain-HTTP
WebSocket upgrade forwards the client's `Proxy-Authorization` — its credential
for *this proxy* — to whatever origin the request names, in cleartext. I
confirmed it by probe, not by reading (Finding B). It is pre-existing and
untouched by this window, the fix is open, correct and green in **PR #2035**,
and it is unmerged. Merging that PR is the one thing this review would have
done first.

| Change | Security surface |
|---|---|
| `rejectZonedDestHost` / `destIPv6Zoned` (`proxy_host_bounds.go`) | A zoned IPv6 destination is refused on HTTP/CONNECT and SOCKS5 before any matcher or dial. **Closes a measured `Block`-rule bypass** |
| `policyRulePersistable` retains unknown actions (`authpolicy.go`) | A newer/unrecognised access action survives `Load`, `ReplaceAll`, rollback, draft commit and backup restore, and blocks terminally on match. **Closes a restriction-removal** |
| `validateStoredPolicyRule` (`ui_helpers.go`, `configversion.go`) | Backup validate/apply tolerate *only* the unknown action; every other check still runs. **Fail-closed** |
| `warnRetainedUnknownAction` + `policy_rules_unknown_action` row | The retained rule is announced once per store and carries a standing diagnostics row. **New detection for a silent blocking cause** |
| `policyTestAuthority` (`ui_policy.go`) | The Policy Tester resolves the typed host through the request parser the data path sits behind, and refuses what the data path refuses. **Operator-trust fidelity** |
| `boundLoginRelay` (`auth_login_relay_bound.go`) | An anonymous caller can no longer pin ~1 GiB per interactive-login state store. **Closes an unauthenticated memory-exhaustion path** |
| `internal/otlp/spans.go` requeue/discard | A buffered span batch is never delivered to a collector it was not collected for. **Closes a pre-existing cross-collector data leak** |
| `internal/threatfeed` key derivation | Allocation-free deny-control hot path; overlong keys **spill, never truncate** |
| `internal/urlcatfeed/noderecord` (IM-028) | One envelope decoder for three node-local records; verdicts proven unchanged over 17,384 inputs |
| `internal/writerlock` (ADR-0060), `internal/listenfault` (ADR-0058), `internal/mcp/livetier` (IM-025), `internal/mcp/events/qualarchive` (IM-024) | Four extractions. **Behaviour-preserving**, each proven differentially |
| `cmd/culvert-maint` startup reconcile (AGT-900) | ~15k lines of new privileged lifecycle logic, **opt-in and default-off** (`reconcile_on_startup = "off"`) |
| `flushOTLPExporters` (CHAOS-126) | The OTLP exporters finally get a terminal flush — **and are the source of Finding A** |
| `packaging/systemd/culvert-maint.service`, `scripts/install-runner.sh`, `pr-fast-gate.yml` | `KillMode=control-group` pinned; docker-group detection narrowed; the agent CI job now triggers on a unit-only edit. **All tightening** |

**Method.** Five independent investigations ran in parallel over (1) the
privileged maintenance agent and packaging, (2) single-writer locking and
persistence, (3) MCP live tier / telemetry / OTLP / qualification archive,
(4) the threat-intel, blocklist and URL-category feed planes, and (5) the admin
control plane, auth/session surfaces and shutdown lifecycle. The proxy data
path, the policy engine, POL-004 and the Policy Tester were reviewed directly.
Every finding below was re-derived from source by the reviewer — no finding
rests on a worker summary. Finding B is proven by probe; Finding A's arithmetic
and Finding C's matching semantics were each re-derived independently.

---

## Findings

### Finding A — LOW, **introduced**: the OTLP flush hook spends the durable-closer reserve

**Location.** `main_shutdown.go:228` (the order constant), `:296` (the budget),
`:409-419` (the hook), `:552` (registration). Mechanism:
`internal/shutdown/registry.go:231-240`. Regressing commit: `62ba2d2`
(CHAOS-126).

**Contract violated.** The flush reserve is carved out for the durable closers
and says so: *"Flush is sized for the durable closers"*
(`main_shutdown.go:68-69`), and `registry.go:191-204` records that the reserve
protects `request-log-close`, `audit-log-close` and `log-closer` — *"the durable
compliance record, the audit FD, and the log flush holding the evidence"* — from
each other. The new hook's own comment claims an immunity it does not have:

```go
// It runs after every DURABLE closer (and is itself bounded to
// otlpShutdownFlushBudget) so an off-box collector that blackholes can
// never spend reserve the local stores need; it runs before the log
// closer so the result still reaches the operator's log file.
shutdownOrderOTLPFlush = 138
shutdownOrderLogCloser = 140
```

`log-closer` **is** a durable closer — it is the log-sink flush — and it runs
*after* 138. For that one hook the claim is false.

**Verified arithmetic.** `hookBudget` computes each hook's watchdog slice as
`remaining - behind*DefaultMinSlice` (`registry.go:231-240`), with
`DefaultMinSlice = 1s`, `DefaultGrace = 3s` and `Flush = 10s`, so the partition
horizon is `phase start + 13s`. Flush-partition hooks are those above
`shutdownFlushBoundary = 105`:

* base — 6 hooks (110, 120, 125, 130, 135, 140) → worst-case slices 8/9/10/11/12/13 s
* head — 7 hooks (+138) → 7/8/9/10/11/**12**/13 s

**Every durable closer loses exactly one second of worst-case budget, and it
loses it unconditionally — including in the shipped default where OTLP export is
disabled — because `behind` counts *registered* hooks, not active ones.**
`reg.Register("otlp-flush", …)` at `main_shutdown.go:552` is not gated on
`Enabled()`. Separately, when a collector *is* configured and blackholes,
`flushOTLPExporters` burns up to `otlpShutdownFlushBudget = 2s` of wall time and
`log-closer`'s abandon instant is the absolute horizon, so the log sink loses up
to two seconds of its flush window to an off-box dependency.

**Attack scenario and preconditions.** Not directly attacker-triggered.
Requires an OTLP endpoint that blackholes (operator misconfiguration, or an
adversary able to blackhole that one route) *concurrently with* a slow or wedged
durable volume. The process is then killed by the container grace with up to 2 s
less log-sink flush than at base, and each earlier closer is abandoned one
second sooner. **Exploitability:** low — two concurrent faults, no bypass, no
disclosure. **Likelihood:** low; the 1 s reduction, however, is certain and
universal. **Impact:** loss of shutdown-diagnostic lines and a marginally larger
chance the next boot must quarantine a store (the CHAOS-50 path). The audit FD
close at 135 still precedes the new hook, so the compliance record itself is not
reordered behind it. **Affected assets:** request log, audit FD, community DB,
log sink, next-boot store cleanliness. **CWE-778** (insufficient logging) with a
**CWE-400** flavour; **OWASP A09:2021**. **Regression risk:** the per-hook slice
is pinned by no test, so the next hook inserted into the flush partition repeats
this silently.

**Suggested fix (minimal, pick one).** Either move the flush below
`shutdownFlushBoundary` (e.g. order 103) so it is charged to the drain budget
rather than the durability reserve — `logger.Printf` stays reachable because the
log closer is later either way — or keep it at 138 but register it only when
`globalOTLPTraces.Enabled() || globalOTLP.Enabled()` **and** raise
`defaultShutdownBudget.Flush` by `otlpShutdownFlushBudget`, so the reserve the
durable closers actually see is unchanged.

**Required tests.** *Positive:* a table pinning each flush-partition hook's
derived watchdog slice at or above its base value. *Negative:* with a blackholed
OTLP endpoint and a `syslog-close` that sleeps, assert `log-closer` runs **and
completes** before the horizon. *Boundary:* `otlpShutdownFlushBudget` exhausted
exactly, and a `ctx` already expired on entry. *Regression:* a structural test
that fails if a hook is added above `shutdownFlushBoundary` without raising
`Flush`. The existing `TestChaos126_OTLPFlushBudgetFitsInsideTheReserve`
(`otlp_shutdown_flush_chaos126_test.go:192`) only pins `2*budget ≤ Flush`, which
is why this slipped.

---

### Finding B — HIGH, **pre-existing**, confirmed by probe: a plain-HTTP WebSocket upgrade hands the client's proxy credential to the origin

**Location.** `proxy_tunnel.go:164-176` (`handleWebSocket`). **Not touched in
this window** — `git diff ef94311..46b4ffa -- proxy_tunnel.go` is empty — so this
is not a regression. It is in this report because it is live in `main` and it is
the highest-severity reachable defect I found.

`handleWebSocket` runs `scrubForwardedHeaders(r)` and then serialises the request
to the origin with `r.Write(destConn)`. `scrubForwardedHeaders` (`proxy.go:66-114`)
removes private `X-Forwarded-For` hops, a private `X-Real-IP`, the internal
`X-User-Identity` and the matching trailers — it does **not** remove hop-by-hop
headers. The two sibling forward paths do: `proxy_http.go:159` and the
SSL-inspect exchange at `proxy_tunnel.go:1419` both call `removeHopHeaders`,
whose table includes `Proxy-Authorization` (`proxy_tunnel.go:1749-1752`). The
WebSocket path never does.

**Proof.** I drove `handleWebSocket` against a raw recording origin with the two
SSRF layers bypassed for loopback exactly as `proxy_websocket_status_test.go`
does. The origin received:

```
GET /ws HTTP/1.1
Host: 127.0.0.1:35231
User-Agent: Go-http-client/1.1
Connection: Upgrade
Proxy-Authorization: Basic c2VjcmV0dXNlcjpzZWNyZXRwYXNz
Upgrade: websocket
```

That base64 decodes to `secretuser:secretpass`. No test in the tree pins this —
`grep -rn "Proxy-Authorization" --include=*_test.go` has no WebSocket hit —
which is consistent with the header never having been stripped here.

**Attack scenario.** Two client-chosen headers, `Upgrade: websocket` and
`Connection: Upgrade`, are enough. A client configured to use Culvert that opens
a `ws://` destination sends `GET http://attacker.example/ws` with
`Proxy-Authorization`, and the proxy writes that credential to the attacker's
origin — whether or not the origin actually upgrades. **Preconditions:** proxy
authentication enabled with Basic credentials (a local account password, an LDAP
password, or an OIDC access token — `auth_oidc.go:72`), and a client that
performs `ws://` through the proxy with an absolute-form request target rather
than CONNECT. **Exploitability:** high once a client reaches an attacker-chosen
`ws://` host; the limiting factor is client behaviour, since browsers generally
tunnel WebSockets over CONNECT, while CLI tools, SDKs and application HTTP
stacks commonly use the absolute-form upgrade this path serves. **Likelihood:**
moderate. **Impact:** direct disclosure of a reusable proxy credential to an
arbitrary third party, in cleartext — credential replay against the proxy and,
where the credential is the directory password, lateral movement.
**Affected assets:** every proxy user's authentication credential.
**CWE-200 / CWE-522 / CWE-532**; **OWASP A02:2021**.

**Suggested fix.** PR #2035 already carries it, and I reviewed it: it reads
`Upgrade` before the strip, calls `removeHopHeaders(r.Header)`, then restores
only the `Connection: Upgrade` / `Upgrade: <type>` pair — the
`httputil.ReverseProxy` shape. The restored value cannot inject a header,
because `net/http` replaces CR/LF in a header value with spaces on write, and
`isWebSocketUpgrade` has already constrained it to `websocket`. Its test
(`proxy_websocket_proxyauth_leak_test.go`) runs the plain path first as a
control proving the fixture would observe the header, covers both the upgrading
and the declining origin, and asserts the handshake survives the strip. Its one
status check is green.

**Recommendation: merge PR #2035.** Nothing in this review ranks above it, and
nothing in this window conflicts with it. Operators who run Basic proxy
authentication should treat credentials used alongside `ws://` destinations as
exposed to those origins, as that PR's changelog entry already states.

---

### Finding C — MEDIUM, **pre-existing and deliberately recorded**, raised because this window resolved the same question the other way: a zoned IPv6 client address matches no source deny control

**Locations.** `internal/admission/engine.go:283-288` (`ipFilterView.contains`),
`:513-525` (`IPFilter.Allowed`), `policy.go:2492-2512` (`matchIPOrCIDR`),
`policy.go:2524-2527` (`sourceLiteralPrefix`).

An IPv6 peer with a link-local scope arrives with its zone intact:
`net.SplitHostPort("[fe80::1%eth0]:1234")` yields `"fe80::1%eth0"`, and nothing
between `r.RemoteAddr` and the matchers strips it (`proxy.go:1555`). Both source
matchers then treat that string as matching nothing:

* `ipFilterView.contains` returns `false` for any address with a zone, by
  design: *"net.ParseIP — what this path used before — rejects a zoned address
  outright… drop them here to keep the previous verdict."*
* `matchIPOrCIDR`'s CIDR arm uses `net.ParseIP(clientIP)`, which returns `nil`
  for a zoned address, so the arm returns `false`; its literal arm requires
  `addr.Zone() == ""`.

I verified the primitives directly: `net.ParseIP("fe80::1%eth0")` is `nil`;
`net.ParseCIDR("fe80::/10")`'s `Contains` of it is `false`; `netip`'s
`Prefix.Contains` of a zoned address is likewise `false`, while the unzoned
address matches in every case.

**Why "matches nothing" is not neutral.** It depends on which side the entry is
on. For `IPFilter.Allowed`, `case "block": return !v.contains(ipStr)` — so in
**block (denylist) mode a zoned client address is admitted**, bypassing the deny
entry. For policy, a source-scoped `Block`/`Drop` rule does not match, and under
first-match-wins evaluation continues to a lower-priority rule or the default
action. Allowlist mode fails the other way and is safe (`contains` false →
`Allowed` false → denied).

**Attack scenario.** The proxy binds the wildcard (`Addr: fmt.Sprintf(":%d", …)`,
`main.go:1218`), so on an IPv6-enabled host it accepts connections on
link-local addresses. An on-link client connects to
`http://[fe80::<proxy>%<iface>]:8080`; its own source address is then link-local
and the proxy sees `clientIP = "fe80::<client>%<iface>"`. Any denylist entry or
source-scoped deny rule covering that client — including `fe80::/10` — does not
apply. **Preconditions:** IPv6 enabled (the default on most Linux hosts), the
proxy on a wildcard bind (the default), the attacker on the same layer-2 segment
as one of the proxy's interfaces, and the operator relying on block-mode IP
filtering or source-scoped deny rules rather than an allowlist.
**Exploitability:** straightforward for an on-link attacker — the client simply
chooses the link-local path; no spoofing and no header control is required.
**Likelihood:** low-to-moderate; it needs adjacency, which is exactly the
position a LAN-side deny entry is usually written for. **Impact:** evasion of a
source-based deny control. **Affected assets:** IP filter denylist, source-scoped
`Block`/`Drop` policy rules. **CWE-290 / CWE-693**; **OWASP A01:2021**.

**Why I am raising a deliberate decision.** The repository has recorded this
choice and reviewed it: the 2026-08-24 review notes *"Zoned probes still match
nothing (`net.ParseIP` rejected them; the new path rejects them explicitly)"*,
and `docs/agent-context/history/admission-and-connection-limits.md` records
zoned addresses as *"the one known divergence… explicitly rejected to keep net's
verdict."* **That recorded rationale is compatibility, not safety** — it argues
that no probe which matched before stops matching. It does not address whether a
*client* presenting a zoned address can thereby evade a deny entry, and I found
no test or document that does. Meanwhile this very window resolved the identical
question on the destination side and resolved it the other way: a zoned
destination that the dialer honours but the matchers ignore is **refused**, and
`proxy_host_bounds.go:489-505` explains at length why stripping the zone and
carrying on would be the weaker answer. The source side still takes the answer
the destination side just rejected. That asymmetry is what makes this worth a
decision rather than another silent preservation.

**Suggested fix.** Mirror the destination resolution: refuse a zoned client
address at ingress, with its own `INVALID_SOURCE`-style outcome, before the
first source matcher — a zone names an interface on this host and means nothing
as a policy subject. Stripping the zone before matching is the alternative, and
it is the weaker one for the same reason the destination gate gives: it keeps
admitting a spelling no legitimate client needs to send. Either way the outcome
should be recorded with its **security** rationale, so the next reviewer is not
left re-deriving it from a compatibility note. This is a posture change outside
this review's authority to make; it is a recommendation, not a patch.

**Required tests.** *Authorization:* a block-mode filter entry for `fe80::/10`
must refuse a client whose `RemoteAddr` is `[fe80::1%eth0]:p`. *Policy:* a
`Drop` rule with `sourceIP: fe80::/10` must match the same client.
*Negative control:* an allowlist-mode filter must keep denying it (already the
behaviour), and an unzoned link-local client must behave exactly as today.
*Boundary:* an empty zone (`fe80::1%`), a numeric zone (`fe80::1%2`), and a
4-in-6 mapped address, so the gate cannot be satisfied by rejecting everything.
*Differential:* the existing `TestIPFilterView_DifferentialAgainstLegacy` oracle
must be updated deliberately rather than silently, since this is a chosen
divergence from `net.ParseIP`'s verdict.

---

## No regression found in

Each item below was cleared with the evidence named, not by inspection alone.

**The zoned-IPv6 destination refusal (#2055, #2053, `9110800`, `5bdbaea`).**
This is a tightening and it closes a *measured* hole: on an IPv6-capable runner,
with a `Block` rule for `::1` under default allow, plain HTTP to `[::1%25lo]`
matched no rule and reached the backend with 200 — because `net/http` decodes
RFC 6874's `%25` once, so the handler sees the authority `[::1%lo]`, the dialer
honours the zone and goes to the same address, while every literal matcher
deliberately leaves a zoned address un-canonicalised and compares `::1%lo`
against a rule for `::1`. The gate refuses instead of stripping, which is the
stronger choice. I checked the placement on both ingresses: on HTTP/CONNECT
`rejectZonedDestHost` sits after the length tiers, the connection limit, the IP
filter and the rate limiter, and **before** Stage-1 authentication — the first
matcher — and before any dial (`proxy.go:1652-1660`); on SOCKS5 the twin runs
after the IP filter, the connection limiter and the greeting/auth, and before
the blocklist and plugin matchers (`socks5.go:519`), so neither is an
unauthenticated oracle. `destIPv6Zoned`'s slicing is guarded (`len(bare) >= 2`
before the bracket strip, `IndexByte` result checked), it refuses an empty or
malformed zone, and it only treats "an address, then `%`" as a zone — a hostname
containing `%` does not parse as an address and is untouched. SOCKS5 `ATYP 0x04`
is sixteen bytes and cannot carry a zone; the free-text DOMAIN form can, and is
covered. I confirmed there is no third ingress: the inspected tunnel's inner
request is not re-dialled and must pass `innerHostPinnedToTunnel` against a
tunnel host that already cleared the gate. `go test -run 'IPv6Zone|Zoned|…' .`
passes, and the new `ipv6-qualification.yml` job fails on a SKIP or a missing
PASS line rather than inferring one from a green shard.

**POL-004: retaining an unknown access action (#2050, #2064, `dc4e01d`,
`abc29c7`, `a52c867`).** The direction is fail-closed and the inversion is the
point: dropping such a rule at a durable door *removed a policy restriction*,
letting matching traffic fall to a lower-priority `Allow` or the default. I
traced every consumer of a matched action rather than trusting the claim.
`canonicalPolicyAction` has exactly one dispatch consumer, `applyPolicyDecision`
(`proxy.go:800-813`), which blocks terminally with `POLICY_BLOCK` and a block
page; `proxy.go:1754` compares the canonical action only to pre-emit the Drop
observation. `Decide` (`authpolicy.go:233-237`) is Phase-0 and deliberately off
the hot path. The CDR store is a different store with its own `Mode` vocabulary,
not `PolicyAction` (`cdr_proxy.go:236`). SOCKS5 does not evaluate access rules
at this revision. So there is no second evaluator that could fail open on a
retained rule. The draft path is covered: `validateCandidateRule` relaxes **only**
for a candidate inheriting the same ID *and* the same unknown action from the
running store, and anything else — including a rule that acquired an unknown
action some other way — goes through the exact ingress validator
(`policy_draft.go:1228-1238`). `staging` is read in exactly one place,
`warnNewlyRetained`, never in evaluation or validation, and only the draft
candidate store sets it (`policy_draft.go:78`); commit publishes rules into the
long-lived `policyStore` with `ReplaceAll`, so the enforcing store can never
inherit the flag and go quiet. The retained rule gets a per-door WARN and a
standing `policy_rules_unknown_action` diagnostics row capped at ten names.
The availability consequence is real and accepted: a control-plane snapshot
whose priority-1 `destFqdn: "*"` rule carries a newer action now blocks
everything it matches where it previously did nothing. That requires
control-plane or admin authority, it is announced in the log and in diagnostics,
and fail-closed is the correct direction for a security gateway.

**`validateStoredPolicyRule` on the backup path (`configversion.go:485`, `:630`).**
I examined this specifically as a validation *relaxation* and it is surgical: it
substitutes `ActionBlockPage` as a probe and runs the full `validatePolicyRule`,
so name, uniqueness, timezone, the `SubjectMatch` refusal and the `Auth`-spec
refusal — the actual fail-open guards — all still run (`ui_helpers.go:156-163`).
I chased the one gap it opens: `isSafeRedirectURL` is checked only when the
action is `Redirect` (`ui_helpers.go:263-269`), so a retained unknown-action rule
carries an unvalidated `redirectURL`. **This grants nothing new.** A rule with
action `Block_Page` and a hostile `redirectURL` was already accepted at base by
the same predicate, so the capability is pre-existing, not introduced; the
unknown action blocks terminally so the URL is never used; an operator editing
the action to `Redirect` trips the strict validator because the action no longer
matches the inherited one; and both renderers escape the value — the legacy UI
through `escHtml` (`static/index.html:15979`, and the summary path at `:13265`
joins into an `escHtml`ed string) and React as a text child
(`AccessRulesPage.tsx:171`). Neither places it in an `href`. No XSS, no
introduced capability.

**The Policy Tester fidelity fix (#2053, #2055, `7f18697`, `2b365a9`,
`afeecf5`).** Strictly tighter, and it removes an operator-trust defect: the
tester answered for a literal percent string where the data path answers for the
decoded IDN, and it reported "no rule matched, the default applies" for hosts
the proxy refuses outright. It now resolves the typed input through
`url.ParseRequestURI` — the same function `net/http` puts in front of
`handleRequest` — rather than a second decoder that would accept escapes the
request parser refuses in a host, rejects a literal space because the request
line is split on spaces before any URL is parsed, re-checks the zone on the
authority the parser extracted (so `user@[::1%25lo]:443` cannot hide one behind
userinfo), and applies both length tiers plus the `INVALID_HOST` validity gate.
`requireRole(w, r, RoleViewer)` and the POST-only method check are intact
(`ui_policy.go:2874-2881`). The one recorded limitation leans safe: the raw
pre-cap measures typed bytes, so a very long percent-encoded host is refused on
length.

**`internal/writerlock` (ADR-0060).** The extraction is semantically
byte-equivalent to `acquireDataDirWriterLock` at `ef94311`, compared
statement-for-statement: same lock file name (compared with `od -c`), same
`O_CREATE|O_RDWR` with no `O_EXCL`, same `0o600`/`0o700`, same
`LOCK_EX|LOCK_NB`, same close-before-return ordering, same "never remove the
file", same verdict integers, and both flock files diff byte-identically against
their base counterparts. The three-verdict semantics are preserved exactly —
`EWOULDBLOCK` → `Held`, **any other error → `Undetermined`**, non-unix →
`Undetermined` — so a filesystem without flock still degrades rather than being
mistaken for free. The guard's load-bearing position (`main.go:245`, after
`checkInterruptedRestore`, before `initLogger`) and every pre-guard startup file
have an empty diff for the window, the ten root pinning tests are unedited, and
twelve package tests were added including file-mode and size assertions base
never had.

**`internal/listenfault` (ADR-0058).** Four listener classifiers converge on one
stateless classifier over a bounded seven-value vocabulary; the raw error, the
bind address and configured paths never enter it. Equivalence is established
three ways — by hand for `classifyAdminUIListenError`, by a differential oracle
over every errno 0–4095 in five wrapper shapes against the pre-move classifier,
and by a root parity table — and each listener's own stage tags keep their
original table positions. No new value, path, address or OS error text reaches
any caller. The `network_error` class still requires an actual timeout, which is
the narrowing the siblings already carried.

**The feed planes.** No destination denied at `ef94311` can be allowed at
`46b4ffa`. The threat-feed hot path now renders its lookup key into a 320-byte
stack array and probes `v.urls[string(key)]` in the one shape Go hashes in
place; an overlong key **spills to the heap rather than truncating**, which the
author correctly identifies as the difference between a trade and a security
defect, since two distinct URLs sharing a truncated key would make one inherit
the other's verdict. The allowlist-masking counter `maskedHits.Add(1)` lives in
exactly one body, `lookupDomain`, that both the fast and fallback paths reach —
the half that must not be duplicated — and I checked the five-branch verdict
table against base line by line. The new `couldBeIPLiteral` gate in front of
`net.ParseIP` is a superset of "ParseIP would succeed", and a hypothetical false
negative fails **closed** (the destination becomes feed-eligible, i.e.
deniable). Evidence: a differential oracle against `NormaliseURL` with a
negative control proving the fast path is actually taken, `FuzzCouldBeIPLiteral`
at 675,305 execs and `FuzzCheckRequestURL` at 222,057 execs with no
counterexample, and spill/collision tests. The IM-028 envelope decoder is pinned
by replaying 17,384 inputs — every truncation, single-byte deletion, space
insertion and eleven substitutions at every offset — against verdict digests
captured from `ef94311` before the bind; signature, digest, authority and seal
verification are untouched, size bounds are byte-identical, no sentinel is
shared, and `refusal()` guarantees a missing sentinel yields an unnamed error
rather than `nil`, so no refusal can become an acceptance. The CHAOS-123
freshness plane has a zero diff this window and the on-delivery latch that was
Finding A of the 2026-11-19 review is intact and shared by all three producers.

**MCP live tier, telemetry, OTLP and the qualification archive.** The
`internal/mcp/livetier` extraction is behaviour-preserving: every transition is
byte-identical modulo renames, with three structural deltas only — injected
collaborators that reproduce base behaviour exactly, a commit lock resolved per
call through `Options.CommitLock` (the same `sync.Mutex` on the same singleton,
same `durableMu → lt.mu` order), and `drainWaitFn` becoming a method with a root
shim. `Arm` still requires `Composed` *and* ready; `AdmitExecution` is
default-deny on the zero value, since `Absent` is `iota == 0`; `New` fails closed
for every nil collaborator. The move is itself a strengthening: the `state` and
`admitClosed` fields were writable from any root file at base and are now
compiler-unreachable from `main`. The gate files received method renames only,
so nothing is newly reachable before production-deps, rollout stage,
canary-read-first or the shutdown envelope. On exported data, `SpanRecord` and
`buildTracePayload` are unchanged, the attribute set off-box is unchanged, and
the only non-enum metric label is the operator-defined rule name — no
attacker-controlled metric label, so no cardinality blow-up. The qualification
archive writes through the unmodified `fileutil.AtomicWrite` at `0600` under
`0700`, every path component is a closed enum or a 64-hex SHA-256, nothing reads
the archive back to make a decision, and a hash mismatch is rejected rather than
trusted. Endpoint validation, TLS verification and the two-layer SSRF guard are
unchanged. **One OTLP change is a security fix, not a regression:** at base a
reconfigure could ship a buffered batch of client IPs, target hosts and
enforcement decisions to a *newly configured* collector it was not collected
for; head discards the ring on an endpoint change, takes destination and batch
under one lock, and pins requeue retention to the endpoint actually posted to.
`-race -count=2` is clean on the three packages.

**The privileged maintenance agent (AGT-900).** The ~15k new lines are opt-in
and default-off — `validateReconcileMode` maps empty to `"off"` and fails `Load`
on any other value, so a typo cannot silently select a different behaviour — and
I verified that default myself (`internal/config/config.go:497-510`), which is
what makes the new surface incapable of changing a base deployment. Every new
`docker` invocation is argv-exec'd with no shell and multiply gated: the two new
`docker tag` sites are triple-validated (`validateReconcileRefs` /
`priorRestorable`, then the runner's own `validatePinnedDigestRef` against the
bound repo) with a literal destination tag, `ComposeContainerInspect` takes a
12–64 lowercase-hex shape check enforced again at the sudoers wrapper, and
`runner.go`/`env.go` with the recorded `.`/`..` `ComposeFile` rejection are
untouched. No new pull, no new `systemctl`, no sudoers change anywhere in the
window. The decision core is pure and first-match-ordered and every branch I
walked fails closed; "matching identities alone" still does not converge, because
`retireIfServing` additionally demands `settleRemaining() == 0` and a fresh
`ReadyOK` probe taken after it, with every error, timeout and absent factory
mapping to not-ready. `PhaseVerified` is now written only *after* the digest
check, which is a tightening over base. Audit is write-then-act with a per-event
`Sync()`, the reconcile lock is a non-blocking `LOCK_EX` on a fixed name opened
`O_NOFOLLOW` under an agent-owned `0750` directory, and the safety wait uses the
monotonic clock from process start so a wall-clock step cannot skip it. The
systemd unit gained `KillMode=control-group` and lost nothing — I compared the
directive sets at both revisions — and `install-runner.sh` **narrowed** docker-group
detection from a `grep -qw` substring match to an exact `id -nG` name match.

---

## Verification

* `go test -count=1 -run 'IPv6Zone|Zoned|ZonedDest|PolicyTest|RetainedUnknown|UnknownAction|POL004|Blocklist' .` → ok.
* `go test -count=1 ./internal/threatfeed` → ok; `FuzzCouldBeIPLiteral` 675,305 execs, `FuzzCheckRequestURL` 222,057 execs, no counterexample.
* `go test -count=1 ./internal/urlcatfeed/... ./internal/blocklistfeed ./internal/listenfault ./internal/writerlock ./internal/otlp ./internal/mcp/livetier ./internal/mcp/events/qualarchive` → ok; the MCP/OTLP three also under `-race -count=2`.
* `go test -count=1 .` for the relay-bound, listener-parity and CHAOS-126 shutdown selections → ok. `go vet` clean on the packages reviewed; `cmd/culvert-maint` focused reconcile/settle/retire selection → ok.
* `go test -count=1 ./...` across the root module at `46b4ffa` → **134 packages ok, exit 0, no failures.**
* The Finding B probe was run against a raw recording origin and then removed; `git status --porcelain` is empty.

**Not run, and why.** Module-wide `-race` and `-shuffle`, golangci-lint at the
gate's pinned version, and CodeQL were not run here. The linter in particular
must be taken from the gate that blocks the change, not from `PATH`
(`docs/agent-context/conventions.md`). **A passing local suite is not a passing
hosted gate**, and nothing above is evidence for the merge gates on any specific
SHA. Finding A needs a per-hook-slice test that does not yet exist, and
Finding C's tests do not exist at all.

## Residual risk

1. **Finding B is live in `main`.** Until PR #2035 merges, every `ws://`
   destination reached through an authenticating Culvert is a credential
   disclosure channel. This is the window's most important open item and it is
   not a product of the window.
2. **Finding C is an unresolved posture asymmetry.** The destination side now
   refuses zoned spellings; the source side still treats them as matching
   nothing, which is fail-open for block-mode filtering and source-scoped deny
   rules. The decision is recorded, but only with a compatibility rationale.
3. **Finding A's per-hook slice is pinned by no test**, so the next hook added
   to the flush partition will shrink the durable-closer reserve silently again.
4. **`ipv6-qualification.yml` is not a required status check.** The evidence
   that the zoned-destination gate executed and passed on an IPv6 host is
   explicit and well built — it fails on a SKIP rather than inferring a pass —
   but it does not gate a merge. Adding it to the required set is a repository
   settings decision (`REPOSITORY-SETTINGS.md` §2) and worth taking now that a
   deny control depends on it.
5. **`internal/writerlock` opens its lock file without `O_NOFOLLOW`**
   (`lock.go:83`), while the maintenance agent's *new* reconcile lock added in
   this same window does use it
   (`cmd/culvert-maint/internal/journal/lock_unix.go:41`). With write access to
   the data directory, a local user can point the lock path at a file they hold
   an flock on and make Culvert refuse to boot, or cause a zero-byte `0600` file
   to be created at an attacker-chosen path. Pre-existing and identical at base;
   the window's own sibling demonstrates the fix. Relatedly, any non-`EWOULDBLOCK`
   error silently downgrades the single-writer guard to `unverified` and boots —
   deliberate and pinned, but it means a local user who can create
   `.culvert-writer.lock` as a *directory* on a loosely-moded data directory
   disables the guard (CWE-636).
6. **`/auth/select?relay=` is public and `isSafeRedirectURL` accepts any public
   absolute http(s) URL**, so a crafted link yields a post-login redirect to an
   arbitrary public host (CWE-601). Pre-existing and unchanged. Note the
   interaction: `boundLoginRelay` degrades an oversized relay to its own
   authority root, which is harmless *only because* that validator is already
   permissive. If it is ever tightened to an allowlist of return origins, the
   degradation becomes a bypass of the tightened rule — worth a differential
   test now, asserting `accepted(bound(x)) ⊆ accepted(x)`.
7. **`POST /api/blocklist` has no `http.MaxBytesReader`** and joins the full
   submitted host list into the audit detail unbounded. Operator-authenticated
   and pre-existing; the window's own change *bounds* the response side.
8. **A blocklist entry that can never match is still stored and listed.** The
   new feedback surfaces the pre-existing divergence — entries are keyed
   lowercased-and-trimmed while the request host is fully normalised — but
   warning is not refusing, so an operator who ignores the warning still
   believes a host is blocked when it is not. The warning also misses a
   leading-dot entry (`.example.com`), which is stored in the exact map and can
   never equal a normalised request host.
9. **Five LOW weaknesses inside the default-off reconcile surface**, the sharpest
   being an asymmetry I verified directly: `decideStandaloneRollbackV2`
   (`reconcile_decision_v2.go:312-327`) skips its partial-application guard when
   the rollback target cannot be identified and falls through to
   `noop/rollback_never_moved_tag`, retiring the record and auditing a false
   reason, where the upgrade branch fails closed on the same condition with
   `target_not_identifiable` (`:233-235`). Reachable only with a crash plus a
   transient `docker image inspect` failure, and `retireIfServing` still demands
   a fresh readiness probe, so what is lost is the post-rollback digest
   verification and audit-reason integrity rather than a running unverified
   image. The minimal fix is one line mirroring the upgrade branch.
