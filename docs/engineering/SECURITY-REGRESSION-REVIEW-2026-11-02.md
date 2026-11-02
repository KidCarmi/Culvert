# Security Regression Review — 2026-11-02

**Scope.** `3c5fab1…110bf9f` (`origin/main`) — the 24 h since the 2026-11-01
review, 11 merged pull requests (#1779 #1780 #1781 #1782 #1783 #1784 #1785
#1786 #1787 #1789), 47 files, +2,384/−138. Four of the eleven are Dependabot
bumps. Nine production Go files changed, six test files, the install script,
twelve CI workflows, the legacy GUI, the OpenAPI surface, the generated
frontend types, the CHANGELOG and five roadmap / design documents.

| PR | Change | Security surface |
|---|---|---|
| **#1779** | `perf: canonical MIME header keys on the request hot paths` — `hdrRealIP` becomes `"X-Real-Ip"`, eleven further call sites are re-spelled, and a new tree-wide AST gate (`TestCanonicalHeaderKeys_Tree`) pins canonicality | proxy request path, header matching, forwarded-header scrub, MCP auth (DPoP), gate integrity |
| **#1782 / #1783** | CHAOS-108 — the operator-configured blocklist feed gets a retry ladder, fleet jitter, lifecycle cancellation and an HTTP status gate; `setFeedIntervalLocked` extracted | threat intelligence, deny-control fail-open, durable state integrity, DoS/herd |
| **#1784** | `security(scan): scope the CHAOS-106 call-site gate to the calling function` — the S-1 fix from the 2026-11-01 review | gate integrity, scanning, response processing |
| **#1780** | `feat(diagnostics): warn when country rules cannot match without a GeoIP database` | diagnostics, RBAC, information disclosure, policy enforcement visibility |
| **#1781** | `fix(install): patch_allow_peers keeps valid TOML when allow_peers has a trailing comma` | cluster peer trust, configuration integrity |
| **#1785 / #1786 / #1787 / #1789** | `golang.org/x/net` 0.61→0.62, `grpc` 1.84→1.85, `brotli` 1.2.6→1.2.7, `harden-runner` 2.22.2→2.22.3 | dependency hygiene, HTTP/2 desync, decompression, CI supply chain |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed 24 h ago?** Every finding is measured against
`3c5fab1`, not against an ideal.

**Method.** The header re-spelling was not accepted on the "Get/Set/Del
canonicalise the key" argument alone, because that argument does not cover the
one shape where it is false: a DIRECT map index. Every use of the three scrub
constants was enumerated (`proxy.go:73,80,82,87,89,94,119,120,121`) and the
only direct index — `r.Header[hdrForwardedFor]` — confirmed to hold an
already-canonical key; then the whole production tree was swept for
`Header[`/`Trailer[` literals and for header-shaped constants outside the
`hdr`/`header` naming convention, to establish that nothing in the tree depends
on the non-canonical spelling today. The new gate was then run against the
failure mode its own doc comment names, rather than being trusted because it is
green. CHAOS-108 was read for the two directions that matter on a deny control
— whether a failed round can now be recorded as success, and whether the new
`nextAttempt` state can be raced — and the redirect/dial guards were read in
`internal/ssrf` rather than taken from the call site's comment. The GeoIP
diagnostics row was read as an information-disclosure question first, against
the path-free contract that `noteStateFileUnreadable` enforces one day earlier
with its own test.

**Five hypotheses were formed against the window's own claims and disproved:**

1. *The new `geoip_database_for_rules` row leaks the absolute `.mmdb`
   filesystem path to a viewer-role reader, breaking the path-free contract the
   `state_file_admin_settings` row enforces one day earlier.* The row does
   interpolate `geoip.LoadError()`, which is `geoip2.Open`'s `*os.PathError`
   and does carry the path (`internal/geoip/geoip.go:58`); `sanitizeLog` only
   neutralises newlines and C0 bytes, so the path survives; and
   `redactContractForRole` is a per-code switch that does not classify the new
   code, so the row reaches viewer and operator verbatim. **Disproved by the
   privilege boundary, not by the text:** `GET /api/geoip` is gated at
   `RoleViewer` (`ui_security.go:1935`) and already returns `"dbPath"` and
   `"lastError"` verbatim at that role. The path is viewer-readable by design
   on the same surface, so the row discloses nothing a viewer cannot already
   obtain, and the asymmetry with `admin_settings.json` — whose path is *not*
   otherwise viewer-readable — is principled rather than an oversight.
2. *One of the twelve re-spelled sites changes header matching or wire bytes.*
   Every substituted site reaches the map through `Get`/`Set`/`Del`/`Add`,
   which canonicalise the lookup key, and the probed map was itself populated
   under `CanonicalMIMEHeaderKey`; the in-tree differential oracle covers all
   six pairs including `DPoP`→`Dpop` on the MCP auth path and
   `X-aws-ec2-metadata-token-ttl-seconds`→`X-Aws-Ec2-Metadata-Token-Ttl-Seconds`
   on the IMDSv2 token request.
3. *The MCP acceptance scenario's `"MCP-Protocol-Version"` fixture key is
   applied through a raw map, so `protocol.bad_version` passes vacuously
   against a listener that now reads `Get("Mcp-Protocol-Version")` — a
   green protocol-rejection criterion over an unexercised control.* Disproved:
   `mcpPostRaw` applies the fixture with `req.Header.Set(k, v)`
   (`internal/mcpacceptance/client.go:131`), which canonicalises and therefore
   correctly overwrites the default set at line 122. The commit message's
   description of that file reaching headers "through a raw map rather than a
   Header accessor" is inaccurate, but the scenario is sound.
4. *CHAOS-108's new per-feed `feedsched.Scheduler` races the admin-API sync
   path, or its `Interval` closure reads `st.interval` outside `Syncer.mu`.*
   Disproved: `NextDelay` is reached only from `scheduleNextLocked`, whose two
   callers hold the write lock; `dueURLs` reads `interval`/`nextAttempt` under
   `RLock`, which excludes those writers; `go test -race` over the CHAOS-108
   suite is clean.
5. *CHAOS-108's status gate turns an outage into a merge refusal but leaves the
   fetch itself reachable to a private address through a redirect.* Disproved:
   `feedCheckRedirect` re-applies `ssrf.PrivateHost` on every hop and bounds
   the chain at five, the transport dials through `ssrf.SafeDialContext`
   (post-resolution, pre-`connect(2)`, closing the rebinding TOCTOU), and
   `PrivateHostContext` splits `host:port` correctly and fails closed on a DNS
   error without caching it.

The one finding that survived was **proved in both directions against the
merged revision, on production shape**: the bypass it fails to see passes the
gate as merged and fails the gate as fixed, naming `proxy.go:87` and
`proxy.go:89`.

---

## 1. Executive Summary

**No security regression was introduced in this window.** The three
security-relevant changes all move the posture forward, verified against
production callers and against `internal/ssrf`'s actual implementation rather
than taken on trust:

- **CHAOS-108** closes a real fail-open window on a **deny control**. Before
  it, `fetchFeedLines` never checked `resp.StatusCode`, so a 5xx error page was
  parsed by `blocklist.NormalizeLine` and **merged**: an HTML body contributed
  the host `<html>`, a plain-text error contributed `upstream`, attributed to
  the feed, saved to disk and never removed — a deny control's durable state
  taking dictation from whatever answered the URL. The same round was recorded
  as a *success*, so an origin serving 503 for a week reported "synced just
  now, no error". Separately, a failed round stamped `lastAttempt` and the
  due-check gated on it, so one transient failure bought the origin a full
  interval of silence — 24 h on a stock install — and a node booting into a
  feed outage merged **no** domains from that feed and did not retry for a day.
  Both are fixed, and the fix is conservative in the only direction that
  matters: re-intervalling can only pull a pending attempt *in*, never push it
  out (`setFeedIntervalLocked`).
- **The CHAOS-106 call-site gate fix** is the correct remedy for the 2026-11-01
  S-1 finding, and it is tighter than its own description: each site is judged
  inside the function that holds it, every nested `FuncLit` gets its own scope,
  and a call site in no function at all reaches the counting pass as a
  violation because nothing there can fail closed.
- **The dependency bumps** are all forward, all hash-updated, and
  `harden-runner` stays SHA-pinned across all twelve workflows. No workflow
  line other than those pins changed — in particular no `permissions` block, no
  `GOTOOLCHAIN` override, and no gate threshold.

The review found **one weakness in gate integrity**, in the structural gate
this window introduced — the same class of finding as 2026-11-01's S-1, in a
file whose entire motivating lesson is that "a structural gate that silently
stopped matching would be worse than no gate: it would read as a green
guarantee of a property nothing was checking."

---

## 2. Security Findings

### S-1 — `TestCanonicalHeaderKeys_Tree` is green over a direct-map-index scrub bypass

| | |
|---|---|
| **Severity** | Medium (gate integrity on a security control; latent, no live exposure today) |
| **Regression risk** | None in posture — the gate is new in this window. The window shipped a guarantee strictly weaker than its own documentation asserts. |
| **CWE** | Verification gap: CWE-1127 (compiler/analysis tool not detecting the condition). Consequence if tripped: CWE-200 / CWE-668 (internal topology exposure) and CWE-290 (spoofing via a trusted header) |
| **OWASP** | A05:2021 Security Misconfiguration; A01:2021 Broken Access Control (for the `X-User-Identity` leg) |
| **Files** | `proxy_canonical_header_keys_test.go` (the gate); the protected contract is `proxy.go:66-114` (`scrubForwardedHeaders`), `proxy.go:117-122` (`scrubTrailerKeys`) |

**Affected contract.** `proxy.go:186-191` and the gate's own header comment
state the property the gate exists to hold:

> The same rule binds `hdrForwardedFor` and `hdrUserIdentity` harder, because
> both are ALSO used as direct map keys (the `r.Header[hdrForwardedFor]` slice
> read in `scrubForwardedHeaders`, which does not canonicalise): a
> non-canonical spelling there would silently miss the header rather than
> merely cost an allocation.

and, in the gate file:

> For the keys ALSO used as direct map indices … the rule is load-bearing for
> CORRECTNESS too: a non-canonical spelling there misses the header outright.
> **That is the failure this gate is really here to prevent.**

**The defect.** The matcher has exactly two arms
(`scanFileForNonCanonicalKeys`): an `*ast.CallExpr` whose `Fun` is a
`SelectorExpr` naming `Get`/`Set`/`Del`/`Add`/`Values` on a Header-ish
receiver with a **`BasicLit` first argument**, and an `*ast.ValueSpec` whose
identifier matches `^(hdr|header)[A-Z0-9_]`. Three shapes are therefore
invisible — and the first two are precisely the expression forms in which the
correctness failure occurs:

1. **A direct map index** — `r.Header["X-Real-IP"]`, `r.Header["X-Bad"] = …` —
   is an `*ast.IndexExpr`, matched by neither arm.
2. **`delete(r.Header, "X-Real-IP")`** is a `CallExpr` whose `Fun` is an
   `*ast.Ident` (`delete`), not a `SelectorExpr`, so `scanHeaderCall` returns
   on its first type assertion.
3. **A constant named outside the `hdr`/`header` convention** — e.g.
   `realIPKey = "X-Real-IP"` — fails the `ValueSpec` arm's name regex, and at
   the call site `node.Args[0]` is an `*ast.Ident` rather than a `BasicLit`, so
   the accessor arm skips it too. The convention is documented nowhere and
   enforced nowhere.

**Attack scenario.** A maintainer adds a fourth forwarded-header leg, or
rewrites the scrub's `X-Real-IP` branch in the shape the function already uses
for `X-Forwarded-For` two statements above it — a direct slice read, which is
the *idiomatic* choice there and is the shape the surrounding comment
recommends for a multi-line header — and spells the key the way the IETF and
nginx write it, `X-Real-IP`. Nothing fails. `golangci-lint` is silent,
`TestCanonicalHeaderKeys_Tree` is green, and the gate's message explains that
canonicality is guaranteed tree-wide.

- **Preconditions.** A code change to `scrubForwardedHeaders`,
  `scrubTrailerKeys`, or any future forwarded-header leg that reaches the map
  by index or `delete` rather than by accessor. No attacker precondition.
- **Exploitability.** Once present, trivial and unauthenticated: the client
  simply sends the header. For the `X-User-Identity` leg the client *chooses*
  the value.
- **Likelihood of introduction.** Moderate. The direct-index form is already
  present in the same function, the non-canonical spelling is the one every
  external document uses, and the window's own commit message records that this
  exact constant "sat behind a comment claiming the constants were canonical
  through several performance sweeps of this very file".
- **Impact.** For `X-Real-IP`/`X-Forwarded-For`: the private internal hop is
  forwarded upstream — internal network topology disclosure, which is the
  stated purpose of the scrub. For `X-User-Identity`: a **client-supplied
  identity claim reaches the upstream**, which the function's own doc comment
  calls out as the thing it exists to stop ("set internally by auth context;
  must not be trusted from downstream clients or leak upstream"). That is an
  authorization-relevant bypass at any upstream that trusts the header.
- **Affected assets.** Internal addressing of the deployment's network; the
  identity assertion the gateway makes to upstreams; the trailer path, which
  carries the same three keys.

**Proved in both directions, on production shape.** The `X-Real-IP` branch of
`scrubForwardedHeaders` was temporarily rewritten as a direct index plus
`delete` with the non-canonical literal — a faithful reproduction of the
plausible future edit — and the tree re-run:

```
gate AS SHIPPED, over the injected bypass:
    --- PASS: TestCanonicalHeaderKeys_Tree (0.39s)
    --- PASS: TestCanonicalHeaderKeys_SelfCheck (0.00s)
    ok   github.com/KidCarmi/Culvert

gate AS FIXED, over the same injected bypass:
    --- FAIL: TestCanonicalHeaderKeys_Tree (0.35s)
        proxy.go:87:22: non-canonical header key "X-Real-IP"
            (direct map index: literal); use "X-Real-Ip".
        proxy.go:89:21: non-canonical header key "X-Real-IP"
            (delete() map key: literal); use "X-Real-Ip".

and the injected shape IS a live bypass, not a style finding:
    --- FAIL: TestCanonicalHeaderKeys_ScrubStillScrubs/private_is_removed
        set via "X-Real-IP": after scrub X-Real-Ip = "10.1.2.3", want ""
        set via "X-Real-Ip": after scrub X-Real-Ip = "10.1.2.3", want ""
        set via "x-real-ip": after scrub X-Real-Ip = "10.1.2.3", want ""
    --- FAIL: TestCanonicalHeaderKeys_ScrubStillScrubs/loopback_is_removed
        set via "X-Real-IP": after scrub X-Real-Ip = "127.0.0.1", want ""
```

The third line of each triple is the one that matters: the client's own casing
is irrelevant, because `textproto.ReadMIMEHeader` has already normalised it —
the miss is entirely on the gateway's side, so no client cooperation is needed.

**Latent today, not live.** The whole production tree was swept to confirm no
current code trips the blind spots. Every header-name constant in production is
canonical — `hdrForwardedFor` `"X-Forwarded-For"`, `hdrRealIP` `"X-Real-Ip"`,
`hdrUserIdentity` `"X-User-Identity"`, `headerRequestID` `"X-Request-Id"`,
`headerTraceparent` `"Traceparent"`, `headerTracestate` `"Tracestate"`,
`AttemptHeader` `"Mcp-Culvert-Attempt-Id"` — and the only direct `Header[...]`
literal indices in production Go are `auth_oidc_flow.go:1207,1230`, which index
a JOSE token's claim map, not an `http.Header`.

**Fix (applied in this branch, test-only).** Three arms added to the one
matcher the self-check already exercises, so the self-check keeps proving *this*
code can fail rather than a reimplementation of it:

- `scanHeaderIndex` for `*ast.IndexExpr` on a Header/Trailer receiver;
- `scanHeaderDelete` for `delete(hdrMap, key)`;
- `scanHeaderCallIdent` plus `collectHeaderKeyDecls`/`classifyHeaderKeyExpr`, so
  a key reaching a header through **any** identifier is judged by its declared
  **value** instead of by the spelling of its name. The declaration table is
  built **per package directory**, because that is how Go resolves an
  identifier: a same-named constant in an unrelated package must not be able to
  convict — or to excuse — this one.
- `TestCanonicalHeaderKeys_Tree` now parses per directory to supply that table.

**The precision problem this fix had to solve, recorded because it is the
interesting part.** The first version of the index arm narrowed on the receiver
name alone, exactly as the accessor arm does — and immediately produced two
**false positives** on `auth_oidc_flow.go:1207,1230`, where `unverified.Header`
and `t.Header` are a JWT/JOSE token's `map[string]any` of lowercase claim
names, spelled identically to an `http.Header` index. The accessor arm is safe
on receiver name alone only because it *also* requires a
`Get`/`Set`/`Del`/`Add`/`Values` call, which only `net/http`'s `Header` has; an
index expression carries no such second signal. Distinguishing the two
populations properly needs `go/types`, which would mean type-checking the whole
module from source inside a unit test. The map-keyed arms therefore require a
second, independent signal — a hyphen (`fieldNameShaped`) — which separates the
two populations cleanly here: HTTP field names used as map keys in this tree
are multi-token, JOSE parameters and ordinary lowercase map keys are single
tokens. What that gives up is recorded in §6.

**Required tests (all present and passing).**

| Kind | Test |
|---|---|
| Positive (covered shapes still caught) | `TestCanonicalHeaderKeys_SelfCheck` — exact multiset over the real matcher |
| Negative (no false positives) | the same self-check's `url.Values.Get("page")`, `map[string]string` and **JOSE `kid`/`alg`/`typ`** controls, kept as a standing control for the false positive the first version produced |
| Regression / both directions | `TestCanonicalHeaderKeys_IndexArmFailsClosed` — the real matcher over `scrubForwardedHeaders`' own shape: **0** findings without the resolver, **2** with it, each required to name the constant it resolved through |
| Boundary | hyphenated vs single-token keys; canonical constants under non-conventional names (`okKey`); a hyphenated non-header constant (`notAHeader = "fail-closed"`) never used in a header context |
| Tree-wide no-false-positive control | `TestCanonicalHeaderKeys_Tree` passes clean over all 200+ production files |
| Behavioural oracle | `TestCanonicalHeaderKeys_ScrubStillScrubs`, `TestCanonicalHeaderKeys_WireIdentical`, `TestBenchGate_ScrubAllocsInSitu` — unchanged and passing |

**No production code is changed by this fix.** `git diff` touches
`proxy_canonical_header_keys_test.go` only; `proxy.go` is byte-identical to
`110bf9f`.

---

## 3. Risk Rating

| | |
|---|---|
| **Window verdict** | **No regression.** Posture improved on a deny control (CHAOS-108) and on gate integrity (CHAOS-106). |
| **S-1** | Medium. Latent gate-integrity defect; no live exposure at `110bf9f`. Fixed in this branch, test-only. |
| **Residual** | Four items in §6, all pre-existing and none introduced by this window. |

---

## 4. Regression Analysis

**Changes that could have weakened posture, and why they did not.**

- **Twelve header-key re-spellings on the request path, including the MCP DPoP
  and `Mcp-Protocol-Version` reads and the IMDSv2 token request.** Semantically
  inert: every substituted site reaches the map through an accessor that
  canonicalises the lookup key, and the only direct index in the scrub
  (`r.Header[hdrForwardedFor]`) holds an already-canonical key. The six
  substituted pairs are pinned by a differential oracle that asserts one map
  slot, mutual readability under both spellings, and `Del` symmetry.
- **`X-Xss-Protection`, `Etag`, `X-Culvert-Pac-Version`,
  `Www-Authenticate` response headers.** `Header.Set` canonicalises the stored
  key and `Header.Write` emits the map key, so the wire bytes were already the
  canonical form before the change; the security headers in
  `securityMiddleware` are byte-for-byte what they were.
- **CHAOS-108's new scheduler state.** The one direction that could have
  regressed is a *slower* retry, which would extend the fail-open window the
  change exists to close. `setFeedIntervalLocked` only ever pulls `nextAttempt`
  in (`due.Before(st.nextAttempt)`), never pushes it out, and a feed with
  auto-sync disabled is stamped but skipped by `dueURLs`' interval check.
- **CHAOS-108's cancellation threading.** The manual "Sync Now" path
  deliberately keeps `context.Background()`, so an operator who clicks and
  navigates away does not abort the fetch; only the scheduler path inherits the
  lifecycle context. `httpTimeout` still bounds both via
  `context.WithTimeout(ctx, …)`.
- **`patch_allow_peers_numeric_uid`.** The new branch reuses an existing
  trailing comma instead of emitting a second one, so `allow_peers = ["a",]`
  becomes `["a", "uid"]` rather than invalid TOML. This strictly *prevents* a
  malformed cluster peer-trust list; it cannot add a peer that the un-patched
  path would not have added.
- **Twelve CI workflows.** Diffed line by line with the `harden-runner` pins
  excluded: the remainder is **empty**. No `permissions`, no `GOTOOLCHAIN`, no
  threshold, no gate removed. All pins remain full 40-character SHAs.
- **Four dependency bumps.** All forward, all with `h1:` and `/go.mod` hashes
  updated in `go.sum`. `golang.org/x/net` 0.61→0.62 and `grpc` 1.84→1.85 are
  the two that carry HTTP/2 framing and desync exposure, and both move
  *upward*. No `replace`, no downgrade, no new direct dependency.

**Backward-compatibility surfaces checked.** `api/openapi/openapi.{json,yaml}`
and `frontend/src/api/types.gen.ts` change only by the regenerated source hash
and the terminology rename ("hash cache" → "scan verdict cache") in
descriptions and Prometheus `# HELP` text. No metric name, field name, enum
value or route changed, so no persistence or wire contract moves.

---

## 5. Verification

Toolchain taken from `go.mod` (`toolchain go1.27.3`), linter from the gate that
blocks (`pr-fast-gate.yml` → `golangci-lint@v2.15.0`, built with the `go.mod`
toolchain), per `docs/agent-context/conventions.md`.

| Check | Result |
|---|---|
| `go build ./...` | clean |
| `go vet .` / `go vet ./internal/blocklistfeed/...` | clean |
| `go test .` (package main, full) | **ok**, 428.9 s |
| `go test ./internal/... ./cmd/...` | **ok**, all packages |
| `go test -race -run 'TestChaos108\|TestCHAOS108' ./internal/blocklistfeed/...` | **ok** |
| `golangci-lint run --new-from-rev origin/main` (the gate's own command) | **0 issues** |
| `golangci-lint run` full tree, this branch | 174 findings |
| `golangci-lint run` full tree, base `110bf9f` (change stashed) | 174 findings, **per-linter counts identical** — `gocritic` 40, `gocognit` 24, `cyclop` 24, `noctx` 17, `gosec` 15, `staticcheck` 14, `nestif` 8, `funlen` 8, `errcheck` 8, `unparam` 7, `dupl` 4 |

The full-tree comparison is run in addition to `--new-from-rev` because
`cyclop`, `funlen` and `gocognit` attribute to a function's **declaration**
line, which a diff-scoped pass cannot see — the case `conventions.md` names
explicitly, and the case PR #1783 in this very window was opened to fix.

**Not run, and why.** The hosted Fast PR Gate, Deep Gate, CodeQL, the DAST
nightly and the edge-case lab were not run — they are hosted gates for a
specific SHA and a local pass is not a passing hosted review. The
`docs-guidance` checker was not required: this branch touches no `AGENTS.md`,
`CLAUDE.md` or native skill, and the review document is not a registered
guidance path.

---

## 6. Residual Risk

All four are **pre-existing** and none was introduced by this window. They are
recorded because each is a named, evidenced gap with a sibling precedent in the
tree, not as findings against these pull requests.

1. **`internal/blocklistfeed` has no feed size cap, while its sibling does.**
   `fetchFeedLines` reads the whole body into an unbounded `[]string`.
   `bufio.Scanner` caps a single *line* at 64 KiB and fails closed on overflow
   (`scanner.Err()` is checked), but total volume is unbounded.
   `internal/threatfeed` has an explicit `maxFeedLines = 500_000` with the
   comment "safety cap per feed to limit memory usage"
   (`internal/threatfeed/threatfeed.go:204,957`). CHAOS-108's thesis was that
   this loop is "the fourth feed loop" brought to parity with its siblings on
   cadence and status; the sibling's memory cap is still absent. A hostile or
   compromised third-party origin at an operator-configured URL can drive node
   memory. CWE-400 / CWE-789.
2. **`redactContractForRole` is a per-code switch with no completeness gate.**
   Four codes are classified; every other operator-contract row is
   viewer-visible by default, and `operator_contract_wall_test.go` gates the
   *plumbing* (that `buildOperatorContract()` only ever reaches
   `writeOperatorContract`) rather than per-row classification. That default is
   deliberate and documented, and this window's new row is genuinely
   viewer-safe (§2 hypothesis 1) — but the question did not have to be asked
   for the row to ship, and the next row that does carry admin-only facts will
   reach viewers silently.
3. **CHAOS-106's `chaos106BranchesOn(scope, …)` inspects nested `FuncLit`s
   within the scope**, so a refusal bound in the enclosing function can be
   satisfied by an `if` inside a closure that may never execute. The commit
   accepts this explicitly ("Kept permissive on the branch's shape and on where
   inside the function it sits, since only its ABSENCE reopens the bypass"), and
   it is strictly tighter than the file-wide version it replaced.
4. **S-1's fix does not catch a bare single-token non-canonical literal used as
   a direct index** — `r.Header["traceparent"]`, which is how the W3C spec
   writes it — because the hyphen is the only signal that separates an
   `http.Header` index from a JOSE claim map without `go/types`. Single-token
   field names in this tree are declared under the `hdr`/`header` convention
   (`headerTraceparent`, `headerTracestate`) and are therefore caught at their
   declaration by `scanHeaderDecl`, independently of how they are later used.
   The gap is an inline single-token literal with no declaration behind it. It
   is recorded in the gate's own doc comment rather than left for a reader to
   discover.

---

## 7. Files

**Reviewed (production):** `proxy.go`, `pac.go`, `ui_middleware.go`,
`ui_security.go`, `cdr_metrics.go`, `diagnostics.go`, `geoip_database_health.go`,
`release_catalog_http.go`, `saas_feed_download.go`,
`internal/blocklistfeed/blocklistfeed.go`, `internal/mcp/runtime/listener.go`,
`internal/mcpacceptance/client.go`, `internal/uitls/uitls.go`,
`cmd/cireport/github.go`, `scripts/install.sh`, twelve `.github/workflows/*`,
`go.mod`, `go.sum`.

**Read as supporting evidence (unchanged this window):**
`internal/ssrf/ssrf.go`, `internal/geoip/geoip.go`, `internal/threatfeed/threatfeed.go`,
`state_corruption.go`, `admin_settings.go`, `ui_policy.go`, `connlimit.go`,
`internal/mcpacceptance/scenarios.go`, `operator_contract_wall_test.go`.

**Changed by this review:** `proxy_canonical_header_keys_test.go` (test-only),
this document.
