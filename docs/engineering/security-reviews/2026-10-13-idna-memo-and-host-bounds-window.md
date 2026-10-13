# Security review — the memoized IDNA slow path and the destination-host bounds

**Date:** 2026-10-13
**Reviewer role:** Security Regression Engineer (scheduled run)
**Scope reviewed:** `origin/main` at `77c0c58`. The designated branch
`claude/epic-bardeen-rcrv01` was level with `main` at session start (0 ahead,
0 behind), so there was no pending delta to review; the window taken instead is
the newest substantive code change on `main` — PR #1598, `7bae696` +`545452c`,
the memoized IDNA slow path in `internal/hostutil` — read together with the
destination-host bound tiers it sits under (`proxy_host_bounds.go`), plus the
convention sweep and dependency/CI window in §6.

---

## 1. Executive summary

**No security regression found.** The memo is a correct, bounded memoization of
a pure function, and it is the right shape for the problem: it sits *behind* the
already-canonical ASCII fast path, so ordinary traffic neither reads nor writes
it; it is direct-mapped with a fixed 1024 slots and a per-process random slot
seed, so the client-chosen key space cannot grow the table; and every hit
re-verifies the full key, so a collision degrades to a recomputation rather than
to another host's answer. `idna.ToASCII` under the zero-option profile has no
clock, configuration or I/O, so there is no staleness to invalidate and a hit is
indistinguishable from recomputing. The follow-up commit `545452c` had already
closed the one real defect in the first revision (an oversize authority retained
whole, ~2.1 MB across a full table).

What this review contributes is three **gates for properties whose failure mode
is a security one rather than a performance one**, which the shipped test file
did not pin, and one **factual defect in the bound's own rationale**.

The security-critical property is not throughput: `NormalizeHostStrict` is the
**fail-closed** gate that the HTTP and SOCKS5 dispatch paths use so a host that
cannot be canonicalized is *refused* rather than evaluated un-normalized against
FQDN, blocklist and category matching (RISK-013). A memo that answered a
rejected host from a neighbouring accepted entry would convert that gate into a
fail-**open** one, silently, for a host the client chooses. The shipped
collision test alternates two *accepted* hosts, so it exercises the mechanism
but cannot observe the verdict crossing — the half with the consequence. That
crossing, the key-clone property the footprint ceiling rests on, and the one
legitimate destination shape no case covered are now gated, each verified
failing against the specific defect it claims to catch (§5).

**Verdict:** no regression in the reviewed window. One documentation/reasoning
defect (SEC-IDNAMEMO-1, Informational, corrected here), one measured residual
amplification gap left deliberately at its pre-memo behaviour (§8), three new
regression gates, no runtime behaviour change.

---

## 2. Security findings

### SEC-IDNAMEMO-1 — The retention bound's stated justification is false for the input it measures

| | |
|---|---|
| **Severity** | **Informational** (no exploitable path; invites a future High-impact refactor) |
| **CWE** | CWE-1109 Use of Same Variable for Multiple Purposes (raw vs. canonical host); CWE-1053 Missing Documentation for Design |
| **OWASP** | A04:2021 Insecure Design |
| **Regression risk** | Introduced by #1598; **not** a behaviour regression |
| **Status** | Corrected in this change |

`maxMemoHostLen` is checked against the **raw** key (`len(host)`, post-lowering
and post-dot-trim), which is correct and load-bearing: the key is what an entry
retains, so it is what the footprint ceiling is derived from. The *justification*
beside it was not:

> Refusing to memoize such a host costs nothing: a name longer than this cannot
> be resolved by any DNS server, and both dispatch gates refuse it immediately
> after canonicalizing it […]

That sentence is true of a **canonical** name and false of the **raw** input the
check measures. Punycode *shrinks* a wide IDN. `maxDestHostLen` in
`proxy_host_bounds.go` already carries an explicit warning about exactly this
conflation — "**This bound is applied to the NORMALIZED host, never to the raw
bytes**, and the difference is the whole of the Codex P2 finding on PR #1446" —
and `maxRawDestAuthorityBytes` (1 KiB) exists precisely because a legitimate IDN
can be far longer raw than canonical.

Measured at this tree against the real `x/net/idna`: the widest legitimate
internationalized destination is **883 raw bytes → 251 canonical bytes**. Both
dispatch tiers **admit** it (the raw pre-cap is 1024, the canonical refusal is
253 and it measures 251), it resolves, and it is *never memoized*.

**Attack scenario:** none directly. The harm is prospective and it is the
refactor the retired sentence invites. A future reader who takes "refusing to
memoize one costs nothing" at face value, and who notices that this host's
canonical form fits comfortably, has an obvious "fix": move the length check
onto the normalized form. Doing so retains an 883-byte key per slot and the
ceiling this file asserts (~554 KB) becomes ~1.3 MB of process memory that a
client chooses the contents of — the same class of defect `545452c` had just
closed, reintroduced on the strength of a comment.

**Preconditions / exploitability / likelihood:** not exploitable as it stands.
Likelihood of the prospective refactor: moderate, because the sentence reads as
a justification for tightening and nothing executable contradicted it.

**Impact:** none today; bounded memory growth (≈2.4× the asserted ceiling) if the
refactor lands.

**Affected assets:** process memory on the proxy data path.

**Recommended fix / safe implementation:** keep the check on the raw key, state
why, and distinguish the two cases it covers — a host whose canonical form is
*also* oversize (refused by the dispatch gates, so not retaining it is free) from
one whose canonical form *fits* (admitted and legitimate, so not retaining it is
a deliberate, costed gap). Add an executable control that re-measures the
883/251 figure so the derivation cannot drift silently. Done in
`internal/hostutil/idnamemo.go` and
`TestIDNMemo_MaximalLegitimateIDNIsAnswerTransparent`; the matching CHANGELOG
sentence is corrected the same way.

---

## 3. Regression analysis

Each property was checked at the task revision against the pre-change behaviour,
not against the commit message's description of it.

| Property | Verdict | Evidence |
|---|---|---|
| Memo key completely determines the answer (pure function) | **No regression** | `normalizeHostStrictUncached` reads only `host`: `net.ParseIP`, `stripIPv6Brackets`, `idna.ToASCII`. No clock, configuration, I/O or process state. |
| Fail-closed verdict (`ok=false` ⇒ refuse) preserved | **No regression** | A rejection is memoized as `("", false)`; a hit re-verifies the full key. Gated in both directions by `TestIDNMemo_RejectionIsNeverUpgradedToAcceptance`. |
| Collision cannot return another host's answer | **No regression** | `e.host == host` on every hit. Mutating that check away is shown producing a fail-open (§5). |
| ASCII fast path untouched | **No regression** | Memo sits below `isCanonicalASCIIHost`; `TestIDNMemo_FastPathNeverTouchesMemo`, 0 allocs. |
| Table cannot grow with the client-chosen key space | **No regression** | 1024 fixed slots, direct-mapped, no eviction bookkeeping; 104 KB retained after 65 536 distinct IDN hosts. |
| Slot selection not precomputable by an adversary | **No regression** | Per-process `maphash.MakeSeed()`. Forced collisions degrade to recomputation, i.e. to pre-memo behaviour. |
| Entry publication race-free | **No regression** | Entries immutable once built; published through one `atomic.Pointer` store. `-race -count=2 -shuffle=on` clean. |
| Retained bytes bounded (no caller-buffer pinning) | **No regression** | `strings.Clone` on the key; the identity case shares that clone. Now gated by `TestIDNMemo_StoredKeyDoesNotAliasTheCallerBuffer`. |
| Oversize authority not retained | **No regression** (defect existed in `7bae696`, fixed in `545452c`) | `TestIDNMemo_OversizeHostsAreNotRetained`. |
| Two-tier destination-host bound still enforced at every entry point | **No regression** | `rejectOversizeDestHost` (raw), `rejectOversizeCanonicalHost` (canonical), `rejectOversizeUnnormalizableHost` (no canonical form). The memo is answer-transparent on the un-retained branch. |

**Admission engine (#1522–#1525, `internal/admission`).** Spot-checked the
extraction for the fail-open shapes its scoped guide names. `IPFilter.Allowed`
reads one published view and keeps the fail-closed `default: return false` for an
unknown mode, with `""` (disabled) still allowing — the documented posture.
Mode and entry set come from a single view, so a concurrent mutation can no
longer be observed half-applied, which is *stronger* than the pre-extraction
RWMutex shape. `publishExemptViewLocked` is pinned per mutator by
`TestRLExemptView_EveryMutatorRepublishes`, which is the right gate: a mutator
added without it is a revoked exemption that keeps bypassing the rate limit.
No regression found; `./internal/admission` green under `-race`.

---

## 4. Attack scenarios

**S1 — Fail-open canonicalization via a colliding memo entry (prevented; now gated).**
The direct-mapped table shares a slot between any two hosts that hash to it.
Suppose a hit did not re-verify the full key. An attacker sends a destination
authority with a malformed ACE label — `xn--0.example.com` — which the strict
gate must refuse (RISK-013), timed so that an accepted host occupying the same
slot is resident. Demonstrated against the mutated implementation:

```
NormalizeHostStrict("xn--0.example.com") = ("xn--bcher8063-q9a.example.com", true)
```

The request is admitted, and every downstream engine — policy FQDN matching, the
blocklist, the threat feed, category resolution, the SSL-bypass matcher — then
evaluates **a different destination than the one the request names**, including
the connection's own logging and audit attribution. Preconditions: an attacker
who can send requests and who can find a colliding accepted host (the seed is
per-process and unknown, so this is a brute-force search against a 1024-slot
table — cheap). Exploitability under the defect: high. Likelihood of the defect:
only via refactor, which is what the gate is for. Impact: policy bypass with
mis-attributed audit. CWE-290 / CWE-807; OWASP A01:2021.

**S2 — Memory exhaustion by caller-buffer pinning (prevented; now gated).**
The key reaches the memo as a substring of whatever the caller holds — on the
request path, a slice of net/http's header buffer. Had the entry kept it instead
of a clone, each slot would pin that entire backing array. Measured against the
un-cloned shape: **1 048 601 bytes held alive behind a 25-byte key**. The failure
is invisible to every byte-counting test, because `len(e.host)` reports 25 — so
`TestIDNMemo_BoundedFootprint` would have stayed green while the process retained
one buffer per slot. An attacker needs only requests with large headers and
distinct short IDN hosts. CWE-401 / CWE-770; OWASP A04:2021.

**S3 — Ceiling escape by re-deriving the bound from the canonical form
(prospective; now gated).** SEC-IDNAMEMO-1's refactor. `maxMemoHostLen` moves
onto `norm`, the 883-byte legitimate IDN becomes retainable, and a client parks
up to ~1.3 KB of strings per slot. CWE-770.

**S4 — Memo thrash (not viable).** An attacker sends only never-before-seen IDN
hosts so every lookup misses. Per *request* the memo still wins, because the
~10× fan-out supplies its own reuse — one engine misses and the other nine hit
(measured −73% CPU / −88% allocations cold). The isolated single-miss case the
benchmarks report as the memo's one loss (+22% ns, +1 alloc) is a shape the
request path cannot produce. Worst case is recomputation, i.e. today's cost.

**S5 — Cross-client history oracle via hit/miss timing (accepted, pre-existing
class).** The table is process-wide, so a memo hit (~54 ns) versus a miss
(~700 ns) is in principle an oracle on whether another client has visited a given
internationalized destination. Even at the ~6 µs the full fan-out gives, this is
far below the network and TLS-handshake variance of the request that carries the
probe, and the proxy already exposes strictly louder oracles of the same fact
(the 30 s-TTL SSRF DNS cache, upstream connection reuse, TLS session resumption).
Not actionable; recorded in §8 so it is a decision rather than an omission.

---

## 5. Required tests — and their negative controls

A gate that has never failed is a comment. Each was run against a mutated
`internal/hostutil/idnamemo.go` carrying the exact defect it claims to catch, and
the mutation reverted (`git diff` empty) before the final run.

| Gate | Defect injected | Observed failure |
|---|---|---|
| `TestIDNMemo_RejectionIsNeverUpgradedToAcceptance` | hit returns the resident entry without `&& e.host == host` | `NormalizeHostStrict("xn--0.example.com") = ("xn--bcher8063-q9a.example.com", true), want ("", false)` — the fail-open of S1 |
| `TestIDNMemo_StoredKeyDoesNotAliasTheCallerBuffer` | `key := host` in place of `strings.Clone(host)` | `the memo stored the caller's string rather than a clone, pinning its 1048601-byte backing array behind a 25-byte key` |
| `TestIDNMemo_MaximalLegitimateIDNIsAnswerTransparent` | the `len(host) > maxMemoHostLen` pre-check removed (bound left on `norm` only) | `1 slots filled by an 883-byte legitimate IDN host` |

Coverage of the task's required test classes: **positive** (the accepted host
keeps its answer across four alternating rounds and from both slot residencies);
**negative** (the rejected host stays `("", false)` on cold, warm-hit and
post-eviction lookups); **regression** (all three gates above, each verified
failing); **boundary** (the 883/251 shape, asserted to straddle `maxMemoHostLen`
raw and to fit canonically — the test fails loudly if either half moves, so an
`x/net/idna` upgrade that changes the expansion ratio moves the fixture rather
than silently invalidating the reasoning); **malformed input** (the rejected
family is malformed Punycode, which is what the fail-closed gate exists to
refuse); **concurrency** (the shipped `TestIDNMemo_ConcurrentStress` — ~1.3 M
verified normalizations under continuous eviction — re-run here under `-race
-count=2 -shuffle=on`). **Authentication/authorization** classes do not apply:
`internal/hostutil` is a pure string seam with no identity, no roles and no I/O.

---

## 6. Convention and dependency sweep

Checked at this revision, beyond the diff:

- **No bare `http.NewRequest`** in non-test code (the `noctx` contract).
- **No un-gated `InsecureSkipVerify`.** Every site is either config-gated with an
  at-site `// #nosec G402` and an operator warning, or pin-verified: `cdr.go`
  (`VerifyPeerCertificate`) and `internal/mcp/upstreamclient/transport.go`
  (`VerifyConnection` → base64 SHA-256 of the leaf SPKI) both *replace* chain
  verification with an exact pin rather than dropping it. `tlsConfig`'s unpinned
  branch keeps `RootCAs` + `ServerName` + `MinVersion: tls.VersionTLS12`.
- **`fmt.Printf` in package main** appears only on CLI/startup console paths that
  run before or outside the application logger (`main.go` break-glass reset and
  backup output, `dp_enrollment.go`, `ui_tls_custom.go`, `ui_support.go`), not on
  request or admin-handler paths. Consistent with the recorded convention.
- **`unsafe`** is used by the new gate in a test file only, with existing
  precedent (`metrics_histogram_shard_test.go`,
  `internal/blocklist/hotread_test.go`) and one production site
  (`internal/mcp/limits/limits.go`). Pointer identity is the only way to observe
  the clone; no byte-counting assertion can.
- **CI/dependency window (`28a43ef`)** re-read for a weakened gate, since
  "lint budget" in a commit subject is the shape that usually is one. It is not:
  the change raises golangci-lint's `--timeout` from 5 m to 10 m (under a 15 m
  job bound) after a cold-cache runner expired *with 0 issues*, so a slow
  analysis is reported as a linter error rather than read as a clean pass. The
  toolchain moves to go1.26.9 and `x/net` to v0.60.0 to clear GO-2026-6617 (an
  HTTP/2 HPACK encoder race reachable from the inspected-H2 tunnel and the
  control-plane gRPC server) plus twelve stdlib advisories. No gate relaxed, no
  workflow `GOTOOLCHAIN` override.
- **IDNA profile divergence** between `hostutil` (zero-option) and the feed/config
  seams `internal/urlcatfeed` + `internal/upstream` (`idna.Lookup`, i.e. UTS-46
  with STD3) is pre-existing and directionally safe: the ingestion side is
  *stricter*, so it drops entries it cannot canonicalize rather than storing one
  under a key the request path would not produce. No concrete bypass path was
  reachable — a host whose two profiles disagree normalizes, on the request path,
  to an A-label no resolver answers for. Recorded, not raised as a finding.

---

## 7. Verification

Run at this tree (`go1.26.9`, from `go.mod` `toolchain`):

| Check | Result |
|---|---|
| `go build ./...` | clean |
| `go vet ./...` | clean |
| `gofmt -l` (excluding `frontend/`) | clean |
| `go test ./internal/hostutil/ -race -count=2 -shuffle=on` | ok |
| `go test ./internal/admission/ ./internal/ssrf/ -race` | ok |
| `go test . -run 'Chaos69\|NormalizeHost\|HostStrict\|OversizeHost\|Policy'` | ok |
| Three negative controls (§5) | each confirmed failing, then reverted |
| `python3 docs/agent-context/check.py` | passes |
| `go test ./...` (full module) | green, 0 failures, earlier in the session; after the container's resolver failed, **9 failures on this branch against 11 on a pristine `origin/main` control** — the branch set is a strict subset, so this change introduces none. See the caveat below. |
| `golangci-lint` | **NOT RUN** — see below |

**Two honest caveats.**

*Lint was not run.* The container's `golangci-lint` v2.5.0 is built with go1.25
and panics on this go1.26.9 module (`package requires newer Go version go1.26
(application built with go1.25)`); building it from source under this toolchain
still reports its own language version as go1.24 against the config's `1.25`
target. CI installs it differently, so that gate is **unverified here**. The
added file is tests and comments, with no new production code for `gosec` to
read. Note separately that `.golangci.yml` pins `run.go: "1.25"` while `go.mod`
`toolchain` is `go1.26.9`; that is a pre-existing mismatch, outside this window.

*Nine root `IdP` tests fail in this container and it is the environment, not this
change.* Midway through the session the sandbox resolver stopped answering
(`getaddrinfo("example.com")` → `Name or service not known`). The IdP fixtures
use `Issuer: "https://example.com"`, and `isPrivateHost` → `ssrf.PrivateHost`
**fails closed on resolution errors** — the correct, documented posture — so the
upserts are refused with "URL must be https:// and must not point to a private
address". Not a regression, and arguably the guard demonstrating its contract.

The control is a full `go test ./...` on a pristine `origin/main` worktree in the
same container, compared by failing test name:

```
branch: 9 failing tests        main (control): 11 failing tests
on BRANCH but not on main:  (none)
on main but not on branch:  TestEtcd_AcquireDenied_RevokesScratchLease
                            TestEtcd_Conformance_Embedded
```

The branch's failing set is a strict **subset** of main's — this change
introduces no failure. The two extra rows on main are embedded-etcd tests in
`internal/halease`, which flaked there because the two full suites were running
concurrently (port contention); they are unrelated to this window either way.
The full-module green row above was measured before the resolver failed.

---

## 8. Residual risk

1. **A legitimate wide IDN in the 254…1024-byte raw band is never memoized.**
   Measured: the 883-raw/251-canonical host costs **12 allocations per
   normalization, warm**, against **0** for a memoized host — times the ~10×
   per-request fan-out. Both dispatch tiers admit it, so a client can select this
   shape at no cost to itself and pay the gateway the full un-memoized fan-out.
   This is **exactly its pre-memo behaviour**, so it is not a regression, and the
   absolute worst case remains the ~1.3 ms per request the 1 KiB raw pre-cap was
   already sized and accepted for in `proxy_host_bounds.go`. It is left as is
   deliberately: covering it means retaining keys up to the raw cap, which
   multiplies the retained-bytes ceiling to ~1.3 MB — a sizing decision for the
   owners, not a security fix, and not one to make from a scheduled review. Now
   stated in code, in the CHANGELOG, and re-measured by a gate.
2. **Negative entries occupy slots.** A memoized rejection is correct (the
   function is pure) but consumes a slot an accepted host could use. Worst case
   is recomputation.
3. **Hit/miss timing oracle.** §8 S5 — accepted, dominated by pre-existing
   oracles.
4. **Unverified lint gate** in this container (§7).
5. **`.golangci.yml` `run.go: "1.25"` vs `go.mod` `toolchain go1.26.9`** —
   pre-existing, unreviewed here, worth a look in a CI window.

---

## 9. Files

| File | Change |
|---|---|
| `internal/hostutil/idnamemo_security_test.go` | **new** — three gates, with the negative controls recorded in §5 |
| `internal/hostutil/idnamemo.go` | comment only — SEC-IDNAMEMO-1's rationale corrected; no code change |
| `CHANGELOG.md` | the memo's retention-bound paragraph corrected; the new gates recorded under Unreleased → Security |
| `docs/engineering/security-reviews/2026-10-13-idna-memo-and-host-bounds-window.md` | this review |

No runtime behaviour changes in this window.
