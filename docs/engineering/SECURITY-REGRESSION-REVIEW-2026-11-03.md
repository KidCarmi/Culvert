# Security Regression Review — 2026-11-03

**Scope.** `110bf9f…c65bbd2` (`origin/main`) — the 24 h since the 2026-11-02
review, 7 merged pull requests (#1792 #1793 #1794 #1795 #1796 #1797 #1798),
24 files, +3,251/−81. Seven production Go files changed; the rest is tests, the
CHANGELOG, two review documents and four roadmap documents.

| PR | Change | Security surface |
|---|---|---|
| **#1796** | CHAOS-109 — byte and entry budgets on all three feed ingest paths (`internal/feedsync`, `internal/blocklistfeed`, `internal/threatfeed`), **plus** `fix(feeds): accept a feed body of exactly the byte budget`, the boundary off-by-one Codex found in that same PR | threat intelligence, deny-control integrity, DoS / memory exhaustion, fail-open direction |
| **#1797** | `perf(logstore): remove per-entry allocation from the history-store flush path` — one retained buffer and `json.Encoder` for the whole batch, Badger handed a subslice per entry | request-log integrity, record-boundary correctness, memory safety |
| **#1793** | `diag: warn when the admin UI TLS certificate is expiring, expired or corrupt` + `diag: make the action depend on the certificate source` | diagnostics, RBAC, information disclosure, TLS posture visibility |
| **#1795** | `security(proxy): cover the direct map index in the canonical-header-key gate` + `test(proxy): resolve header-key constants by lexical scope` | gate integrity, header matching, forwarded-header scrub |
| **#1798** | `test(yara): wait for the abandoned worker in TimeoutFailsClosed` | scan fail-closed, test determinism |
| **#1794** | `docs: align Go version statements with go.mod toolchain` | prose accuracy only (`README.md`, `docs/architecture.md`) |
| **#1792** | `docs: terminology governance review 2026-11-02` (no findings) | documentation only |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed 24 h ago?** Every finding is measured against
`110bf9f`, not against an ideal.

**Method.** CHAOS-109 was read in the one direction that matters on a deny
control: can a round that did NOT see the whole feed end up authoritative, and
can it end up *recorded* as one that did. That meant reading the commit's own
safety argument — "the merge overwrites keys and never deletes" — to its
primitive rather than accepting it, so `catdb.BulkWrite` and
`blocklist.MergeFromLines` were both read for a `Delete`/`DropAll` that is not
there. The logstore buffer reuse was not accepted on its three documented
invariants: the single-owner claim was checked by enumerating every caller of
`flushBatch` and `newBatchEncoder`, and the "Badger does not retain the value
past Flush" claim was checked empirically, because it is a statement about a
dependency and not about this tree — the package's own round-trip and
concurrency gates were run under `-race` against real Badger, and they are
built to catch exactly this (payload lengths vary per entry, so a stale
subslice cannot coincidentally match, and the URI is derived from the Host, so
a crossed buffer is detectable without knowing which entries were dropped). The
new diagnostics rows were read as an information-disclosure question first,
against the path-free contract the 2026-11-02 review established, and then
against `redactContractForRole`, which is a per-code switch that does not
classify them. The canonical-key gate change and the YARA change were
confirmed to be test-only before being read further.

**Five hypotheses were formed against the window's own claims. Four were
disproved; one survived, plus two smaller findings.**

1. *A truncated `feedsync` import wipes category coverage, so an origin that
   pins the new aggregate cap with junk in early archive members suppresses the
   `malware`/`phishing` categories outright.* **Disproved at the primitive.**
   `catdb.BulkWrite` is `wb.Set` per key and nothing else
   (`internal/catdb/catdb.go:330`), and `Delete`, `DropAll` and `DropPrefix`
   do not appear anywhere in the package. A truncated round therefore adds
   fewer NEW domains and every previously categorised domain stays categorised.
   The commit's safety claim is accurate.
2. *A spent byte budget in `internal/threatfeed` is recorded as a successful
   short feed, which is the failure its own comment says it exists to prevent.*
   **Disproved.** `fetchTextFeed` returns `sc.Err()`
   (`internal/threatfeed/threatfeed.go:977`), `fetchFeedInto` turns any error
   into `replaced=false`, and `carryForward` then copies that source's previous
   entries forward — so an overrun yields the union of the partial fetch and
   the full last-known-good set. Strictly additive; fail-closed.
3. *The logstore buffer reuse publishes crossed or stale records, because
   Badger retains the value slice past `WriteBatch.Flush` or the encoder is
   shared.* **Disproved both structurally and empirically.**
   `newBatchEncoder()` is called once, in `writeLoop`
   (`internal/logstore/logstore.go:478`), and `flushBatch` only from the
   `flush` closure on that same goroutine — the sole production callers.
   `reset()` runs at the TOP of the next `flushBatch`, which is strictly after
   the previous call's `Flush` returned, so invariant 2 is satisfied by control
   flow rather than by comment. `go test -race ./internal/logstore/` passes,
   including `TestFlushBatchRoundTripMultiFlush` (3 flushes, 549 entries,
   per-entry payload lengths) and `TestFlushBatchConcurrentAdd` (8 producers).
4. *The new `ui_tls_cert_expiry` / `ui_tls_cert_corrupt` rows leak admin-only
   facts to a viewer, since `redactContractForRole` does not classify them and
   both renderers are gated at `RoleViewer` (`diagnostics.go:2804`,
   `ui_support.go:301`).* **Disproved on content.** The rows carry a day count
   and nothing else — no subject, no path, no key material — and the one
   configuration fact they do expose (that the certificate comes from
   `-tls-cert`/`-tls-key` or `tls_cert`/`tls_key` rather than an upload) names
   only documented setting names. A viewer negotiates this very certificate to
   reach the GUI, so `NotAfter` and custom-vs-self-signed are already available
   to them from their own TLS handshake. The author's design note states the
   path-free constraint explicitly and the code honours it.
5. *The new `blocklistfeed` line cap removes existing deny entries when it
   truncates.* **Disproved.** `MergeFromLines` only assigns `b.exact[line]` and
   `b.wildcards[key]` (`internal/blocklist/blocklist.go:940`); there is no
   delete on the path.

---

## 1. Executive summary

**No authentication, authorization, policy-precedence, TLS, proxy,
request/response-processing, secrets, session, crypto or audit regression was
introduced in this window.** The window's largest change (CHAOS-109) moves the
posture in the *right* direction: three ingest paths that were bounded only by
an HTTP timeout now carry declared byte budgets, and the two directions that
matter on a deny control — a failed round must not become authoritative, and a
partial round must not delete coverage — are both handled correctly and were
verified at the primitive rather than taken from the commit message.

Three findings survived verification. One is a fail-direction defect in this
window's own code, reproduced and **fixed in this branch**. Two are reported
and not fixed here, because both fixes reach surfaces (admin API/GUI parity,
and a global's type across the admin control plane) wider than an unattended
regression review should change on its own.

| ID | Finding | Severity | Regression risk | Status |
|---|---|---|---|---|
| **S-1** | `internal/feedsync`'s `boundedReader` rejects an archive of exactly the byte budget, failing every sync round | **Low** | In-window; the identical defect was fixed in the two sibling copies by #1796 and missed here | **Fixed in this branch** |
| **S-2** | A truncated ingest round is attested as a complete success on every health, metrics and diagnostics surface | **Medium** | In-window (two new truncation points) over a pre-existing blind spot | Reported |
| **S-3** | `uiCustomTLSCorrupt` is an unsynchronized `bool` written by one admin handler and now read by three more surfaces | **Low** | In-window widening of a pre-existing race | Reported |

---

## 2. Security findings

### S-1 — A category-feed archive of exactly the ingest budget fails every round

**Severity: Low. CWE-754 (improper check for unusual condition), CWE-20.
OWASP A04:2021 Insecure Design. Regression risk: in-window.**

`internal/feedsync`'s `boundedReader.Read` rejected the read taken once the
budget was *reached*, without checking that any byte had actually *exceeded* it:

```go
if b.read >= b.limit {            // feedsync.go:165, before the fix
    return 0, fmt.Errorf("%s exceeded its %d-byte budget: %w", …)
}
```

Because the same function truncates `p` so a single read can never cross the
limit, a stream of exactly `limit` bytes is consumed in full, leaves
`b.read == b.limit`, and then fails on the next read — the read that a
well-behaved reader must still make to observe `io.EOF`.

All three copies of `boundedReader` were introduced by the same commit
(`4666d7a`). Codex then found this off-by-one during review of that PR
(#1796, P2 4448735208) and the follow-up commit in the same PR (`7276734`)
corrected it in `internal/blocklistfeed` and `internal/threatfeed` by probing
for one more byte at the boundary. The category-feed copy — the only one of the
three carrying *two* budgets, on the compressed body and on the decompressed
archive — was left as written. So the defect and its fix shipped in one PR,
with one of the three call sites missed.

**Attack scenario.** Not primarily an attack: the dominant case is a
legitimate feed. A hostile mirror gains nothing, since it can fail the round
just as easily by sending one byte more. The exploitable shape is narrow — an
origin that can size its body to the budget exactly and wants rounds to fail
*while looking like a budget overrun rather than an outage* — and the realistic
shape is a feed, or a lowered test budget, that lands on the boundary.

**Preconditions.** The response body is exactly `maxFeedCompressedBytes`
(512 MiB), or the archive expands to exactly `maxFeedDecompressedBytes`
(4 GiB), and the final data-bearing read does not itself carry `io.EOF` — the
shape of a chunked response that flushes its last payload before the
terminating chunk.

**Exploitability: low** (requires an exact power-of-two match).
**Likelihood: low** at the production limits, **material** for any lowered
limit — and these limits are deliberately `var` so the bound gates can lower
them, which is precisely how a boundary bug becomes reachable.
**Impact: availability of a deny-control data plane.** The error is
`errBudgetExceeded`, which `parseTarball` routes to a failed round;
`syncRound` charges `failDownload` and returns false. Category coverage then
freezes at its last-good contents and does not advance for as long as the feed
stays that size — the failure repeats deterministically every round, since the
condition is a property of the archive, not a transient.
**Affected assets:** URL-category classification data, and therefore every
policy rule keyed on a category.

**Reproduced** before the fix, with the production reader and a
chunked-response-shaped source:

```
read 4096 bytes, err=compressed feed body exceeded its 4096-byte budget: ingest byte budget exceeded
REPRODUCED: body of exactly the budget (4096 bytes) rejected as an overrun
```

**Fix (applied in this branch).** Port #1796's `probeBoundary` to the third
copy: at exactly the budget, read one more byte — a clean `io.EOF` completes
the body, a real byte is the overrun, and any other outcome (a transport
error, or a no-progress `(0, nil)`) is passed through unchanged so an origin
is not blamed for a budget it did not overrun. Enforcement one byte past the
budget is unchanged, and `errBudgetExceeded` is preserved, which matters
because `ingestTarMember` routes that sentinel to a failed round rather than to
the log-and-continue arm a corrupt member takes — losing it would report an
origin overrun to the operator as a benign `skipping <member>` line.

### S-2 — A truncated ingest round is attested as a complete success

**Severity: Medium. CWE-778 (insufficient logging), CWE-654 (reliance on a
single security mechanism), CWE-1286. OWASP A09:2021 Security Logging and
Monitoring Failures. Regression risk: in-window, over a pre-existing blind
spot. Not fixed here.**

CHAOS-109 introduces two new truncation points, and both take the **success**
path in full:

- `internal/feedsync`: reaching `maxDomainsTotal` stops reading further archive
  members, logs one line, and `break`s out of `parseTarball`, which returns
  `entries, nil`. `syncRound` then sets `lastSync`, stores `totalDomains`,
  resets `consecutiveFailures` to 0 and clears `lastFailure`
  (`feedsync.go:446-449`).
- `internal/blocklistfeed`: reaching `maxFeedLines` logs one line and returns
  `lines, nil`. `SyncFeedContext` then takes `scheduleNextLocked(st, true)` —
  resetting the retry ladder — sets `st.lastSync` and clears `st.lastError`.

The data-plane consequence is genuinely safe, and hypotheses 1 and 5 above
confirm it: both stores are merge-only, so a truncated round adds fewer new
entries and removes none. **The attestation is what regresses.** The health
snapshot the admin API serves carries `LastSuccess`, `ConsecutiveFailures`,
`Domains` and `LastFailure` (`feedsync.go:293-302`) and has no field that can
express "this round did not see the whole feed". An operator reading
"last success: 2 minutes ago, 4,000,000 domains, 0 consecutive failures"
cannot distinguish a complete import from one that stopped at the cap with
archive members never read. The only signal is a single `obs.Printf` line in
the process log.

That matters because the cap is close to the live data. The code's own comment
records the real UT1 feed at "~3–4 M domains across all categories" against a
`maxDomainsTotal` of 4,000,000. A feed at 3.5 M growing 15 % begins truncating
— silently, recorded as healthy, and deterministically every round thereafter,
because archive order is stable. On a fresh deployment there is no previous
data to fall back on, so the categories in later members have *zero* coverage
while the control plane reports a successful sync of four million domains.

The same blind spot already exists, with a worse consequence, in
`internal/threatfeed` — **pre-existing**, introduced 2026-10-26, not in this
window. There, reaching `maxFeedLines` (500,000) exits the scan loop with
`sc.Err() == nil`, so `fetchFeedInto` returns `replaced=true`, and
`carryForward` then *skips* that source's previous entries. A truncated
threat-feed fetch therefore **drops** previously known-malicious URLs rather
than merely failing to add new ones, and is still recorded as a clean round.
This window did not create that, but CHAOS-109's comment asserts the two loops
"agree on the posture", and on truncation semantics they do not.

**Attack scenario.** A compromised or hostile feed origin — for `feedsync`, a
community GitHub mirror Culvert does not control — places high-volume junk in
early archive members (any mapped category directory; entries need only contain
a dot) so the aggregate cap is spent before the members carrying real
`malware`/`phishing` domains are reached. 4 M synthetic entries are ~72 MB
uncompressed and compress to a few MB, well inside both byte budgets. The node
reports a healthy, complete sync. The same origin could always have omitted
those members outright, so the *capability* is not new; what is new is that the
suppression now also looks like success from inside the product, and that a
non-malicious oversized feed reaches the same state.

**Preconditions.** A feed large enough to reach the cap, by growth or by
origin control. No authentication bypass and no privilege is required of the
attacker beyond control of the feed origin (for `blocklistfeed`, an
operator-configured URL).
**Exploitability: low-to-moderate.** **Likelihood: moderate** — the growth
path needs no attacker at all. **Impact: silent, persistent degradation of
deny-control coverage, invisible to the surfaces built to detect exactly that.**
**Affected assets:** category classification data, remote blocklist coverage,
threat-feed coverage, and the health/metrics/diagnostics attestation itself.

**Recommended fix (not applied here).** Make truncation a first-class outcome
rather than a log line:

1. Return truncation from the parse rather than discarding it —
   `parseTarball` already computes the boolean; propagate it to `syncRound`
   instead of consuming it in a `break`.
2. Record it on the syncer (`lastRoundTruncated`, plus the cap that was hit)
   and surface it in the health snapshot beside `LastFailure`, as a distinct
   state from both success and failure. A truncated round should keep its
   fresh data and its advanced `lastSync` — it is not a failed round — but must
   not clear the truncation marker.
3. Raise an operator-visible diagnostics row (WARN) and an alert, in the shape
   `checkAdminUITLSCert` uses: contributes nothing unless truncation occurred.
4. Align `internal/threatfeed` so a line-capped fetch is `replaced=false`, i.e.
   carry the source's previous entries forward instead of dropping them. This
   is the one piece that changes a fail-open into a fail-closed and should land
   first; it is independent of the attestation work.

Per `AGENTS.md`, a new operator-visible setting normally needs the admin API
endpoint, the `uiRoutes` entry and a UI surface. This is operator-visible
*state* rather than configuration, but it still crosses the GUI/API parity
contract and three package boundaries, which is why it is reported rather than
changed here.

### S-3 — `uiCustomTLSCorrupt` is an unsynchronized global with a runtime writer

**Severity: Low. CWE-362 (race condition), CWE-567 (unsynchronized access to
shared data). Regression risk: in-window widening of a pre-existing race. Not
fixed here.**

`uiCustomTLSCorrupt` is a plain `bool` (`ui_tls_custom.go:63`) with a
**runtime writer on an HTTP handler goroutine** — `apiCertsUpload` clears the
latch at `ui_security.go:405` after a successful re-upload (writer added
2026-10-26, pre-window) — and readers on other HTTP handler goroutines. Before
this window the only runtime reader was `GET /api/settings/network`
(`ui_config.go:2288`). #1795 added three more by reading it in
`checkAdminUITLSCert` (`diagnostics_ui_tls_cert.go:27`), which
`buildOperatorContract` reaches from `GET /api/diagnostics`
(`diagnostics.go:2810`), the support-report renderer (`ui_support.go:310`) and
the support-bundle collector (`support_collectors.go:81`). The first two are
gated at `RoleViewer`, so an unprivileged-but-authenticated reader can now
trigger the racing read.

`uiCustomTLSActive`, read on the adjacent line, is **not** affected: it is
written only by `resolveUITLSCertKey` during startup, which happens-before the
listeners serve. The sibling state in the same file —
`adminUITLSCertNotAfter`/`adminUITLSCertKnown` — is correctly guarded by
`adminUITLSCertMu`, which makes the omission on this one variable an
inconsistency rather than a considered choice.

**Attack scenario and impact are limited.** A `bool` does not tear on any
supported architecture, so the observable outcome is a *stale* value, not a
corrupt one: a diagnostics or support-bundle read concurrent with a cert
re-upload may show or omit the `ui_tls_cert_corrupt` WARN row for one request.
No authorization decision, TLS behaviour or persisted state depends on it. It
is nonetheless a data race under the Go memory model, it is reachable by a
viewer-role request, and it is the kind of access a `-race` CI gate will flag
as soon as a test exercises both paths concurrently.

**Recommended fix (not applied here).** Guard the variable with the
`adminUITLSCertMu` that already sits in the same file and already protects the
same subsystem's state, behind a small accessor pair
(`setUICustomTLSCorrupt` / `uiCustomTLSCorruptNow`), and route the runtime
writer and all three runtime readers through them; the startup writer can stay
direct. An `atomic.Bool` is equally correct. Either shape touches
`ui_tls_custom.go`, `ui_security.go`, `ui_config.go`,
`diagnostics_ui_tls_cert.go` and roughly ten direct assignments across two test
files, which is why it is reported rather than changed in a review branch.

---

## 3. Risk rating

| ID | Attack vector | Preconditions | Exploitability | Likelihood | Impact | Severity |
|---|---|---|---|---|---|---|
| S-1 | Feed origin / natural feed growth onto an exact budget boundary | Body exactly at the budget; final read without `io.EOF` | Low | Low (production limits), material (lowered limits) | Category coverage freezes; round fails deterministically | **Low** |
| S-2 | Hostile or compromised feed origin; or ordinary feed growth | Feed large enough to reach a cap | Low–Moderate | Moderate | Silent deny-control coverage degradation; threat-feed variant **loses** entries | **Medium** |
| S-3 | Authenticated viewer-role read concurrent with an admin cert upload | Two concurrent admin-UI requests | Low | Low | Stale diagnostics row; memory-model UB | **Low** |

No finding reaches High or Critical. Nothing in this window weakens
authentication, authorization, policy precedence, TLS termination or
negotiation, request or response processing, persistence of security-relevant
state, secret handling, session validation, cryptography or the audit trail.

---

## 4. Regression analysis

**What improved this window.** Three ingest paths that a third-party origin
could previously spend unbounded memory and CPU on — bounded only by a 5-minute
(or 30-second) HTTP timeout — now carry declared byte budgets, with the
expansion bounded independently of the compressed input rather than one standing
in for the other. The `feedsync` per-member cap, which an origin stepped around
simply by repeating a tar member path, is replaced by an aggregate cap charged
against the shared map. The fail direction is correct in every case verified:
byte overruns fail the round and leave last-good data authoritative; entry caps
truncate against merge-only stores. `#1796` closed a real boundary defect found
in review. `#1797` tightened the canonical-header-key gate to cover the direct
map index, which is the *correctness* failure that gate exists to prevent, and
documented the single-token residual in the gate's own doc comment rather than
leaving it for a reader to find.

**What regressed.** Only S-1 is a defect in this window's own code, and it is a
fail-*closed* defect: it refuses a legitimate feed rather than accepting a
hostile one. S-2 is an attestation gap widened by two new truncation points.
S-3 is a new set of readers on an already-racy global.

**Compatibility.** No persistence or wire format changed. `logstore`'s
new encoder is byte-identical to the `json.Marshal` output it replaces —
pinned by `TestFlushEncodeByteIdentity` against `json.Marshal` for
HTML-escapable runes, invalid UTF-8, U+2028/9, the nested `dec` block and the
zero `Entry`, so a change in `encoding/json` fails the build rather than
silently rewriting persisted records. Sequence-number consumption, the
skip-an-unencodable-entry behaviour, the per-entry TTL read and the
`bytesUsed` accounting are all preserved from the replaced loop.

**Test-only changes** (no production behaviour): `#1797`'s gate arms,
`#1798`'s YARA inflight-baseline cleanup — which fixes real cross-test
pollution under `-shuffle` and is exactly the global-test-cleanup discipline
`conventions.md` requires — and the Go-version prose alignment in `README.md`
and `docs/architecture.md`, which corrects stale prose toward `go.mod` as the
source of truth rather than the reverse.

---

## 5. Verification

Run at `c65bbd2` plus this branch's change, with the `go.mod` toolchain
(`go1.27.3`):

| Check | Result |
|---|---|
| `go build ./...` | pass |
| `go test -race ./internal/logstore/` (flush encode + batch) | pass |
| `go test -race ./internal/feedsync/` | pass |
| `go test ./internal/blocklistfeed/ ./internal/threatfeed/ ./internal/yara/` | pass |
| `go test . -run 'TestCanonicalHeaderKeys\|UITLSCert'` | pass |
| `golangci-lint run --new-from-rev origin/main` (v2.15.0, pinned by `pr-fast-gate.yml`) | **0 issues** |
| `golangci-lint run` full tree (v2.15.0) | 174 issues, **all pre-existing**; `internal/feedsync` contributes none |
| `python3 docs/agent-context/check.py` | exit 0 |

The linter on the container's `PATH` (`/usr/local/bin/golangci-lint`, v2.5.0)
panics on this module's language version — the failure mode `conventions.md`
names as repeatedly misrecorded as "local lint is unavailable". The pinned
v2.15.0 built with the `go.mod` toolchain runs clean; it must be invoked by
absolute path, because the stale binary shadows it.

**Not run, and why:** the full aggregate CI suite and the hosted gates for this
exact SHA. A passing local check is not a passing hosted review or merge gate.
The 512 MiB / 4 GiB production budgets were not exercised at full size; the
boundary gates lower the limit, which is why these limits are `var`.

---

## 6. Required tests

**Added in this branch** (`internal/feedsync/ingest_budget_boundary_test.go`),
mirroring the sibling packages' gate added by #1796:

| Test | Class |
|---|---|
| `TestBodyOfExactlyTheBudgetIsAccepted` | positive boundary — the regression itself |
| `TestOneBytePastTheBudgetIsAnOverrun` | negative control — the budget is still enforced, and still with the sentinel that fails the round |
| `TestShortBodyNeverProbesPastEOF` | below-boundary arm |
| `TestBoundaryProbePassesThroughTransportErrors` | malformed/aborted-input arm — a transport cut at the boundary must not be reported as an origin overrun |

The existing CHAOS-109 bound gates were re-run and still pass, which matters
because they lower the budgets and assert the overrun path:
`TestCompressedBodyBudgetFailsTheRound`, `TestDecompressedBudgetFailsTheRound`,
`TestBudgetOverrunIsNotLoggedAsASkippedMember`,
`TestSkippedMembersAreChargedToTheExpansionBudget`,
`TestDuplicateMembersCannotExceedTheAggregateCap`,
`TestBoundedReaderReportsOverrunAsAnErrorNotEOF`.

**Required before S-2 is fixed** (not written here):

- Positive: a round that reaches `maxDomainsTotal` reports truncation in the
  health snapshot while still advancing `lastSync` and keeping its data.
- Negative: a complete round reports no truncation; a *failed* round reports
  failure and not truncation. The three states must be distinguishable.
- Regression: a truncated round does not delete previously categorised domains
  (pins hypothesis 1 as an executable contract rather than a read of
  `catdb`).
- Fail-direction: a line-capped `internal/threatfeed` fetch carries the
  source's previous entries forward instead of replacing them — the one arm
  that converts a fail-open into a fail-closed.
- Boundary: exactly at the cap, and one entry below it.
- Malformed input: an archive whose early members are junk in a mapped category
  directory, asserting that later members' categories are either ingested or
  reported as missed.
- Concurrency: a truncated round concurrent with lookups serves a
  self-consistent view.
- Authorization: the new truncation row is role-classified deliberately in
  `redactContractForRole` — or deliberately recorded as viewer-safe, as the
  existing `ui_tls_cert_*` rows are.

**Required before S-3 is fixed** (not written here): a `-race` test driving
`apiCertsUpload`'s latch clear concurrently with `buildOperatorContract`, which
fails before the fix and passes after; plus a check that the startup writer and
the test assignments still observe the same value through the accessors.

---

## 7. Residual risk

1. **S-2 is unfixed.** A truncated feed round still reports as a complete
   success on every operator-facing surface, and the `internal/threatfeed`
   line-cap variant still drops that source's previous entries while reporting
   a clean round. The `feedsync` aggregate cap (4,000,000) sits close to the
   live feed's documented size (~3–4 M), so this is a growth path and not only
   an attack path.
2. **S-3 is unfixed.** The race is benign in its observable effect today, but a
   `-race` gate that starts exercising both paths will flag it, and the next
   piece of state added beside it may not be a non-tearing `bool`.
3. **`redactContractForRole` still classifies by enumerated code**, so every
   new diagnostics row reaches `RoleViewer` verbatim unless someone remembers
   to classify it. This window's two new rows are genuinely viewer-safe (§2
   hypothesis 4), but as the 2026-11-02 review noted, the question did not have
   to be asked for them to ship. Unchanged this window; carried forward.
4. **The canonical-header-key gate's single-token residual stands.** An inline
   non-canonical single-token field name used as a direct index
   (`r.Header["traceparent"]`) is not caught by the map-keyed arms, because a
   hyphen is the only signal separating an `http.Header` index from a JOSE
   claim map without `go/types`. Declared constants stay covered at their
   declaration. Recorded in the gate's own doc comment; unchanged this window.
5. **The feed byte budgets were not exercised at production size.** 512 MiB and
   4 GiB are asserted by gates that lower the limits. The boundary arithmetic
   is identical at any limit, which is the argument for the gates — but it is
   an argument, not a full-size measurement.
6. **Badger's non-retention of value slices past `Flush` is a dependency
   property**, verified empirically at v4.9.6 by the package's round-trip and
   concurrency gates rather than guaranteed by an API contract. A Badger
   upgrade that buffered values past `Flush` would corrupt request-log records
   silently; those gates are what would catch it, and they must keep running
   under `-race`.

---

## 8. Files

**Reviewed (production, changed this window):** `internal/feedsync/feedsync.go`,
`internal/blocklistfeed/blocklistfeed.go`, `internal/threatfeed/threatfeed.go`,
`internal/logstore/batchencode.go`, `internal/logstore/logstore.go`,
`diagnostics.go`, `diagnostics_ui_tls_cert.go`.

**Reviewed (tests/docs, changed this window):**
`proxy_canonical_header_keys_test.go`, `internal/yara/yara_test.go`,
`internal/logstore/batchencode_test.go`,
`internal/logstore/batchencode_bench_test.go`,
`internal/feedsync/ingest_bounds_chaos109_test.go`,
`internal/blocklistfeed/ingest_bounds_chaos109_test.go`,
`internal/blocklistfeed/ingest_budget_boundary_test.go`,
`internal/threatfeed/ingest_bounds_chaos109_test.go`,
`internal/threatfeed/ingest_budget_boundary_test.go`,
`diagnostics_ui_tls_cert_test.go`, `README.md`, `docs/architecture.md`,
`CHANGELOG.md`, `roadmap/CHAOS-*.md`.

**Read as supporting evidence (unchanged this window):**
`internal/catdb/catdb.go` (`BulkWrite`, and the absence of any delete),
`internal/blocklist/blocklist.go` (`MergeFromLines`), `ui_tls_custom.go`,
`ui_security.go` (`apiCertsUpload`), `ui_config.go`, `ui_support.go`,
`support_collectors.go`, `diagnostics.go` (`redactContractForRole`,
`writeOperatorContract`), `internal/ssrf/ssrf.go` (via `threatfeed`'s
`NormaliseURL` private-IP exclusion), `.github/workflows/pr-fast-gate.yml`,
`go.mod`.

**Changed by this review:** `internal/feedsync/feedsync.go` (S-1 fix),
`internal/feedsync/ingest_budget_boundary_test.go` (new gates),
`CHANGELOG.md`, this document.
