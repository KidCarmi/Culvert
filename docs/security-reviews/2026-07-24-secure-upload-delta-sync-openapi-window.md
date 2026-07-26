# Security Regression Review — M6 secure upload + CP/DP delta sync + OpenAPI contract + bootstrap catalog (window `6349722` → `2eef667`)

> **Reviewer role:** Security Regression Engineer (AppSec / Secure Code Review / Product Security)
> **Review date:** 2026-07-24
> **Baseline:** `6349722` — end of the previous review's window (see PR #878; the prior report file is not yet on `main`)
> **Head:** `2eef667` (`main`)
> **Scope reviewed:** every code-bearing change in the window — 29 first-parent
> merges (PRs #869–#910), 192 files, ~53k insertions (~11k of it Go across 92
> files) — reviewed as six parallel domain deep passes plus orchestrator
> verification of every MEDIUM finding against the working tree at `2eef667`.
>
> The window is dominated by five clusters:
> 1. **M6 "secure upload"** — the appliance→TAC support-bundle egress path
>    (PRs #879, #883, #885, #886, #887, #895): `support_upload*.go`,
>    `support_tac_trust.go`, `internal/supportupload/`, and the SPA panel.
> 2. **CP/DP delta sync + marshal caching** (PR #869): `controlplane_delta.go`
>    (new), `cluster_convergence.go` (new), the unenrolled config-pull exfil
>    throttle, and DP epoch-floor persistence.
> 3. **OpenAPI contract program** (PRs #880, #896): `api/openapi/*`,
>    `internal/apicontract/`, `cmd/apibundle`, and two new CI workflows.
> 4. **Bootstrap catalog integration** (PR #884): `bootstrap_resolve.go`,
>    `release_bootstrap_provenance.go`, `scripts/install.sh`.
> 5. **CodeQL log-injection fix batch** (PRs #900, #904, #906, #907, #908) plus
>    connlimit (#874), terminology (#875), and quiet-danger UI (#898).
>
> Two docs-only design PRs (#909 M7 telemetry, #910 MCP gateway baseline) were
> reviewed for insecure-default commitments only.
>
> `go build -o culvert .` is green at `2eef667`.

---

## Executive summary

**Verdict: no CRITICAL or HIGH security regressions.** The window's two
largest new attack surfaces — an outbound egress channel to a vendor cloud
(M6) and a new authenticated-fleet sync RPC (delta sync) — were both built
fail-closed, and the three failure modes that most often sink features of
this shape are explicitly and correctly closed:

- an admin-settable URL that could bypass the trust anchor — **closed**
  (the TAC trust key is env/baked-only, GET-only over the API, and a
  configured key may never rebind a baked `key_id`);
- plaintext diagnostics leaving the appliance — **closed** (bundles are
  sealed to TAC's X25519 public key *before* egress; the appliance holds no
  private key, so a hostile gateway or MITM gets ciphertext only);
- a credential or secret leaking through config export, version rollback, or
  CP→DP sync — **closed** (the TAC bearer credential is node-local in its own
  0600 file, on no `configSurfaces` row; the delta path routes through the
  same `redactUnenrolledSnapshot` helper as the full path, now pinned by a new
  both-doors AST test).

The classic **cache-confusion regression** was specifically hunted on the new
marshal caches and is **absent**: `gcMarshalCache` structurally never holds a
redacted blob, and `gcDeltaRemainderCache` carries the `enrolled` bit *in its
cache key*. Delta application is epoch-fenced before any mutation and guarded
by three independent anti-replay/anti-rollback checks.

**Seven findings are recorded — two MEDIUM, four LOW, one INFO-class group.**
Neither MEDIUM is a confidentiality break; both are resource-exhaustion
primitives created by new code, and both are one-to-few-line fixes:

- **M1 — MEDIUM** (availability): a **TAC-gateway-controlled `chunk_size`**
  drives an unbounded `make([]byte, chunkSize)` in the upload worker. A
  hostile/compromised gateway returns `chunk_size: 9223372036854775807` and
  the proxy process dies on `makeslice`; the queue entry persists, so it
  crash-loops on every boot. `internal/supportupload/upload.go:172-176`,
  `support_upload_wire.go:343`.
- **M2 — MEDIUM** (pre-auth memory growth): the **new unenrolled config-pull
  exfil throttle is itself an unbounded allocation**. `unenrolledConfigPull.
  attempts` is a `map[string][]time.Time` keyed on peer IP that never deletes
  a key, on a listener that accepts callers with no client certificate
  (`VerifyClientCertIfGiven`). IPv6 is not collapsed to /64.
  `controlplane_server.go:188-218`.
- **L1 — LOW**: unpinned GitHub Actions (`@v7`, `@v4`) in the two new
  API-governance workflows — 8 of 177 `uses:` sites in the repo, the only
  unpinned ones, in a workflow slated to become a required merge check.
- **L2 — LOW**: the bootstrap **verifier binary has no version floor** — the
  root of trust for a fresh install is whatever `releases/latest` reports,
  and the cosign identity pin matches *any* signed `v*` tag.
- **L3 — LOW**: delta blocklist cap is checked **after** mutation, so the
  over-cap set is realized in the live enforcement maps before rejection.
- **L4 — LOW**: upload drain/re-arm write-back is last-writer-wins, so a
  concurrent admin consent can strand a consented upload in `rejected`.
- Plus an INFO group: `CULVERT_BOOTSTRAP_SKIP_VERIFY` is a stronger
  break-glass than any sibling; a narrow secrets-wall pattern set; two
  pre-existing unconfirmed destructive UI row actions; a dead unvalidated
  `IPList` field adjacent to an unescaped render; gateway-controlled
  `received_offset` and `last_error` hardening.

The 2026-07-19 report's six findings are **all still open** — every one of
their files is untouched in this window (status table in §"Prior-finding
status").

---

## Security findings

### M1 — MEDIUM: gateway-controlled `chunk_size` is an unbounded allocation → proxy crash-loop

| | |
|---|---|
| **Severity** | MEDIUM |
| **CWE** | CWE-789 (Memory Allocation with Excessive Size Value); secondary CWE-400 |
| **OWASP** | A05:2021 Security Misconfiguration / A04:2021 Insecure Design (missing bound on external input) |
| **Regression risk** | New code (PR #883/#887) — no baseline behavior to preserve |
| **Affected assets** | Proxy data-plane availability (the whole process, not just the upload worker) |

**Location.** `internal/supportupload/upload.go:172-176` returns the gateway's
`chunk_size` with only a `<= 0` floor and **no upper bound**:

```go
cs := resp.ChunkSize
if cs <= 0 {
    cs = defaultChunkSize   // 4 MiB
}
return resp.UploadID, cs, nil
```

Consumed at `internal/supportupload/upload.go:239` (`buf := make([]byte,
chunkSize)`) and independently at `support_upload_wire.go:343`
(`transferSealed`, same line shape).

**Attack scenario.** The TAC gateway answers `POST /v1/uploads:init` with
`{"upload_id":"x","chunk_size":9223372036854775807}`. `transferSealed` calls
`make([]byte, 9.2e18)` → `runtime: makeslice: len out of range` (or an OOM
kill on a merely large-but-plausible value like `1<<40`). The panic is in the
upload worker goroutine, which is not `recover()`-wrapped, so it takes the
**entire proxy process** down. The queue entry is persisted in a non-terminal
state, so `supportUploadTick` retries 30s after the next boot — a crash-loop,
i.e. a durable availability DoS on the data plane driven entirely from
outside the appliance.

**Preconditions.** Upload enabled + origin set + TAC trust key configured +
an admin has consented to at least one bundle (the feature is armed), and the
gateway response is attacker-influenced: a compromised TAC tenant, a hijacked
DNS record for the TAC domain, or an operator `origin` pointed at an
attacker-controlled public host. The `init` response body carries **no
authentication of its own** — only TLS to the configured origin — so anyone
who can occupy that origin qualifies.

**Exploitability.** Low-to-medium (requires the armed feature plus gateway
position), but the trigger is a single JSON integer and there is no
validation whatsoever. **Likelihood** low today; rises the moment the feature
is broadly deployed. **Impact** high for availability, none for
confidentiality or integrity.

**Recommended fix (safe implementation).** Clamp at the boundary where the
value crosses the trust edge, and defensively at the second consumption site
(they are separate code paths):

```go
const maxChunkSize = 64 << 20 // 64 MiB

cs := resp.ChunkSize
if cs <= 0 || cs > maxChunkSize {
    cs = defaultChunkSize
}
```

Additionally allocate `min(chunkSize, size)` rather than `chunkSize` — the
buffer never needs to exceed the object being sent. Prefer the clamp-to-default
over an error return: a gateway proposing a silly chunk size should not be able
to fail an operator-consented upload either.

**Required tests.**
- *Boundary / malformed input*: `Init` with `chunk_size` = `math.MaxInt64`,
  `-1`, `0`, `1<<40`, `64<<20`, `(64<<20)+1` → returns the clamped value, no
  panic (`internal/supportupload`).
- *Regression*: `support_upload_wire_test.go` — fake transport returns a huge
  `chunkSize` from `Init`; `transferSealed` completes or errors, never panics.
- *Positive*: a normal `chunk_size` is still honored end-to-end.

---

### M2 — MEDIUM: the new unenrolled config-pull throttle is an unbounded pre-auth allocation

| | |
|---|---|
| **Severity** | MEDIUM |
| **CWE** | CWE-770 (Allocation Without Limits or Throttling); secondary CWE-400 |
| **OWASP** | A04:2021 Insecure Design |
| **Regression risk** | New guard added by PR #869 — the guard itself is the new surface |
| **Affected assets** | Control-plane process memory |

**Location.** `controlplane_server.go:188-218`.

```go
var unenrolledConfigPull = struct {
    mu       sync.Mutex
    attempts map[string][]time.Time
}{attempts: map[string][]time.Time{}}
```

`unenrolledConfigPullAllow` prunes the *slice* for the key being accessed, then
writes it back — **including when the pruned slice is empty**
(`unenrolledConfigPull.attempts[ip] = recent`). Keys are never deleted, the map
has no cap, and a key never touched again is never swept at all.

**Attack scenario.** The exfil throttle keys on the gRPC peer IP and is
consulted on both `GetConfig` (`controlplane_server.go:140`) and
`GetConfigDelta` (`controlplane_delta.go:380`). The cluster gRPC listener
uses `tls.VerifyClientCertIfGiven` (`controlplane_tls.go:91`) so that
unenrolled nodes can call `Enroll` — meaning **an attacker with no
credentials** can reach both methods. One call per source address permanently
adds a map entry + slice header + IP string (~100 B). IPv6 is **not**
collapsed to /64 here, unlike the documented `internal/autoexclude` client-token
practice, so a single /64 allocation yields 2⁶⁴ distinct keys. This is the
"rate-limiter as amplifier" shape: the anti-abuse control is the unbounded
allocation, on the pre-auth surface, and the throttle's own 10/min ceiling does
not bound *distinct keys*.

A secondary, non-exploitable observation: the guard is **fail-open on an empty
peer address** — `if ip := peerSourceIP(ctx); ip != "" && !allow(ip)`. That
branch is unreachable over real gRPC/TCP, so it is a robustness issue, but a
fail-open default in a security guard is the wrong polarity for this codebase.

**Preconditions.** Network reachability to the CP cluster gRPC listener; no
credentials. Bulk-address capability (trivially IPv6) for practical impact.

**Exploitability.** Moderate — slow memory growth rather than instant
exhaustion, but unauthenticated, unbounded, and on a service whose compromise
is fleet-wide. **Impact**: CP availability (and with it, config distribution to
the whole fleet).

**Recommended fix (safe implementation).** Four changes, in priority order:

1. **Cap the map** (e.g. 4096 distinct IPs) with expired-first eviction, or
   sweep expired keys on an amortized schedule. The in-repo precedent for
   exactly this attacker-controlled-key problem is `topHosts` in `store.go`
   (decay pass amortized to once per cap-many new-key insertions).
2. **Delete the key** when `len(recent) == 0` instead of storing an empty slice.
3. **Collapse IPv6 peers to /64** before keying, matching the `autoexclude`
   client-token precedent (IPv4 stays raw — a /24 would over-collapse a NAT
   fleet).
4. **Fail closed** (or fall back to a shared global bucket) when
   `peerSourceIP` returns `""`.

Note this narrows the resource boundary and never widens the throttle: an
evicted key is re-admitted at full quota, which is the pre-PR-#869 behavior, so
the fix cannot make throttling weaker than baseline.

**Required tests.**
- *Boundary*: `TestUnenrolledConfigPull_MapBounded` — N ≫ cap distinct IPs →
  `len(attempts) <= cap`.
- *Regression*: `TestUnenrolledConfigPull_ExpiredKeyReclaimed`.
- *Malformed/adversarial input*: `TestUnenrolledConfigPull_IPv6CollapsedTo64`.
- *Negative / fail-closed*: `TestGetConfig_NoPeerIPIsThrottled`.
- *Concurrency*: `-race` test hammering `unenrolledConfigPullAllow` from N
  goroutines across M IPs while eviction runs.
- *Positive*: the existing `TestGetConfig_UnenrolledExfilThrottled` and
  `TestGetConfigDelta_UnenrolledExfilThrottled` must stay green (the 10/min
  contract is unchanged).

---

### L1 — LOW: unpinned GitHub Actions in the two new API-governance workflows

| | |
|---|---|
| **Severity** | LOW |
| **CWE** | CWE-829 (Inclusion of Functionality from Untrusted Control Sphere); CWE-1357 |
| **OWASP** | A08:2021 Software and Data Integrity Failures |
| **Regression risk** | Policy regression — breaks an otherwise-uniform repo convention |

**Location.** `.github/workflows/pr-api-governance.yml:44,59,66,118,133,140`
and `.github/workflows/api-contract.yml:44-45` — `actions/checkout@v7`,
`actions/setup-go@v7`, `actions/cache@v4`.

**Evidence.** Verified repo-wide: **8 tag-pinned `uses:` sites vs 169
SHA-pinned** — the eight are exactly these two new files (PR #896). Every
other workflow pins a full 40-hex commit SHA with a version comment, and most
jobs additionally run `step-security/harden-runner`; these two do neither.

**Attack scenario.** A mutable tag (`v7`, `v4`) can be re-pointed by a
compromised upstream maintainer account. Blast radius is genuinely limited —
both workflows are `pull_request` (never `pull_request_target`), carry
`permissions: contents: read`, and receive no secrets — but
`pr-api-governance.yml` is explicitly designed (its own header) to become a
**required, merge-blocking branch-protection check**, so a tag repoint could
silently neuter or fake the breaking-change and client-generation gates.

**Knock-on effect worth noting:** because these files are tag-pinned,
dependabot's `setup-go` bump landed as `@v5` → `@v7` rather than a SHA bump —
the pin-loosening self-perpetuates through automated updates.

**Recommended fix.** SHA-pin all eight sites with version comments (e.g.
`actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0` — that SHA
was verified against upstream as exactly `v7.0.0`); add `harden-runner` to match
sibling workflows; consider reusing the existing `./.github/actions/setup-go-cache`
composite as the other 55 call sites do.

**Required tests.** A repo-wide workflow-invariant test asserting no
`uses: …@vN` remains in `.github/workflows/` (the
`release_workflow_invariants_test.go` pattern). That wall would have caught
this at PR time and prevents recurrence.

---

### L2 — LOW: the bootstrap verifier binary has no version floor (downgrade-selectable root of trust)

| | |
|---|---|
| **Severity** | LOW (structural; grows with every release) |
| **CWE** | CWE-1328 / CWE-757 (downgrade to less-secure variant); CWE-494 |
| **OWASP** | A08:2021 Software and Data Integrity Failures |

**Location.** `scripts/install.sh:702-720` (`resolve_verifier_version`),
`:797-830` (`verify_bootstrap_verifier`).

**Detail.** The verifier binary — documented in the installer itself as "the
ROOT OF TRUST for the entire fresh install" — is fetched at whatever tag
GitHub's **unauthenticated** `releases/latest` JSON (or the HTML `Location`
redirect) reports. It *is* cosign-verified, but the pinned identity
(`MAINT_SIGSTORE_SAN_REGEX`, byte-equal to `officialSigstoreSANRegex` per
`TestReleaseIdentitySSOT`) matches **any** `refs/tags/v.*` release. There is no
monotonicity or minimum-version constraint on the verifier itself.
`safe_release_tag` prevents traversal to another repo but deliberately accepts
any well-formed tag.

**Attack scenario.** An on-path attacker who can satisfy TLS to github.com —
an org TLS-inspection CA, which is precisely this product's own deployment
reality — rewrites the `tag_name` to an *old but genuinely signed* release.
It cosign-verifies cleanly and executes as the trust root. Impact today is
bounded (all releases carrying `bootstrap-resolve` share trust roots, and the
catalog it verifies still enforces signature + freshness + rollback), but this
becomes a working trust downgrade the moment any past release ships a
verify-path bug, a since-rotated ed25519 root, or a widened identity. Note the
project **already closed this exact class on the catalog side** (SEC-F2b
monotonic floor) — the verifier side has no equivalent.

**Recommended fix.** Enforce a minimum verifier version in `install.sh` as a
rendered constant (the first tag carrying the hardened trust roots); longer
term, have the catalog pin the current verifier digest so day-2 machinery
ratchets it forward. Record the verifier version/digest in `bootstrapDecision`
(currently absent).

**Required tests.** Extend `install_catalog_bootstrap_contract_test.go`
(`TestInstaller_ValidatesVerifierDownloadInputs`) to assert a version-floor
check exists; a shell-function test that a below-floor tag is rejected and an
at-floor tag accepted.

---

### L3 — LOW: delta blocklist cap is enforced *after* mutation

| | |
|---|---|
| **Severity** | LOW |
| **CWE** | CWE-400 / CWE-770 |

**Location.** `controlplane_delta.go:263-281` (`applyBlocklistDeltaSnapshot`).

**Detail.** The DP's memory ceiling is checked as `if n := bl.Count(); n >
maxSnapBlockedHosts` **after** `bl.ApplyDelta(...)` has already inserted every
host from the chain into the live enforcement maps. The check does correctly
prevent *persistence* (`bl.Save()` runs after) and the caller full-resyncs, and
the realized overshoot is bounded by the wire frame (CP ring 32 MiB, single
delta 8 MiB) — hence LOW, not MEDIUM. But the guard's own comment claims it
prevents the DP being OOM'd, which post-mutation placement does not fully
deliver.

**Preconditions.** A malicious or compromised (mTLS-authenticated) CP, or a CP
bug producing an over-cap chain.

**Recommended fix.** Pre-check before mutating —
`if bl.Count()+chainAddedCount(chain) > maxSnapBlockedHosts { return err }`
(a conservative `sum(len(chain[i].Added))` is fine) — keeping the post-check as
defense-in-depth.

**Required tests.** `TestApplyBlocklistDelta_OverCapRejectedBeforeMutation` —
assert `bl.Count()` is **unchanged** (not merely unpersisted) after rejection.

---

### L4 — LOW: upload drain/re-arm write-back is last-writer-wins (TOCTOU)

| | |
|---|---|
| **Severity** | LOW (fail-closed; correctness/availability, no data exposure) |
| **CWE** | CWE-367 (TOCTOU), CWE-362 |

**Location.** `support_upload_queue.go:362-373` (`dueUploadEntries` snapshots
under the mutex, then releases it), `support_upload_worker.go:62-76` (loop over
the stale snapshot, then blind `saveUploadQueueEntry(updated)`).

**Detail.** `drainUploadEntry` sets `State = uploadStateUploading` only on the
**in-memory copy** (`queue.go:304`), never persisting it before the network
round-trip. `enqueueUpload`'s re-arm correctly no-ops on a persisted
`uploading` entry (`queue.go:231`) — but the entry is never persisted in that
state, which is exactly the hole. If an admin re-consents a `deferred` bundle
(new seal, new `BundleSHA256`, `UploadID=""`, `Attempts=0`) while the worker is
finishing an attempt on the pre-re-arm snapshot, the worker's write-back
restores the **old** hash/upload-id/attempts. The queue entry then describes
bytes that no longer exist on disk; the next attempt uploads the new blob
claiming the old hash, the gateway's complete-time hash check fails, and the
entry goes terminal-`rejected`.

**Assessment.** Fails **closed** — no wrong data is delivered and there is no
confidentiality impact — but it destroys an operator-consented evidence upload,
and the window is one network round-trip wide, so it is realistically reachable
during a retry storm.

**Recommended fix.** Make the write-back a compare-and-set: re-load under
`uploadQueueMu` and persist only if a generation counter / `UpdatedAt` still
matches the snapshot. Alternatively persist the `uploading` transition durably
before releasing the lock, which activates the existing re-arm no-op.

**Required tests.** A `-race` concurrency test driving `enqueueUpload` re-arm
concurrently with `finishUploadDrain` on one bundle, asserting the persisted
`BundleSHA256` always matches the on-disk sealed blob.

---

## Informational notes (no action required unless noted)

1. **`CULVERT_BOOTSTRAP_SKIP_VERIFY=1` executes an unverified downloaded root
   of trust** (`scripts/install.sh:799-801`). Unlike
   `CULVERT_RELEASE_CATALOG_VERIFY=permissive` — which still rejects a
   present-but-invalid signature — this skips verification entirely, and the
   binary then drives `docker pull` decisions on a sudo-capable host. Its
   stated audience (air-gapped hosts) cannot download the binary anyway (the
   offline path is `CULVERT_PROXY_SEED_REF`), so the legitimate use is nearly
   empty while the abuse value — one env var in a pasted "support" command — is
   high. *Suggested*: replace with an operator-supplied
   `CULVERT_BOOTSTRAP_VERIFIER_SHA256=<hex>` pin, which serves the
   egress-filtered case without an unverified-execution mode.
2. **Gate-10 secrets wall has scope and pattern gaps**
   (`apicontract_secrets_test.go:13-31`). It scans 4 files;
   `api/route-classification.yaml` (4,200+ hand-maintained lines) and
   `docs/api/*.md` are unscanned. Patterns cover PEM, `AKIA…`, `gh?_…`, and
   RFC1918 IPv4 — missing JWTs (`eyJ…`), credentialed URLs
   (`scheme://user:pass@`), webhook URLs, `sk-`-shaped keys, internal hostname
   suffixes (`.internal`/`.corp`/`.local`), IPv6 ULA. Current content verified
   clean by independent sweep; this is a prospective-leak gap into a publicly
   distributed artifact.
3. **Two destructive UI row actions have no confirmation at all** —
   `secRemoveIP` (`static/index.html:7697`, removes an IP-filter entry; in
   allow-list mode this can drop an IP's proxy access instantly) and
   `removeRewriteRule` (`:8283`). Both **pre-date** PR #898 (verified against
   `10d25c8^1`); #898 only changed the button class. The other nine migrated
   handlers all have `confirmAction`. *Suggested*: add tier-1 confirms and a
   source assertion that every `danger-quiet` button's handler contains a
   confirm call.
4. **Dead `IPList []string // full replace` field** (`ui_security.go:177`) is
   declared but never read; only `IPAdd`/`IPRemove` are applied, both validated
   through `net.ParseCIDR`/`net.ParseIP`. This matters because
   `renderSecIPList` (`static/index.html:7673-7678`) interpolates `${ip}` into
   `innerHTML` **without** `escHtml` — safe today only because every entry
   provably round-trips through the parser. Someone "finishing" the dead field
   without validation turns it into stored XSS. *Suggested*: delete the field
   (or wire it through `IPFilter.Add`) **and** add `escHtml(ip)` regardless.
5. **Gateway-controlled `received_offset` is not bounded by `size`**
   (`support_upload_wire.go:339-360`). Bounded in practice (a negative offset
   errors on `ReadAt`; an over-size offset just ends the loop and hits the
   receipt-hash backstop), so hardening only: `if offset < 0 || offset > size
   { offset = 0 }`.
6. **`LastError` carries up to 256 bytes of gateway-controlled text** into the
   viewer-readable queue view and the durable audit trail
   (`support_upload_queue.go:323`). `sanitizeLog` is applied at persist time
   and the GUI escapes it, so **no log-injection and no stored XSS** —
   residual is cosmetic/social-engineering (attacker text appearing
   appliance-authored). *Suggested*: store a classified error code plus a
   `[\x20-\x7E]`-filtered subset.
7. **Terminal-state pruning can orphan sealed ciphertext**
   (`support_upload_worker.go:74-95`, `support_upload_queue.go:263-278`). The
   blob is 0600 and encrypted to TAC's public key (the appliance holds no
   private key), so this is disk retention, not disclosure; the bundle-size
   janitor limits blast radius. *Suggested*: call `removeSealedUpload` inside
   `pruneTerminalUploadEntriesLocked`.
8. **`deltaRemainderCache` is single-slot** (`controlplane_delta.go:299-345`).
   Correctness is right (the `enrolled` bit is in the key — see SAFE below),
   but an unenrolled poller alternating with enrolled DPs evicts the enrolled
   variant every call, forcing a full re-marshal per poll (bounded by the
   10/min throttle). *Suggested*: two slots, or mirror `gcMarshalCache` and
   never cache the unenrolled remainder.
9. **`b.ExportedAt` reaches two audit `Detail` strings unsanitized**
   (`ui_config.go:839`, `:1118`) — pre-existing, admin-only, stored
   structurally and rendered through `escHtml`, not forwarded to syslog. Not a
   CWE-117 terminal sink. *Suggested*: `sanitizeLog` or RFC3339 validation.
10. **Bootstrap provenance is recorded, not proven**
    (`release_bootstrap_provenance.go:32-51`). `/data/bootstrap_decision.json`
    is on the container-writable volume and is republished with no signature
    or cross-check against the running image, so a compromised appliance can
    forge the "which digest provisioned this host" answer that IR is told to
    trust. Nothing *gates* on it; viewer-RBAC and a 64 KiB bound apply.
    *Suggested*: document it as a claim, or annotate `"verified": bool` after
    cross-checking `bootstrap.image_ref` against the running image.
11. **Fresh-host catalog replay window** (`bootstrap_resolve.go:397,416`): a
    fresh host has floor 0, so an on-path attacker can replay any validly
    signed, unexpired (≤180d) catalog. Inherent to the documented posture and
    identical to runtime (`release_catalog_http.go:88`); bounded by the
    freshness gate and by `stage_rollback_floor` on volume-kept reinstalls
    (which fails closed).
12. **Transient sanitization weakening between #906 and #908 — resolved.**
    PR #906 replaced a correct `sanitizeLog(peerAddr)` with an inline
    two-`ReplaceAll` form covering only `\n`/`\r`, dropping tab/C0 coverage;
    PR #908 restored `sanitizeLog` (`ha.go:279`). Exposure was nil (`%q`
    escapes control bytes anyway; the value is operator-supplied HA config).
    HEAD is correct — recorded as a process note.
13. **Design-doc advisory (PR #910):** the MCP credential-broker design admits
    a configurable `fail-open-if-cached-and-policy-permits` mode
    (`docs/design/mcp/CONFIG-SURFACE-MATRIX.md`). The doc already mandates the
    right guardrails (default fail-closed; a hardcoded floor that write/
    high-risk profiles can never resolve to fail-open). *Implementation-review
    checkpoint*: reject the fail-open enum at **validation** time for write
    profiles, not merely ignore it at runtime, and pin it with the
    already-named `mcp_gateway_broker_failure_test.go`.

---

## Regression analysis — surfaces verified safe

### M6 secure upload (the window's largest new attack surface)

**Trust anchor cannot be widened by an admin.** `resolveTACTrustKeys`
(`support_tac_trust.go:155-189`) adds baked keys first, and a configured
(`CULVERT_TAC_TRUST_KEYS`) key reusing a baked `key_id` with a different
fingerprint is **dropped with a warning** — an env override can never silently
rebind a baked pin. Set size capped at 64. Every key validates through
`sealbox.ValidateRecipientPublicKey` (`internal/sealbox/sealbox.go:74-91`),
which rejects low-order Curve25519 points — the exact class of key that would
make a "sealed" blob openable by anyone. **There is no admin API write verb**:
`apiSupportTACTrust` is GET-only with an explicit 405. Origin and trust anchor
are therefore fully decoupled — pointing `origin` at an attacker host yields
ciphertext the attacker cannot decrypt.

**Sealed before egress, sealed once.** `sealAndEnqueueUpload`
(`support_upload_wire.go:202-226`) seals to the active X25519 public key,
writes `upload.csb.sealed` 0600 atomically, and hashes the **sealed** bytes so
the wire hash covers ciphertext. `realUploadFunc` opens *only* the sealed file
— the plaintext tgz is never read by the network path. Idempotency is enforced
under `uploadConsentMu`.

**SSRF: four independent layers.** Config-time `validateUploadOrigin`
(`support_upload.go:115-139`) does inline `url.Parse` + https-only + empty-host
reject + `net.ParseIP`→`isPrivateIP`, and strips an IPv6 zone (`%eth0`)
*before* `ParseIP` — closing the `https://[fe80::1%25eth0]` bypass. Dial-time
`ssrf.SafeDialContext` guards the **post-resolution** IP, closing DNS
rebinding. Per-request `c.originGuard(c.base.Host)` (`upload.go:271-276`) is
the non-obvious one that matters: with `HTTPS_PROXY` set, the dial guard only
ever sees the proxy address, so the resolving pre-check is what stops a private
origin being tunneled. `ssrf.PrivateHost` fails closed on DNS failure.

**Redirects hardened on all three axes** (`upload.go:144-157`): ≤5 hops,
**any non-https redirect refused** (the credential-leak stopper — Go preserves
`Authorization` and replays the PUT body across same-host redirects), and
`ssrf.PrivateHost` re-applied per hop. **No `InsecureSkipVerify` and no custom
`TLSClientConfig` anywhere** in the M6 surface (grepped). Responses bounded by
`io.LimitReader(…, 64 KiB)` including error bodies; 60s per-request timeout;
`http.NewRequestWithContext` throughout.

**Credential containment.** Stored 0600 in a 0700 dir via tmp+rename
(`support_upload.go:79-90`). Never echoed — `uploadStatus` returns
`credential_set: bool` only. **Verified absent from every config surface**:
grepped `config_surfaces.go`, `ui_config.go`, `configversion.go`,
`controlplane_snapshot.go` for `uploadConfig`/`tacTrust` — zero hits; the
handler deliberately does not call `saveConfigVersion`. So export, rollback,
and CP→DP push cannot carry it off the node.

**AuthZ + C2 parity exact on all four routes.** GET config/tac-trust/uploads =
`RoleViewer`; PUT config and POST consent = `RoleAdmin`, both `Mutating` +
`AuditExpected` with matching `auditEvent` calls. Metadata is never more
permissive than the handler (invariant #2). `TestUploadGUI_ConsentRequiresAdmin`
proves viewer **and operator** get 403. `TestNoInboundTACSurface` pins all four
as non-public.

**Consent gate: five fail-closed preconditions** before any egress state exists
(`wire.go:112-148`) — admin role → `supportBundleIDRe` shape → `uploadEnabled()`
→ `tacTrustConfigured()` → bundle must be `bundleStateReady` (the M4 privacy
approval gate) → `confirm=true` → `case_id` must match the already-bound case
(an operator cannot redirect an evidence bundle to a different case).
`TestNoAutoUpload` source-scans the startup slices to prove nothing
auto-uploads.

**Path safety and bounds.** Every path derives from
`^csb_[a-z2-7]{26}$`-validated IDs, validated on write, read, enqueue, and both
HTTP entry points — traversal impossible. A record whose persisted `BundleID`
disagrees with its filename is rejected (`queue.go:149-151`), closing a
confused-deputy deletion. Non-terminal queue capped at 256 **including on the
`rejected → queued` re-arm path** (the subtle one), terminal at 256 with
oldest-first eviction, `LastError` at 256 bytes. Backoff is deterministic
2s→10min with a shift-overflow guard; 4xx → no retry; the worker drains
serially on a 30s tick and never holds `uploadQueueMu` across network I/O.

**Injection.** Only two headers are set (constant `Content-Type`, `Bearer`
credential); Go's header writer rejects CR/LF. The gateway-supplied `upload_id`
goes through `url.PathEscape`. `sanitizeLog` + `%q` applied at every
attacker-influenced log sink. **GUI: every rendered field escaped** — all of
`d.origin`, `k.key_id/source/fingerprint`, `u.bundle_id/case_id/state/attempts/
receipt.sig/last_error`, and all `err.message` paths go through `escHtml`; the
only unescaped interpolations are `uploadStateColor()` returns from a closed set
of CSS-variable literals.

### CP/DP delta sync

**Authentication identical to the full path.** `GetConfigDelta` registers
through the same method table, `wrapUnary` adapter, listener, TLS config, and
16 MiB `MaxRecvMsgSize` as `GetConfig`, and applies the same three gates in the
same order (`ServableConfig()` → `callerIsEnrolledNode` → throttle). It does
not widen the bootstrap-reachable contract.

**Redaction wall covers the delta path, with a new both-doors test.** Redaction
moved into one shared `redactUnenrolledSnapshot` (`controlplane_server.go:165-174`);
the delta remainder builder calls it inside the cache-fill under the same
`!enrolled` condition. The AST parity test was correctly re-anchored to the
helper (with a `t.Fatal` if it vanishes or zeroes nothing), and the **new**
`TestConfigSurfaces_RedactionCallers` asserts *both* files call it — exactly the
right control for "a second secret-bearing surface appeared elsewhere".

**No cache confusion (the specific class hunted).** `gcMarshalCache` is
populated **only** from the enrolled branch — the unenrolled path returns
before reaching it — so it structurally cannot hold a redacted blob nor serve a
full one to an unenrolled caller. `gcDeltaRemainderCache` serves both classes
but includes `enrolled` **in the key**; redaction is applied *before* marshal
inside the same critical section, so no window exists where an unredacted blob
sits under an unenrolled key. Both expose `reset()` for test isolation against a
swapped store.

**Epoch fencing consulted before any mutation.** `applyDeltaReply` calls
`dpObserveEpoch("config delta", reply.Epoch)` as its **first** statement,
before unmarshal, validation, or any store touch. The reply epoch is stamped
from `globalHA.CurrentEpoch()`, which returns 0 when a lease-configured CP does
not hold the lease — the zombie shape `dpObserveEpoch` rejects.

**Three independent anti-replay/rollback checks.** (a) Strict sequential base
(`BaseVersion != lastVersion` → reject) kills replays; (b) strict forward
monotonicity, whose comment correctly identifies and guards the *inverse*
attack (a hostile CP jumping `lastVersion` to freeze the DP on stale config);
(c) cryptographic convergence — `SyncedFingerprint() != targetFP` returns
**before** `Save()` and before any non-blocklist store is touched, so a
truncated/duplicated/reordered chain cannot persist. CP-side, a non-contiguous
publish clears the ring and `chain()` fails on gaps or `Resync` markers.

**A stale/forged delta cannot downgrade security config.** Blocklist applies
first and is fingerprint-verified; on failure the function returns before
policy rules, default action, external auth, and IdP profiles are touched — a
bogus blocklist delta cannot flip default-deny. Pinned by
`TestApplyDeltaReply_RejectedBlocklistLeavesRemainderUnapplied`. Separately,
`ApplyDelta` never removes an operator's **manual** block from enforcement, so a
hostile `removed` list cannot un-block an admin-pinned host.

**DP epoch-floor persistence (D4) closes a hole rather than opening one.**
`atomicWriteFile(…, 0o600)`, monotonic CAS load that only ever *raises* the
floor, corrupt file leaves the ratchet unchanged, and seeding is wired **before**
the first poll — closing the restart window where an epoch-0 zombie CP would
have been accepted.

**`seedReplicatedSnapshot` does not weaken HA gating**: it sets `s.snap` but
deliberately not `published`, does not advance the version, and does not notify
— so a standby that has only seeded a replicated bundle still cannot serve
config.

**Convergence telemetry creates no new trust dependency**: `MetricsReport.
SyncedFP` arrives on `PushMetrics`, gated by `verifyNode` (cert-serial pinning +
revocation) before storage, and is read only for display — no policy, issuance,
or config decision consumes it. `nodeConvergence` carries IDs, ints, booleans;
`CPFP` is an XOR-of-SHA256 digest, and viewer-level exposure matches the
existing `/api/cluster/metrics`.

### OpenAPI contract program

**The docs are not served by the appliance** — no Go file outside the
apicontract tooling references `api/openapi`; the only embedded FS is
`//go:embed static` plus `trusted_root.json` and `default_categories.json`;
`ui_routes_meta.go` has zero openapi routes. **No route-inventory or
auth-allowlist change.** The public docs build filters on
`x-culvert-visibility` and is walled by `TestOpenAPI_PublicDocs_NoInternalLeak`
plus byte-equal regeneration; extracting every path from `index.public.html` at
HEAD yields exactly the 8 expected public/health routes. All HTML output is
`html.EscapeString`-escaped with no external assets.

**Role-classification drift cannot downgrade authz.** Three-link chain, each a
CI-blocking *equality*: router `uiRoutes.MinRole` ⇄ manifest `min_role` (plus
MUTATING/AUDIT drift), manifest ⇄ spec `x-culvert-permission`, plus a live-router
bijection with unclassified/stale/phantom detection. Runtime authz never reads
the manifest (C2 reads `uiRoutes`), so drift could only ever be documentation
drift — and it is walled anyway. All gates ran green at HEAD.

**Workflow fundamentals sound** (L1 aside): `pull_request` never
`pull_request_target`; `permissions: contents: read`; no secrets; untrusted PR
body/labels passed via `env:` and consumed quoted (`printf '%s' "$PR_BODY" |
grep -qiF`) — the canonical safe pattern, no expression-in-script injection.
`scripts/openapi/*.sh` receive no untrusted input, quote all expansions, use
`mktemp` staging, and **hard-fail on tool errors** rather than skipping.

### Bootstrap catalog

**No verification bypass.** `bootstrap-resolve` reuses the runtime trust kernel
verbatim (`combinedReleaseTrustKeys`, `resolveSigstoreWiring`,
`NewTrustStoreWithSigstore(…, VerifyEnforce, …)`, `LoadVerifiedCatalog` re-verify
of the staged dir) and **always** enforces — the `CULVERT_RELEASE_CATALOG_VERIFY`
break-glass is deliberately not honored, and a no-roots build fails closed.
Changing the catalog URL cannot change trust. **No silent downgrade to tag
enumeration**: the disabled-origin sentinel hard-fails and legacy GHCR tag
discovery survives only behind an explicit break-glass env, pinned by four
tests. The resolved image is shape- and allowlist-gated **twice** (Go side
`repo@sha256:<64hex>` + `repo == proxyRepo`; shell side re-gates the verifier's
stdout before `docker pull`, defending even a compromised verifier). SSRF uses
the inline CodeQL-visible preflight *plus* the provider's dial/redirect guard;
credentialed mirror URLs are redacted to host-only and the origin passes via env,
not argv. **No `curl|sh` of unverified content** — the verifier is downloaded,
cosign-verified against the pinned identity, capability-probed with `grep -qa`
(never executed blind), then run under `timeout`. Reinstall anti-rollback stages
the surviving floor conservatively and can only fail closed. 16
`TestBootstrapResolve_*` tests pin the fail-closed contract.

### CodeQL fix batch and small PRs

All four sanitization fixes use the project-standard `sanitizeLog` (strips
`\n`/`\r`/`\t` then all remaining control bytes) with `%q`, applied to the right
value, with **no control-flow change** and no sanitized value feeding a security
decision. `logWarnf`/`logErrorf` render identically to before, then sanitize.
`proxy_tunnel.go`'s `proto` comes from a closed switch of five constants, so the
wrap is a no-op on real values; the **relay security behavior is untouched** —
raw-relay block, `idleCopyCounted` idle bounding, activity stamp, byte
accounting, teardown, and hop-by-hop stripping are all outside the diff. HA
sanitization preserves the real peer address (only control bytes are replaced),
so split-brain investigation is unimpaired.

**PR #874 does not touch per-IP limiting** — the limiter lives in
`internal/connlimit/` and is unmodified; the change is a byte-exact
allocation optimization of `generateTraceparent` (layout verified identical,
`crypto/rand` source and all-zero fallback unchanged). **PR #900 merged nothing**
(the Copilot branch's diff against its own parent is empty — the CodeQL alert was
triaged as a false positive). **PR #871** is test + roadmap only. **PR #875** is
wording-only in `ui_config.go` (two audit `Detail` strings, two comments — no
handler, route, `requireRole`, or validation touched) and a package comment in
`internal/pac/inventory.go`.

### UI

PR #898's diff is **CSS + class-attribute only** — zero JS handler lines
changed, no confirmation or authz code removed. Nine of eleven migrated actions
have `confirmAction`/tier-2 confirms at HEAD (the two exceptions pre-date the PR
— note 3). The test walls are real and well-aimed: the confirm dialog's OK
button is pinned **solid** danger, bulk-delete/clear-all/CA-rotate/CDR-revoke are
pinned solid, no inline `on*=` handlers, and the E2E test asserts clicking a
quiet row button **still opens** the confirm dialog — precisely the
"did a destructive action become one-click" wall.

### Dependencies and supply chain

All three GH-Action SHA pins in the dependabot bumps were **verified authentic**
against upstream via `git ls-remote` (annotated tags dereferenced):
`actions/checkout 9c091bb2…` = `v7.0.0`, `softprops/action-gh-release 3d0d9888…`
= `v3.0.2`, `github/codeql-action 7188fc36…` = `v4.37.1`. All 80 checkout / 4
gh-release / 5 upload-sarif existing uses **remained SHA-pinned** — the loosening
in L1 came from the new files, not the bumps. checkout v6→v7 is a Node-24
migration whose one breaking change is a security *tightening*
(`pull_request_target` fork-checkout block — the repo uses it nowhere). grpc
1.82.0→1.82.1 cherry-picks an xds/RBAC panic fix, inert here (no xDS). go-ldap
3.4.13→3.4.14 surfaced no CVE/GHSA, and the asn1-ber change moves *forward* from
an untagged pseudo-version to released `v1.5.8`. New OpenAPI deps (kin-openapi
MIT, jsonschema/v6 Apache-2.0, oasdiff yaml forks) are permissive-licensed,
passed the `go-licenses` gate, and are confined to CI/contract tooling — not the
datapath. The Go toolchain pin (1.25.12) is unchanged.

### Design docs

**PR #909 (M7 telemetry)** commits to the right defaults: off by default,
opt-in, consent-separated, explicit "telemetry on by default" non-goal; the
metric-eligibility table is **default-deny** (`TelemetryEligible bool // default
false`); `telemetryEnabled()` requires a credential; endpoint validation forbids
userinfo, redirects disabled with `Authorization` never re-sent; "no AI
consumption by default". Its codebase claims were spot-checked and are accurate.
**PR #910 (MCP baseline)** is likewise secure-by-default (origin allowlist
fail-closed on empty, audience + RFC 8707 resource binding, no query-string
tokens, no token passthrough), and its `[FACT]` claims about the existing tree
are accurate and self-deprecating in the right direction — the claim that the
RFC 7662 path has no replay protection was verified true (`auth_oidc.go:114-151`
is a pure TTL cache) and is used to *require* net-new protection rather than
overclaim coverage. Only note 13 above needs an implementation checkpoint.

---

## Prior-finding status (2026-07-19 report, PR #878)

Every file underlying the six prior findings is **untouched in this window**
(`git diff 6349722..2eef667` over `readyz_dp_health.go`, `support_export.go`,
`decryption_metrics.go`, `internal/pac/compile_profiles.go` is empty), so all
six remain open. PR #878 itself is still open and unmerged.

| # | Finding | Status | Evidence |
|---|---|---|---|
| F1 | `/ready` `node_cert` row embeds the raw renewal error | **OPEN** | `readyz_dp_health.go:122-133` still formats `(last error: %s)` with `lastErr` on both the expired and expiring branches. |
| F2 | partial bundle delete can flip PENDING → READY | **OPEN** | State-derivation shape unchanged (`ui_support.go:595-602,641,670`); M6 added routes but did not touch the gate. |
| F3 | sealed-export audit omits the recipient | **OPEN** | `support_export.go:214` still `auditEvent(r, "support.bundle.download_sealed", id, support.BundleFormat)` — no recipient name/fingerprint. |
| F4 | unconditional `DECRYPT_FAILED` feed rows | **OPEN** | `decryption_metrics.go:220` unchanged. |
| F5 | autoexclude engine doesn't clamp `confirmN ≥ 2` internally | **OPEN (unreachable)** | Engine still floors at `<= 0` only (`internal/autoexclude/autoexclude.go:194-196`); both outer validators still enforce `≥ 2`. |
| F6 | expired-node re-enrollment inherits prior labels | **OPEN (accepted)** | Enrollment path unchanged in this window. |

The 2026-07-16 report's F1-rollback half (`applyConfigBackup` installs
`b.PolicyRules[i]` verbatim without `stampObjectRefIDs`) also remains open —
`configversion.go` is untouched this window.

---

## Risk rating summary

| ID | Finding | Severity | Exploitability | Impact | Regression risk |
|---|---|---|---|---|---|
| M1 | Gateway `chunk_size` → unbounded alloc → crash-loop | MEDIUM | Low-medium (armed feature + gateway position) | High (data-plane availability) | New code |
| M2 | Unenrolled-pull throttle map unbounded, pre-auth | MEDIUM | Moderate (unauthenticated, IPv6-cheap) | Medium (CP availability → fleet config) | New guard |
| L1 | Unpinned actions in new required-check workflows | LOW | Low (needs upstream tag compromise) | Medium (CI gate integrity) | Policy regression |
| L2 | No version floor on the bootstrap verifier | LOW | Low today, structural | Medium (install trust root) | Pre-existing class, new path |
| L3 | Delta cap checked post-mutation | LOW | Low (needs CP compromise) | Low (bounded by frame) | New code |
| L4 | Upload drain/re-arm write-back race | LOW | Very low as attack | Low (fails closed) | New code |

**Recommended fix order: M1 → M2 → L1 → L2 → L3 → L4.** M1 and M2 are each a
handful of lines and both are pure narrowing — neither can weaken an existing
control.

---

## Residual risk

1. **The M6 gateway is a trusted-response surface.** Every M1/L4/note-5/note-6
   finding is the same root shape: the appliance treats the TAC gateway's JSON
   as well-formed. Confidentiality is structurally protected (sealing means a
   hostile gateway learns nothing), and integrity is protected by the
   receipt-hash check — but *availability* and *local state consistency* still
   trust the gateway. A systematic "validate every gateway-supplied scalar at
   the trust edge" pass would close the class rather than the instances.
2. **Pre-auth reachability of the cluster gRPC surface** (`VerifyClientCertIfGiven`)
   is a deliberate bootstrap contract, and M2 is its second-order cost. Any
   future per-peer state added to that surface inherits the same unbounded-key
   hazard; the fix should be a shared bounded-keyspace helper, not a local patch.
3. **Verifier-vs-catalog trust asymmetry** (L2): the catalog has a monotonic
   floor, the binary that verifies it does not. Until that is closed, the
   install chain's weakest link is version selection, not signature checking.
4. **Prospective-leak walls are narrower than the artifacts they guard**
   (note 2): the OpenAPI bundle is publicly distributed, and the secrets wall
   scans 4 of the ~6 files that feed it.
5. **Six prior findings plus the 2026-07-16 rollback-half finding remain open.**
   None is attacker-triggerable without a filesystem fault, an already-compromised
   CP, or an admin-issued credential, but the backlog is now two review cycles
   deep and PR #878 is still unmerged.

---

## Files reviewed (code-bearing, this window)

`internal/supportupload/upload.go`, `support_upload.go`,
`support_upload_wire.go`, `support_upload_queue.go`, `support_upload_worker.go`,
`support_tac_trust.go`, `ui_support.go`, `persistent_admin_state_startup.go`,
`controlplane.go`, `controlplane_client.go`, `controlplane_delta.go`,
`controlplane_server.go`, `controlplane_snapshot.go`, `controlplane_tls.go`,
`cluster_convergence.go`, `cluster_metrics.go`, `dp_enrollment.go`,
`ha.go`, `ha_fencing.go`, `bootstrap_resolve.go`,
`release_bootstrap_provenance.go`, `release_api.go`, `main.go`,
`scripts/install.sh`, `internal/apicontract/*`, `cmd/apibundle/main.go`,
`api/openapi/*`, `api/route-classification.yaml`, `logger.go`,
`proxy_tunnel.go`, `connlimit.go`, `ui_config.go`, `ui_security.go`,
`ui_routes_meta.go`, `internal/pac/inventory.go`, `static/index.html`,
`.github/workflows/*`, `go.mod`/`go.sum`, plus the corresponding `*_test.go`
walls.
