# PR2 — Decryption-Profile Security-Generation Fencing

**Status:** IMPLEMENTATION. Part of the final production-hardening wave for adaptive
decryption. Base: `origin/main` after PR1 (#855, certVerification=permissive retirement).

## Problem

Adaptive decryption-exclusion entries are keyed by `(profileID, host)` (the scope is
the matched decryption profile's stable ID). A profile **edit preserves the same
stable ID**. So a previously-learned exclusion remains valid — and continues to
bypass SSL inspection — after a *security-significant* same-ID profile edit, until
its TTL (default 12h) expires.

Example: an operator learns a bypass for `host` under a fail-open profile whose
`MinTLSVersion` is `1.3`. They then tighten the profile (`CertVerification: skip →
strict`, or narrow the TLS floor, or flip `InspectHTTP2`). The host is still bypassed
under the *old* posture for up to 12h, even though the security meaning of "this host
couldn't be inspected" changed. The learned exclusion no longer reflects the profile
it is attributed to.

`OnInspectError: fail-open → fail-close` is a special case already covered by the
gated read (a fail-close rule never consults the cache), but a profile that stays
fail-open while changing *other* security fields is the open gap.

## Security invariant

An adaptive exclusion is only valid for the **exact inspection posture** under which
it was learned. A security-relevant edit to the owning profile must invalidate its
learned entries immediately (miss → re-inspect), while a cosmetic edit (rename,
display metadata) must NOT. The `(profileID, host)` policy-isolation boundary must be
**narrowed** (per-posture), never broadened.

## Current behavior

`Contains(scopeID, host)` returns a hit whenever a non-expired entry exists for
`(scopeID, host)`, regardless of whether the profile's security posture has changed
since the entry was learned. `Observe` promotes without recording the posture.

## Target behavior

Introduce a deterministic **security generation** (`securityGen`) — a fingerprint over
ONLY the profile fields that change the *meaning or safety* of a learned exclusion:

| Field | Why it is security-effective |
|---|---|
| `OnInspectError` | The fail-open/fail-close gate — the bypass-authorization field. |
| `CertVerification` | Origin-cert posture (strict/skip/inherit) on the inspect leg. |
| `OnUnsupported` | Fail-close/fail-open posture for unsupported-TLS. |
| `MinTLSVersion` / `MaxTLSVersion` | Determine the `unsupported_params` learn signal — a host un-inspectable under a 1.3 floor may be inspectable under 1.2. |
| `InspectHTTP2` | Native-H2 vs strip-to-H1 changes the client-leaf ALPN and the upstream handshake — an inspection-compatibility determinant. |

**Excluded (cosmetic / not security-effective):** `ID`, `Name`, `CreatedAt`,
`UpdatedAt`, `StallTimeoutSecs` (a per-stream inactivity timeout — it does not change
whether a host can be decrypted or whether bypass is authorized).

- The fingerprint is **precomputed in the profile store** at every write (Add / Update
  / UpdateByID / ReplaceAll·Load), so the CONNECT hot path never hashes. Rename does
  not recompute (security fields unchanged), so a rename never invalidates entries.
- The scope accessors (`FailOpenScope`, `FailOpenScopeByID`) return the precomputed
  gen alongside the scope ID — one extra stored-string read, zero allocation.
- Cache entries **store** the gen they were learned under; `Contains(scopeID, gen,
  host)` and `Observe(scopeID, gen, …)` compare it. A mismatch is a **miss** — the
  session returns to normal inspection and re-learns under the new posture. The
  `scopeID` stays PURE (profile ID) so per-scope metrics/audit/UI are unaffected; the
  gen is a separate dimension on the entry, not folded into the scope label.
- The gen is a pure function of the synced profile fields and is **never
  persisted/synced** — it is recomputed identically on every node (CP→DP) and across
  restarts, so it can never drift.

### Behavior matrix

| Event | Effect on learned entries |
|---|---|
| Rename / display-only edit | Preserved (gen unchanged). |
| Security-relevant edit (cert/TLS/H2/OnUnsupported/OnInspectError) | Invalidated — `Contains` misses immediately; re-inspect. |
| fail-open → fail-close | Not consulted at all (gated read) AND gen changes. |
| Deleted + recreated with a new ID | Isolated as today (different scope). |
| CP→DP snapshot | DP derives the identical gen from the synced fields. |
| Process restart | gen recomputed from persisted fields — identical. |

## Rejected alternatives

- **Fold the gen into the `scopeID` token** (`profID@gen`): simplest (no cache
  signature change) but corrupts `scopeID` — it is used as a Prometheus label
  (`culvert_decrypt_autoexclude_{active,hit_total,total}{scope}`) and the audit/UI
  scope name. Rejected: keep `scopeID` pure, add gen as a separate entry dimension.
- **Hash the gen on the CONNECT path**: allocates per request, fails the
  `TestBenchGate_AutoExcludeResolveAllocs` zero-alloc contract. Rejected: precompute
  in the store.
- **Persist/sync the gen**: redundant (derivable) and a drift hazard — a gen written
  by an old binary could mismatch a new binary's recompute. Rejected: always recompute
  locally from the synced fields.
- **Include `StallTimeoutSecs`**: not security-effective (a timeout, not a
  decrypt-compatibility or bypass-authorization determinant). Excluded.
- **Fingerprint the effective PER-RULE posture (rule-inherited fallback fields)**:
  when a profile leaves a field to inherit (`CertVerification==""` →
  `rule.TLSSkipVerify`; `InspectHTTP2==nil` → `rule.StripALPN`), the effective value
  is rule-level. Folding it into the gen would require either re-scoping the
  exclusion from `(profileID, host)` to per-rule — which the wave explicitly forbids
  (broadening/re-scoping the isolation boundary) — or hashing the rule on the CONNECT
  hot path (rejected on perf). Rejected here: the gen fingerprints the PROFILE's own
  declared posture. The inherited cert-verify axis is immaterial to exclusion validity
  (cert-verify failures are never a learn reason; a bypassed session runs no inspect
  leg), and the inherited inspection-mode axis at most leaves a TTL-self-healing
  bypass. Operators who need a field to fence exclusions set it explicitly on the
  profile. Per-rule effective-posture fencing is a candidate for a **separate ADR**.

## Concurrency

The gen compare happens under the same `RWMutex` that already guards `Contains`
(RLock) and `Observe` (Lock); a concurrent profile edit publishes a new gen through
the store's own lock, and the CONNECT path reads the (immutable-after-publish) gen
string via the scope accessor. No new lock, no new hot-path allocation.

## Tests

Rename preserves usability; display-only edit preserves; fail-open→fail-close no
consult; TLS floor/cap change invalidates; cert-verification change invalidates;
inspection-mode (H2) change invalidates; concurrent edit + Contains race-free;
old-DP-snapshot vs new-CP-snapshot cannot disagree (same fields → same gen);
determinism across restart (recompute); benchgate no hot-path alloc regression.
