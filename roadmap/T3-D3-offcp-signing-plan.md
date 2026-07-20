# T3 D3 — Off-CP config signing (the H5 control that unblocks a larger trusted fleet)

**Status:** DESIGN (decision-complete, pre-red-team). This is the concrete "real
10M prerequisite" the T3 scale plan names: before a fleet can safely trust a
larger CP-authoritative config surface pushed over CP→DP sync, the integrity of
that surface must be anchored OFF the CP, so a compromised-but-authenticated CP
(H5) cannot forge it. P1 shipped delta sync deliberately WITHOUT this (recorded
sign-off: the full-snapshot path has identical exposure, so P1 was not a
regression — see T3-config-sync-scale-plan.md §"D3 DEFERRED"). This slice pays
that debt for BOTH the full (`GetConfig`) and delta (`GetConfigDelta`) paths.

**One-line thesis:** sign the ABSOLUTE state (a per-version manifest of canonical
per-surface hashes) with an admin/operator key held OFF the CP-serving process;
the DP verifies its own resulting state against that manifest after applying
EITHER path, against a baked/offline trust root — reusing the release-catalog
TrustStore/VerifyMode machinery, but with a DISTINCT config-signing trust root.

---

## 0. Threat model (why this exists, stated precisely)

**H5 — compromised-but-authenticated CP.** Two concrete forms:
1. A **fenced-out zombie** leader (valid mTLS client cert, stale lease epoch) that
   keeps answering `GetConfig`/`GetConfigDelta`.
2. The **current** leader, compromised (RCE on the CP-serving process, or a
   malicious operator with CP shell), holding a live valid lease epoch.

What the EXISTING controls do and do not cover:
- **mTLS** authenticates the transport peer — defeated by (1) cert theft and (2)
  by construction (the compromised box holds its own valid cert).
- **ADR-0005 epoch fence** rejects form (1): a zombie's stale epoch loses the
  `dpLastSeenEpoch` ratchet. It does **nothing** against form (2) — a live leader
  has a valid epoch.
- **The XOR `syncedFP`** is explicitly NOT an authenticity control (linear over
  token hashes, trivially forgeable by a content-controlling party — see
  `internal/blocklist/delta.go:126`). It detects transport corruption /
  missed-or-duplicated deltas, nothing adversarial.

**So the residual, uncovered threat is form (2): a live-epoch compromised leader
pushing a maliciously-crafted config the whole fleet applies.** D3 is the control
for exactly this: content whose integrity is anchored to a key the compromised CP
does not hold, so the fleet refuses config the off-CP authority never signed.

**Non-goals (explicitly out of scope for D3, documented so the red-team doesn't
mistake them for gaps):**
- Availability. A compromised CP can always REFUSE to serve / serve stale
  (documented bounded-LWW posture). D3 defends INTEGRITY, not liveness.
- Confidentiality of the config (already handled by redaction + mTLS).
- Rollback/replay of a *validly signed older* version — defended by the existing
  monotonic version + epoch ratchet, NOT by the signature (see §6).

---

## 1. The central tension (lead with the hard part)

**The CP-authoritative host/policy set is edited at admin RUNTIME through the CP
web UI.** If the signing key lives on the CP-serving process, a compromised CP
signs anything and D3 is worthless. Therefore **the key MUST NOT be reachable from
the CP-serving surface.** But runtime UI editing implies the CP produces the new
content. These two facts are in fundamental tension; there is no free lunch, and
any design that hides this tension is wrong.

**Resolution — the signing authority is off-CP; the CP stages and distributes but
never signs.** A signed config surface is changed by a
`stage → review diff → sign off-CP → publish` flow:

- The CP UI stages a proposed change to a signed surface and shows the exact
  canonical diff + the new manifest bytes to be signed.
- An **admin signing device** — an offline/air-gapped ed25519 key, a hardware
  token, or a CI/GitOps identity (Sigstore) — signs the manifest. The key never
  touches the CP-serving process.
- The signed manifest is uploaded back to the CP, which now merely DISTRIBUTES it
  (and the corresponding content) to the fleet. The CP cannot mint a new one.

Three supported custody modes (operator picks per deployment; all verify
identically on the DP):

| Mode | Key custody | H5 posture | Ergonomics |
|---|---|---|---|
| **GitOps / offline (recommended)** | admin ed25519 key on an air-gapped signer or hardware token; or a Sigstore CI identity signing a committed policy artifact | **Full H5** — CP compromise yields no signing capability | Change = commit/sign out-of-band, then publish. No live UI edit of signed surfaces. |
| **Detached-admin (UI-preserving)** | admin's client-side key (offline CLI / hardware token / WebAuthn-style), used to sign the staged diff shown by the UI | **Full H5** — key is on the admin's device, never on the CP | Live UI workflow preserved: admin reviews the staged diff and signs from their own device. |
| **Co-located authority (transitional, documented-weak)** | a separate-process/separate-privilege signer on the CP host | **Partial** — survives CP-serving-process RCE, NOT full-box root compromise | Zero operator change; a migration crutch only. Loudly documented as NOT a full H5 control. |

The DP does not care which mode produced the manifest — it verifies a signature
against a trusted public root. Mode is purely an operator custody choice. **The
default posture ships with NO baked config-signing root** (so verification is
INACTIVE until an operator provisions a root — see §5.4), because unlike the
release catalog there is no universal built-in signer for a customer's own
admin/policy content.

---

## 2. What is signed — the SignedConfigManifest (absolute-state, extensible)

A single detached manifest per config version binds that version to the canonical
hash of each SIGNED surface. Signing the ABSOLUTE state (not the transition) is
the key move that makes the delta path free-ride: the DP verifies the STATE it
ends up in, regardless of how it got there.

```
SignedConfigManifest (canonical JSON, the signed bytes):
{
  "schema_version": 1,
  "wire_contract_version": 1,          // D2 canonical-encoding contract version
  "config_version": <int64>,           // the ConfigSnapshot.Version this pins
  "created_at": "<RFC3339 UTC>",       // provenance only; NOT a freshness gate (see §6)
  "surfaces": {
    "cp_authoritative_hosts": "<sha256-hex>",   // D3 slice-1 (T3-named surface)
    // future, additive: "policy_rules": "...", "pac": "...", "node_groups": "..."
  }
}
```

The **detached signature envelope** reuses the release-catalog shape verbatim
(`catalogSigEnvelope` — `{schema_version, alg:"ed25519", key_id, sig(base64)}`),
so `parseSigEnvelope` + `ed25519.Verify` + the `TrustStore` key ring are reused
directly. A Sigstore-identity variant reuses `sigstoreVerifier` the same way
(scheme composition per §5.3).

**Why a manifest of hashes, not a signature over the whole snapshot:**
- The snapshot is huge (~60 MiB) and re-marshaled per-fleet — signing raw bytes
  couples the signature to a marshaling that already varies (remainder cache,
  omitempty). A manifest of canonical hashes is tiny, marshaling-independent, and
  is what both paths can reconstruct.
- It is **extensible without a wire break**: folding `policy_rules` in later is an
  additive `surfaces` key + a new DP recompute; an old DP ignores unknown surface
  keys (forward-compat), a new DP treats an ABSENT expected surface per mode
  (enforce → reject if the surface is one it enforces; see §3 completeness rule).

### 2.1 Canonical hash (D1/D2) — the real prerequisite this slice must build

The signed `cp_authoritative_hosts` hash is a **SHA-256 over the canonically
encoded CP-authoritative host set**, NOT the XOR `syncedFP`. The XOR FP is linear
and forgeable; it stays as the cheap transport/misapply detector. The canonical
hash is the authenticity anchor. D2 canonical encoding, pinned exactly (any change
= `wire_contract_version` bump):

1. Take the CP-authoritative set only (`FeedList()` — non-manual, CP-synced;
   feed-derived hosts EXCLUDED, matching the D1 drift-hash scope).
2. Per host: trim, drop comments/blanks, case-fold (lower), IDN→punycode,
   strip trailing dot, normalize wildcard `*.x`↔`.x` to ONE canonical form
   (reuse `normDeltaHost` — already the shared CP/DP normalizer, so the hash is
   computed identically on both sides).
3. Dedup, then **sort byte-lexicographically**.
4. `SHA-256( "\n"-join(sorted tokens) + "\n" )`. Empty set = hash of `""`-domain
   sentinel (pin a fixed constant so empty is unambiguous and distinct from
   "unsigned").

This lives in `internal/blocklist` next to `feedSetFingerprint` as
`CanonicalCPAuthoritativeHash(hosts []string) string` (pure function, CP-side to
advertise, DP-side to recompute) + a Store method over its own applied set. It is
a NEW function; the XOR FP is untouched (no hot-path change, no benchgate risk —
this hash is computed only at sync/publish time, off the `IsBlocked` path).

---

## 3. Verification flow (DP side) — covers BOTH full and delta

After the DP applies a config version V by EITHER path (full `GetConfig` apply, or
`GetConfigDelta` chain apply), and BEFORE it advances `KnownVersion`/persists
last-good:

1. Obtain the manifest for V (rides the same reply — see §4). If absent:
   - `disabled` mode → proceed (break-glass).
   - `permissive` mode → proceed with a loud `config_signature_missing` warn +
     counter (migration/mixed-fleet).
   - `enforce` mode → **REJECT**, do not advance version, do not persist, stay on
     last-good, count `config_signature_missing`, alert. (Fail-closed.)
2. `parseSigEnvelope` + verify the signature over the manifest bytes against the
   config-signing `TrustStore` (§5). Invalid signature / unknown key_id / wrong
   alg → **REJECT** regardless of mode except `disabled` (present-but-invalid is
   NEVER a fall-through — mirrors the catalog "artifact-owns-outcome" rule).
3. Bind the manifest to the applied state: `manifest.config_version == V` AND
   `manifest.surfaces.cp_authoritative_hosts == DP.CanonicalCPAuthoritativeHash(applied set)`.
   Any mismatch → **REJECT** (the CP served a signature for a DIFFERENT content
   than it served as data — the core tamper detection).
4. **Completeness rule (anti-downgrade for future multi-surface manifests):** the
   DP rejects a manifest that OMITS a surface the DP is configured to enforce.
   Slice-1 enforces exactly `cp_authoritative_hosts`; when `policy_rules` is
   folded in, a manifest lacking it is a downgrade → reject. (Prevents a
   compromised CP from stripping a surface to make it "unsigned/optional".)
5. Only on all-pass: advance version, persist last-good + the manifest (so a
   restart re-verifies against durable state).

**Delta path specifics.** The delta reply already carries `TargetVersion` +
`TargetFP` (XOR). It gains the manifest for `TargetVersion`. The DP applies the
chain, checks the XOR `TargetFP` (cheap misapply/corruption gate — unchanged),
THEN runs steps 1–5 with the recomputed CANONICAL hash. The XOR check staying
first means a corrupted-but-non-adversarial delta is caught cheaply before the
SHA work; the canonical+signature check is the adversarial backstop. A resync
falls back to full `GetConfig`, which carries the same manifest — no separate
signing path.

---

## 4. Wire changes (additive, omitempty, mixed-fleet-safe)

Reuse the snapshot discipline: every field additive + `omitempty`; an old peer
omitting them degrades to the zero value, never errors.

- `ConfigSnapshot` gains `SignedManifest json.RawMessage` +
  `SignedManifestSig json.RawMessage` (the detached envelope). Both `omitempty`.
  On `GetConfig` these ride the snapshot for `Version`.
- `getConfigDeltaReply` gains the SAME two fields, carrying the manifest for
  `TargetVersion`. The CP stores `(version → manifest, sig)` alongside the delta
  ring and the last-good, and serves whichever the reply targets.
- **Redaction parity:** the manifest + sig are PUBLIC integrity material (no
  secrets) → they are NOT redacted for un-enrolled callers, and this must be
  pinned by the existing redaction-parity wall (`config_surfaces_test.go` /
  `redactUnenrolledSnapshot`) so a future refactor can't accidentally strip them.
- **CP storage:** the signed manifest for the current version is durable on the CP
  (`<dataDir>/config_signing/manifest-v<N>.json` + `.sig`), replicated to the HA
  standby alongside the delta ring, so a failover serves the same signed manifest
  (no re-sign-on-promotion — the standby has no key either, by design).
- `MetricsReport` (reverse telemetry) gains `SignedManifestVerified bool` +
  `ManifestKeyID string` (omitempty) so the fleet-convergence surface shows which
  DPs are enforcing signed config and under which key — a straggler on an
  unverified/old manifest is visible.

---

## 5. Trust roots & verification machinery (reuse, don't reinvent)

### 5.1 A DISTINCT config-signing trust root
The release-catalog roots (`bakedReleaseTrustKeysJSON`, the Sigstore `ci.yml`
identity) authenticate *Culvert releases* signed by *this repo's CI*. Config
signing authenticates *a customer's admin/policy content* signed by *their*
offline authority. **These are different trust domains and MUST NOT share keys.**
D3 introduces its own:
- Baked: `bakedConfigSignTrustKeysJSON` (EMPTY in the OSS tree — no universal
  built-in config signer; a customer provisions their own).
- Env-extended (public keys only): `CULVERT_CONFIG_SIGN_TRUST_KEYS` (JSON array of
  `{key_id, alg:"ed25519", public_key:"<base64>"}`), EXTENDS the baked set —
  identical shape + semantics to `CULVERT_RELEASE_CATALOG_TRUST_KEYS`.
- Optional Sigstore identity for the GitOps mode:
  `CULVERT_CONFIG_SIGN_SIGSTORE_IDENTITY` + `_TRUSTED_ROOT`, mirroring the release
  vars, so a customer signing policy via their own CI keyless flow can pin their
  own `{issuer, san_regex}`.

### 5.2 Reused primitives (no new crypto)
`TrustStore` + `NewTrustStore` (ed25519 ring, length-checked fail-closed),
`parseSigEnvelope`, `verifyEd25519Scheme`, `sigstoreVerifier`, the `schemeOutcome`
tri-state + `verifyIndexSignature` composition, and `VerifyMode`
(enforce/permissive/disabled) are reused as-is by pointing them at the manifest
bytes instead of the catalog index bytes. The only new code is the config-signing
key/env wiring + the manifest struct + the DP recompute/bind + the wire plumbing.

### 5.3 Scheme composition (identical to catalog)
Sigstore-identity first, ed25519 second, then the mode-based no-artifact decision.
A present-but-invalid artifact for a scheme REJECTS (never falls through) —
artifact-owns-outcome, closing the strip-one-sig downgrade. Non-emptiness in
enforce mode is satisfied by EITHER a configured ed25519 ring or a Sigstore
identity.

### 5.4 Verify mode resolution (`CULVERT_CONFIG_SIGN_VERIFY`)
- Default = **enforce whenever a config-signing root is present** (baked ∪ env ∪
  Sigstore identity+root); with NO root present, config-signature verification is
  **INACTIVE** (not "disabled break-glass" — simply unconfigured, since the OSS
  default bakes no root). An operator opts into H5 protection by provisioning a
  root; until then behavior is byte-identical to today (mTLS + epoch fence only).
- `permissive` (accept missing, reject invalid) and `disabled` (skip) are explicit
  logged break-glass, read once at startup — same contract as
  `CULVERT_RELEASE_CATALOG_VERIFY`.
- **This is a DP-side control.** The DP's verify mode + roots gate what IT accepts.
  A per-DP env means a heterogeneous fleet can roll enforce gradually.

---

## 6. Fence orthogonality, replay, rotation, revocation

- **Signature ⟂ epoch fence.** The signature proves CONTENT authenticity (off-CP
  key). The epoch fence proves LEADER authority/liveness (ADR-0005). Both are
  enforced independently; neither substitutes for the other. A live-epoch
  compromised leader passes the fence but CANNOT forge the manifest → rejected at
  §3 step 2/3. A zombie with a stale epoch is rejected at the fence before signing
  even matters.
- **Replay of a validly-signed OLDER version** is NOT defended by the signature
  (an old manifest is genuinely signed). It is defended by the EXISTING monotonic
  `config_version` + durable `dpLastSeenEpoch` ratchet: the DP already refuses a
  version ≤ its current known version / a lower epoch. `created_at` is provenance
  only — deliberately NOT a freshness gate, because clock-skew freshness gates on
  admin-rate config cause false rejects (learned from the release-catalog 5-min
  skew handling). The monotonic version is the anti-rollback control.
- **Key rotation:** additive — publish the new public key into the trust ring
  (baked bump or `CULVERT_CONFIG_SIGN_TRUST_KEYS`) to the fleet FIRST, then start
  signing with the new key. `key_id` in the envelope selects. Overlap window =
  both keys trusted. No wire break.
- **Revocation:** remove the compromised `key_id` from the ring + roll to the
  fleet. Because verification is a positive allowlist (ring lookup), a removed key
  fails closed immediately on nodes that received the updated ring. (No CRL/OCSP —
  the ring IS the allowlist, same as the catalog.)

---

## 7. Scope honesty — slice-1 is a PARTIAL H5 control (say it loudly)

Slice-1 signs `cp_authoritative_hosts` only (the T3-named surface). **A compromised
CP can still forge every UNSIGNED surface** — most importantly `policy_rules` (it
could push an allow-rule for its own C2 domain, bypassing the blocklist entirely).
Therefore:
- D3 slice-1 does NOT by itself close H5 for config integrity. It closes it for the
  ONE surface T3 growth depends on (the host set that scales to 10M), and builds
  the manifest mechanism that folds in the rest.
- The manifest is designed multi-surface from day one (§2) precisely so
  `policy_rules` (and PAC, node-groups, bandwidth) can be added as pure additive
  surfaces + a DP recompute, each with a completeness-rule downgrade guard (§3.4).
- **Recorded residual:** until `policy_rules` is signed, an operator relying on D3
  for H5 must understand the blocklist is authenticated but policy is not. This is
  documented in the operator runbook and surfaced on the governance/convergence
  panel (which surfaces list which surfaces are signed).

A red-team may argue slice-1 is security-theater without policy coverage. The
counter: (a) it is the prerequisite for the STATED 10M goal (the host set), (b) it
is strictly better than today (one more forgeable surface removed), (c) it ships
the mechanism, and (d) the residual is documented, not hidden. If the red-team
finds this insufficient, the fallback is to widen slice-1 to cover
`policy_rules` in the same manifest before shipping (mechanism already supports it
— it's just one more DP recompute + one more `surfaces` key).

---

## 8. GUI parity (mandatory — no CLI-only feature)

- `GET /api/cluster/config-signing` (viewer): verify mode, trust-root key_ids +
  algs (public), current signed manifest {version, per-surface hashes, key_id,
  verified}, and the STAGED-but-unsigned diff (if any).
- `POST /api/cluster/config-signing/stage` (admin): stage a signed-surface change,
  returns the exact manifest bytes to sign off-CP.
- `POST /api/cluster/config-signing/publish` (admin): upload the signed manifest +
  envelope; CP validates the signature against its OWN trust ring before
  distributing (defense-in-depth; the DP re-verifies independently), then serves
  it to the fleet.
- Convergence panel gains a per-DP "signed config" column (from the
  `MetricsReport` additions) + a straggler alert for DPs on an unverified/old
  manifest.
- All handlers: `requireRole` + `uiRoutes` metadata + `saveConfigVersion` on
  mutations, per the admin-API pattern. Route-count deltas updated in the D0/C1
  parity tests.

---

## 9. Non-negotiable invariants (red-team targets)

1. The config-signing key is NEVER reachable from the CP-serving process (custody
   modes §1). A design that puts it there is a fail.
2. The DP verifies the ABSOLUTE state it applied (recomputed canonical hash),
   binding manifest.version == applied version — for BOTH full and delta paths.
3. A present-but-invalid signature REJECTS in every mode except `disabled`
   (artifact-owns-outcome; no scheme fall-through on invalid).
4. `enforce` = default when a root is present; INACTIVE (byte-identical to today)
   when no root is present. Never silently "on" with no root, never silently "off"
   with a root.
5. Signature ⟂ epoch fence: both enforced; neither substitutes.
6. Anti-rollback is the monotonic version + durable epoch ratchet, NOT the
   signature; `created_at` is not a freshness gate.
7. The manifest/sig are public and MUST survive un-enrolled-caller redaction
   (pinned by the redaction-parity wall).
8. Multi-surface completeness: a manifest omitting an ENFORCED surface is a
   downgrade → reject.
9. No `IsBlocked` hot-path change; the canonical hash is computed only at
   sync/publish time.
10. Additive omitempty wire; a mixed fleet (old CP no manifest / old DP ignores
    it) degrades, never errors. Roll trust roots to the fleet BEFORE enforcing.

## 10. Open questions for the red-team (break these)

- **Custody realism:** is the "detached-admin" UI-preserving mode actually
  buildable without smuggling the key onto the CP? Is the staged-diff→off-CP-sign
  flow coherent, or does the review step have a TOCTOU (CP shows diff A, admin
  signs, CP publishes content B)? (Intended defense: the admin signs the MANIFEST
  = the hashes, and the DP binds hash to applied content — so a CP swap post-sign
  fails the DP bind. Verify this holds.)
- **Partial-surface coverage (§7):** is a host-set-only signature a meaningful H5
  control, or theater until policy is covered? Should slice-1 be widened to
  `policy_rules` before shipping?
- **Absolute-state binding on delta:** any state the DP can reach where its
  recomputed canonical hash matches the manifest but the ENFORCED set differs
  (e.g. manual/feed hosts leaking into the canonical set, or a wildcard
  normalization divergence between CP-advertise and DP-recompute)? The hash scope
  (`FeedList()`, CP-authoritative only, `normDeltaHost`) is the load-bearing
  assumption — break it.
- **Empty-set / first-sync / bootstrap:** a brand-new DP with no last-good, or an
  empty CP-authoritative set — does the "hash of empty" sentinel + enforce-mode
  reject-on-missing produce a bricked DP that can never bootstrap? What's the
  safe first-sync-under-enforce story?
- **HA failover:** the standby serves the same signed manifest (no key). Is there
  a window on promotion where the standby's stored manifest lags the version it
  serves → a self-inflicted enforce-mode reject storm?
- **Mixed fleet / rollout ordering:** does enabling enforce on a DP before the CP
  is publishing manifests brick that DP? Is the documented "roots first, then
  enforce, then sign" ordering actually safe at every intermediate step?
- **Key rotation/revocation races:** a manifest signed with new key N arriving at a
  DP that hasn't yet received N in its ring → transient enforce-mode reject. Is the
  overlap-window guidance sufficient, or does rotation need a grace mode?
- **Is D3 even the right 10M prerequisite,** or is the honest blocker the
  `maxSnapBlockedHosts` cap + feed distribution (P3), making D3 a valuable but
  NON-blocking hardening that shouldn't be sequenced as "the 10M prerequisite"?
