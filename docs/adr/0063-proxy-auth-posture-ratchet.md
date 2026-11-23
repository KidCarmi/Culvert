# ADR-0063: The durable proxy-authentication posture is owned by internal/authposture

- Status: Proposed for review with the implementation PR (2026-11-23).
- Numbering: ADR-0061 is the highest merged. ADR-0062 is used by the unmerged
  IM-029 support upload-queue branch, so this record takes 0063.
- Decision owner: product owner decision "Durable Authentication Posture"
  (2026-11-23). Contract: `AUTH-006` in `contracts/registry.yaml`.
- Related: owner Decision 2 (admin-console credentials are not proxy
  identities, `AUTH-005`), ADR-0027 (LDAP as a first-class IdP), ADR-0038
  (instance-owned state), ADR-0054/0060 (leaf packages with injected effects),
  [Package isolation](../../roadmap/PACKAGE-ISOLATION.md).

## Context

Whether proxy traffic must authenticate was decided per request from provider
AVAILABILITY: `resolveRequestAuth` armed its Stage-1 gate when a credential or
SSO provider was usable, when the admin roster held accounts
(`requiredWithoutVerifier`, formerly `rosterWithoutVerifier`), or under the
`Exempt` default; SOCKS5 required USER/PASS on the same credential terms. A
node with no admin-roster account whose last proxy provider was deleted,
disabled or failed to load therefore read as "no backend": the inert guard let
every request continue to Stage 2 as `unauth`, and SOCKS5 offered NO-AUTH. A
provider outage, an operator mistake or a configuration change could silently
remove authentication.

Owner decision: "Once authentication protection is established, it cannot
disappear silently. Only an explicit authorized policy decision may permit
unauthenticated access." Explicit = the `Exempt` default or a scoped `Exempt`
authentication rule.

## Decision

1. **A monotonic, durable ratchet** answers one question: "is proxy
   authentication required even with no usable provider?" It is set by the
   first proxy-provider activation and has no operation that clears it.
   Provider availability stops being the authority for whether authentication
   is required; the ratchet is.

2. **Owner: `internal/authposture`**, a leaf of the authentication domain.
   Exported surface: `Ratchet` (`Open`, `Established`, `Establish`,
   `EstablishFailClosed`, `RecordFresh`, `MigrationPending`, `Status`),
   `Record`, `Encode`, `Decode`, `MergeForRestore`, `Status`, `Problem`,
   `Outcome`, `WriteFunc`, `ReadFunc`, `FormatVersion`. Standard library only;
   the durable writer is injected (production: `atomicWriteFile` →
   `internal/fileutil.AtomicWrite`, temp + fsync + rename + directory fsync),
   so the package needs neither `fileutil` nor the root. No package-level
   state, no `init`, no goroutine, no logging (pinned by `boundary_test.go`
   with negative controls). It is not an authentication engine: it verifies no
   credential and knows no provider.

3. **Instance owned by `Config`** (`cfg.authPosture`, an
   `atomic.Pointer[authposture.Ratchet]`; nil reads as not established and a
   ratchet is created on first use). The proxy's auth state already lives
   there and tests already reset `cfg` per test, so the posture is reset with
   it; the atomic pointer lets the verdict-isolation helper
   (`resetDiagVerdictGlobals`) swap in a fresh ratchet race-free, because the
   production ratchet deliberately has no way down. A separate process-wide
   singleton would have leaked across the root test suite. Package main owns the file
   path (`<dataDir>/proxy_auth_posture.json`), the activation hooks, the
   migration, the restore merge call, the Diagnostics row and the audit/log
   lines (`proxy_auth_posture.go`).

4. **Enforcement reuses the existing fail-closed state.** HTTP:
   `requiredWithoutVerifier := !credCapable && (cfg.ProxyAuthEstablished() ||
   cfg.AuthEnabled())`, so an established node with no provider is the
   owner-Decision-2 "required but nothing can verify" state — a `407` nothing
   can satisfy, via the existing dispatch; no new refusal path. SOCKS5:
   `socks5AuthRequired` gains the same term (USER/PASS only, RFC 1929 failure,
   new bounded reason `auth_established_no_provider`). `Exempt` outcomes are
   decided before any of this and are untouched. The read is one atomic load
   (allocation-free; `TestEstablished_AllocFree`, root benchgate).

5. **Write ordering.** Paths that can refuse an activation (admin API
   `Upsert`, CP→DP `ReplaceAll`) are write-ahead: marker durable → registry
   durable → provider published → success reported; a marker write failure
   refuses the activation (500 / snapshot rejected) with nothing changed.
   Paths that cannot (startup registry load, legacy provider wiring, CHAOS-87
   recovery) are fail-closed: the posture is raised in memory even when the
   write fails, reported `not_durable`, and the next activation retries.

6. **Durability.** The marker is not configuration: it is on no
   export/import or rollback struct (`configBackup`, `AdminSettings`), so
   neither can carry or clear it, and establishing it creates no configuration
   version (audited only, `auth.proxy_posture.established`). It is a Tier-2
   backup artifact; restore merges it with `MergeForRestore` (established or
   corrupt wins, current node first; a fresh record is never carried over; an
   unreadable current marker aborts the restore). A corrupt or unreadable
   marker is established (fail closed) and left untouched.

7. **Migration.** A missing marker is resolved once all evidence is loaded
   (after `LoadAdminSettings`, before the SOCKS5 pre-posture gate opens and the
   HTTP listener starts): any stored IdP profile (enabled or not), a wired
   legacy provider, a legacy `ldap` block or the legacy-LDAP retirement
   sentinel establishes it; otherwise a fresh record is written so the
   migration does not re-run.

8. **CP→DP replication is merge-only.** `ConfigSnapshot.ProxyAuthEstablished`
   (`proxy_auth_established`, `omitempty`; registry row
   `proxy_auth_established`, `kindMeta` + `AppliesOnDP` like `Epoch`, not
   Sensitive so an enrolling DP receives it) is captured from the CP's ratchet
   in `CurrentConfigSnapshot`. On every DP apply path (full, delta remainder,
   last-known-good) `syncSnapshotIdPProfiles` establishes the DP's own marker
   write-ahead when it is true, before the snapshot's profiles; if the DP
   cannot record it the snapshot is rejected. False or absent is a no-op. A CP
   whose posture is established outside an admin write (startup migration,
   IdP recovery) republishes its snapshot so DPs see it without waiting for an
   unrelated change. A DP that enrols after the CP's last provider was
   removed therefore refuses authentication-required traffic.

9. **No reset endpoint.** Explicitly authorized unauthenticated access is
   `Exempt` policy. A host operator can delete the marker file; the next start
   re-derives it from evidence.

## Consequences

- A node upgraded with stored-but-unusable providers refuses
  authentication-required traffic from its first start (documented as a
  breaking change with the remedy).
- `IdPRegistry.Upsert`/`ReplaceAll` can now fail for a marker write, mapped to
  the existing `errIdPPersistFailed` handling.
- `ConfigSnapshot` gains one boolean. An older DP ignores the unknown field
  (it then establishes only from providers it applies); an older CP never
  sends it, which a newer DP reads as "no news".

## Alternatives rejected

- **A field in `admin_settings.json`** (like `LegacyLDAPRetired`): that file is
  rewritten wholesale by every admin settings save, is restored verbatim by a
  full restore, and its save path is best-effort; monotonicity would depend on
  every writer preserving the bit.
- **Deriving "established" from the IdP profile file at request time:**
  deleting the last profile deletes the evidence.
- **A root-only implementation:** the ratchet has no root dependency and a
  small, testable contract; keeping it beside its owner follows the package
  isolation rules.
