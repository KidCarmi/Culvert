# ADR-0002: Decompose the flat `package main` into `internal/` packages, incrementally

- **Status:** Proposed
- **Date:** 2026-06-28
- **Deciders:** Chief Engineering Advisor (proposed); project maintainer (to decide)
- **Related:** DEBT-001, DEBT-002, DEBT-003 (Technical Debt Register)

## Context

The entire root program is one flat `package main`: 152 source files, ~1,950 top-level functions,
187 exported types, and **~359 package-level mutable variables** in a single shared namespace.
Unrelated subsystems — TLS interception, the gRPC control plane, SAML/OIDC, YARA scanning, release
signing, the admin UI — all share that namespace and can read or mutate any global.

Evidence this is a real, paid cost (not a theoretical purity concern):

- Core runtime state is global singletons reachable by both the proxy hot path and the admin write
  path: `policy.go:391 policyStore`, `store.go:646 bl`, `store.go:1602 cfg`, `store.go:56 ts`.
  Safety is by *convention* (each struct's own `RWMutex`), not by language.
- The codebase already carries **dedicated data-race regression tests**:
  `upstream_transport_race_test.go`, `controlplane_cptlsconfig_race_test.go`,
  `controlplane_dp_conn_race_test.go`, `threatfeed_savetodisk_race_test.go`. `CLAUDE.md` devotes a
  hard rule to `upstreamTransport` ("direct field assignment is forbidden — it races against the
  proxy hot path") — institutional memory of a real race.
- The team's **newest** component, `cmd/culvert-maint/`, is already decomposed into
  `internal/{server,ops,runner,auth,config,audit,health}`. The flat root is recognized debt the
  newest code stopped accruing.

The flat layout is the root cause of several debt items (DEBT-001/002/003/005/006) and is the single
biggest drag on the Maintainability and Architecture scores in the Engineering Dashboard.

## Decision (proposed)

Migrate the root program from one flat `package main` to a thin `main` plus a set of `internal/`
packages, **incrementally and leaf-first**, reusing the structure `cmd/culvert-maint` already proves.

Sequencing principles:

1. **Leaf clusters first** — extract subsystems with no inbound dependencies and a clean surface:
   `internal/scan` (yara/clam/scanner), `internal/geoip`, `internal/fileblock`, `internal/totp`.
   These convert convention-boundaries into compiler-enforced boundaries at near-zero risk.
2. **One cluster per PR**, each behind green CI (including `-race`). No cluster moves until its tests
   move with it and pass.
3. **Globals become package-owned**, exposed through narrow constructors/accessors, killing the
   "any file can mutate any global" surface one cluster at a time.
4. **`handleRequest` decomposition (DEBT-002) is a prerequisite spike**, not part of this migration —
   it is done first, in `package main`, to de-risk touching the hot path.
5. **No big-bang rewrite.** The test suite (1.35× source LOC) is the project's greatest asset; a
   rewrite would discard it. This migration *moves* tests with their code.

## Consequences

- **Positive:** compiler-enforced encapsulation; smaller blast radius per change; a shrinking
  data-race surface; lower onboarding cost; the `cmd/culvert-maint` pattern becomes the whole repo's
  convention instead of an exception.
- **Cost:** sustained effort across quarters; import-cycle untangling will surface hidden coupling
  (which is the point — it makes coupling visible and forces it to be addressed).
- **Risk:** moving the proxy hot path is the highest-risk step; it is deliberately *last* and gated by
  the `handleRequest` spike and full `-race` CI.
- **If rejected:** the flat package stays, the registers keep DEBT-001 open as an accepted cost, and
  the Architecture/Maintainability scores stay capped at ~2.5. That is a legitimate choice if the
  maintainer judges the migration cost higher than the carried interest — but it should be a
  *decision*, recorded here, not a default.

## Alternatives considered

- **Status quo (accept the debt).** Viable; must be an explicit, recorded acceptance, not drift.
- **Big-bang re-architecture.** Rejected: discards the test suite and stops feature work for a long
  window with high regression risk.
- **`pkg/` public packages instead of `internal/`.** Rejected: Culvert ships as a single binary with
  no library consumers; `internal/` correctly prevents an accidental public API surface.

## Decision needed from the maintainer

Accept the incremental direction (and let the Advisor open the first leaf-extraction PR after the
`handleRequest` spike), or explicitly **accept DEBT-001 as carried debt** so the registers and scores
reflect a deliberate choice rather than an open question.
