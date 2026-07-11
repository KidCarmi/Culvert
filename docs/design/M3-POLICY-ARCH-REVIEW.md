# M3 Policy Suite — Architecture Review (Palo Alto-class benchmark)

Status: M3 kickoff review — no implementation in this document
Date: 2026-07-11
Method: Culvert's actual policy backend (verified against source, cited
throughout) is benchmarked against the policy-management model that made
PAN-OS the enterprise reference. Every gap is classified **UI-only** (M3 can
build it on existing endpoints), **Backend** (needs a recorded design +
endpoints first), or **Rejected** (does not fit Culvert's product model —
adopting it would be cargo-culting). Nothing in this review invents backend
functionality; per `REDESIGN-ROADMAP.md`, M3 UI slices consume only what
exists.

---

## 1. Culvert's policy architecture today (grounded)

- **Two evaluation stages, two rulebases.** Stage-1 authentication rules
  (`/api/authpolicy`, outcomes Exempt / CredentialRequired / SSORequired)
  decide *who must authenticate*; Stage-2 access rules (`/api/policy`,
  actions Allow / Deny / Redirect) decide *what is allowed*. Distinct
  endpoints, distinct default gates (`default-auth-outcome`,
  `/api/default-action`), deliberately not conflated (the tester renders the
  stages separately so Exempt is never misread as Allow —
  `static/index.html` `runPolicyTest`).
- **First-match, priority-ordered, default-deny** (`policy.go`; Zero Trust
  default when no rule matches).
- **Rule model** (`PolicyRule`, `policy.go:91-142`): priority, name, source
  (IP/CIDR, identity, group, authSource), destination (FQDN glob, category,
  category group, countries), schedule, sslAction (Bypass/Inspect), file
  filtering + profile, CDR, logging flags, action, redirectURL, enabled,
  hitCount. **No timestamps, no tags, no comments, no owner.**
- **Mutation model: live-write.** Create/edit (`POST /api/policy[?priority=]`),
  delete, and reorder (`POST /api/policy/reorder` — full permutation of
  access-rule priorities; `/api/policy/move` for before/after-named) apply
  immediately. Safety nets *after the fact*: automatic config-version
  snapshots (`saveConfigVersion`, 50 max, rollback via
  `/api/config/versions`) and the audit ring (`/api/audit`, actor + action +
  diff).
- **Simulation exists and is good**: `POST /api/policy/test`
  (`ui_policy.go:1286`) dry-runs both stages and returns a **full per-rule
  trace with skip reasons** — `walkPolicyTestRules` emits
  `{priority, name, skipReason}` for every rule walked ("source mismatch",
  "schedule inactive", "destination mismatch") plus the resolved category and
  its tier. No counters are touched (dry-run).
- **Hit counters** are live (`HitCount` per rule, top-10 on the dashboard via
  `/api/dashboard/top-rules`), reset on restart, no last-hit timestamp.

## 2. The benchmark: what makes PAN-OS-class policy management the reference

1. **The rulebase is a dense, ordered, column-rich table** — position number,
   name, tags, source, destination, services/profiles, action, hit data —
   readable top-to-bottom exactly as the engine evaluates it.
2. **Candidate config vs running config.** Edits accumulate in a candidate;
   an explicit **commit** (with validation and a required audit comment)
   activates them; revert discards. Nothing enforcement-relevant changes on
   a keystroke.
3. **Shadow-rule detection at commit** — the system warns when a rule can
   never match because an earlier rule eclipses it.
4. **Rule usage analytics** — hit counts with first/last-hit timestamps and
   an explicit "unused rules" view driving rulebase hygiene.
5. **Policy-match test tool** wired into the rulebase (test a synthetic
   flow, land on the matching rule).
6. **Profiles attach to rules** (content inspection bundles) rather than
   living as disconnected global switches.
7. **Every change is attributable** — commit author, comment, diff, and a
   config-version timeline with per-change rollback.

## 3. Gap analysis

| # | Benchmark capability | Culvert today | Gap class | M3 disposition |
|---|---|---|---|---|
| G1 | Ordered, column-dense rulebase table | Table exists (`#pol-table`) but sparse columns, truncated conditions, actions hidden in a ⋮ menu | **UI-only** | S2: rulebase redesign — priority, name, scope, match, profile chips (SSL/file/CDR), action badge, hits, enabled; disabled rules dimmed + badged (never color alone) |
| G2 | Candidate/commit for **content** edits | Live-write + post-hoc snapshots | **Backend** | Design record required (candidate store, validate, activate, revert). M3 must NOT fake it client-side — a browser crash losing "staged" rules the operator believed saved is worse than live-write. Recorded as the M4+ `policy-draft` design item |
| G3 | Candidate/commit for **ordering** | `POST /api/policy/reorder` takes the complete permutation — the UI already holds the whole future state | **UI-only** | S5: staged reorder — drag edits a client-side order with a sticky "Apply order / Revert" bar; nothing persists until Apply. Honest because unapplied state is *visibly pending* and loss-on-navigation is explicit (unsaved-changes guard). This closes the audit's "reorder persists instantly with no confirm" finding without backend work |
| G4 | Shadow-rule detection | None | **Split** | Authoritative detection needs engine semantics → **Backend** design record. M3 ships **advisory client-side hints** (S5): flag rule B when an earlier enabled rule A has source ⊇ B and destination ⊇ B for the exactly-decidable cases (identical/wildcard-subsumed FQDN globs, equal categories, empty-vs-set sources). Label: "possible shadow — verify with the tester". Never claims completeness; UX-PRINCIPLES §10 (no theater) requires the hedge |
| G5 | Hit counts + last-hit + unused view | `HitCount` only, resets on restart | **Split** | Hits column ships in S2 with a "since restart" caption (honest). Last-hit timestamp + persistence → **Backend** (one field + persistence in the counters path) |
| G6 | Policy-match tool integrated with the rulebase | Tester is a separate view; trace exists server-side | **UI-only** | S4: "Test against this rule's conditions" prefill from any row; trace viewer componentized (`.trace`) and reused by the tester and the Traffic drawer; matched row in the trace links back to the rulebase anchored at that rule |
| G7 | Per-rule change attribution (modified-at/by) | Audit log has it, rules don't | **UI-only (approximation) + Backend (field)** | S3: per-rule "History" opens the audit view filtered to that rule's object key — truthful, zero new fields. A denormalized `modifiedAt/By` on `PolicyRule` is a **Backend** nice-to-have; do not fabricate a column until it exists |
| G8 | Tags / grouping of rules | No field | **Backend** | Defer; a `tags []string` on `PolicyRule` must join the config-surface registry (capture/apply/diff/DP-sync parity, `config_surfaces.go`) — not a UI-slice decision |
| G9 | Required audit comment on change | Audit records actor/diff automatically | **Backend** (optional) | The typed-confirm dialog could carry an optional reason (the revoke-node pattern) once an endpoint accepts one; defer with G2 |
| G10 | Human-readable rule summary in the editor | None (raw form) | **UI-only** | S3: live summary sentence ("Deny CONNECT traffic from group `contractors` to category `gambling`, inspected, weekdays 09-18") assembled from form state; doubles as validation feedback |
| G11 | Editor validation before save | Server-side `validatePolicyRule` on submit | **UI-only** | S3: client pre-validation mirroring the server rules (CIDR shape, glob shape, redirect URL, schedule sanity) + unsaved-changes guard on view switch |

**Rejected from the benchmark** (do not build): multiple rulebase types
(NAT/QoS/decryption — Culvert's two stages are already correctly separated;
inventing more surfaces would be structure without substance); Panorama-style
device-group hierarchy (Culvert's CP→DP snapshot sync already distributes
one authoritative rulebase — `ConfigSnapshot`); commit queues/partial
commits (single-admin-console scale does not justify the state machine).

## 4. Proposed M3 architecture

### Slices (each independently shippable, PR-sized)

- **S1 — modal stack + dialog e2e** ✅ shipped ahead of this review (the
  policy editor drawer depends on nested-modal correctness).
- **S2 — Rulebase table**: column redesign per G1/G5; `tableRows` adoption;
  row → detail drawer (shared `.drawer` component, stack-managed); empty
  state teaching first-rule creation; keyboard row navigation.
- **S3 — Editor**: drawer-hosted form with live summary (G10), client
  validation (G11), unsaved-changes guard, per-rule History (G7).
- **S4 — Decision trace integration**: shared trace component consuming the
  existing `walkPolicyTestRules` payload; tester prefill from rows; Traffic
  drawer's rule chip → anchored rulebase row (G6). Authentication Rules view
  aligned to the same components.
- **S5 — Staged reorder + advisory shadow hints** (G3/G4): Apply/Revert
  commit bar over `/api/policy/reorder`; client-side subsumption hints with
  explicit heuristic labeling.

### Backend design records to open (blocking nothing in S1–S5)

1. `policy-draft` — candidate/commit/validate/revert model (G2, G9); must
   define interaction with config-versioning and CP→DP snapshot sync.
2. `policy-shadow` — authoritative shadow/conflict analysis (G4), likely a
   dry-run endpoint reusing the matcher internals.
3. `policy-metadata` — `modifiedAt/modifiedBy`, optional `tags`,
   last-hit persistence (G5/G7/G8); each field must join the
   `configSurfaces` registry and the snapshot-parity walls (DEBT-006).

### Invariants carried into M3 (non-negotiable)

- The four markup-pinning test suites keep passing; `authpolicy` JS regions
  pinned by `authpolicy_phase*_test.go` are not reformatted.
- No policy-semantics change reaches the engine from a UI slice; every rule
  mutation continues through the existing audited handlers.
- All states honest: staged-vs-applied order visibly distinct; heuristic
  hints labeled; "since restart" on volatile counters.
- Foundation wall tests (`ui_redesign_foundation_test.go`) extended per
  slice (e.g. S5 pins that drag no longer POSTs without Apply).

## 5. Risks

| Risk | Mitigation |
|---|---|
| S5's staged reorder changes muscle memory (drag used to persist) | The commit bar appears on first drag with explicit "not yet applied" state; toast on Apply; roadmap notes a one-release UI hint |
| Client shadow hints produce false positives → alert fatigue | Only exactly-decidable subsumption cases; info-tier badge, never warn/crit; one-click "verify in tester" |
| Editor drawer collides with pinned auth-policy form internals | S3 scope is the ACCESS editor; Authentication Rules alignment (S4) reuses components around the pinned JS, not through it |
| Trace payload shape drifts | Freeze `policyTestTrace` as a documented contract in the S4 PR; wall-test the field names |
