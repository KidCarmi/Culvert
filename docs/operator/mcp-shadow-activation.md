# Controlled MCP Shadow Activation — Operator Runbook

Status: **procedure ready; NOT yet executed against production.** This describes the
exact future procedure to activate Shadow on ONE controlled node. Shadow EVALUATES real
MCP traffic and records evidence; it performs **no** upstream side effect and **no**
credential materialization (Layer B, PR #1226). Live execution (Canary/Production) stays
prohibited — see the abort/limits sections.

Design authority: `docs/design/mcp/SHADOW-ACTIVATION.md`,
`docs/design/mcp/SHADOW-ARCHITECTURE.md`, ADR-0024.

---

## 0. What Shadow does and does NOT do

| | Shadow |
|---|---|
| Evaluates real MCP `tools/call` against policy/inspection | **Yes** |
| Records a formal `ShadowDecision` (would_execute / would_block / would_fail_*) | **Yes** |
| Performs a real upstream tool call (`Upstream.Call`) | **No — structurally impossible** |
| Materializes a credential (`Broker.Materialize`) | **No — structurally impossible** |
| Enforces (returns a real block for an in-scope decision) | **No — it predicts** |

Out-of-scope traffic on a Shadow node behaves as **Observe** (recorded, not evaluated).

---

## 1. Preconditions (everything must be green)

1. The node runs a build containing this phase (readiness split + shadow composition).
2. The MCP Gateway listener is configured and serving (`mcp.gateway.enabled`, valid TLS,
   trusted keys, sender-constraint, min-assurance) — `GET /api/mcp/rollout` →
   `shadow.preflight.reasons` must NOT contain `gateway_listener_not_ready`.
3. Durable telemetry is composed (`mcp.gateway.qualification_telemetry`) — required for
   evidence. Preflight must not report `durable_events_unavailable`.
4. A node-local policy source is composed and a registry/catalog inventory is loaded —
   preflight must not report `policy_unavailable` / `registry_or_catalog_unavailable`.
5. No emergency kill switch engaged for the Gateway capability.
6. **Shadow readiness explicitly enabled**: the node started with
   `CULVERT_MCP_SHADOW_READY=1`. Confirm `GET /api/mcp/rollout` →
   `shadow.evaluator_composed: true`, `shadow.shadow_deps_ready: true`,
   `shadow.live_execution_ready: false`, `shadow.reason: "composed"`.
7. **Live execution stays off**: `shadow.live_execution_ready` MUST be `false`. If it is
   ever `true`, STOP — this build/node is not a valid Shadow-only target.
8. **At least one USABLE tool in the requested scope** — the CP→DP activation that applies
   the signed Shadow config must not be rejected with `no_usable_shadow_tools`. Every Gateway
   `tools/call` against a Quarantined / ReviewRequired / ServerDisabled catalog entry hits the
   policy quarantine hard-override, so Shadow would predict `would_fail_hard_control` for all of
   it and never reach `would_execute` / credential-readiness / stale-decision. The ONLY catalog
   state that evaluates is `Usable`, and **catalog ingestion never produces `Usable` — tool
   approval is a later slice** (`internal/mcp/catalog`). This precondition is therefore the
   gating prerequisite: **until the tool-approval / promotion slice ships, this is UNSATISFIABLE
   and Controlled Shadow activation is not yet reachable in production** (the apply-time preflight
   fails closed with `no_usable_shadow_tools`, by design). Because it is scope-dependent, it is
   checked at APPLY time (when the candidate scope is known), NOT by the node dry-run below — a
   healthy node reports `shadow.preflight.ready: true` yet a signed Shadow activation still fails
   closed with `no_usable_shadow_tools` until the controlled server's tool is promoted to `Usable`
   within the scope.
9. **Durable ShadowDecision evidence must be in the build** (`SHADOW-EVIDENCE-ROUTING-1`, a HARD
   PREREQUISITE — **now SATISFIED**). A real activation requires that the full per-request
   `ShadowDecision` — the Model-1 `Outcome`, credential-plan status, and inspection readiness — is
   recorded **durably**, not only returned in the transient JSON-RPC response body. The durable-evidence
   follow-up shipped the `schema_version:2` envelope: a shadow evaluation now persists a typed
   `Event.Shadow` sub-evidence carrying the full verdict, so per-request outcomes are reconstructable
   from the archive with the SAME facts the client saw, and the evidence-parity / zero-gap exit
   criteria are verifiable. This prerequisite is a build/schema property (not a node-config toggle);
   it is verified by the durable-record tests (`internal/mcp/events/**` shadow_v2_* +
   `internal/mcp/execution/shadow_evidence_parity_test.go`). This is a SEPARATE slice from
   precondition 8 — neither absorbs the other.

**Prerequisite 9 (durable evidence) is CLOSED; prerequisite 8 (a `Usable` scoped tool) REMAINS OPEN,
and BOTH must be closed before any production Controlled Shadow activation.** This build has durable
Shadow evidence but is still NOT activation-ready: precondition 8 fails closed today (no `Usable`
tool via the tool-approval / promotion slice).

Run the operator dry-run: `GET /api/mcp/rollout` and confirm `shadow.preflight.ready:
true` with an empty `reasons` list. This dry-run reports **node** readiness only — the
scope-independent prerequisites above (evaluator composed, no live-exec tier, durable events,
policy, inventory, inspection, live listener, no kill) — because before the first
Observe→Shadow activation the active scope is the empty Observe/Disabled scope, so a
scope-dependent check folded in here would always report not-ready regardless of node health.
A non-empty `reasons` list means the node cannot host Shadow; fix each named reason first. The
scope-dependent usable-tool precondition (8) is enforced separately, at the CP→DP apply that
activates the signed scope — so `shadow.preflight.ready: true` confirms the node is ready but
does NOT by itself mean a signed Shadow activation will be accepted in a build without the
tool-approval slice.

---

## 2. Target scope (ONE controlled deployment)

Shadow REQUIRES a bounded, enumerable scope — an empty or percentage-only scope is
rejected at validation ("no scope = no Shadow"). For the first activation, scope to a
single controlled server + a synthetic principal.

This is the `rollout.SignedConfig` structure the Control Plane fills in and **signs** into
the Gateway payload of a ConfigSnapshot (§3) — you do not hand-write the signature. It is
shown here as its exact JSON wire form so it round-trips through `rollout.SignedConfig`:
`capability`, `mode`, and the nested `scope.capability` / `operations` are **numeric enums**
on the wire (there is no string form), and `selector_schema` is **required** — omitting it
defaults to `0`, which `SignedConfig.Validate` rejects as an unsupported schema.

```json
{
  "selector_schema": 1,
  "capability": 1,
  "mode": 2,
  "scope": {
    "capability": 1,
    "servers": ["controlled-test-server"],
    "principals": ["synthetic-shadow-principal"],
    "operations": [2],
    "high_risk": true
  },
  "scope_revision": 1,
  "connector_mode": "local-client"
}
```

Wire-value legend (all `internal/mcp/rollout`): `selector_schema: 1` (current schema).
`capability: 1` = Gateway (`2` = Management). `mode: 2` = Shadow (`0` Disabled, `1` Observe,
`3` Canary, `4` Production). `operations: [2]` = the write risk class (`1` read, `3`
destructive).

- `servers` / `principals`: the ONE controlled server and the ONE synthetic identity.
- `operations: [2]` with `high_risk: true` — **required to shadow any `tools/call`.** The
  `operations` values are numeric risk classes on the wire: `1` = read, `2` = write, `3` =
  destructive (an empty list admits read only). The runtime classifies EVERY Gateway
  `tools/call` as the **`write`** class (`policyOperation` in
  `internal/mcp/runtime/policy.go`, a conservative default until a finer trusted read/write
  classification ships), so the scope must admit `2` — a read-only scope admits no
  `tools/call` traffic at all: the config would validate and activate, but every intended
  call resolves out of scope and stays Observe, so the controlled experiment records ZERO
  Shadow evaluations. A scope admitting the write/destructive class requires `high_risk:
  true` (validation rejects it otherwise). Admitting the `write` class is SAFE here because
  **Shadow performs no upstream side effect regardless of risk class** — it holds no upstream
  client and no materialize-capable broker (Layer B, #1226), so `high_risk` selects which
  calls are EVALUATED, never any that are executed.
- No `percent` gate (the scope must be enumerable).

Keep the ONE controlled server's tools harmless/reversible even though the scope admits the
`write` class: Shadow will never call them, but a zero-blast-radius target keeps the
experiment safe if a Canary decision for the same scope is ever contemplated later.

Validate the candidate scope first: `POST /api/mcp/rollout/scope/validate` (viewer) and
confirm it reports enumerable and bounded.

---

## 3. Activation

Shadow activation is published through the existing signed CP→DP rollout distribution
path (never an implicit default). The Control Plane signs a `SignedConfig` (§2 above)
into the Gateway payload of a ConfigSnapshot; the DP applies it via the same transaction
that carries the exec-deps gate + the §14 preflight:

1. Publish the signed Observe→Shadow config to the target node only.
2. The DP accept path verifies, in order: capability match → exec-deps
   (`shadow_deps_ready`) → **activation preflight** → durable distribution commit →
   rollout commit. Any failure rejects fail-closed with a bounded reason and NO partial
   state.

There is no auto-promotion: Shadow never advances to Canary/Production on its own, and
Production stays locked behind the absent qualification issuer.

---

## 4. Verification (prove it is Shadow, not execution)

After activation, confirm on the target node:

- `GET /api/mcp/rollout` → `gateway.mode: "shadow"`, `shadow.evaluator_composed: true`,
  `shadow.live_execution_ready: false`.
- `culvert_mcp_shadow_evaluations_total{outcome=...}` increments as in-scope traffic
  flows; the outcome distribution matches expectations.
- **Zero upstream calls**: `culvert_mcp_shadow_*` has no upstream/execution series, and
  the rollout metrics show `executed: 0`, `upstream_ok: 0`, `upstream_err: 0`.
- **Zero credential materializations**: no credential/broker activity (the evaluator
  holds no broker; `materialization_ready` in every shadow evidence record is
  `not_evaluated`).
- Shadow evidence is flowing to the durable archive (execution_state
  `shadow_evaluated`, `executed: false`), derived from the SAME `ShadowDecision` as the
  response.
- Out-of-scope traffic still produces normal Observe decision evidence.

---

## 5. Abort conditions (immediate rollback to Observe)

Abort the activation immediately if ANY of these is observed:

- any real upstream call, or any credential materialization (should be impossible —
  treat as a critical incident);
- `shadow.live_execution_ready` flips to `true`;
- Shadow evidence missing for in-scope traffic, or evidence/response mismatch;
- an unexpected `would_execute` for traffic that policy denies (a laundered verdict —
  should be impossible; `shadow_override` must flag a restrictive policy);
- a stale-decision spike (`would_fail_stale_decision` climbing);
- durability degraded (`culvert_mcp_shadow_evaluation_errors_total` climbing, or the
  telemetry `_degraded` gauge non-zero);
- scope appears wider than configured (out-of-scope subjects being evaluated).

---

## 6. Rollback (Shadow → Observe)

Rollback is deterministic and always accepted (a demotion never needs exec-deps):

1. Publish a signed config with `mode: 1` (Observe) — or `mode: 0` (Disabled) — for the
   Gateway capability to the target node. `mode` is a numeric enum on the wire (see the §2
   legend); the string form `"observe"` does not deserialize, so a rollback payload using it
   would fail to apply instead of demoting the node during an incident.
2. Confirm `gateway.mode` returns to Observe (`1`), the Shadow evidence window clears, and
   `culvert_mcp_shadow_evaluations_total` stops incrementing.
3. To fully disarm the node, restart it without `CULVERT_MCP_SHADOW_READY` — the
   evaluator is then not composed and `Deps.Executor` is nil (byte-identical Observe).

The emergency kill switch (`emergencyDisable`) stops all admission immediately without a
CP round trip and is restart-durable; use it if a rollback publish cannot be issued in
time.

---

## 7. Exit criteria (input to the future Shadow Exit Review)

A controlled Shadow soak is successful only if, for its full duration:

- zero upstream calls and zero credential materializations;
- zero evidence gaps (every in-scope evaluation produced durable evidence);
- no scope escape (only the configured subjects were evaluated);
- Shadow/live pre-call equivalence held (the differential contract from #1226);
- no unauthorized `would_execute` (no laundered DENY/REQUIRE_*);
- acceptable evaluation latency and stable admission;
- restart preserved the intended state (Shadow survived a restart with
  `CULVERT_MCP_SHADOW_READY=1`, or clamped to Disabled without it);
- the rollback drill (Shadow → Observe) worked;
- kill-switch behaviour correct (a killed node emits emergency blocks, never
  `would_execute`);
- operator observability was sufficient (metrics + status + evidence).

These criteria gate any future consideration of Canary — which this phase does NOT
prepare and which remains blocked on live-execution readiness and the
`PREREQ-MCP-KILL-1` side-effect-boundary revalidation.

---

## 8. Binary downgrade across persisted v2 Shadow evidence

Once this node has run a **v2-capable** binary and persisted at least one Shadow decision
event, the Gateway `P-ORD` spool partition holds `schema_version:2` records. A **pre-v2**
binary rejects a v2 record at decode (`unmarshalEvent` uses `DisallowUnknownFields`), so its
spool recovery fails that partition **closed** rather than misverifying it — the deliberate
downgrade posture (`SHADOW-EVIDENCE-ROUTING-1`; `docs/design/mcp/SHADOW-ARCHITECTURE.md` §9).
Rolling the binary back across such evidence therefore needs this procedure. It is
**surgical**: it touches ONLY the partition that holds Shadow evidence and never deletes
unrelated durable evidence.

**What is and is NOT affected**

- The MCP events spool is a BOUNDED, encrypted, per-capability **qualification-telemetry
  cache** — NOT authoritative policy, config, or enforcement state. Clearing it loses
  decision/outcome history, never enforcement.
- A v2 Shadow decision event routes by the tool call's operation class (`criticalityFor`):
  a **read**-class `tools/call` is ordinary → `gateway/P-ORD/`, while a **write** or
  **destructive** call is critical → `gateway/P-CRIT/`. So v2 Shadow evidence can land in
  **either** the `P-ORD` **or** the `P-CRIT` Gateway partition, and BOTH must be archived and
  cleared. `gateway/P-DEN/` holds only coalesced denial aggregates (never a Shadow decision
  event, never v2), so it — together with the sealed DEK (`gateway/dek.sealed`) and the entire
  `management/` subtree — carries NO v2 evidence and MUST be preserved.
- **`gateway/degraded_state.json` may need resetting — but ONLY when the degradation is
  *exclusively* schema-induced.** The realistic emergency order is downgrade → it fails → *then*
  the operator finds this runbook. On that failed boot, spool recovery classified the v2 records
  as corruption and `NewManager` called `OnCriticalCommitFailure`, latching the Gateway domain
  into `critical-durability-degraded` and persisting it to `gateway/degraded_state.json`; that
  lockout blocks write/destructive Gateway operations and reloads on every subsequent boot. But
  this one file ALSO carries the `denial-lane-degraded` track, which corresponds to the `P-DEN`
  partition you are preserving and is NOT re-derived from a partition scan at boot. The
  deterministic, safe gate is therefore the DENIAL track alone (step 5): the critical track is
  about the Gateway critical partition you archive and clear in steps 3–4, so a fresh boot
  re-derives it, while a degraded denial track is real, restart-persistent state you must not
  wipe. Do NOT try to prove the critical degradation is schema-induced from its persisted
  `reason` text — the pre-v2 binary collapses the strict-unmarshal failure into a generic
  corruption reason (`record event invalid`) that cannot distinguish schema-induced from
  unrelated corruption. `management/degraded_state.json` and any other capability's state are
  always preserved.

`<mcp-data-dir>` is the MCP telemetry `DataDir` configured for this node's Gateway; under it
each capability (`gateway/`, `management/`) has per-partition subdirectories (`P-ORD/`,
`P-CRIT/`, `P-DEN/`) with `seg-<id>.dat` segments + `checkpoint.json`, plus `dek.sealed` and
`degraded_state.json`.

**Procedure (node stopped throughout — never mutate a live spool)**

1. Stop the node (or bring the container down).
2. Locate `<mcp-data-dir>` and confirm the layout above.
3. **Archive first, then clear.** Tar the whole `gateway/` subtree to durable storage OUTSIDE
   the data dir, so the v2 evidence stays readable later by a v2-capable binary (and for
   forensics):
   ```
   tar -czf /var/backups/culvert/mcp-gateway-spool-$(date +%Y%m%dT%H%M%SZ).tgz \
       -C <mcp-data-dir> gateway
   ```
4. Clear BOTH Shadow-bearing partitions — remove the segments and checkpoint of `P-ORD` and
   `P-CRIT` (the directories are recreated on next open; recovery treats an empty partition as
   fresh):
   ```
   rm -f <mcp-data-dir>/gateway/P-ORD/seg-*.dat  <mcp-data-dir>/gateway/P-ORD/checkpoint.json
   rm -f <mcp-data-dir>/gateway/P-CRIT/seg-*.dat <mcp-data-dir>/gateway/P-CRIT/checkpoint.json
   ```
   Do NOT touch `gateway/P-DEN`, `gateway/dek.sealed`, or anything under `management/`.
5. **Reset the Gateway degraded state — gated ONLY on the denial track.** A failed pre-v2 boot
   latches `critical-durability-degraded` into `gateway/degraded_state.json` from the v2 records
   you just cleared, which would otherwise keep write/destructive Gateway operations blocked after
   recovery. Inspect the file (plain JSON, `0600`) and remove it ONLY when the `"denial"` track is
   normal — value **`1`** (`StateNormal`):
   ```
   rm -f <mcp-data-dir>/gateway/degraded_state.json
   ```
   Why the denial track is the whole gate, and why the `"critical"` `"reason"` is deliberately NOT
   used:
   - The `"critical"` track is about the Gateway critical partition (`P-CRIT`) you archived and
     cleared in steps 3–4. Whatever caused it — the schema-induced v2 records, or an unrelated
     prior commit failure — its data is now archived (forensics preserved) and the partition is
     reset, so a fresh boot re-derives the correct critical state (and re-degrades only if a real
     durability problem still exists). Its persisted `"reason"` CANNOT serve as proof: the pre-v2
     binary collapses the strict-unmarshal failure into a generic `record event invalid` →
     `recovery detected spool corruption: …` that does not distinguish schema-induced corruption
     from unrelated corruption.
   - The `"denial"` track is different: it corresponds to the `P-DEN` partition you are PRESERVING
     and, unlike the critical track, is NOT re-derived from a partition scan at boot — a
     `denial-lane-degraded` latch re-asserts only on the next denial commit failure, so a `2` there
     is real, restart-persistent state that deleting the file would silently wipe. The numbering
     (`internal/mcp/events/state/state.go`): `0` is `StateUnknown` (NOT normal — fails closed on
     load), `1` is `StateNormal`, `2` is `StateDenialLaneDegraded`. The safe case is exactly
     `"denial": 1`.

   If `"denial"` is `2` (degraded) or `0` (unknown): **LEAVE THE FILE** — it carries real
   denial-lane state tied to the preserved `P-DEN`, and because both tracks share one file the
   critical lockout stays too. Address the denial-lane degradation through the normal recovery path
   first; once `"denial"` is back to `1`, delete the file then. Never touch
   `<mcp-data-dir>/management/degraded_state.json` or any other capability's state.
6. **Reset the export cursor for every partition you cleared — unconditionally.** Clearing a
   partition restarts its commit sequence at 1, but the archive exporter's cursor still holds
   the old (high) `afterSeq`; `CommittedForExport` skips any segment whose `lastSeq <= afterSeq`
   and `exportStep` returns without an error on the resulting empty batch, so a **retained**
   cursor SILENTLY drops every new event of the reset partition (with no logged mismatch) until
   the restarted sequence overtakes the old cursor. Remove the matching cursor files so the
   exporter restarts from the fresh partitions:
   ```
   rm -f <mcp-data-dir>/export_cursors/gateway/ord.cursor \
         <mcp-data-dir>/export_cursors/gateway/crit.cursor
   ```
   Leave `den.cursor` and the `management/` cursors alone (their partitions were not cleared).
7. Start the pre-v2 binary. Its spool recovery now sees empty `P-ORD` and `P-CRIT` (fresh
   partitions) — and, if you reset it in step 5, no schema-induced Gateway degraded-state
   lockout — and starts clean; `P-DEN` and `management/` recover normally.

**Reading the archived evidence — offline is the default.** To consult the archived v2
evidence, unpack the tarball to a **scratch location** and point a **v2-capable** binary/tool
at that copy. Do this offline; **never point a pre-v2 binary at it** (it re-introduces the same
rejected records), and **never unpack it back over the node's live data dir**. Once the node
has taken any traffic after step 7, its `P-ORD`/`P-CRIT` hold NEW evidence, so restoring the
archive in place would overwrite that downgrade-period evidence — and, because the export
cursors live OUTSIDE the `gateway/` subtree (under `export_cursors/gateway/`, so a subtree
restore does not bring matching cursors back), the cursors advanced during the downgrade would
silently suppress every restored record whose sequence is below the current cursor (the same
skip in step 6). Treat the archive as read-only history, not a spool to reinstate.

**In-place restore is only for a no-traffic revert.** If you downgraded by mistake and the node
took **no** traffic afterwards (its `P-ORD`/`P-CRIT` are still the empty fresh partitions from
step 7), you may restore the pre-downgrade spool exactly: with the node **stopped**, replace the
empty `gateway/P-ORD` and `gateway/P-CRIT` with the archived copies, then **reset
`ord.cursor` and `crit.cursor`** (as in step 6) so the restored lower-sequence records are not
suppressed, and start a v2-capable binary. Do NOT do this once post-downgrade evidence exists —
the two hash-chained histories cannot be merged into one partition; keep that evidence and read
the archive offline instead.

**Why validation is not weakened to make downgrade transparent.** A v1 reader silently
reinterpreting a v2 record would misreport its digest and could surface an inconsistent
verdict as valid; the fail-closed rejection is deliberate. Downgrade is a rare, deliberate,
node-local operator action, not a silent-safe default.
