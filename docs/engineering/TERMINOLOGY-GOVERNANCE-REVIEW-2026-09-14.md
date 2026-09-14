# Culvert Language & Terminology Governance Review — 2026-09-14

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Fetched `origin/main` at review start and again immediately before opening this PR (per
> the DEBT-014 process lesson). Both fetches resolved to the identical commit, `993b390` — the same
> commit the still-open `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-13.md` PR (#1380) already audited through.
> **There is therefore no new commit window for this pass to audit**: `main` has not advanced since the
> prior scheduled run. Re-running that same diff-scope audit a third time (after #1380, and before it
> #1372 for 2026-09-12) would duplicate work already done and still pending merge, with nothing new to
> find — so this pass did not repeat it. Both prior reports remain open, unmerged PRs
> (`#1372`, 2026-09-12; `#1380`, 2026-09-13) as of this writing; nothing in this report depends on either
> merging first, and nothing here conflicts with their content (disjoint files: MCP canary vocabulary,
> Policy Learning "Accept to Draft" wording, and PAC "steering profile" wording, none of which this pass
> touches).

---

## Executive Summary

**No new terminology drift found, and no code changed this pass** — but this pass produced a genuine,
code-verified correction to two existing carry-over backlog entries (T-21+T-32 and, separately, T-21
alone), whose recorded migration-risk ratings turn out to be wrong once actually traced to the
implementation. Both corrections argue for **not** attempting either fix casually, which is itself the
useful output: a future pass (automated or human) reading only the prior "Low risk / Small PR" ratings
would be reaching for a same-day rename that this investigation shows is not safe as scoped.

Since there was no new commit window, this pass instead re-examined the two lowest-priority-looking
open items on the carry-over list, T-21 and T-32 (paired since 2026-08-01, both about reclaiming
"snapshot"/"Config Version"/`cp_version` as unambiguous terms in the Cluster and SaaS-feed admin
surfaces), by reading the actual code paths their recommended fixes would touch — something no prior
report in this pair's six-week history had done beyond the call site that introduces each field.

### T-32 — the recorded "Low" migration risk is wrong; the field participates in an integrity check

T-32 (first raised 2026-08-01, `SnapshotSHA256`/`snapshot_sha256` colliding with the two pre-existing
"snapshot" meanings) has carried a **"Migration risk: Low today ... zero API/GUI exposure yet"** rating
across seven reports. That rating is about *external compatibility* (nothing reads the field from a live
GET response yet — still true, re-confirmed: `apiURLCatFeedStatus`, `ui_policy.go:1460`, still only calls
`globalSaaSFeedStatus.Snapshot()` and never touches `effectiveCategoryView`/`SnapshotSHA256`). It did not
account for **on-disk compatibility**, which is the actual hazard:

- `saas_feed_activation.go:99-101`: *"The JSON field order below is FIXED and load-bearing: the canonical
  bytes must be byte-stable across writers/platforms (golden-bytes test pins this)."*
- `saas_feed_activation.go:112`: `SnapshotSHA256 string \`json:"snapshot_sha256"\`` is one of those fixed
  fields, in both `activationRecord` and its CRC-omitted view `activationRecordSansCRC` (line 139).
- `saas_feed_activation.go:170-176` (`encodeActivationRecord`) computes `crc32c` over the canonical bytes
  of that exact struct shape; `saas_feed_activation.go:284-292` (read-back validation) **re-derives** the
  CRC from the record as decoded and rejects the record with `errActCRC` ("crc32c corruption") if it does
  not match the stored value.

Renaming the JSON tag (e.g. to `content_sha256`, per T-32's own suggestion) changes the struct's canonical
byte form. `encodeGoing forward` records would be internally consistent, but **any activation record
already persisted under the old key** — i.e. any node that has activated even one SaaS feed generation
before this hypothetical fix ships — would decode with the renamed field empty (`encoding/json` silently
leaves an unmatched key unpopulated), and the read-back CRC check would then legitimately recompute a
different value and reject a perfectly valid, unmodified record as **corrupt**. A wording fix would turn
into a fail-closed feed-activation outage on any node with existing state — exactly the class of hazard
this program's own T-17/T-29/T-30 entries already reserve the "needs an alias/compat path, not a same-day
rename" treatment for; T-32's write-up simply hadn't traced far enough to notice this field is CRC-guarded.

**Correction applied to the backlog (not a fix, a re-rating):** T-32's action is not "rename the field" as
currently written. A correct fix needs either (a) a `schema_version`-gated migration that decodes both the
old and new key for one version's worth of records before the old key is retired (mirroring how
`OnInspectError`'s additive-field degrade already works elsewhere in this codebase), or (b) accepting the
byte-identical field name as permanent and fixing only the *English* collision in comments/docs (i.e., stop
calling it "the snapshot" in prose while leaving `SnapshotSHA256` as the wire/on-disk name). **Migration
risk raised from Low to Medium; Est. PR size raised from Small to Small-Medium.** The "land before F3b-4
wires it onto a live GET" urgency in the original write-up still holds and is, if anything, now more
important: fixing this before external exposure is still cheaper than after, but "before exposure" no
longer means "trivial" — the on-disk compatibility hazard exists today, independent of API exposure.

### T-21 — the recorded risk direction was right, but the actual PR surface is larger than described

T-21 (`cp_version` / "CP Config Version," Cluster panel) has no version of T-32's problem: `cluster_convergence.go:41,59`'s `fleetConvergence` is a purely ephemeral, computed-per-request response
(`computeFleetConvergence()`) with no persisted form and no CRC/signature contract — confirmed by reading
the whole file. On that axis, it remains genuinely low-risk to rename.

What the six prior mentions of this entry ("Small PR: one GUI label + one JSON field + its one consumer")
did not record: the field is exposed through this repo's OpenAPI pipeline, not just consumed by
`static/index.html`. `api/openapi/openapi.yaml`/`openapi.json` document it (both files contain
`cp_version`, confirmed by direct grep), and `frontend/src/api/types.gen.ts:5925` carries a generated
`cp_version: number` entry produced by `frontend/scripts/generate-types.sh` from that spec. That script's
first action is `sh scripts/assert-toolchain.sh` — an exact Node/npm version assertion — before running the
pinned, network-isolated `tools/openapi-gen` workspace. A correct PR touching this field therefore needs,
beyond the GUI label and the Go struct: a manual edit to `api/openapi/openapi.yaml` (the hand-maintained
contract `cmd/apibundle` bundles from, per the Makefile's `api-bundle`/`api-bundle-check` targets, both
gated on PRs) and a regeneration of `types.gen.ts` under the exact pinned frontend toolchain, or CI's
`api-bundle-check` and `frontend-verify.yml` gates fail on drift. (No `frontend/dist` behavior actually
changes — grep confirms no component under `frontend/src` reads `cp_version`; it is an unused generated
type today — but the generated *files* still need to match, and CI checks that they do.)

**Why not fixed this pass:** this sandbox's Node runtime is v22.22.2; the project's pinned frontend
toolchain (used for every prior GUI-copy fix in this program, e.g. T-53's rebuild note) is Node
24.19.0/npm 11.17.0, and `assert-toolchain.sh` is designed to refuse exactly this mismatch. Regenerating
`types.gen.ts` here would either fail outright or risk producing an artifact that doesn't match what the
pinned toolchain would produce, for a field two reports already correctly identified as safe to touch on
every axis they checked. **No risk-rating change, but Est. PR size raised from Small to Small-Medium** to
record the two additional generated-artifact steps a correct implementation needs.

**No code was changed in this pass.** Both corrections are re-ratings of existing backlog entries, written
so a future implementer (automated or human) does not repeat the "Low risk, same-day rename" reading of
either entry's prior text.

**Terminology Health Score: 8.7 / 10** (unchanged — no new drift, no backlog item resolved; a corrected
risk rating on an already-open item does not itself move the score).

---

## Carried-Over Findings (unchanged in substance; two re-rated as above)

All previously-open finding IDs remain open: T-9, T-11, T-12, T-13 (residual), T-17, T-18, **T-21+T-32
(paired — risk ratings corrected above, action still not taken)**, T-25 (residual), T-29, T-30, T-33,
T-34, T-39. Full descriptions are unchanged from `TERMINOLOGY-GOVERNANCE-REVIEW-2026-09-11.md` (the last
merged report) and are not restated here except where corrected above. Two further reports
(`-2026-09-12.md`, `-2026-09-13.md`, PRs #1372/#1380) are pending merge as of this writing and introduce
additional items (T-53 already merged via #1355; T-55/T-56 proposed by #1380) that this report does not
duplicate, verify, or depend on — they touch disjoint files from this pass's investigation.

---

## Stop-Condition Assessment

No new terminology drift was found, because there was no new commit window to search — `main` is
identical to the commit the immediately-prior (still-open) report already audited. Rather than file a
third, content-free "nothing new" report against a window two other pending PRs already cover, this pass
used the time to verify, at the code level, two of the oldest open backlog entries' recorded risk/effort
estimates — and found both understated in ways that matter for whether a future pass should attempt them
casually. T-32's rating changes from a compatibility standpoint (Low → Medium risk: an on-disk CRC
contract this program had not previously traced); T-21's does not change in risk but does in scope (Small
→ Small-Medium: OpenAPI/frontend-codegen artifacts this program had not previously traced). No rename was
executed, and none is recommended without the additional care each corrected write-up now describes. No
cosmetic or preference-driven renames were proposed.
