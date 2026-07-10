# M1 — Dual-publish verification, production refresh, detection, re-sign — Detailed Design (v1)

**Milestone:** M1 (post-M0 acceptance, `roadmap/M0-ACTIVATION-EVIDENCE.md`).
**Scope (frozen by owner):** (1) dual-publish verification, (2) production HTTP
catalog refresh, (3) detection/canary/alerting, (4) weekly no-bump re-sign +
180-day freshness. **Out:** repo-private (M2), Pages retirement (M3), rings/
percentage rollout/telemetry/Release Console (M4+), any M0 redesign absent a proven
regression. Plus two M0-activation regression guards (one already shipped).

## 0. Prerequisite audit (evidence)

| Fact | Evidence |
|---|---|
| Manual refresh seam exists | `release_api.go:63` `refresh func(context.Context) error`; `POST /api/releases/catalog-refresh` (line 190, 264-297) drives the REAL auto-seed path; proven live in the M0 tamper drill ("Refresh failed" = this endpoint failing closed) |
| Auto-seed is startup-only today | `release_autoseed.go` (called from startup wiring); no periodic loop |
| Re-sign spec mode implemented, CI plumbing absent | `release_spec.go:44-206` `specModeResign` (requires `resign_now`+`resign_created_at`, preserves `created_at`+`catalog_version`); no `RESIGN` env in `ci.yml`/`release_gen_test.go` |
| Signing context is pinned to tag refs of ci.yml | `officialSigstoreSANRegex = ^…/ci\.yml@refs/tags/v.*$`; `ci.yml` has `workflow_dispatch` ⇒ dispatching **at a tag ref** yields a matching SAN |
| R2 publisher refuses re-signed bytes at an existing tag prefix | create-only staging + origin-digest guard (M0-PR3): different index bytes at `history/stable/<tag>/` ⇒ loud abort — CORRECT for releases, must be designed around for re-signs |
| Alerting engine available | `alerts.go:35` `fireAlert(event, AlertPayload)` (delivery + retry in `internal/alerts`) |
| Live baseline | R2 live serves verified `v1.0.0` (`catalog_version=341`, `expires_at 2026-09-25`); Pages authoritative; publisher enabled |

## 1. Slice A — Dual-publish verification (PR M1-1)

**Goal:** after each release, PROVE Pages and R2 serve the same verified catalog.

- New job `dual-publish-verify` in `publish-catalog-r2.yml` (after the confirm step)
  — or a separate `workflow_run` workflow; decision at review. It fetches
  `index.json` from BOTH origins (`kidcarmi.github.io/Culvert/release-catalog`,
  `catalog.culvertlabs.com/release-catalog`), asserts sha256(pages) ==
  sha256(r2) == the release-bundle digest, and runs the env-gated baked-root served
  gate against BOTH origins.
- Divergence ⇒ job fails RED + (Slice C) fires an alert. It never mutates either
  origin (verify-only; `contents: read`, no id-token).
- Timing caveat: Pages deploys via its own `workflow_run`; the check must tolerate
  Pages lag (bounded retry, e.g. 10 min) before declaring divergence.

## 2. Slice B — Production HTTP catalog refresh (PR M1-2)

**Goal:** appliances converge on new/re-signed catalogs without restarts.

- Background loop in the proxy (new `release_refresh.go`): every
  `release.refresh_interval` (default **6h**, jittered ±10%, YAML+env, GUI parity
  via `/api/releases` + settings panel), call the EXISTING `rm.refresh` seam.
- Semantics (all already enforced by the holder/auto-seed path — the loop adds no
  new trust logic): unchanged catalog (ETag 304) ⇒ no-op; new verified catalog ⇒
  install + floor ratchet; verify/freshness/rollback failure ⇒ keep current catalog,
  count + alert (Slice C). Never fails the proxy hot path.
- Runs ONLY when `CULVERT_RELEASE_CATALOG_URL` is configured (same condition as
  startup auto-seed). Loop registered via the background-services startup slice;
  clean shutdown via context.
- Concurrency: serialize with the manual refresh endpoint (single-flight mutex —
  both call the same seam).

## 3. Slice C — Detection / canary / alerting (PR M1-3)

**Goal:** operators learn about catalog problems from alerts, not outages.

- New alert events via `fireAlert`: `release_catalog_stale` (installed catalog’s
  `expires_at - now < threshold`, default 30d — the 180-day freshness watchdog),
  `release_catalog_refresh_failing` (N consecutive refresh failures, default 3),
  `release_catalog_recovered` (first success after failures). Emitted by the Slice-B
  loop; state in the refresh loop (no new stores).
- `/api/releases` gains `last_refresh{at,ok,error}`, `consecutive_failures`,
  `expires_in_days` (GUI parity: surface in the Release panel).
- Prometheus: `culvert_release_catalog_refresh_total{result}`,
  `culvert_release_catalog_expires_in_seconds` gauge.
- **Canary (bounded to scope):** the dual-publish job (Slice A) IS the publish-side
  canary; appliance-side “canary” here = the stale/failing alerts above. No rings,
  no percentage rollout (out of scope).

## 4. Slice D — Weekly no-bump re-sign + 180-day freshness (PR M1-4, most complex)

**Goal:** the served catalog’s `expires_at` never lapses even with no releases.

- **Signing context:** a tiny scheduler workflow (`resign-catalog.yml`, weekly cron
  + manual dispatch; `actions: write` ONLY) resolves the latest `v*` tag and
  dispatches **`ci.yml` at that tag ref** with a `resign=true` input — so the
  keyless signature’s SAN is `ci.yml@refs/tags/v<latest>` and matches the pinned
  identity. The scheduler itself signs nothing (no id-token).
- **ci.yml resign path:** `workflow_dispatch` gains a `resign` boolean input. When
  true, `catalog-pipeline` runs a REDUCED path: skip build/docker/release; download
  the tag’s existing release bundle; extract `created_at` from the CURRENT index;
  run the gate in `specModeResign` (new envs `CULVERT_RELEASE_SPEC_RESIGN=1`,
  `_RESIGN_NOW`, `_RESIGN_CREATED_AT`) → byte-new index, SAME `catalog_version` +
  `created_at`, fresh `generated_at`/`expires_at` (+180d); keyless-sign; **verify
  end-to-end** (`TestReleaseCatalogKeylessVerify`); attach to the release as a
  versioned resign asset (`culvert-release-catalog-<tag>-r<YYYYMMDD>.tar.gz`) —
  the original release asset is never replaced.
- **R2 publish of a re-sign:** the R2 publisher gains a matching `resign` dispatch
  input: stage to `history/stable/<tag>-r<YYYYMMDD>/` (create-only preserved; a
  NEW prefix, so the M0 digest guard stays intact for real releases), verify the
  staged URL through the baked-root gate, promote (idempotent copy; live pointer
  last), purge, confirm. Rollback floor: `catalog_version` unchanged ⇒ `>= floor`
  passes; appliances accept via ETag-change + verify.
- **Pages re-sign:** `publish-catalog-pages.yml` is UNTOUCHED (M3 boundary). Its
  `workflow_dispatch` can already republish a tag; the resign asset naming keeps its
  `culvert-release-catalog-*` glob compatible — **decision for review:** whether the
  weekly flow also re-dispatches Pages (dual-publish parity for re-signs) or Pages
  keeps the original signature until its retirement (divergence-by-design the Slice-A
  check must then tolerate for resigns). Recommended: re-dispatch Pages too, keeping
  the two origins byte-identical (its newest-asset pick must then prefer the newest
  `culvert-release-catalog-*` file — verify its `head -n1` glob ordering).
- **Failure posture:** every step fails closed; a failed re-sign leaves both origins
  serving the previous (still-valid) catalog; the Slice-C stale alert is the
  backstop (fires at 30d remaining, giving ~5 weekly retries before lapse).

## 5. M0-activation regression guards

- **Quoted allow-list token:** SHIPPED (PR #634, `assertEgressAllowListWellFormed`,
  mutation-proven). No further work.
- **Secret-name contract (PR M1-1, small):** extend `TestWorkflowInvariants` to pin
  the publisher’s exact secret/var reference sets: `secrets.{R2_S3_ENDPOINT,
  R2_S3_ACCESS_KEY_ID, R2_S3_SECRET_ACCESS_KEY, R2_BUCKET, CF_ZONE_ID,
  CF_CACHE_PURGE_TOKEN}` and `vars.{R2_PUBLISH_ENABLED, R2_PUBLIC_BASE}` — scan all
  `${{ secrets.* }}`/`${{ vars.* }}` references in `publish-catalog-r2.yml` and
  assert set-equality with the documented contract (drift in either direction
  fails), keeping the runbook table in lock-step.

## 6. PR plan (single-scope each)

| PR | Contents |
|---|---|
| M1-1 | Dual-publish verify job + secret-name-contract invariant |
| M1-2 | Refresh loop (`release_refresh.go`) + config + API/GUI surface + tests |
| M1-3 | Alerts + metrics + status fields + tests |
| M1-4 | Re-sign: scheduler workflow + ci.yml resign path + R2 publisher resign input + workflow-invariant extensions + gate tests |

Order: M1-1 → M1-2 → M1-3 → M1-4 (each from merged main; no stacking).

## 7. Invariants preserved (owner directives)

R2 publish path byte-unchanged except the additive resign input (M1-4); Pages
untouched; fail-closed everywhere; additive migration; all workflows idempotent;
production mutations recoverable (re-sign assets are versioned; live pointer
restorable by re-publish — proven in M0).

## 8. Open questions for design review

1. Slice A placement: job inside `publish-catalog-r2.yml` vs separate workflow
   (workflow_run timing vs permission isolation)?
2. Refresh default interval (6h?) and whether refresh-failure alerts need
   rate-limiting beyond the consecutive-failure threshold.
3. Resign staging prefix format (`<tag>-r<YYYYMMDD>`) — collision/ordering concerns?
   Idempotent same-day re-runs (create-only 412 + digest guard semantics)?
4. Should the weekly re-sign also re-dispatch Pages (recommended) — and does the
   Pages workflow’s newest-asset pick handle multiple `culvert-release-catalog-*`
   assets correctly?
5. `resign_created_at` source: read from the CURRENTLY SERVED index (R2) vs the
   release bundle’s index — which is authoritative for created_at preservation?
6. Does dispatching ci.yml at a tag with `resign=true` interact safely with the
   tag-path guards (`require-gate.sh` asserts on the tagged commit — re-runs should
   still pass) and the docker/auto-tag jobs (must be skipped on resign)?
