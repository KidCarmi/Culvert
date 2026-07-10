# M0 Operational Activation & Validation — Acceptance Evidence Ledger

**Date:** 2026-07-10. **Verdict: M0 (Foundation & Safety) ACCEPTED — implementation
AND operational validation complete.** Every completion criterion was demonstrated
against real Cloudflare R2 infrastructure with a real signed release (`v1.0.0`,
`catalog_version=341`). GitHub Pages remains authoritative (retirement is M3);
repo-private remains owner-only (M2).

## Infrastructure (owner-provisioned, validated)

| Item | State | Evidence |
|---|---|---|
| R2 bucket `culvert-catalog` | ✅ | Cloudflare API (created 2026-07-10 14:01 UTC, EEUR) |
| Custom domain `catalog.culvertlabs.com` | ✅ | DNS→CF anycast; valid TLS (GTS `WE1`, exp 2026-10-08); CF-origin serving |
| 6 secrets + 2 vars (exact workflow names) | ✅ | `R2_S3_ENDPOINT/_ACCESS_KEY_ID/_SECRET_ACCESS_KEY`, `R2_BUCKET`, `CF_ZONE_ID`, `CF_CACHE_PURGE_TOKEN`; `R2_PUBLIC_BASE`, `R2_PUBLISH_ENABLED` |
| `release` environment + required reviewer | ✅ | protection_rules: required_reviewers=[KidCarmi]. (Documented: does NOT gate the publisher's repo secrets — see runbook Step 2 scope note) |
| `v*` tag ruleset | ✅ | `v-tag-protection` target=tag enforcement=active, deletion+non_fast_forward, no bypass actors (id 18781638) |
| Egress allow-list incl. catalog host | ✅ | PR #633 (host) + PR #634 (unquote wildcard) merged; harden-runner allowed-domains map confirmed in run logs |

## Publish pipeline (Steps 10–15)

| Criterion | Evidence |
|---|---|
| Signed bundle pre-proven against baked root (offline) | `LoadVerifiedCatalog` PASS on the `v1.0.0` release bundle: `catalog_version=341`, `expires_at 2026-09-25` |
| **First real R2 publish succeeds** | run **29108273025** — all steps green |
| **Verify passes (trust boundary)** | `Verifying staged catalog at https://catalog.culvertlabs.com/history/stable/v1.0.0` → `{"Action":"pass","Test":"TestServedVerify_BakedRootGate"}` (real PASS record, baked root + pinned ci.yml identity) |
| **Promotion succeeds** | ETag-pinned server-side copy (`cdac6739…`), sidecars→manifests first, index LAST |
| **Cache purge succeeds** | CF purge + confirm-loop converged |
| **Live catalog verified** | workflow: `live index confirmed (9c48ec58…)`; independent cross-check: sha256 of the offline-verified bundle index == `9c48ec584f65e0bd3faa5fcca6041aa22acb1718317279af27f5d689d0c21714` (identical) |

## Drills (Steps 16–19)

| Drill | Evidence |
|---|---|
| **Fail-closed under real failure** (bonus) | run **29107940865**: egress-blocked stage → verify/promote/purge SKIPPED, zero objects staged, live untouched |
| **Disable drill** | run **29109037997**: dispatched with `R2_PUBLISH_ENABLED=false` → job SKIPPED before any step (no secret read, zero writes) |
| **Recovery/idempotency drill** | run **29109136096**: create-only 412 `already staged — continuing` ×3 (immutable history), digest guard passed, verify re-PASS, idempotent re-promote, `live index confirmed`. R2 conditional-write support empirically proven |
| **Tamper/rollback drill** | Live `release-catalog/index.json` overwritten with garbage (dashboard) + purge → live sha `715b867c…` ≠ good; **appliance REJECTED it fail-closed** (`sigstore verification failed: … invalid signature when validating ASN.1 encoded signature`); recovery = one re-publish (run **29110374976**, green) → live sha restored to `9c48ec58…` |
| **Appliance verification** | Docker-compose CP with `CULVERT_RELEASE_CATALOG_URL=https://catalog.culvertlabs.com/release-catalog`: rejected tampered catalog at startup (above); after recovery, logs `release catalog: Sigstore identity signature VERIFIED` ×3 (staged verify + post-install reload + holder load) — catalog installed |

## Security validation checklist

- **Least privilege:** R2 keys scoped to the one bucket (functionally proven); purge token proven by working purge (scope attestation: Zone→Cache Purge documented in runbook).
- **No accidental publish:** all 8 `workflow_run`-triggered invocations to date skipped/neutral; only explicit dispatches published.
- **Publisher fails closed:** demonstrated twice under REAL failures (egress block; tamper→appliance reject).
- **Live cannot change before verify:** promote is unreachable without a `-json` PASS record (pinned by `TestWorkflowInvariants`); observed in the failed run (skip cascade).
- **Pages authoritative:** `publish-catalog-pages.yml` untouched throughout.

## Activation findings (recorded, non-blocking)

1. **Quoted allow-list token bug** (mine, M0-PR3): `"*.r2.cloudflarestorage.com:443"` inside a block scalar is a literal-quoted token → harden-runner blocked R2. Fixed + invariant-pinned in **PR #634**.
2. **Secret-name drift** (operator): initial secrets used non-workflow names (`R2_ACCOUNT_ID` etc.). Corrected to the 6 canonical names. *Hygiene: the 3 old-name secrets should be deleted.*
3. **Pinned-tag rollback observation:** recreating the proxy rolled back to a stale `culvert/proxy:pinned` (v0.0.296-era) because the legacy updater updates the running container but never re-tags the pin. Re-seeded from the **catalog-pinned digest** (`ghcr.io/kidcarmi/culvert@sha256:0dd8ed50…`). This is live confirmation of the M1 motivation (catalog-driven update path owns the pin at the sudo boundary).
4. `release` env `deployment_branch_policy` is null (terraform skeleton would set `protected_branches: true`) and the env does not gate the publisher — both documented; optional hardening in the runbook.

## Gate

**M0 Operational Validation: COMPLETE. M1 (Dual-publish + refresh + detection) is
unblocked** and begins with a fresh plan → independent design reviews lifecycle.
