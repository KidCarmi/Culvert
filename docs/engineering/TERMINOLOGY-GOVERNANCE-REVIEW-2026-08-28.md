# Culvert Language & Terminology Governance Review — 2026-08-28

> **Owner:** Language & Terminology Governance routine · **Status:** Point-in-time review (repeatable)
> **Method:** Audited `e698a12..cc9479f` (65 commits, 7 on the first-parent path; 89 files changed,
> +8709/-557 lines), dominated by the MCP Shadow-execution activation/hardening slice (Codex rounds on
> PR #1234/#1235: preflight scoping, credential-plan/request-inspection biconditionals, the durable
> `schema_version:2` ShadowDecision evidence envelope, the binary-downgrade runbook) plus one CHAOS-56
> graceful-shutdown fix, one fileblock lock-free hot-path change, one HA self-fence ordering fix, and a
> policy-learning benchgate de-flake. Method: (1) full-repo grep for every new `culvert_*`/`stat_*` metric
> and counter name introduced in the window (`mcp_shadow_metrics.go`, the CHAOS-56 shutdown watchdog) against
> every existing family sharing a prefix or a word, looking for the same same-window-collision shape T-47
> caught twice; (2) read the new durable-evidence field names (`schema_version`, `ActionClass`,
> `would_block`) in `internal/mcp/events/model` against the pre-existing Shadow/Observe vocabulary for a
> repeat of the `drifted_tools`/`review_required_tools` split; (3) diffed `static/index.html` for new GUI
> copy (none touched by this window — confirmed by file-list absence); (4) checked all fifteen still-open
> carry-over finding IDs' dependent files against this window's changed-file list; one intersected
> (`metrics.go`, T-31's own file) and was pulled forward for a fix rather than re-confirmed as unchanged.
> **Companion change:** one long-queued backlog item (T-31) is fixed in this pass.

---

## Executive Summary

**No new terminology drift was found in this window.** The MCP Shadow-execution hardening work is
internally consistent — `ActionClass`/`would_block`/the v2 evidence envelope are used identically across
the executor, the durable writer, the archive validator, and the seven runbook/doc updates that accompany
them; nothing in the window introduces a second name for a concept this program already tracks, or reuses
an existing name for something new. The one file-list intersection with the open backlog was `metrics.go`
against **T-31** (the `culvert_clamav_blocked_total` vs. `culvert_clam_scan_errors_total` family split,
open since 2026-08-01) — the window's touch to that file (CHAOS-56 shutdown-sequence lines, unrelated) does
not itself change T-31, but since the file was already open in an editor for this review, T-31 was pulled
off the backlog and fixed in the same pass rather than re-confirmed unchanged for an eighteenth time.

**T-31, fixed this pass:** `culvert_clam_scan_errors_total` now dual-emits under the canonical
`culvert_clamav_scan_errors_total` name — same value, same source counter
(`secscan.Counters().ClamScanError`), zero behavior change to the legacy series. This closes the one
outlier in the `culvert_clamav_*` metric family (`culvert_clamav_blocked_total` was always spelled
correctly; only the scan-error counter, added 2026-07-26, missed the `av`). The operator runbook
(`docs/operator/scan-capacity-and-timeouts.md`) gains one clause pointing new dashboards/alert rules at the
canonical name; the existing `stat_clam_scan_error` JSON field, the `scan_clam_error` alert name, and every
other T-31-adjacent surface are untouched — this fix is scoped to the one `/metrics` series T-31 named, not
a broader "fix everything that says clam" pass (the neighboring `culvert_clam_saturated_total` is a
distinct, not-yet-queued finding and is deliberately left alone here).

**Terminology Health Score: 8.7 / 10** (up from 8.6 — one more Low-Medium backlog item closed at zero
migration risk, zero compatibility impact, following the same additive-dual-emit precedent as T-38. The
score does not move further because fourteen carry-over findings remain open and unchanged, and because
this window's clean pass on a large, fast-moving subsystem (MCP Shadow execution) is one data point, not a
structural improvement to the process gaps this program has already recorded — see the 2026-08-25 review's
ADR-number-reservation recommendation, still unaddressed.)

---

## Findings

### T-31 — ClamAV metric family: `clamav` everywhere except `culvert_clam_scan_errors_total` (carried over — fixed this pass)

- **Business concept:** a mid-request ClamAV scan fault (daemon unreachable/protocol error; content
  forwarded unscanned, fail-open) — one member of the `culvert_clamav_*` Prometheus metric family that
  reports on the ClamAV antivirus engine.
- **Current names before this fix:** `culvert_clamav_blocked_total` (`metrics.go:715-717`, the family's
  other member) vs. `culvert_clam_scan_errors_total` (`metrics.go:723-725`, added 2026-07-26 per CHAOS-52,
  missing the `av`).
- **Why the current naming was problematic:** an operator or dashboard author filtering `/metrics` by the
  `culvert_clamav_*` prefix — the natural query for "everything about the ClamAV engine" — silently misses
  the scan-error counter, the one series that distinguishes "daemon is down" (fail-open, alertable) from
  "daemon is merely at capacity" (`culvert_clam_saturated_total`, a distinct, correctly-named-relative-to-
  itself but not-yet-queued finding left out of scope here).
- **Fix:** `metrics.go` gains a second rendered series, `culvert_clamav_scan_errors_total`, immediately
  after the existing `culvert_clam_scan_errors_total` block, populated from the same
  `scanCounters.ClamScanError` value passed a second time to the single `fmt.Fprintf` call that renders the
  whole `/metrics` body — no new counter, no new read of `secscan.Counters()`, so the two series can never
  drift apart in value. The legacy name is kept permanently (same precedent as T-38's `drifted_tools`): no
  existing consumer of `culvert_clam_scan_errors_total` is asked to migrate. A new pinning test,
  `TestMetrics_ClamAVScanErrorsDualEmit` (`clamav_metrics_dualemit_test.go`), asserts both series render
  with the identical value on every `/metrics` scrape. `docs/operator/scan-capacity-and-timeouts.md`'s
  signal table gains one clause directing new dashboards/alert rules at the canonical `culvert_clamav_*`
  name; the existing `stat_clam_scan_error` status-API field name, the `scan_clam_error` alert name, and
  the PromQL examples in that runbook are left as-is (out of this finding's scope, and each has its own
  existing-consumer compatibility cost that a metric-name dual-emit does not).
- **Verification:** `go build ./...` clean, `go vet ./...` clean, `gofmt -l` clean on both touched Go
  files, `go test -run TestMetrics_ClamAVScanErrorsDualEmit -v .` passes.
- **Affected code:** `metrics.go`.
- **Affected API:** `GET /metrics` (additive series; `culvert_clam_scan_errors_total` unchanged).
- **Affected GUI:** none (the Security → Content Scanning panel reads the JSON status API, not
  `/metrics`, for this tile).
- **Affected Documentation:** `docs/operator/scan-capacity-and-timeouts.md` (one clause added to the
  signal table).
- **Affected Configuration:** none.
- **Migration Complexity:** Trivial (additive Prometheus series, zero breaking change).
- **Compatibility Risk:** None.
- **Estimated PR Size:** Small.
- **Priority:** Low-Medium (matches the finding's priority since it was first raised on 2026-08-01 —
  real but narrow drift, on a metric with no known external dashboard dependency at the time it was
  opened).

---

## Carried-Over Findings (unchanged)

Fourteen previously-open finding IDs remain open and unchanged this pass: T-9, T-11, T-12, T-13
(residual), T-17, T-18, T-21 + T-32 (paired), T-25 (residual), T-29, T-30, T-33, T-34, T-39. None of their
dependent files intersected this window's changed-file list (T-31's own intersection is addressed above).
Full descriptions remain in the reports where each was first raised and in
`TERMINOLOGY-GOVERNANCE-REVIEW-2026-08-25.md`'s carry-over list, to avoid duplicating unchanged text.

---

## Recommended Refactoring Plan (priority order)

Unchanged from 08-25 for the still-open carry-over items; T-31 is resolved in this pass and no longer
appears on the plan.

| Priority | Finding | Action | Migration risk | Est. PR size |
|---|---|---|---|---|
| Medium-High | T-39 (carried over) | Decide the QUAL-2/3 bootstrap-fleet name and the QUAL-4 policy-source name; rename `qualification_inventory_file`/`qualification_telemetry`/`qualification_policy_file` and their operator-doc titles/GUI strings away from bare "qualification"; reserve that word for the Production receipt gate | Medium | Small-Medium (needs a naming decision first) |
| Medium | T-18 (carried over) | Rename `internal/sealbox.Seal`/`Open` to name the trust property; relabel GUI; rename the audit-event string | Low | Small-Medium |
| Medium | T-21 + T-32 (carried pairing) | Rename Cluster panel's `cp_version` and F3b's `snapshot_sha256` to unambiguous, non-colliding names | Low | Small |
| Medium | T-17 (carried over) | Alias `decryption_redact_hosts`/`/api/decryption/redaction` to traffic-destination-scoped names | Medium | Medium |
| Medium | T-29 (carried over) | Alias YAML/CLI `rate_limit`/`-rate-limit` to accept `rate_limit_rpm` as well | Low-Medium | Small |
| Medium | T-30 (carried over) | Alias YAML `max_conns_per_ip` / wire `MaxConnsPerIP` toward `conn_limit_max_per_ip` | Low-Medium | Small |
| Medium | T-33 (carried over) | Stop overwriting `PolicyAction`/`PolicyReason` for pre-/post-policy gate failures; add a dedicated field for those instead | None today (zero production consumers); rises once a consumer exists | Small |
| Medium | T-25 residual (carried over) | Unify or cross-validate the M5 recipient registry and M6 TAC-trust-key store | Medium | Small-Medium |
| Medium | T-9 (carried over) | Rename `exportedAt` → `capturedAt` with read-compat alias | Low-medium | Medium |
| Medium | T-11 (carried over) | Reconcile `allow`/`deny` default-action vocabulary vs. the four-value `PolicyAction` enum | Low / Medium-large | Small / Medium-large |
| Medium | T-12 (carried over) | Alias Maintenance Agent wire routes `/v1/upgrades/*` → `/v1/updates/*` | Medium | Medium |
| Low | T-34 (carried over) | Standardize `apiURLCatFeedStatus`'s SaaS block field names on the F3b-4 status endpoint's vocabulary | Low | Small |
| Low | T-13 residual (carried over) | Decide whether README/enterprise-doc "TLS Inspection" branding should unify with in-app "SSL" | Low | Small |

Also still queued (process-level, not a mechanical rename): the ADR-number reservation convention
recommended in the 2026-08-25 review.

---

## Stop-Condition Assessment

Terminology is **not** fully consistent. This pass found no new drift in a large, fast-moving window
(MCP Shadow-execution hardening — internally consistent naming throughout, confirmed by reading rather
than by name-matching) and fixed one long-queued Low-Medium backlog item (T-31) at zero migration risk and
zero compatibility impact, following the same additive-dual-emit precedent T-38 established. Fourteen
still-open carry-over findings were re-confirmed unchanged. No cosmetic or preference-driven renames were
proposed.
