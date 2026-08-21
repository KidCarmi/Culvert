# Policy Rollout Guide

Deploying egress policy safely: the model, staged rollout, validation, rollback, and test→prod promotion — with the gaps that shape a safe rollout.

> **Enterprise-readiness verdict:** **Policy engine, candidate/commit Draft Mode, draft-aware dry-run testing, rollback, and export/import promotion are production-ready. Safe staged rollout is still weak** — there is no monitor-only enforcement mode (GAP-POL-01) and no node-scoped targeting (GAP-POL-02), so pilots must be expressed as user/IP populations and enforcement is all-or-nothing per rule. A non-enforcing **Policy Learning Mode** (ADR-0025) ships today and helps *design* the pilot's allow rules from observed traffic, but it is not a monitor-only enforcement mode itself — see [`docs/operator/policy-learning-mode.md`](../operator/policy-learning-mode.md).

---

## 1. Policy model

- **Structure:** priority-ordered rules; each rule ANDs any of 8 match dimensions — Source IP/CIDR, authenticated identity, IdP group, auth source, destination FQDN (exact/wildcard), URL category / category group, destination country (GeoIP), time schedule (day/time/IANA tz).
- **Actions:** `Allow`, `Drop`, `Block_Page`, `Redirect`; each rule also carries `SSLAction` (`Inspect`/`Bypass`).
- **Evaluation:** priority-sorted, **first match wins**, empty field = "any" (`policy.go:638-689`).
- **Default-deny (Zero Trust):** no-match ⇒ deny once any rule exists or `default_action: deny` is set. A fresh install with zero rules and no explicit default starts in passthrough so you can't lock yourself out — **set `default_action: deny` (or `POST /api/default-action` with body `{"action":"deny"}`, operator role) for production.**
- **GeoIP fails closed:** unknown country does not match.
- **Conflict detection:** same-priority, different-action overlaps are surfaced as warnings (advisory, non-blocking).

## 2. Rule ordering & exceptions

- Priority via `POST /api/policy/reorder` (full) or `POST /api/policy/move` (relative), operator role; add auto-assigns/deconflicts priority.
- **Exceptions are pure ordering:** a higher-priority `Allow` short-circuits a lower-priority `Drop`. Express exceptions as narrow allow rules above the broad deny. There is no separate exception-list object.

## 3. Pilot / staged rollout — work around the gaps

> **⛔ GAP-POL-01 — no monitor-only enforcement.** A blocking rule always blocks; the per-rule `LogTraffic` flag only controls whether *allowed* traffic is logged. There is no observe-only mode that logs would-be blocks without blocking. **Recommended pilot pattern:**
> 1. Author the intended deny rules but set them to `Allow` + `LogTraffic=true`, scoped to a pilot population (see below).
> 2. Watch the live feed / request-log export for what those rules match.
> 3. When confident, flip the action to `Drop`/`Block_Page` and widen scope.
> This is laborious (edit every rule twice) but is the only safe observation path today.

> **⛔ GAP-POL-02 — no node-scoped rollout.** Policy has no node dimension; the Control Plane pushes the same ruleset to all Data Plane nodes (node-group labels drive bandwidth/QoS only). **Scope pilots by *population*, not by node:** `SourceIP`/CIDR (a pilot subnet), `SourceGroup` (a pilot AD/IdP group), or `SourceIdentity`. If you must canary by proxy *node*, that is unsupported — use a separate pilot appliance.

## 4. Validation before enforce

- **Policy Tester** (`POST /api/policy/test`, viewer role; GUI "Policy Tester") dry-runs a synthetic request `{sourceIP, identity, authSource, groups, host, protocol, method}` with no side effects, returning the first-match rule, action, a per-rule trace with skip reasons, and the Stage-1 auth outcome. It evaluates the **effective** ruleset — the draft candidate when Draft Mode is engaged, otherwise the running store — and the response carries a `rulebase: "draft" | "running"` indicator (see GAP-POL-03 below).

> **GAP-POL-03 — RESOLVED (ADR-0026 / F4).** The tester previously evaluated only the *running* store. It now evaluates `effectivePolicyList()`, so a candidate authored under Draft Mode is validated in place before commit; the `rulebase` field states which set was evaluated. The tester also adopts the canonical one-instant-per-evaluation schedule semantics (ADR-0026), fixing a narrow schedule-boundary divergence from the enforcement evaluator.

## 4a. Draft Mode — candidate/commit for rule content

- **Opt-in, per instance:** `PUT /api/policy/draft {require_commit: true}` (admin) arms Draft Mode. Default is off — behavior is byte-identical to the pre-draft direct-write model when disarmed.
- **Candidate/commit lifecycle:** while armed, every mutating policy handler writes to a **candidate** rulebase (a separate `policy_draft.json`), not the live store. Review the pending diff and any advisory rule-shadow findings on the draft panel, then `POST /api/policy/draft/commit` (operator, requires a comment) to atomically publish the candidate to the live store and record it as a config version; `POST /api/policy/draft/revert` discards it. See `docs/design/POLICY-DRAFT-DESIGN.md`.
- **Policy Learning Mode (ADR-0025, shipped):** accepted policy-learning recommendations land in this same candidate as disabled `Allow`/`Inspect` rules — commit remains the sole activation step. See [`docs/operator/policy-learning-mode.md`](../operator/policy-learning-mode.md).

## 5. Rollback

- Every config mutation auto-snapshots (`saveConfigVersion`); 50 versions kept.
- **Dry-run first:** `POST /api/config/versions {version:N, dry_run:true}` returns validation warnings + a field-level diff, applying nothing.
- **Roll back:** `POST /api/config/versions {version:N}` (admin) validates, then applies under lock with leaf-first dependency ordering, skipping invalid rules, and records the rollback as a new version + audit event. GUI: **Settings → Config Versions** with diff + typed-confirmation rollback.
- **Diff any two versions:** `GET /api/config/diff?from=N&to=M`.

> **GAP-POL-04 — whole-config rollback.** Rollback restores the *entire* config surface atomically — rolling back a bad policy also reverts unrelated changes since that version. Some fields (alert webhooks, block-page HTML, upstream proxies, conn-limit) are intentionally off the rollback surface. For **policy-only** movement use export/import (§6).

## 6. Test → production promotion

- **Export:** `GET /api/config/export?section=policy` (admin) — exports `PolicyRules` + `DefaultAction` (or `section=all`). Webhook secrets are redacted and must be re-entered in prod.
- **Import:** `POST /api/config/import?mode=merge|replace` (admin). Merge validates+appends (priority collisions auto-reassigned — use **replace** for a clean, identical promotion). Category taxonomy is applied leaf-first. **Import never wipes on empty** — a replace with zero rules does not clear prod (empty wipes are a rollback-only capability).
- Both audit and snapshot on completion.

**Recommended promotion flow:** author + Policy-Tester-validate on a test appliance → `export?section=policy` → `import?mode=replace` to prod → verify with Policy Tester on prod → snapshot.

## 7. Approval, ownership, emergency access

- **Approval workflow:** not built in. Use the export JSON as the change-control artifact (attach to the ticket); the config-version + audit trail is the after-the-fact record. Operator role can reorder/move/set default-action (`ui_policy.go:2009`); admin role gates import/rollback (`ui_config.go:915`, `configversion.go:162`) — use the role split to separate authoring from promotion.
- **Emergency access (open the gate fast):** `POST /api/default-action` with header `Content-Type: application/json` and body `{"action":"allow"}` (operator role) opens *unmatched* traffic; or a top-priority broad `Allow` rule. Revert via config-version rollback. (The handler decodes an `action` field and rejects anything other than `"allow"`/`"deny"` with 400 — `ui_policy.go:1363-1372`.)

## 8. Audit evidence

Every policy change (default-action, move, reorder, SSL-bypass, import, rollback) emits an `auditEvent` + a config version recording actor, action, and timestamp. Enable persistent audit (`-audit-log`) so this survives restarts.

## 9. Checklist

- [ ] `default_action: deny` set for production (Zero Trust enforced).
- [ ] Pilot scoped by IP/IdP-group; monitor via `Allow`+`LogTraffic` before flipping to enforce (GAP-POL-01 workaround).
- [ ] Rules validated with Policy Tester.
- [ ] Config snapshot taken before each change; rollback dry-run rehearsed.
- [ ] Promotion via `export?section=policy` → `import?mode=replace`.
- [ ] Role split (operator authors, admin promotes) in place; change tickets carry the export JSON.
