# Policy Learning Mode

Policy Learning Mode (`internal/policylearn`, ADR-0025) is a **non-enforcing**
observation mode that watches allowed and blocked traffic during an explicit
session and proposes candidate Allow rules for policy design — closing the
"how do I stage a new access policy" gap (GAP-POL-01) without giving the
feature any path to change enforcement itself.

It never blocks, allows, rewrites, or reorders anything on its own. Every
output is a **born-disabled** rule (`Enabled: false`) placed in the [Policy
Draft](../enterprise/POLICY-ROLLOUT-GUIDE.md) candidate, where the existing
review → dry-run → commit workflow is the only way it can ever take effect.

## Enabling it

Enablement is a **governed admin surface only** — there is deliberately no
YAML key, CLI flag, or environment variable for it:

- `GET /api/policy-learning` — status (viewer)
- `GET`/`PUT /api/policy-learning/config` — enable/disable + guardrail
  (viewer read, **admin** write)

GUI: **Policy Learning** panel in the sidebar (`Enable Policy Learning`
button, admin-only).

**Enabling ≠ observing.** Turning the feature on only constructs the engine;
no traffic is observed until an operator explicitly starts a Learning
session (below). Enabling with no active session costs one atomic nil-check
on the request path.

**Durability is split, deliberately:**

| State | Where | Config-surface exposure |
|---|---|---|
| Enabled flag + recommendable-category guardrail | `admin_settings.json` (`PolicyLearningSaved` sentinel) | **Node-local only** — off export/import, off config-version rollback, off CP→DP sync |
| Sessions, aggregated evidence, recommendations, subject-pseudonymization key | `<dataDir>/policy_learning.json` + `<dataDir>/policy_learning_subject.key` | Never governed or synced, regardless of the sentinel above |

Disabling the feature while a session is active is refused (`409`).
Disabling never deletes on-disk state — it only stops the engine.

## Running a session

`POST /api/policy-learning/session` with `{"action": "start"|"complete"|"cancel"}`
(operator+), or the **Start Learning** / **Complete Learning** / **Cancel
Session** buttons in the GUI.

- Only **one session may be active at a time** on a node.
- A session auto-completes after 90 days if never stopped manually
  (`StoppedBy: "system:max-duration"`).
- Up to 8 terminal (completed/cancelled) sessions are retained per node;
  older ones are pruned FIFO.
- Recommendations are generated per-session, on demand, from a
  **completed** session only (`POST /api/policy-learning/recommendations/generate`,
  operator+, or the **Generate Recommendations** button on a completed
  session's row).

## What is observed

Per policy decision, while a session is active: the resolved **subject**
(pseudonymized before persistence — see below), auth source, groups
(bounded to 16 per observation), the **normalized destination host**, method,
matched rule, action, and SSL action.

**Deliberately never observed or persisted:** URLs, paths, query strings,
headers, bodies, cookies, credentials, client IP, or any open-ended
metadata. Unauthenticated/exempt traffic contributes no group evidence.

**Blocked traffic contributes zero positive evidence.** A blocked or
threat-blocked request counts only as a request count — it can never raise
confidence, and there is no field for "blocked users."

Raw subjects are never written to disk. The durable store holds only an
HMAC-SHA256 token derived from `(AuthSource, Subject)` under a node-local
key (`policy_learning_subject.key`) — losing or rotating that key is a
recorded degradation (`subject_key_changed`), never a silent merge across
subject populations.

## Recommendations and confidence

Each recommendation proposes **one** rule for an observed group × category
pair:

```
Action:       Allow
SSLAction:    Inspect
Enabled:      false
SourceGroup:  <observed group>
DestCategory: <observed category>
```

Confidence is **HIGH / MEDIUM / LOW** from named, disclosed predicates —
never a composite score:

| Confidence | Requires |
|---|---|
| HIGH | ≥30 allowed requests **and** ≥5 distinct subjects **and** ≥5 distinct days |
| MEDIUM | ≥5 allowed requests **and** ≥2 distinct subjects **and** ≥2 distinct days |
| LOW | anything below MEDIUM |

Volume alone can never reach HIGH — the distinct-subject and distinct-day
gates are structural. HIGH is additionally capped down to MEDIUM (never
lower) when the session had transport loss, a restart gap, category-taxonomy
churn/overflow, a policy-content change mid-session, or a strict majority of
the evidence resolved through a community/UT1-tier category. Thresholds are
fixed in this release (not admin-editable) and are surfaced verbatim on
every recommendation and via `GET /api/policy-learning`
(`recommendation_policy`).

**Coverage** (subjects/days/hosts observed, transport loss) is reported
separately from confidence, as facts — there is no percentage/"membership"
field, because the true population denominator is never known.

A recommendation goes **stale** — flagged, not deleted — when the policy
rulebase, the category taxonomy, the recommendable-category guardrail, or
the decision-policy thresholds it was generated against have since changed.
Staleness is recomputed by the server on every read.

## Accepting a recommendation

`POST /api/policy-learning/recommendations` with
`{"id", "action": "accept"|"reject", "if_version", "reason"?}`, or the
**Accept to Draft** / **Reject** buttons on a recommendation card.

- **Accept requires `RoleAdmin`** (a stricter check than the endpoint's
  operator floor — Reject only needs operator). `if_version` is a required
  optimistic-lock fence against the current policy version.
- Accept is refused with `409` unless Policy Draft mode is armed
  (`RequireCommit`). It writes **only** into the draft candidate — never the
  running rulebase — via the single translator that owns this boundary
  (`plTranslateRecommendation`), which fixes `Action=Allow`,
  `SSLAction=Inspect`, `Enabled=false` on every accepted rule regardless of
  any other field.
- Accept is idempotent under retry: reconciliation on the next admin call
  finalizes a durably-written rule rather than duplicating it, and never
  latches "accepted" without proof the rule exists on disk.
- Reject latches the recommendation as rejected with a bounded, sanitized
  reason. It performs no policy or config mutation.

Accepting a recommendation does **not** enable the rule or commit the
draft — both remain deliberate, separate steps in the existing [Policy
Draft workflow](../enterprise/POLICY-ROLLOUT-GUIDE.md).

## Bounds

All bounds are counted and surfaced on overflow — evidence is only ever
allowed to *undercount*, never inflate:

| Bound | Value |
|---|---|
| Groups per observation | 16 |
| Aggregation cells per session | 8,192 |
| Subjects per cell | 512 |
| Subject tokens, session-wide | 65,536 |
| Distinct days tracked per cell | 92 |
| Top hosts / rule-hits / tier-hits per cell | 10 / 8 / 8 |
| Recommendations per generation | 64 |
| Recommendations retained (durable) | 256 (superseded evicted first) |
| Sessions retained | 8 |

## Guardrail: recommendable categories

`GET`/`PUT /api/policy-learning/config` (admin write), or the
**Recommendable Categories** panel. This is a **fail-closed allowlist**:
only listed category names can ever be recommended, and an admin-set
**empty** list means nothing is recommendable — there is no denylist mode.
Until governed, it is seeded from the built-in business-category set.
Changing it changes recommendations' identity, so existing recommendations
go stale; it is refused while a session is active.

## RBAC summary

| Action | Minimum role |
|---|---|
| View status / sessions / recommendations | Viewer |
| Enable / disable / edit guardrail | Admin |
| Start / stop / cancel session, generate recommendations, reject | Operator |
| **Accept a recommendation to draft** | **Admin** |

## Related

- `docs/adr/0025-policy-learning-advisory-boundary.md` — architecture
  rationale and the advisory-boundary threat model.
- `docs/enterprise/POLICY-ROLLOUT-GUIDE.md` — the Policy Draft/commit
  workflow that accepted recommendations feed into.
