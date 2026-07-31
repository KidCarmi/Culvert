# Feed Source Reconciliation — Decision Package

**Status:** ✅ **APPROVED — owner decisions recorded (2026-07-31).** Dispositions
below are the approved plan; the dataset edits are applied in the following
implementation commit. This document turns the readiness conflicts in the embedded
SaaS dataset (`internal/urlcat/default_categories.json`) into an explicit,
per-conflict decision table that makes the dataset `Ready == true`.

> **Scope:** dataset-source reconciliation only. No runtime wiring, no F3a/F3b/F5,
> no engine change, no Sigstore/protocol change, no publication.

## Owner approval (recorded 2026-07-31)

- **Groups A–D, E, N** — approved as recommended (mechanical / suffix-constrained /
  bare-suffix).
- **Groups F–M** — approved as recommended in §4, with the explicit calls:
  - CRM/Marketing, Productivity/PM, Messaging/Video/Teams → recommended canonical.
  - **Elastic, Splunk, SonarQube → the security-oriented assignment.** This makes
    all three **Security Tools**. For Splunk and SonarQube that matches §4's
    recommendation; **for Elastic this is a DEVIATION** from §4's recommended
    `Analytics` — the owner's explicit "security-oriented" instruction governs.
    Recorded as a projection deviation (§5).
  - Replit → Dev Tools.
  - **Amazon** → narrow retail to `www.amazon.com`, keep AWS = Cloud Infrastructure
    (anti-overblock takes priority over matching the apex).
  - **GitHub Copilot** → Dev Tools (via `github.com`); loss of a separate AI signal
    accepted.
  - **Path values** (`google.com/travel`, `linkedin.com/learning`) → removed, NOT
    broadened to parent domains.
  - `nhs.uk` → `www.nhs.uk`; bare `s3.amazonaws.com` → removed.

---

## 1. Verified current inventory (independently reproduced)

Reproduced from a clean `origin/main` (PR #975 merged, commit `ea17b87`) by running
`urlcatfeed.EvaluateReadiness` over the embedded dataset:

```
READY=false  raw=662  unique=625  | invalid=4  multi=32  suffix=6  catname=0  structural=0
```

| Metric | Value | Matches prior doc? |
|---|---|---|
| Raw host entries | 662 | ✅ |
| Unique normalized hosts | 625 | ✅ |
| Categories | 21 | ✅ |
| **Invalid hosts** | **4** | ✅ |
| **Multi-category hosts** | **32** | ✅ |
| **Ancestor/descendant suffix conflicts** | **6** | ✅ |
| Category-name violations | 0 | ✅ |
| Generator-parity structural issues | 0 | ✅ |

**No discrepancy.** Counts are byte-for-byte identical to the committed inventory
(the pinned test `TestSourceDatasetReadiness` asserts 4/32/6/0/0). Reproduce with
`go test ./internal/urlcatfeed/ -run TestSourceDatasetReadiness -v`.

---

## 2. Engine constraints that bound every decision

Confirmed against `policy.go:matchCategory` → `urlcat.Store.MatchesHost` (unchanged
in `main`):

1. **One host = exactly one category.** The engine does **independent per-category
   suffix membership**, so a host in two categories is matched by both — there is
   no primary. We do **not** add longest-match / first-match / priority / winner-
   picking, and we do **not** modify the engine to accommodate source data.
2. **A suffix descendant PINS its ancestor's category.** Because `example.com`
   suffix-matches `sub.example.com`, if `sub.example.com` is category X then
   `example.com` must also be X (or the child must move). This makes **3 of the 6**
   suffix conflicts *constrained* (the parent's category is forced by an existing
   child), and it constrains the corresponding multi-category parent decisions.
3. **Whole-candidate rejection is preserved.** The published feed stays
   deterministic and fail-closed; `Ready` must mean "`Generate` will succeed."
4. **Avoid broad parent-domain categories.** A bare parent (`amazon.com`,
   `github.com`) suffix-captures unrelated subdomains — the source of the
   cross-product conflicts below. Resolutions prefer narrow, specific hosts.

---

## 3. Decision tables (one row per conflict)

Disposition legend: **REASSIGN** (pick one of its current categories) ·
**RECAT** (assign a category not currently listed) · **REPLACE** (swap the entry
for a specific host) · **REMOVE**. "Approval" = whether the choice is a genuine
product judgment (⚠) vs. mechanical/constrained (—).

### 3A. Multi-category hosts (32)

**Group M1 — Password/secrets managers → Security Tools** (mechanical)

| Raw entry | Normalized | Current | Recommended | Proposed | Alt | Approval |
|---|---|---|---|---|---|---|
| 1password.com | 1password.com | Productivity \| Security Tools | REASSIGN | **Security Tools** | Productivity | — |
| bitwarden.com | bitwarden.com | Productivity \| Security Tools | REASSIGN | **Security Tools** | Productivity | — |
| lastpass.com | lastpass.com | Productivity \| Security Tools | REASSIGN | **Security Tools** | Productivity | — |

**Group M2 — App-hosting / PaaS → Cloud Infrastructure** (mechanical)

| Raw entry | Normalized | Current | Recommended | Proposed | Alt | Approval |
|---|---|---|---|---|---|---|
| fly.io | fly.io | Cloud Infrastructure \| Dev Tools | REASSIGN | **Cloud Infrastructure** | Dev Tools | — |
| heroku.com | heroku.com | Cloud Infrastructure \| Dev Tools | REASSIGN | **Cloud Infrastructure** | Dev Tools | — |
| netlify.com | netlify.com | Cloud Infrastructure \| Dev Tools | REASSIGN | **Cloud Infrastructure** | Dev Tools | — |
| railway.app | railway.app | Cloud Infrastructure \| Dev Tools | REASSIGN | **Cloud Infrastructure** | Dev Tools | — |
| render.com | render.com | Cloud Infrastructure \| Dev Tools | REASSIGN | **Cloud Infrastructure** | Dev Tools | — |
| vercel.com | vercel.com | Cloud Infrastructure \| Dev Tools | REASSIGN | **Cloud Infrastructure** | Dev Tools | — |

**Group M3 — iPaaS / workflow automation → Automation & Integration** (mechanical)

| Raw entry | Normalized | Current | Recommended | Proposed | Alt | Approval |
|---|---|---|---|---|---|---|
| ifttt.com | ifttt.com | Automation & Integration \| Productivity | REASSIGN | **Automation & Integration** | Productivity | — |
| make.com | make.com | Automation & Integration \| Productivity | REASSIGN | **Automation & Integration** | Productivity | — |
| n8n.io | n8n.io | Automation & Integration \| Productivity | REASSIGN | **Automation & Integration** | Productivity | — |
| zapier.com | zapier.com | Automation & Integration \| Productivity | REASSIGN | **Automation & Integration** | Productivity | — |

**Group M4 — Clear single-category** (mechanical)

| Raw entry | Normalized | Current | Recommended | Proposed | Alt | Approval |
|---|---|---|---|---|---|---|
| grafana.com | grafana.com | Analytics \| Dev Tools | REASSIGN | **Analytics** | Dev Tools | — |
| salesforce.com | salesforce.com | CRM \| Marketing | REASSIGN | **CRM** | Marketing | — |
| todoist.com | todoist.com | Productivity \| Project Management | REASSIGN | **Productivity** | Project Management | — |
| docs.google.com | docs.google.com | Cloud Storage \| Productivity | REASSIGN | **Productivity** | Cloud Storage | — |

**Group M5 — Suffix-CONSTRAINED parents** (forced by an existing child; §2.2)

| Raw entry | Normalized | Current | Recommended | Proposed | Forced by | Approval |
|---|---|---|---|---|---|---|
| confluence.atlassian.com | confluence.atlassian.com | Productivity \| Project Management | REASSIGN | **Project Management** | `atlassian.com`=PM | — (constrained) |
| hubspot.com | hubspot.com | Marketing \| CRM | REASSIGN | **CRM** | `app.hubspot.com`=CRM | — (constrained) |
| cloudflare.com | cloudflare.com | Cloud Infrastructure \| Security Tools | REASSIGN | **Cloud Infrastructure** | `dash.cloudflare.com`=Cloud Infra | — (constrained) |

> These three also close suffix conflicts #1, #3, #6 (§3B). Choosing the other
> category would create a fresh suffix conflict with the pinning child, so they are
> effectively decided — unless the owner also moves the child.

**Group M6 — Genuine product judgment (⚠ owner decision; recommendation given)**

| Raw entry | Normalized | Current | Recommended | Proposed | Alternative | Approval |
|---|---|---|---|---|---|---|
| intercom.com | intercom.com | CRM \| Marketing | REASSIGN | **CRM** | Marketing | ⚠ |
| drift.com | drift.com | CRM \| Marketing | REASSIGN | **Marketing** | CRM | ⚠ |
| monday.com | monday.com | CRM \| Project Management | REASSIGN | **Project Management** | CRM | ⚠ |
| airtable.com | airtable.com | Productivity \| Project Management | REASSIGN | **Productivity** | Project Management | ⚠ |
| notion.com | notion.com | Productivity \| Project Management | REASSIGN | **Productivity** | Project Management | ⚠ |
| notion.so | notion.so | Productivity \| Project Management | REASSIGN | **Productivity** | Project Management | ⚠ |
| teams.microsoft.com | teams.microsoft.com | Messaging \| Video Conferencing | REASSIGN | **Video Conferencing** | Messaging | ⚠ |
| teams.live.com | teams.live.com | Messaging \| Video Conferencing | REASSIGN | **Video Conferencing** | Messaging | ⚠ |
| replit.com | replit.com | AI \| Dev Tools | REASSIGN | **Dev Tools** | AI | ⚠ |
| elastic.co | elastic.co | Analytics \| Dev Tools \| Security Tools | REASSIGN | **Security Tools** (owner override; §4 recommended Analytics — see §5 deviation) | Analytics | ⚠ approved |
| splunk.com | splunk.com | Analytics \| Security Tools | REASSIGN | **Security Tools** | Analytics | ⚠ approved |
| sonarqube.org | sonarqube.org | Dev Tools \| Security Tools | REASSIGN | **Security Tools** | Dev Tools | ⚠ approved |

Per-group narrative for §3A:
- **Security impact:** none of these change the trust model; they change *which*
  policy category a host falls under. Mis-categorizing a security product (M1) as
  Productivity would let a "block Productivity" rule miss it and a "allow Security
  Tools" rule not cover it — so M1 → Security Tools is the safer, expected mapping.
- **Admin UX:** enterprise admins expect one predictable category per SaaS host. A
  host silently in two categories today means a rule targeting either category
  matches it — surprising and hard to reason about. Single-category removes that.
- **Breadth/overblocking:** all M-group hosts are specific (no bare parents), so no
  overblocking risk from these reassignments.
- **Rationale:** M1–M4 map each host to its dominant, industry-standard function.
  M5 is forced by the suffix child. M6 are the genuine blends (CRM↔Marketing,
  chat↔meetings, docs↔work-mgmt, IDE↔AI, observability↔SIEM) where the owner should
  confirm; the recommendation picks the vendor's primary positioning.

### 3B. Ancestor/descendant suffix conflicts (6)

| # | Descendant {cat} under Ancestor {cats} | Type | Recommended | Proposed | Alternative | Approval |
|---|---|---|---|---|---|---|
| 1 | app.hubspot.com{CRM} under hubspot.com{CRM,Marketing} | parent multi-cat | resolve parent | **hubspot.com → CRM** (M5); child unchanged | recat app.hubspot.com | — |
| 3 | confluence.atlassian.com{Prod,PM} under atlassian.com{PM} | child multi-cat | resolve child | **confluence.atlassian.com → PM** (M5) | move atlassian.com | — |
| 6 | dash.cloudflare.com{Cloud Infra} under cloudflare.com{Cloud Infra,Sec} | parent multi-cat | resolve parent | **cloudflare.com → Cloud Infra** (M5); child unchanged (redundant, may prune) | recat dash | — |
| 2 | aws.amazon.com{Cloud Infra} under amazon.com{E-Commerce} | **cross-product** | REPLACE parent | **amazon.com → www.amazon.com** (E-Commerce); keep aws.amazon.com = Cloud Infra | REMOVE aws.amazon.com (lose AWS infra signal) | ⚠ |
| 4 | console.aws.amazon.com{Cloud Infra} under amazon.com{E-Commerce} | **cross-product** | (same as #2) | resolved by the amazon.com→www.amazon.com replace | REMOVE console.aws.amazon.com | ⚠ |
| 5 | copilot.github.com{AI} under github.com{Dev Tools} | **cross-product** | REMOVE child | **REMOVE copilot.github.com** → Copilot classified Dev Tools via github.com | recat copilot → Dev Tools (identical effect) | ⚠ |

Narrative for §3B:
- **#1/#3/#6 are mechanically closed** by the M5 parent/child reassignments — no
  separate decision.
- **#2/#4 (Amazon):** `amazon.com` as a bare parent (E-Commerce) suffix-captures
  `aws.amazon.com` and `console.aws.amazon.com` — a broad-parent overblock and the
  direct cause of the conflict. **Recommended: replace `amazon.com` with
  `www.amazon.com`** (the actual retail host). `www.amazon.com` and `aws.amazon.com`
  are siblings (neither is a suffix of the other), so E-Commerce keeps the Amazon
  retail signal for the main site **and** AWS stays Cloud Infrastructure — both
  signals preserved, overblock removed. *Coverage note:* bare `amazon.com` typed by
  a user (no `www`) would no longer match E-Commerce; regional retail domains
  (`amazon.co.uk`, …) are separate hosts and out of scope here. **Owner: confirm the
  retail signal narrowing to `www.amazon.com` is acceptable.**
- **#5 (Copilot):** an AI signal for a subdomain of a Dev-Tools parent is **not
  expressible** under one-category + suffix matching (github.com suffix-matches
  copilot.github.com regardless). **Recommended: remove `copilot.github.com`** — it
  is redundant (already Dev Tools via `github.com`). *Coverage note:* GitHub Copilot
  traffic is classified **Dev Tools**, not AI. Flagging Copilot as AI would require
  an engine change (out of scope) or de-categorizing `github.com` (not viable). **Owner:
  confirm Copilot = Dev Tools.**
- **Security/UX/breadth:** the amazon.com replace is the key *anti-overblock* fix.
  Removing `copilot.github.com` and the bare-suffix entries (§3C) all reduce
  breadth; none weakens the trust model.

### 3C. Invalid host entries (4)

| Raw entry | Valid host? | Category | Type | Recommended | Proposed | Alternative | Approval |
|---|---|---|---|---|---|---|---|
| google.com/travel | no (URL path) | Travel | path value | REMOVE | drop the entry | host-only `travel.google.com` **only if** it is a real, non-conflicting host (Google Travel lives at `google.com/travel`, so no clean host) | ⚠ |
| linkedin.com/learning | no (URL path) | Education | path value | REMOVE | drop the entry | host-only equivalent (LinkedIn Learning is `linkedin.com/learning`; no clean host) | ⚠ |
| nhs.uk | no (public suffix) | Health | bare PSL suffix | REPLACE | **`www.nhs.uk`** (Health) | drop the entry | — |
| s3.amazonaws.com | no (PSL private suffix) | Cloud Infrastructure | bare suffix | REMOVE | drop the entry | a concrete host (bare suffix over-matches every S3 bucket) | ⚠ |

Narrative for §3C:
- **Do NOT convert path values to broad parent hosts.** `google.com/travel` →
  `google.com` would classify **all of Google** as Travel (massive overblock);
  `linkedin.com/learning` → `linkedin.com` would classify all LinkedIn as Education.
  Both are **removed**, not expanded. *Coverage loss:* Travel loses its Google Travel
  entry (16 other Travel hosts remain); Education loses LinkedIn Learning (25 remain).
- **`nhs.uk`** is a UK public-suffix registry entry, not a host; the intended target
  is the NHS website **`www.nhs.uk`** — a safe, specific replacement.
- **`s3.amazonaws.com`** is a PSL private-domain suffix; a bare-suffix entry would
  match every `<bucket>.s3.amazonaws.com`. It is infrastructure plumbing, not a
  categorizable SaaS destination — **removed** (Cloud Infra retains 35 hosts, incl.
  `aws.amazon.com`).

---

## 4. Consolidated approval (grouped)

| # | Decision group | Items | Recommendation | Needs explicit approval? |
|---|---|---|---|---|
| A | Password managers → Security Tools | 1password, bitwarden, lastpass | as recommended | Batch-approve (mechanical) |
| B | PaaS hosting → Cloud Infrastructure | fly.io, heroku, netlify, railway, render, vercel | as recommended | Batch-approve (mechanical) |
| C | iPaaS → Automation & Integration | ifttt, make, n8n, zapier | as recommended | Batch-approve (mechanical) |
| D | Clear single | grafana→Analytics, salesforce→CRM, todoist→Productivity, docs.google.com→Productivity | as recommended | Batch-approve (mechanical) |
| E | Suffix-constrained parents | hubspot.com→CRM, confluence.atlassian.com→PM, cloudflare.com→Cloud Infra | forced by child | Confirm (closes 3 suffix conflicts) |
| F | CRM ↔ Marketing / PM blends | intercom→CRM, drift→Marketing, monday→PM | recommendation given | ⚠ Explicit |
| G | Productivity ↔ PM | airtable, notion.com, notion.so → Productivity | recommendation given | ⚠ Explicit |
| H | Messaging ↔ Video | teams.microsoft.com, teams.live.com → Video Conferencing | recommendation given | ⚠ Explicit |
| I | Analytics ↔ Security ↔ Dev | elastic→Analytics, splunk→Security Tools, sonarqube→Security Tools | recommendation given | ⚠ Explicit |
| J | AI ↔ Dev | replit→Dev Tools | recommendation given | ⚠ Explicit |
| K | Amazon retail vs AWS | amazon.com → www.amazon.com; keep aws/console = Cloud Infra | recommendation given | ⚠ Explicit (retail narrowing) |
| L | GitHub Copilot | remove copilot.github.com (→ Dev Tools via github.com) | recommendation given | ⚠ Explicit (AI signal lost) |
| M | Path values | remove google.com/travel, linkedin.com/learning | recommendation given | ⚠ Explicit (coverage loss) |
| N | Bare suffixes | nhs.uk → www.nhs.uk; remove s3.amazonaws.com | as recommended | Confirm |

**Owner action:** batch-approve A–D (and confirm E, N); make an explicit call on
F–M (the recommendation is the default if you approve without changes).

---

## 5. Projected post-resolution readiness

Assuming every recommendation is accepted:

| Metric | Current | Projected | Δ |
|---|---|---|---|
| Invalid hosts | 4 | **0** | −4 |
| Multi-category hosts | 32 | **0** | −32 |
| Suffix conflicts | 6 | **0** | −6 |
| Category-name / structural | 0 / 0 | 0 / 0 | 0 |
| Unique valid hosts | 625 | **≈625** | ≈0 |
| Raw entries | 662 | **≈625** | −37 |
| Categories | 21 | 21 | 0 |
| **`Ready`** | **false** | **true** | ✅ |

Unique-host arithmetic: −1 `amazon.com` +1 `www.amazon.com` (replace) · +1
`www.nhs.uk` (replaces invalid `nhs.uk`) · −1 `copilot.github.com` (remove) · path
values and `s3.amazonaws.com` were never valid (no effect on the 625). Net ≈ 0 →
**~625 unique hosts, each in exactly one category (raw == unique).** (If the owner
chooses the AWS-remove alternative in K instead, unique drops by ~2.)

---

## 6. Coverage loss & behavioral change

- **Travel** loses Google Travel; **Education** loses LinkedIn Learning (path values,
  no host-only equivalent).
- **E-Commerce**: Amazon retail narrows from bare `amazon.com` to `www.amazon.com`;
  AWS is no longer mis-classified as E-Commerce (the fix).
- **Cloud Infrastructure** loses the `s3.amazonaws.com` bare suffix (overblock removed).
- **AI** loses `copilot.github.com`; Copilot classified **Dev Tools**.
- **Secondary signals dropped** for the 32 multi-category hosts (e.g. `cloudflare.com`
  no longer also Security Tools; `splunk.com`'s non-chosen category dropped). This is
  the intended effect of one-host-one-category.
- **Net behavior:** narrower, deterministic, predictable single-category classification;
  no broad-parent overblocking; trust model, determinism, and fail-closed rejection
  unchanged.

---

## 7. Acceptance criteria for the later implementation PR

The implementation PR (separate, owner-approved; edits the source dataset only) is
DONE when:

1. `urlcatfeed.EvaluateReadiness(<dataset>).Ready == true`.
2. **Zero** invalid hosts.
3. **Zero** multi-category assignments (every host in exactly one category).
4. **Zero** ancestor/descendant suffix conflicts.
5. `TestSourceDatasetReadiness` is flipped from asserting the 4/32/6/0/0 inventory to
   asserting `Ready == true` (the pinned not-ready gate becomes the ready gate).
6. Deterministic generation tests remain green
   (`TestGenerate_Deterministic_RepeatedAndShuffled`, `TestCanonical_Golden`).
7. Full repository gates remain green: `go test ./...`, `-race`, determinism,
   `golangci-lint`, `staticcheck`, govulncheck+gosec, gitleaks, CodeQL, Snyk.

**No engine change, no fallback/unsigned behavior, no Sigstore identity/issuer/SAN/
root/protocol change** is permitted to reach these criteria — only source-dataset
edits per the approved dispositions above.

---

## 8. Prior report (superseded)

This decision package supersedes the earlier narrative inventory. The underlying
conflict facts (32 multi / 6 suffix / 4 invalid) are unchanged and independently
re-verified (§1); this revision adds per-conflict dispositions, the suffix-constraint
analysis, the consolidated approval grouping, projected counts, and acceptance
criteria.
