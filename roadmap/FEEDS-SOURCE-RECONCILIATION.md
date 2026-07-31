# Feeds Source Reconciliation — `internal/urlcat/default_categories.json`

**Status:** PRODUCT REVIEW REQUIRED. This report is the deterministic output of the
F1 readiness evaluator (`urlcatfeed.EvaluateReadiness`) run against the current
embedded SaaS dataset. **No category assignments are changed here.** The dataset is
**not publication-ready** under `signed_manifest_v1`, and F5 must be unable to
publish until it is.

> **Load-bearing engine constraint:** the policy engine
> (`policy.go:matchCategory` → `urlcat.MatchesHost`) does **independent
> per-category suffix matching** — a host can satisfy *multiple* categories at
> once, and there is **no** "primary category." The signed feed therefore requires
> **exactly one category per host** and **no ancestor/descendant host in a
> different category**. Multi-label categorization is **not supported** by the
> current engine; every conflict below must resolve to a single category.

## Summary (deterministic)

| Metric | Value |
|---|---|
| Raw host entries | 662 |
| Unique normalized hosts | 625 |
| Invalid hosts | 4 |
| Multi-category hosts | 32 |
| Ancestor/descendant suffix conflicts | 6 |
| Category-name violations | 0 |
| **Ready to publish** | **NO** |

Reproduce: `go test ./internal/urlcatfeed/ -run TestSourceDatasetReadiness -v`.

---

## 1. Invalid hosts (4) — not valid DNS hosts

| Host entry | Reason it violates the model | Proposed resolution | Product impact |
|---|---|---|---|
| `google.com/travel` | Contains a URL path — not a hostname; the feed carries hosts only. | **Remove** (host-only). `google.com` is too broad to categorize as "Travel"; a dedicated Travel host (e.g. `travel.google.com`) would work **only if** it is not already categorized elsewhere. Recommend **remove** pending a real Travel host. | Loss of a path-scoped "Travel" signal for Google Travel. Path-level categorization is out of scope for a host feed. |
| `linkedin.com/learning` | URL path, not a hostname. | **Remove**; if LinkedIn Learning needs a category, use a host-only entry (`learning.linkedin.com`) **only if** not conflicting. Recommend **remove**. | Loss of a path-scoped "Education" signal for LinkedIn Learning. |
| `nhs.uk` | `nhs.uk` is a **public suffix** (PSL) — a bare suffix would match essentially every `*.nhs.uk` host via the engine's suffix walk. | **Replace** with `www.nhs.uk` (the actual service host). | None material; the intended target (the NHS website) is `www.nhs.uk`. |
| `s3.amazonaws.com` | `s3.amazonaws.com` is a **PSL private-domain public suffix**; a bare-suffix entry over-matches every S3 bucket host. | **Remove** or replace with a concrete host. AWS S3 is infrastructure, not a categorizable SaaS destination at the suffix level. Recommend **remove** (already covered by `aws.amazon.com` intent — see §3). | None material. |

---

## 2. Multi-category hosts (32) — one host in >1 category

Each host below is assigned to two or more categories. The engine cannot express
that; each must collapse to **one** category. A **proposed primary** is given with a
one-line rationale. Rows marked **⚠ OWNER** are genuine product judgment calls where
the "best" category is not obvious and needs sign-off.

| Host | Current categories | Proposed primary | Rationale |
|---|---|---|---|
| `1password.com` | Productivity / Security Tools | **Security Tools** | A password manager is a security product. |
| `airtable.com` | Productivity / Project Management | **Productivity** ⚠ OWNER | Positioned as a database/productivity platform; PM is a use case. |
| `bitwarden.com` | Productivity / Security Tools | **Security Tools** | Password manager. |
| `cloudflare.com` | Cloud Infrastructure / Security Tools | **Cloud Infrastructure** ⚠ OWNER | Primary identity is edge/infra; security is a feature set. |
| `confluence.atlassian.com` | Productivity / Project Management | **Project Management** | Atlassian PM/collab suite (see suffix conflict §3). |
| `docs.google.com` | Cloud Storage / Productivity | **Productivity** | Document editing is productivity; storage is Drive. |
| `drift.com` | CRM / Marketing | **Marketing** ⚠ OWNER | Conversational marketing; overlaps CRM. |
| `elastic.co` | Analytics / Dev Tools / Security Tools | **Analytics** ⚠ OWNER | Search/observability core; SIEM + dev are extensions. |
| `fly.io` | Cloud Infrastructure / Dev Tools | **Cloud Infrastructure** | App-hosting platform. |
| `grafana.com` | Analytics / Dev Tools | **Analytics** | Observability/dashboards. |
| `heroku.com` | Cloud Infrastructure / Dev Tools | **Cloud Infrastructure** | PaaS hosting. |
| `hubspot.com` | CRM / Marketing | **CRM** ⚠ OWNER | CRM platform with a marketing suite (see suffix §3). |
| `ifttt.com` | Automation & Integration / Productivity | **Automation & Integration** | Integration automation. |
| `intercom.com` | CRM / Marketing | **CRM** ⚠ OWNER | Customer messaging/support. |
| `lastpass.com` | Productivity / Security Tools | **Security Tools** | Password manager. |
| `make.com` | Automation & Integration / Productivity | **Automation & Integration** | iPaaS automation. |
| `monday.com` | CRM / Project Management | **Project Management** ⚠ OWNER | Work-management platform. |
| `n8n.io` | Automation & Integration / Productivity | **Automation & Integration** | Workflow automation. |
| `netlify.com` | Cloud Infrastructure / Dev Tools | **Cloud Infrastructure** | Web hosting/deploy platform. |
| `notion.com` | Productivity / Project Management | **Productivity** ⚠ OWNER | Docs/notes core. |
| `notion.so` | Productivity / Project Management | **Productivity** ⚠ OWNER | Same product as `notion.com`. |
| `railway.app` | Cloud Infrastructure / Dev Tools | **Cloud Infrastructure** | App hosting. |
| `render.com` | Cloud Infrastructure / Dev Tools | **Cloud Infrastructure** | App hosting. |
| `replit.com` | AI / Dev Tools | **Dev Tools** ⚠ OWNER | Online IDE with AI features. |
| `salesforce.com` | CRM / Marketing | **CRM** | The canonical CRM. |
| `sonarqube.org` | Dev Tools / Security Tools | **Security Tools** ⚠ OWNER | Code-security scanning; used in dev. |
| `splunk.com` | Analytics / Security Tools | **Security Tools** ⚠ OWNER | SIEM-leaning; also analytics. |
| `teams.live.com` | Messaging / Video Conferencing | **Video Conferencing** ⚠ OWNER | Teams consumer meetings + chat. |
| `teams.microsoft.com` | Messaging / Video Conferencing | **Video Conferencing** ⚠ OWNER | Teams meetings + chat. |
| `todoist.com` | Productivity / Project Management | **Productivity** | Personal task manager. |
| `vercel.com` | Cloud Infrastructure / Dev Tools | **Cloud Infrastructure** | Frontend hosting/deploy. |
| `zapier.com` | Automation & Integration / Productivity | **Automation & Integration** | iPaaS automation. |

**11 rows are ⚠ OWNER** judgment calls (CRM-vs-Marketing, Messaging-vs-Video,
Productivity-vs-PM, infra-vs-security). These are the unresolved decisions in §5.

---

## 3. Ancestor/descendant suffix conflicts (6)

A host that is a proper DNS suffix of another must share its category (else the
engine's suffix walk yields ambiguous membership). Format: `descendant{cats}` under
`ancestor{cats}`.

| # | Conflict | Why it violates the model | Proposed resolution |
|---|---|---|---|
| 1 | `app.hubspot.com{CRM}` under `hubspot.com{CRM,Marketing}` | Ancestor is multi-category (§2) AND descendant differs. | Resolve `hubspot.com` → **CRM** (§2); then both are CRM → conflict gone. |
| 2 | `aws.amazon.com{Cloud Infrastructure}` under `amazon.com{E-Commerce}` | Descendant (AWS) is infra; ancestor (Amazon retail) is e-commerce; suffix walk fuses them. | **Keep both** but this requires the engine to prefer the more-specific host. Since it does NOT, **move `aws.amazon.com` handling to a longest-match exception is unavailable** → recommend the feed **drop `amazon.com`** as too broad, keep `aws.amazon.com` = Cloud Infrastructure. ⚠ OWNER (losing the Amazon-retail signal). |
| 3 | `confluence.atlassian.com{Productivity,Project Management}` under `atlassian.com{Project Management}` | Descendant multi-category (§2); once resolved to Project Management, matches ancestor. | Resolve `confluence.atlassian.com` → **Project Management** (§2) → conflict gone. |
| 4 | `console.aws.amazon.com{Cloud Infrastructure}` under `amazon.com{E-Commerce}` | Same as #2. | Same as #2 — drop broad `amazon.com`, keep AWS hosts = Cloud Infrastructure. ⚠ OWNER. |
| 5 | `copilot.github.com{AI}` under `github.com{Dev Tools}` | GitHub Copilot categorized AI; parent GitHub is Dev Tools; suffix fusion. | ⚠ OWNER: either **drop `copilot.github.com`** (let it inherit Dev Tools) or **accept** it as Dev Tools. Keeping a distinct AI signal for a subdomain of a Dev-Tools host is not expressible. |
| 6 | `dash.cloudflare.com{Cloud Infrastructure}` under `cloudflare.com{Cloud Infrastructure,Security Tools}` | Ancestor multi-category (§2). | Resolve `cloudflare.com` → **Cloud Infrastructure** (§2); then both infra → conflict gone. |

**Note:** the earlier review flagged 4 suffix conflicts (#2, #4, #5, and the
hubspot pair). The evaluator additionally surfaces #3 and #6 because it compares
full category **sets**, so a descendant under a *multi-category* ancestor is a
conflict until the ancestor is resolved. Resolving the §2 multi-category rows makes
#1, #3, #6 disappear automatically; only the genuine cross-product conflicts (#2,
#4, #5) need explicit product decisions.

---

## 4. Category names

**0 violations.** All 21 category names are valid UTF-8, NFC, trimmed, control-char
free, and within bounds under the F1 contract.

---

## 5. Unresolved decisions requiring owner approval

1. **11 multi-category primaries** marked ⚠ OWNER in §2 (CRM-vs-Marketing:
   drift/hubspot/intercom/salesforce·monday; Messaging-vs-Video: teams.*;
   Productivity-vs-PM: airtable/notion.*; infra-vs-security: cloudflare;
   analytics/security: elastic/splunk/sonarqube; AI-vs-Dev: replit).
2. **Amazon retail vs AWS** (§3 #2/#4): keep the broad `amazon.com` = E-Commerce
   signal and drop AWS-host categorization, or drop `amazon.com` and keep AWS =
   Cloud Infrastructure? They cannot coexist under suffix matching.
3. **`copilot.github.com`** (§3 #5): distinct AI signal is not expressible under a
   Dev-Tools parent — drop or accept as Dev Tools.
4. **Path-scoped destinations** (`google.com/travel`, `linkedin.com/learning`):
   accept removal, or introduce host-only equivalents if they don't conflict.
5. **Whether to keep any `*.amazonaws.com` / PSL-suffix entries** at all, given
   they are infrastructure suffixes, not SaaS destinations.

---

## 6. Path forward (no assignments changed here)

1. Product review resolves §5.
2. A curated source dataset (single-category, suffix-safe, host-only) is produced —
   **as a separate, reviewed change**, not inside the trust kernel.
3. `TestSourceDatasetReadiness` flips from asserting *not-ready* to asserting
   *ready* (the F5 publish precondition).
4. F5's CI publisher calls `EvaluateReadiness` and **refuses to publish** unless
   `Ready == true`.

Until then, the feed ships **only** the `go:embed` baseline as the offline bootstrap
(unchanged); no signed artifact is published.
