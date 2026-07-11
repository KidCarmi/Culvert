# Culvert Screen Specifications — First Vertical Slice (M1)

Status: Phase 6 deliverable of the GUI redesign program
Date: 2026-07-11
Legend: **[E]** existing functionality restyled · **[U]** UI-only improvement ·
**[B]** backend dependency (not built until recorded) · **[F]** future concept.

---

## 1. Application shell

**User goal**: orient, navigate, know at a glance whether the console is live
and who/what role I am.

**Structure**
- Sidebar (fixed, 232px; off-canvas <860px — unchanged mechanics) [E]
  - Brand block: logo, product name, version line.
  - Nav sections per `INFORMATION-ARCHITECTURE.md` §2: OVERVIEW / MONITOR /
    POLICIES / OBJECTS / PLATFORM / ADMINISTRATION. Same `data-view` values,
    same `data-min-role` gating. [E, regrouped U]
  - Each item: SVG icon (`<use href="#i-…">`) + label (+ existing badges:
    blocked count, update NEW). [U]
  - Keyboard: `tabindex="0"`, `role="button"`, Enter/Space activates,
    `aria-current="page"` on active. [U]
  - Footer: proxy/UI port health rows (dot + text), uptime, theme toggle. [E]
- Topbar [E]: hamburger (mobile), title ("Section / Item" from `viewMeta`),
  meta line, server time, LIVE/STALE pill, username + role badge, sign out.

**States**: viewer role hides gated sections (existing `applySession`);
tick-loop pause (20 consecutive errors) now also shows a `banner.warn` under
the topbar: "Connection to Culvert lost — retrying stopped. Reload to
resume." [U — fixes silent-stall gap]

**Accessibility**: nav is in `<nav aria-label="Primary">`; sections are
headings for AT; focus ring on items. [U]

---

## 2. Overview dashboard (`data-view="dashboard"`)

**User goal**: *Is Culvert operational? Is traffic flowing? Do I need to act?*

**Page hierarchy**
1. **Posture strip** [U — new presentation of existing data only]
   Six compact posture items, each: icon + label + state text + drill-down.
   | Item | Source (existing) | States |
   |---|---|---|
   | Proxy | `/api/stats` reachable + `proxyPort` | Operational / Unreachable (tick failure) |
   | Traffic | SSE `rps`, `activeConns` | Flowing (n req/s) / Idle / Stale |
   | Engines | `/api/dashboard/threats` fetch ok + `/api/security-scan/status` | Healthy / Degraded (fetch fails) |
   | CA | `/api/ca-cert.notAfter` | Valid (Nd) / Expiring soon / Expired |
   | Logging | `/api/stats.logWriteErrors`, `/api/dashboard/health.logStore` | Persisting / Write errors (n) |
   | Updates | SSE `updateAvailable`, `latestVersion` | Current / Update available |
   Every state is text + color; unknown = "Unknown" (muted), never green.
   No fabricated signals; each item links to its owning view.
2. **Metric cards** [E]: Total / Allowed / Blocked / Auth failures / Active
   connections (ids `d-total`, `d-allowed`, `d-blocked`, `d-auth`, `d-active`,
   `d-rps` kept). Each gains a `title` definition ("All requests since start —
   counters reset on restart") and a click-through (Traffic view filtered). [U]
3. **Charts row** [E]: Request rate (60 min, `#rateChart`), traffic breakdown
   (`#breakdownChart`); colors from tokens via `chartTheme()`. [U]
4. **Threat engine breakdown** [E]: ClamAV/YARA/DPI/Threat-feed blocked
   counters (`d-clam`, `d-yara`, `d-dpi`, `d-feed`).
5. **System health** [E]: memory/goroutines/GC/SSE/blocklist (`d-mem-alloc`…).
6. **Top rules / Top hosts** [E]: tables (`top-rules-table`,
   `top-hosts-table`); "approximate beyond 10k hosts" caption added [U].
7. **Destination countries / Recent requests** [E] (`country-chart-wrap`,
   `dash-log`).
- CA-expiry banner and Getting-Started banner stay (ids kept), restyled to
  `banner.*` components. [E]

**Empty**: zero traffic → Getting-Started banner (existing logic `total===0`).
**Loading**: skeleton blocks on cards/posture until first fetch. [U]
**Error**: individual posture items degrade to "Unknown"; global failure →
STALE pill + topbar banner.
**Permissions**: viewer-safe (all endpoints viewer-readable). [E]

---

## 3. Traffic (`livefeed`) — M2 spec (summary)

Triage table (time/source/destination/action/rule/level) [E] + row-expand
detail drawer (full URI, bytes, duration, country, engine verdict) [U] + rule
chip linking to Access Rules [U] + existing filters/source/history/retention
[E]. Streaming rows over SSE is **[B]** (today only counters are broadcast).

## 4. Access Rules (`policy`) — M3 spec (summary)

List: priority · name · scope · match · action badge · hits · enabled [E
fields, U presentation]; disabled rules dimmed + badge; reorder with commit/
revert bar [U]; "Test this rule" prefills Policy Tester [U]; per-rule History
→ audit filtered by object [U]. Draft state, conflict/shadow detection,
modified-at: **[B]**.

## 5. Login & first-run — M2 spec (summary)

Existing overlay flows kept ([E]; setup wizard, login, TOTP prompt via
`totp_required`); restyle to tokens, add `aria` roles, focus management, and
explicit session-expired message on 401-triggered overlay [U]. Session-expiry
pre-warning: **[B]** (needs TTL introspection endpoint).
