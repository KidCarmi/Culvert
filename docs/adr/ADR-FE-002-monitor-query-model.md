# ADR-FE-002 — Monitor query model: snapshot/query-driven, not stream-driven

- **Status**: Accepted (2026-08-22)
- **Deciders**: frontend-modernization program owner (external review), Round-5 directive
- **Context**: FE-4 operational surfaces (Overview, Monitor → Traffic, Monitor → Audit,
  Diagnostics, Governance) for the v2 administration frontend.
- **Supersedes**: the earlier FE-4 SSE/live-dashboard direction recorded in
  `FRONTEND-MIGRATION-PLAN.md` (FE-4) and the FE-X04 consumption assumption in
  `FRONTEND-FEATURE-PARITY.md`.

## Decision

CULVERT's new administration frontend is **not** a live-streaming operations UI. The v2
Monitor surface follows the mature security-appliance model: explicit queries, explicit time
ranges, server-side filtering, bounded server-side pagination, explicit refresh, and visible
snapshot freshness. It must scale to high traffic volumes and many concurrent administrative
sessions without turning every open browser tab into a streaming consumer.

**CULVERT Monitor is QUERY-DRIVEN, not STREAM-DRIVEN.**

1. The new v2 UI does **NOT** consume `/api/events`. Zero `EventSource` construction, zero
   SSE reconnect machinery, zero LIVE/STALE stream state, zero SSE auth-cleanup owner exist
   in the v2 bundle; browser qualification asserts no request to `/api/events` is ever made.
2. The existing backend SSE implementation (`internal/sse`, `/api/events`) **remains
   available** — it is not deleted, modified, or broken by this decision.
3. The legacy frontend (`static/index.html`) may continue consuming SSE until cutover.
4. The v2 Dashboard/Monitor surfaces use SNAPSHOTS and BOUNDED QUERIES exclusively
   (`/api/stats`, `/api/timeseries`, `/api/dashboard/*`, `/api/logs`, `/api/audit`,
   `/api/diagnostics`, `/api/governance/control-plane`).
5. **Manual Refresh is the default** interaction on every operational surface.
6. Any future auto-refresh control must be: OFF by default; minimum interval 30 s;
   running only while its route is mounted; running only while the document is visible
   (paused on `document.hidden`, with no catch-up burst on return); never mutating;
   cancelled at navigation and at the auth boundary; never persisted in browser storage.
7. Every operational surface displays snapshot freshness ("Updated HH:MM:SS"), advancing
   ONLY on a successful response — a failed refresh keeps the previous snapshot visible
   with an explicit stale/error indicator and never fakes freshness.
8. Traffic-history filtering and pagination are **server-owned**: the browser never
   downloads large result sets to filter locally.
9. **No exact-total calculation may require an unbounded history scan merely to render
   pagination.** The Monitor pagination contract is keyset/cursor-based (`has_more` +
   opaque `next_cursor`), not "page N of M" backed by an O(history) count.
10. **No background traffic-log stream exists in the browser.**

## The traffic-history cursor contract (implemented this round)

`GET /api/logs?source=store` gains a keyset mode, activated only when the request carries a
`cursor` parameter (present-but-empty = first page). The pre-existing offset/limit/`total`
mode is byte-compatible and untouched for existing clients.

- Ordering: newest-first over the store's native time-ordered key
  (8-byte big-endian unix-millis ++ 4-byte big-endian seq) — a total order, so
  tie-breaking is deterministic and paging is stable under concurrent appends (new
  entries get strictly newer keys and can never duplicate or displace entries below an
  issued cursor).
- Cursor: opaque, stateless — `base64url(JSON{v, ts, seq, fp})`. `ts/seq` name the last
  entry returned (log-entry coordinates, not raw datastore keys — no Badger key bytes,
  paths, or filesystem internals leak); `fp` is a bounded fingerprint of the logical
  query (from/to + every filter parameter), so a cursor from query A is refused (400)
  when presented with query B's parameters, and the decoded `ts` is validated against
  the request's time window — a forged cursor can only reposition pagination inside the
  window it already reads. Decoding is length-capped; malformed input is a controlled 400.
  No server-side session cursor storage exists.
- Page size: default 100, hard server clamp 500 (the legacy 5000 offset ceiling is
  deliberately NOT the Monitor behavior).
- Response: `{logs, next_cursor, has_more, history, snapshot_at, limit}` — no `total`.
  `history:false` truthfully reports a disabled/unavailable store.
- Cost: `logstore.QueryPage` visits only the entries needed to fill one page (plus one
  look-ahead match for `has_more`), bounded by the store's scan cap as a backstop; the
  deterministic `Scanned` seam is asserted by tests — page-40's scan cost equals
  page-1's, where the old offset/exact-total contract's cost grew linearly with depth.

## Consequences

- FE-4 carries no SSE reconnect design, LIVE/STALE state, or SSE memory-soak requirement.
- `FRONTEND-FEATURE-PARITY.md` FE-X04 is dispositioned: legacy/backend capability
  RETAINED; intentionally NOT consumed by the v2 administration frontend. This is an
  approved product/scale decision, not lost parity.
- The offset mode of `/api/logs` remains for compatibility (legacy SPA, CLI users); the
  v2 UI uses only the cursor mode for history queries.
- Future live-ish needs (if ever re-approved) require a new ADR; nothing in FE-4 may
  quietly re-introduce a stream consumer.
