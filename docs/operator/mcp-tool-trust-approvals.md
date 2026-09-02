# MCP Tool-Trust Approvals (ADR-0034)

The MCP catalog classifies every discovered tool into an eligibility state
(`quarantined`, `review_required`, `pending_narrowing`, `server_disabled`,
`usable`). **No ingestion path ever produces `usable`** — a tool becomes `usable`
only when a privileged human explicitly trusts one exact observed tool fingerprint
for one declared purpose. That trust decision is a supply-chain control, not an
execution authorization.

Three concepts stay separate:

- **Trust** — is this exact observed tool eligible to be considered? (this feature)
- **Availability** — can the tool appear in this environment? (rollout scope)
- **Authorization** — may THIS call execute now? (the policy engine, always)

A `usable` tool bypasses nothing. Runtime policy remains authoritative for every
invocation: `usable` + a DENY / REQUIRE_APPROVAL / REQUIRE_CONFIRMATION rule still
denies / requires approval / requires confirmation, and `usable` with no matching
rule is still default-deny.

## Purpose / trust ceiling

An approval carries a purpose, and the two purposes are **disjoint** — one approval
never satisfies both.

- **`shadow_evaluation`** trusts the tool for Controlled Shadow evaluation and nothing
  more. It makes the tool `usable` (a materialized projection of active shadow
  approvals). It can NEVER satisfy a live-execution prerequisite.
- **`live_execution`** authorizes the tool to be considered for a real MCP upstream side
  effect under Canary. It is issuable **only under stronger governance** (below) and is a
  TRUST decision only: it does **not** make the tool `usable`, arms no executor, and cannot
  by itself move Canary out of `live_executor_absent`. Runtime policy remains authoritative
  for every call.

**A tool being safe enough to observe is not permission to let it change reality.**
`shadow_evaluation` and `live_execution` are separate reviews; a shadow approval can never
be upgraded into a live one, and vice-versa.

### Governed `live_execution` issuance

A `live_execution` approval must satisfy every one of these, all enforced server-side and
fail-closed:

- **Four-eyes.** The requester and the approver must be **distinct authenticated
  principals** (compared on the login subject, not display name or IP). Self-approval is
  refused, and a request with no authenticated session is refused outright.
- **Mandatory finite TTL ≤ 24h.** You MUST supply an explicit `expires_in_seconds` in
  `1..86400`. There is no silent default; a `0`/omitted expiry is rejected. The 24h ceiling
  is enforced again at approval time, measured from the approval instant.
- **Exact current state at approval.** The approver's decision re-verifies the exact
  reviewed target — the tool and server still exist, identity and fingerprint and format
  still match, and the catalog and server revisions have not advanced. Any drift between
  request and approve fails closed and never retargets. A new fingerprint is a NEW review.
- **No broad forms.** No server-wide, wildcard, all-fingerprints, all-tenants, group-wide,
  both-purposes, or approve-future live grant can be expressed.

Revocation and expiry are immediate and first-class for live approvals too, and survive
restart (a revoked or expired grant never resurrects; reapproval is a new decision).

## Workflow

All routes are tenant-scoped (`?tenant=<owner-scope>`). The tenant comes from the
server's registered ownership scope; you select it, and every read/write is scoped to
it.

1. **Review** the tool in the inventory: `GET /api/mcp/tools?tenant=…&server_id=…&tool_name=…`.
   Note its `fingerprint` (hex digest) and the catalog `revision`. The
   `ToolAnnotations` a server declares are **untrusted hints** and never change
   eligibility.
2. **Request** (operator): `POST /api/mcp/tool-approvals?tenant=…` with
   `{ "server_id", "tool_name", "fingerprint": "<hex you reviewed>", "catalog_revision": <n>,
   "purpose": "shadow_evaluation", "reason", "ticket_ref", "expires_in_seconds": <optional> }`.
   The request binds the exact reviewed fingerprint; if the tool has already changed,
   the request fails closed (`tool_fingerprint_mismatch` / `tool_approval_stale`). A
   request is NOT a grant — it changes no eligibility.
3. **Approve** (admin): `POST /api/mcp/tool-approval-decision?tenant=…` with
   `{ "approval_id", "action": "approve" }`. The backend re-verifies the exact
   fingerprint against the live catalog immediately before promoting; any drift, a
   disabled/re-identified server, or a tenant mismatch fails closed and never
   retargets to a different tool. On success the tool becomes `usable`.
4. **Revoke** (admin): `POST /api/mcp/tool-approval-decision?tenant=…` with
   `{ "approval_id", "action": "revoke", "reason" }`. Trust is withdrawn immediately
   (the tool returns to `quarantined`). A revoked approval never re-activates from a
   later identical discovery — re-approval requires a new decision.

Prefer a short-lived approval (`expires_in_seconds`) for the first Controlled Shadow
run: an expired approval keeps no tool `usable`. Trust is re-derived on every
inventory read and Shadow preflight, and a background sweep also runs on a timer, so
an expired grant's tool is demoted within that interval even during an active Shadow
run with no operator reads.

### Live-execution workflow (governed)

The same two routes carry the `live_execution` path; the difference is purpose plus the
stronger governance above. Approve routes by the stored purpose, so a live request is
approved through the live path and a shadow request through the shadow path — the two can
never cross.

1. **Review** the tool exactly as above; note the `fingerprint` and catalog `revision`.
2. **Request** (operator): `POST /api/mcp/tool-approvals?tenant=…` with
   `{ "server_id", "tool_name", "fingerprint", "catalog_revision", "purpose":
   "live_execution", "reason", "expires_in_seconds": <1..86400, REQUIRED> }`. The request
   is attributed to your authenticated session principal; you cannot request `live_execution`
   from an unauthenticated context. Omitting the expiry, or exceeding 24h, is rejected.
3. **Approve** (admin, DISTINCT principal): `POST /api/mcp/tool-approval-decision?tenant=…`
   with `{ "approval_id", "action": "approve" }`. Four-eyes is enforced on your login
   subject — you cannot approve your own request even from a different session or IP. The
   backend re-verifies the exact current target and the ≤24h TTL and fails closed on any
   drift. On success the approval becomes `active`. **The tool does NOT become `usable`**
   and nothing is armed — the grant only makes the Canary readiness row
   `live_execution_approval_invalid` satisfiable for that exact `(tenant, server, tool,
   fingerprint)`.
4. **Revoke** (admin) works identically and withdraws the live grant immediately.

Issuing a live approval performs no execution, retrieves no credential, and does not
activate or transition Canary. It is purely a durable, reviewable, revocable trust decision.

## Durability & recovery

Approvals are the source of truth, persisted to
`<dataDir>/mcp_tooltrust/approvals.json` (atomic write, schema-versioned, bounded,
tenant-scoped, secret-free — never a token, credential, or raw schema/body). The
catalog `usable` state is a materialized projection: on restart the boot inventory
re-seeds every tool `quarantined`, then each active, unexpired, unrevoked approval
whose bound fingerprint matches the freshly-seeded tool is re-applied. A corrupt or
newer-schema store fails closed — no trust is materialized and the file is left for
out-of-band recovery.

## Rug-pull protection (the core invariant)

An approval binds to the exact fingerprint digest, which covers every security-relevant
tool dimension (server id, pinned identity, name, input/output schema, description /
title / annotations, credential profile, destination class). Any change to any
dimension changes the digest, and the tool immediately loses `usable`. A same-named
tool on another server, or a re-declared tool, is a different fingerprint and is never
covered by the old approval.

## Scope of this feature

This feature does NOT activate Shadow, Canary, or Production, compose an executor or
upstream client, materialize a credential, or approve anything server-wide, wildcard,
or in bulk. A `shadow_evaluation` approval makes exactly one thing reachable: a scoped,
human-approved tool that satisfies the Controlled Shadow usable-tool prerequisite. A
`live_execution` approval makes exactly one thing reachable: the Canary readiness row
`live_execution_approval_invalid` becomes satisfiable for one exact target. Neither arms
the live-execution tier, and issuing a live approval never causes an MCP upstream side
effect or retrieves a production credential.
