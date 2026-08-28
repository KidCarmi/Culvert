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

An approval carries a purpose. Only **`shadow_evaluation`** is issuable today; it
trusts the tool for Controlled Shadow evaluation and nothing more. It can NEVER
satisfy a live-execution (Canary/Production) prerequisite — a future live phase must
introduce a stronger, separately-reviewed purpose. `live_execution` is defined so the
model is complete but is refused at issue (`approval_purpose_unsupported`).

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
run: an expired approval keeps no tool `usable`.

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
or in bulk. It makes exactly one thing reachable: a scoped, human-approved tool that
satisfies the Controlled Shadow usable-tool prerequisite.
