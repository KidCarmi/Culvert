# MCP Gateway Qualification Inventory (QUAL-2)

This document describes the **static qualification inventory** for the MCP Agent
Security Gateway "Observe" listener. It is the operator-facing schema for
`mcp.gateway.qualification_inventory_file`.

## What it is (and is not)

The qualification inventory is a **bounded, static, node-local JSON file** that
seeds a known Gateway fleet — a dedicated tenant, its registered servers, and
their known tools — so that a correctly authenticated Model-A request for a seeded
server can pass registry resolution and reach the QUAL-1 **Observe-only** decision
boundary. It exists purely to make a qualification environment enumerable and
resolvable.

It is **not** a dynamic registration product:

- loaded **once at startup**; there is no hot reload and no admin-API upload;
- **disabled by absence** — with no file set, the registry/catalog are empty
  (byte-identical to QUAL-1);
- it **never enables MCP on its own**: `mcp.gateway.enabled` still gates the
  listener;
- it composes **no policy, events, executor, upstream client, broker, or
  credential provider** — QUAL-2 does not execute tools, materialize credentials,
  or start any qualification/evidence clock.

A seeded tool is **known inventory, not an approval**: every tool lands
`quarantined` (the record-only-Observe disposition). Nothing in this file can make
a tool `usable`.

## Configuration

```yaml
mcp:
  gateway:
    enabled: true
    # ... QUAL-1 TLS / mTLS / OAuth settings ...
    qualification_inventory_file: "/etc/culvert/mcp/qualification-inventory.json"
```

- **Node-local, startup-only.** Read once; changes require a restart.
- **No secret material.** The file carries only opaque references (server ids,
  endpoint identities, pinned identities, credential-profile *references*). Never
  a raw credential, bearer token, client secret, or private key.
- **No default file.** There is no baked default; an absent value keeps MCP
  disabled/empty.

## Failure behavior (fail closed)

If the file is set but **unreadable, oversized (> 1 MiB), malformed, has unknown
fields, or fails any validation**, the Gateway listener **does not bind** (the
activation is `invalid` with a bounded, secret-free reason). The inventory is
**never partially seeded**: it is all-or-nothing. The Secure Web Gateway path is
unaffected. The admin overview reports the inventory `state` as `invalid` — an
invalid inventory is **never** rendered as an empty healthy fleet.

## File schema

Top level:

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | integer | yes | Must be `1`. |
| `tenant` | string | yes | The single dedicated qualification tenant (owner scope). Every server is bound to it. |
| `servers` | array | yes | 1..N Gateway servers (bounded by the catalog limits). |

Each **server**:

| Field | Type | Required | Notes |
|---|---|---|---|
| `server_id` | string | yes | Stable opaque registry id (not a hostname/URL). Unique within the file. |
| `endpoint` | string | yes | Canonical endpoint **reference** (never dialed). Unique within the file. |
| `pinned_identity` | string | yes | The verified, pinned identity (e.g. a SPIFFE id or cert fingerprint). Compared **exactly**. |
| `capability` | string | no | If present, must equal `gateway`. Force-bound to Gateway regardless. |
| `credential_profile` | string | no | Opaque **reference** to a scoped credential class. Never a raw credential. |
| `enabled` | bool | no | Defaults to `true`. A disabled server is registered and visible but not resolvable (the pipeline 404s it). |
| `tools` | array | no | 0..N known tools for this server. |

Each **tool**:

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | string | yes | Exact tool name. Unique per server. |
| `input_schema` | object | yes | The tool's JSON-Schema input **definition** (bounded). This is a schema, not arguments. |
| `output_schema` | object | no | Optional JSON-Schema output definition. |
| `description` | string | no | Human-facing description (folded into the descriptive fingerprint). |
| `title` | string | no | Human-facing title. |
| `annotations` | object | no | Tool annotations object. |
| `destination_class` | string | no | One of `none`, `approved`, `internal`, `arbitrary`, `unknown` (default `unknown`). |

The fingerprint is computed by the **existing** catalog ingestion path from these
fields — there is no separate fingerprint format and no precomputed-hash input.

## Example

```json
{
  "schema_version": 1,
  "tenant": "qualification",
  "servers": [
    {
      "server_id": "qual-echo-1",
      "endpoint": "mcp+https://qual-echo-1.qual.svc",
      "pinned_identity": "spiffe://qual/echo-1",
      "credential_profile": "profile:qual-readonly",
      "enabled": true,
      "tools": [
        {
          "name": "echo",
          "input_schema": { "type": "object", "properties": { "text": { "type": "string" } } },
          "description": "Echoes its input back.",
          "destination_class": "none"
        }
      ]
    }
  ]
}
```

## Admin visibility

Once loaded, the fleet is enumerable read-only via the existing endpoints (viewer
role, tenant-scoped):

- `GET /api/mcp/servers?tenant=qualification`
- `GET /api/mcp/tools?tenant=qualification`
- `GET /api/mcp/overview` reports a safe `inventory` block:
  `state` (`not_configured` / `loaded` / `invalid`), `servers`,
  `verified_servers`, `tools`, `quarantined_tools`, `review_required_tools`, and
  `execution_enabled: false`.

The admin views are **redacted**: they never expose the raw endpoint, pinned
identity material, credential contents, complete schemas, arguments, outputs, or
the inventory file path. A wrong tenant sees no data and a uniform not-found on an
exact lookup (no cross-tenant existence leak).

## Boundaries preserved

Loading an inventory does **not** change any QUAL-1 guarantee: the listener stays
disabled-by-default, mTLS/OAuth-gated, Observe-only and non-executing; Management
stays inactive and non-mutating; Production stays qualification-locked; and no
qualification/evidence clock starts. Inventory readiness is **one dependency** for
Observe, not a declaration that Observe may begin.
