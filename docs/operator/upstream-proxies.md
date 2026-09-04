# Upstream proxies (parent-proxy chaining) — the v2 model, credentials, and what "eligible" means

Culvert can forward **plain-HTTP** requests through a parent proxy chain
("upstream proxies"). This page is the operator contract for the v2 model
that shipped with Batch 2 / 2F-C: how an entry is identified, how a
credential is stored, why a parent is or is not selected, and what the
`/api/upstream` read model is telling you.

Scope reminder: chaining covers the plain-HTTP forward path only
(`coverage.summary: plain_http_only`). CONNECT, WebSocket and SOCKS5 traffic
is never chained (PX-1, recorded).

## 1. Identity and authority

Every effective entry has a stable **id** and a canonical **authority**:

| Source | id | Editable through the API |
|---|---|---|
| `managed` (GUI / API / import) | server-assigned ULID | yes |
| `yaml` (`upstream_proxies:` in `config.yaml`) | `yaml-<128-bit authority digest>` | **no** — 409 `yaml_owned`; edit the YAML and reload |

The authority is `scheme://[username@]host:port`, normalized before it is
compared or hashed: scheme lower-cased (`http` or `https` only — the
approved C4 grammar; `socks5` is refused on every input path), host
lower-cased, trailing dot stripped, IDNA-encoded, bracketed IPv6 literals
accepted, the effective port defaulted per scheme (80/443). Two
spellings of one authority are the same authority.

**Existing `config.yaml` inline credentials keep working.** A YAML URL such
as `http://svc:secret@parent:3128` becomes a read-only `yaml-<digest>` entry
whose credential is retained **in memory only**: it is never written to
`admin_settings.json` (plaintext or sealed), never returned by the API,
never audited or logged, and cannot be edited, cleared or replaced through
the API (409 `yaml_owned`). It reports `credentialState: configured`, is
probed and selected like any other configured parent, and disappears when
you remove it from the YAML and reload.

**The effective pool never carries an authority twice** — YAML vs YAML,
managed vs managed, or YAML vs managed. A mutation that would create a
duplicate is refused before anything is published (409
`duplicate_authority`, with the count only). A YAML authority that also
appears in a saved managed list is YAML-owned: the managed copy is skipped,
never adopted.

## 2. Credentials are write-only and sealed

A parent that requires `Proxy-Authorization` gets its password through
**one** endpoint, `POST /api/upstream/entries/{id}/credential`:

- `{"action":"replace","password":"…","revision":<entry revision>}` (Tier 2)
  seals the password with AES-GCM under the node-local key file
  `<dataDir>/.upstream_cred_key` (0600), bound cryptographically (AEAD) and
  structurally to the entry's **immutable id and** its authority hash.
  Ciphertext moved onto another entry — even one recreated with the very
  same authority — is `mismatch` and is never unsealed, probed or sent.
- `{"action":"clear","confirm":"<entry id>","revision":<entry revision>}`
  (Tier 3) removes it; the typed confirmation must equal the exact entry id.

The password is never returned by any read, never logged, never audited,
never exported, never rolled back, never synced CP→DP, and never written to
`admin_settings.json` in cleartext. What the file holds is the sealed
document `upstream_proxies_v2`; the legacy `upstream_proxies` list beside it
is credential-free.

`credentialState` on each entry is **derived by the server** and is refused
if a client sends it (400 `credential_state_not_accepted`):

| state | meaning | selected / probed? |
|---|---|---|
| `none` | no material | yes (credential-free) |
| `configured` | sealed, key present, authority matches | yes |
| `unusable` | key file missing/unreadable, or wrong key | **no** |
| `mismatch` | the sealed authority hash does not match the entry | **no** |

The key is minted only on the first `replace` (or by the boot migration
below) when no key file exists **and** no ciphertext exists anywhere. It is
**never** re-minted after a failed read or while sealed material exists —
a missing key makes every credential `unusable` and the panel says so.
Restore the original key file to recover; otherwise clear and re-enter each
credential.

**An authority change while a credential exists is refused** (409
`credential_bound`). There is no combined rebind: clear the credential (T3),
edit the entry, then set the credential again. Deleting an entry whose
credential is `configured`, `unusable` or `mismatch` is refused too (409
`credential_present`) — clearing is always an explicit, confirmed step.

### When the stored document is rejected

If `upstream_proxies_v2` in `admin_settings.json` fails validation at load
(for example a duplicate authority, or an entry that no longer parses),
the node fails **closed and remembers**: the managed entries are not
published, `GET /api/upstream` shows `degraded {reason, count}`, and until
the file is repaired and the node restarted every managed mutation — v2
create/update/delete/credential, the v1 adapter, and config import — is
refused with 409 `document_rejected`, no key is minted, and every unrelated
settings save carries the rejected upstream sections forward verbatim so
the only copy of any sealed credential is never overwritten. A refused
`config.yaml` seed is reported separately as `yamlDegraded` and stays
visible even when a valid managed document loads.

## 3. Endpoints and fencing

| Endpoint | Role | Fence |
|---|---|---|
| `GET /api/upstream` (alias `/api/upstream/settings`) | viewer | — |
| `POST /api/upstream/entries` | admin | document `revision` |
| `PUT /api/upstream/entries/{id}` | admin | entry `revision` |
| `DELETE /api/upstream/entries/{id}?revision=` | admin | entry `revision` |
| `POST /api/upstream/entries/{id}/credential` | admin | entry `revision` |
| `POST /api/upstream/health` | admin | — |
| `POST /api/upstream` (v1 adapter) | admin | document `revision` |

Every mutation echoes the token it loaded: 428 `precondition_required` when
missing, 409 `stale` (with `current.revision`) when the object changed, 404
`vanished` when the entry is gone. The change is persisted **before** the
2xx is written; a persistence failure is a non-2xx with zero mutation.
Audit records carry the entry id, the redacted authority and the action —
never a password.

### The v1 adapter (`POST /api/upstream`)

The legacy bulk endpoint survives as a **credential-free** adapter for
scripts: a URL carrying any userinfo is refused (400 `userinfo_not_allowed`),
an invalid entry refuses the whole list (400 `invalid_entry` — nothing is
dropped), and the call is refused outright while any managed entry holds a
credential (409 `credentialed_entries_present`). A credentialed entry can
never be replaced or removed by omission. GET URLs never carry userinfo.

The shipped admin panel (`static/index.html`) uses the per-entry endpoints;
the adapter restrictions and the panel switch landed in the same commit.

## 4. Health, eligibility, and the effective mode

Probes are tri-state and classified by a bounded reason:

| probe outcome | status / reason |
|---|---|
| never probed (new entry) | `unprobed / none` |
| dial or TLS failure | `unhealthy / connect_failed` |
| deadline exceeded | `unhealthy / timeout` |
| HTTP 407 | `unhealthy / proxy_auth_failed` |
| 2xx / 3xx | `healthy / none` |
| any other status | `unhealthy / probe_http_error` |

A credential-ineligible entry (`unusable` / `mismatch`) is **not probed**.
Probe bodies are bounded, drained and discarded.

Each entry carries `health {status, reason, lastProbeAt, source}` where
`source` is `periodic` (the health loop, cadence shown top-level as
`probe {configured, interval}`) or `manual` (`POST /api/upstream/health`);
`probe` is kept as a compatibility alias of the same verdict.

A parent is **eligible** when
`(credential none OR configured with a matching id + hash) AND (probe unprobed OR healthy) AND circuit.Allow()`.
The authenticated URL is built only inside the two transport selectors —
the request proxy selector and the per-probe proxy selector — after that
eligibility check, and nowhere else; the probe transport never receives a
URL carrying userinfo.

`mode` on the read model:

`effective.since` is the instant the current mode was first observed and
re-stamps only on a transition. `coverage` reports the truth per client
path: `{plainHttp: chained, connect: direct, websocket: direct, socks5: direct, summary: plain_http_only}`.

| mode | meaning |
|---|---|
| `no_pool` | nothing configured — direct egress is the operating mode |
| `chained` | at least one eligible parent |
| `no_eligible_parent` | parents exist, none eligible, no request has fallen back yet |
| `direct_fallback` | a request fell back to direct egress (PX-2 fail-open); the `upstream_pool_down` alert fires once per transition |

## 5. Boot migration from the pre-v2 file

A pre-v2 `admin_settings.json` (sentinel set, `upstream_proxies` with
userinfo URLs, no `upstream_proxies_v2`) is migrated **once** at load,
durable-or-nothing: every URL is parsed first (one parse failure ⇒
`migration.state: degraded`, `reason: parse_failed`, nothing rewritten,
runtime unchanged), the key is opened or minted only if a password exists,
each password is sealed in memory, the complete v2 document plus a
credential-free legacy list are written atomically, and only after that
write succeeds does the runtime swap to the sealed document. `GET
/api/upstream` shows the outcome under `migration` and the key under `key`.

**Behaviour change to know about**: before 2F-C a saved (even empty)
managed list replaced the YAML seed. Now YAML entries are read-only and
always present; the saved list governs the managed entries only. A YAML
authority you also managed in the GUI is now YAML-owned.

## 6. Log hygiene

Transport errors from a parent can embed the proxy URL, including the
password. Culvert never logs, persists, audits or returns a raw transport
error on this path: logs carry a bounded reason class plus the redacted
authority and the safe entry id; the read model and the health/diagnose
surfaces carry the classified probe state only.

## 7. Export and import (schema 2)

`GET /api/config/export` (full or `?section=upstream`) is `version: 2` and
carries the managed entries as
`upstream_proxies_v2: {entries: [{id, scheme, host, port, username,
credentialState}]}` plus `upstream_credentials: "omitted"`. An export never
carries a password, the sealed record, ciphertext, a key id, the legacy
`xxxxx` echo or a legacy URL, so it can be attached to a ticket.

Importing a version-2 document is planned before anything is touched:

| incoming entry | meaning |
| --- | --- |
| `preserve` | same id and unchanged authority — the sealed credential stays |
| `create` | new managed entry (state `none`) |
| `update` | authority change on an entry without a credential |
| `requiresReplacement` | the entry declared a credential (`credentialState` ≠ `none`) but is not a `preserve`: it lands as a new or updated entry in the `requiresReplacement` state (an existing entry that still holds material is refused instead, see below) |

| existing entry | meaning |
| --- | --- |
| `retain` | kept |
| `remove` | replace mode only, and only for the identity-bearing v2 document |

A plan that would destroy a credential (authority change or removal of a
credentialed entry) is refused with **409 `credential_clear_required`** and
the complete plan (`credentialClearRequired: [ids]`) before any store is
touched. Clear those credentials deliberately (Tier-3) first, then import
again — the import confirmation word is Tier-2 and never substitutes for
the clear. A real password in the document is refused (400
`credentials_not_importable`); duplicate ids are refused (400).

Recommended ceremony:

```
POST /api/config/import?dryRun=1            → plan + importDigest, nothing applied
POST /api/config/import?importDigest=sha256:… → applies exactly that plan
```

The digest is recomputed under the save lock; if the document moved in
between the commit answers 409 `import_stale` (re-run the dry-run). The
result carries counts only: `upstream: {preserved, omitted, cleared,
requiresReplacement}`.

A pre-v2 legacy list (`upstream_proxies` with `xxxxx` passwords) is still
accepted: omission never removes, and `xxxxx` preserves only an exact,
unique authority match.

## 8. Backups never carry parent-proxy credentials

Both backup modes (plain and encrypted) archive a sanitized
`admin_settings.json`: every sealed credential is removed and the entry
is marked `requiresReplacement: true`; the manifest records
`credentialsOmitted: true`; `.upstream_cred_key` is never archived. The
live file and the running pool are not touched by a backup.

**Restore** boots every formerly credentialed entry into the distinct
state `requiresReplacement`: ineligible, never probed, never sent
unauthenticated. Until you act, the effective mode is
`no_eligible_parent` (or `direct_fallback` once a plain-HTTP request has
fallen back — parents are never contacted). The restore dry-run prints
`credentials requiring replacement: N`; the commit keeps the usual
`--confirm`; an archive carrying a node-local key file is refused; an
existing `.upstream_cred_key` on the target is preserved in every mode.
Surfaces: `credentialsRequiringReplacement` on `GET /api/upstream`, the
`upstream_credentials` operator-contract row (count only) and the
Upstream Proxies panel badge + banner. Set each credential again
(Replace, Tier-2) or clear it (Clear, Tier-3).

## 9. Preparing a downgrade to the previous release

The previous release (admin-settings schema 1) reads credentials from
the legacy `upstream_proxies` URLs and cannot unseal the v2 record. Before
booting it on this data directory:

```
culvert --prepare-downgrade --target-schema 1                 # dry-run (mandatory)
culvert --prepare-downgrade --target-schema 1 --confirm <word> # commit
```

The word is `<data-dir basename>-schema1` (for `/data`: `data-schema1`)
and the dry-run prints it. The commit unseals every credential in memory
only and atomically rewrites `admin_settings.json` (0600, fsync, rename)
with full legacy URLs, removing `upstream_proxies_v2`; it refuses when
the key is missing or unusable, when any credential is `mismatch`,
`unusable` or `requiresReplacement` (fix those first), and when the file is
already prepared. Output, log and audit carry counts only. The prepared
file contains the passwords in cleartext by construction — that is the
predecessor's format, and the reason the command is explicit and offline.

Booting the CURRENT binary on a prepared file re-migrates it once
(`migration.reason: re-migrated_after_prepare`, credentials re-sealed).

If a prepared credential is wrong, the previous release does NOT fall
back to direct egress: the parent's 407 is forwarded to the client on
every request (its breaker counts transport errors, and a 407 is a
well-formed response). Requests fail loudly; nothing reaches the parent
unauthenticated.

## 10. Manual health check

`POST /api/upstream/health` (admin) probes every eligible entry with a
5-second deadline each, one run at a time, at most one accepted run per
10 seconds (429 `probe_rate_limited` / `probe_in_flight` with
`Retry-After`). An accepted run is audited as `upstream.probe.manual`
with counts (`probed/healthy/unhealthy/skipped`) and `scope=node-local`;
a refused run leaves no success audit. `requiresReplacement` and other
credential-ineligible entries are skipped. The periodic loop is never
gated and the classifier is unchanged.
