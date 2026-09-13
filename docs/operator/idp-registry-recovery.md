# Identity Provider writes — operation recovery, ceremonies and registry repair

*Relevant to any node whose Identity Providers are managed from the new admin
frontend (`/app/objects/identity-providers`, FE-6A.2) or through the admin
API (`/api/idp`). Everything on this page is node-local: the registry file
(`-idp-profiles-file`, compose `/data/idp_profiles.json`), the operation
ledger beside it (`idp_operations.json`) and the legacy-LDAP cutover record
in `admin_settings.json`. Nothing here is exported, versioned or synced.*

The write surface never guesses. Every mutation is fenced on a server token,
every success is verified against the server's own facts, and a response
that cannot be verified is reported as **unproven** — never as a success,
never as a failure. This page explains what each posture means and what to
do about it.

---

## 1. Fences

| Write | Fence (query string) | Missing | Stale |
|---|---|---|---|
| `POST /api/idp` (create) | `documentRevision=` — the registry's content-derived revision from `GET /api/idp` | `428 precondition_required` with `current.documentRevision` | `409 stale` with `current.documentRevision` |
| `PUT /api/idp/{id}` (update) | `revision=` — the ENTRY revision from the loaded profile | `428 precondition_required` with `current.revision` | `409 stale` with `current.revision` |
| `DELETE /api/idp/{id}` | `revision=` — the entry revision | `428` | `409 stale` |

The frontend never retries a stale write. It shows the server's current
token beside the one it sent and asks you to reload the profile and review
the candidate again — the other administrator's change is what you would
otherwise overwrite.

`409 referenced` on a delete lists the authentication rules that still
select the provider (`references[]`, the same facts as
`/api/objects/references?type=idp`). The frontend renders each as a link to
the rule; retarget or delete those rules first.

## 2. Operation identity and the recovery marker

A **create**, and an **update that retires the legacy YAML LDAP block** (see
§4), is dispatched with a client-minted `operationId` (UUID v4). Before the
request is sent the browser writes a small **recovery marker** to
`sessionStorage` (`culvert.idp.operation-recovery.v1`): the operationId, the
action, the profile name/type (and id for an update), the fence it was sent
under, whether it carries a cutover, and a digest of the NON-SECRET
candidate. The marker never holds a secret, a request body, or a server
response. It is bound to the authenticated username; a different subject
discards it and a sign-out purges it.

If the response is lost — tab closed, network death, a 2xx the browser
cannot verify — the page shows **"Unresolved provider operation"** on the
next visit with three controls:

| Control | What it does |
|---|---|
| **Recover** | `GET /api/idp/operations/{operationId}` (admin only). Renders the server's state verbatim: `pending`, `committed` (+ "audit pending" when the durable audit entry has not landed yet), `aborted` (+ the refusal code), `outcome_unknown`. A `committed` record clears the marker and reloads the registry. |
| **Re-send** | Offered ONLY when the ledger answers `404 not_found` (the intent was never recorded, so nothing was written). Reopens the editor bound to the SAME operationId; the candidate must match the marker's digest. A changed candidate is a new operation. |
| **Abandon** | Typed on the operationId. Deletes the marker without touching the server. Use it only after Recover has answered, or when you have confirmed the state another way. |

Replay is safe by contract: re-sending the same operationId with the same
candidate returns the RECORDED result (`replayed: true`) — including when
the original fence is stale by then — and writes nothing. A different
candidate under the same operationId is `409 operation_mismatch`.

`503 operation_ledger_degraded` means the ledger file is unreadable or
corrupt; the registry still serves and writes, but operation-identified
creates/cutovers are refused until the file is repaired (see the GET's
`operations.degradedReason`).

## 3. Unproven outcomes

A 2xx whose media type is not JSON, whose body does not decode, whose
identity does not match the dispatched candidate, or whose commit fact is
missing is **unproven**. The frontend:

1. closes the dialog and drops every secret it held;
2. latches the page (every mutation and the directory test are blocked);
3. re-reads the registry ONCE (a transport death waits for your **Refresh**);
4. shows what the read model proves — and, for an operation-identified
   write, keeps the recovery marker so **Recover** settles it.

The latch clears only after a successful read-back. No server error text is
ever rendered; refusals are shown by their contracted code.

## 4. The legacy-LDAP authority cutover

A node booted with a YAML `ldap:` block cuts over to the registry the first
time an enabled registry LDAP profile is published. FE-6A.2 makes that
transition an explicit ceremony bound to server facts:

- `GET /api/idp/legacy-ldap` (`present: true`) publishes
  `cutoverConfirmValue` — the legacy directory URL, i.e. the identity of the
  authenticator being retired.
- Every cutover-bearing write (`POST /api/idp` or `PUT /api/idp/{id}` that
  enables an LDAP profile while the block is present and not retired)
  requires `?operationId=` (`428 operation_id_required`) **and**
  `?cutoverConfirm=<cutoverConfirmValue>` (`428 cutover_confirm_required`,
  `409 confirm_mismatch`, both carrying `current.confirmValue`). Both are
  decided BEFORE anything is written.
- The frontend's cutover ceremony asks you to type the confirm value. The
  provider identity, the entry/document revision and the operationId are
  bound into the same request.

After the commit the legacy card shows `retired: true`, the cutover record
(`cutover.trigger: admin_api`, the actor, the profile, the registry revision
it was bound to) and `cutoverDurability: durable`. The record carries its
own identity; the ledger key the card joins it with is the enabling
profile's provenance `operationId`.

Boot idempotence (FE-6A.2 correction, Blocker 4): on every later boot of a
node that has cut over and still carries the YAML block, the startup slice
only OBSERVES the shadow (fail-closed: the legacy authenticator stays
retired); the durable record is reconciled when `admin_settings.json`
loads. A completed admin cutover therefore keeps the same record identity
(`cutover.operationId`, `trigger`, `registryRevision`, `actor`) and emits
NO new `idp.legacy_ldap.retired` audit entry across any number of restarts.
Only a boot on which no durable record exists mints the boot-observed record
and its one-time audit. If the settings file is missing, corrupt or
unreadable at boot, the retirement stays in force and nothing is invented.

Break-glass revert is unchanged: see `ldap-identity-provider.md`.

## 5. Repairing a quarantined registry

A registry file that fails to load at boot is moved aside (never deleted)
and the node boots **degraded**: `GET /api/idp` reports `degraded: true`
with a bounded `degradedReason` and every write is refused
(`409 registry_degraded`). The frontend renders "quarantine evidence:
recorded" on the page and shows the evidence itself — the quarantined file's
base name — ONLY inside the **Repair registry** ceremony, where you type it
exactly. `POST /api/idp/repair {confirm}` answers `409 confirm_mismatch`
with `current.confirmValue` on a mistyped value, `409 not_degraded` when
there is nothing to repair, and `{ok, repaired, evidence, revision}` on
success (audited `idp.repair`).

Repair acknowledges the quarantine and starts an empty registry. To restore
the previous profiles instead, stop the node, inspect the quarantined copy
beside the registry path, fix or restore it, and restart.

## 6. Legacy import

**Import legacy configuration** (`POST /api/idp/legacy-ldap/import`) creates
a DISABLED registry profile from the YAML block and copies the bind
credential server-side; the browser never receives it. Since the FE-6A.2
correction the import is an ordinary fenced, identified write:

- `?documentRevision=` (the loaded registry document revision — `428
  precondition_required` / `409 stale` with `current.documentRevision`) and
  `?operationId=` (`428 operation_id_required`) are required; the fence is
  decided inside the registry transaction.
- The operation is ledger-recorded as `idp.import` with the same intent /
  replay / mismatch / pending / lookup semantics as a create: a repeat of the
  same operationId answers `replayed: true` and imports nothing twice; the
  candidate commitment binds the legacy source identity (URL, base DN, bind
  DN, credential presence, StartTLS, skip-verify, filter, group) — never the
  credential.
- The answer is action-bound: `imported: true`, the disabled ldap profile
  (identity, entry revision, `operationId` provenance), the RESULTING
  `documentRevision`, a credential-free `source` identity and the fleet
  publication facts.
- The frontend writes the recovery marker (action `import`) BEFORE the
  request. An unproven answer keeps the marker, latches the page and
  re-reads the registry once; **Recover** looks the operation up in the
  ledger; a `404` offers a re-send of the SAME import operation; a changed
  legacy block is refused locally and by the appliance (`operation_mismatch`).

Enabling the imported profile afterwards is the cutover in §4.

## 7. Secrets

OIDC `clientSecret`, LDAP `bindPassword`, inline SAML metadata and the
directory-test username/password are write-only: sent once in the request
body, never returned by any read, never placed in a URL, marker, storage,
log, audit entry or summary. Reads carry presence indicators only
(`clientSecretConfigured`, `inlineMetadataConfigured`,
`bindCredentialConfigured`). Leaving a secret field empty on an edit keeps
the stored value; the explicit "Clear …" control sends an empty value. A
failed or stale write never re-fills a secret field.

## 8. Directory test

**Test directory** runs `POST /api/idp/test` against the staged candidate
with transient credentials. The server bounds the run (45 s watchdog, 5 s
dial); the browser abandons at 60 s. `ok: false` is a FAILED test rendered
step by step with a closed error vocabulary (`timeout`, `tls_failed`,
`unreachable`, `invalid_credentials`, `no_such_object`,
`insufficient_access`, `directory_error`); an unverifiable answer is
unproven, never "passed".

## 9. Commit-time directory preflight (write boundary)

Every create or update that introduces an ENABLED LDAP provider, or changes
the connection spec (URL, StartTLS, skip-verify, bind DN, bind password, base
DN) of an enabled one, crosses the authoritative directory test at the write
boundary — before the ledger intent, after the replay and fence pre-checks —
and no request parameter can skip it (`?preflight=` is accepted for
compatibility and changes nothing). A label-only edit of an enabled provider
does not re-dial.

A failure is the bounded refusal `422 preflight_failed` with
`current.step` (`reachable`, `tls`, `service_bind`, `base_dn`,
`user_lookup`) and `current.reason` (the closed vocabulary in §8) plus the
sanitized report. It is decided before anything is written: registry,
ledger, cutover record, audit trail and fleet publication are untouched, and
the frontend releases the recovery marker (nothing to settle). A directory
that is down at save time therefore cannot become the enabled authenticator;
fix the directory (or the candidate) and save again.
