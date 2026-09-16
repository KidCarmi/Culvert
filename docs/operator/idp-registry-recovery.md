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

**Recovery is action-bound (round 4, Blocker 2).** `GET
/api/idp/operations/{id}` is an action-discriminated record: an
`idp.import` record exposes the NON-SECRET `importSourceRevision` it was
bound to and no other action does. The browser's Recover clears an import
marker and reports the commit ONLY when the record's `operationId`, its
`action` and its `importSourceRevision` all equal the marker's (the marker
carries the exact reviewed token the POST was dispatched with); a record
under the same id with another action or another token is rendered as
"not bound — outcome unproven": the marker is kept, nothing is re-sent and
no success is claimed.

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

Boot idempotence (FE-6A.2 correction, Blocker 4; round 3, Blocker 3): on
every boot of a node that carries the YAML block beside an enabled registry
LDAP profile, the startup slice only OBSERVES the shadow (fail-closed: the
legacy authenticator stays retired) and every settings-load outcome is
routed through one state machine:

- **Readable settings with a record** — the same identity is adopted; a
  record whose audit was never proven (`auditPending`, a crash between the
  record's save and its audit) completes exactly one operation-keyed audit
  and clears the flag. No new record, no new audit, however many restarts.
- **Missing settings** — a known truth: the observed transition is recorded
  now. The record and the sentinel are saved TOGETHER first; the success
  audit (`idp.legacy_ldap.retired`, keyed on the record's `operationId`
  through the idempotent audit boundary) follows the successful save.
- **Unreadable or corrupt settings** — an unknown truth: the observation
  stays PENDING. The legacy authenticator stays shadowed, nothing is minted
  or audited, `cutoverDurability` reports `pending_reconciliation`, a
  corrupt file is quarantined (`admin_settings.json.corrupt.<ns>`, never
  overwritten), and NO save serialises the sentinel without its record.

**Storage recovery re-reads the file (round 4, Blocker 1).** While the
observation is pending, EVERY admin save first re-reads and parses the
authoritative `admin_settings.json` under the save boundary — the boot's
outcome is never trusted as the truth about the file:

- the file is readable again and carries a durable cutover ⇒ that EXACT
  record and sentinel are adopted (same `operationId`, same trigger, same
  actor), the observation is consumed, and NO new audit is emitted — a
  restored file wins over the boot-time guess, with or without a restart;
- the file is still unreadable, or readable but unparseable ⇒ the save is
  **refused** (a persist failure on the API; the process log says
  `save REFUSED — admin settings: the authoritative file is still
  unreadable …`) with zero file and zero runtime mutation — the evidence is
  never replaced by an unrelated write, and the observation stays pending
  for a later recovery;
- the file is missing (quarantined at boot, or removed since) or readable
  with no sentinel ⇒ nothing durable exists: the observed transition is
  minted, persisted by that save, and audited exactly once after it.

The process log records the load posture the boot observed (`readable`,
`missing`, `unreadable`, `corrupt_quarantined`) beside every recovery
decision. Remedy for a refused save: restore readability of the original
file (nothing else is needed — the next save adopts it), or deliberately
remove it to start from an empty store.

A completed admin cutover therefore keeps its record identity and emits no
new audit on any later boot; an observed transition is audited once, after
it is durable, and never twice.

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
- **The import is bound to the source the administrator REVIEWED** (round
  3). `GET /api/idp/legacy-ldap` publishes `importSourceRevision`, a
  server-owned keyed commitment (`isr1:<64 hex>`, HMAC under the node-local
  candidate key) over every security-effective field an import would copy,
  the bind credential VALUE included — it discloses nothing. The import
  must echo it (`428 import_source_required`); if the YAML changed since it
  was reviewed — a restart on an edited config, or a credential-only change
  — the appliance answers `409 import_source_stale` with the CURRENT token
  before the fence, the intent and any registry write, and the browser
  re-reads the source for review. The operation record is bound to the
  token: a replay must name it, and success/replay answers echo it — the
  browser accepts an answer only for the exact source it reviewed. The
  literal `unavailable` means the ledger key is unusable on this node (the
  import is not offered).

Enabling the imported profile afterwards is the cutover in §4.

### 6.1 The candidate-commitment key

`<data>/.idp_candidate_key` (0600, beside `idp_operations.json`) keys every
candidate commitment and every reviewed-source token. It is created
DURABLY and EXCLUSIVELY (temp file, fsync, `link(2)` publication, directory
fsync — exactly one generation wins a concurrent start, and every process
reads the published one); a failed publication leaves the ledger fail-closed
for that boot rather than a key of unknown durability. It is node-local:
never archived, never restored, never synced. **A ledger that already holds
keyed commitments is never re-keyed**: if the key is missing, short or
unreadable the ledger reports `operation_ledger_degraded` (reason
`unreadable`, detail naming the key) and every identified write and lookup is
refused until the ORIGINAL file is restored and the node restarted — a fresh
key would verify none of the recorded intents, so every exact-candidate
replay would answer `operation_mismatch`. Only a ledger with no
commitment-bearing record (a fresh node) mints a key.

**The confidentiality boundary is validated before the key is trusted
(round 4, Blocker 3).** The key is inspected with non-following metadata
on every load: it must be a regular file, not a symlink, with no group or
world permission bit (`0600`). A symlink, a non-regular object or a
group/world-readable mode is `operation_ledger_degraded` (reason
`unreadable`, detail naming the boundary) — the key is **never** re-moded
or replaced, with or without commitments beside it, because a key readable
beyond the appliance would turn the published `importSourceRevision` into
an offline guessing oracle for short bind passwords and a silent "fix"
would hide that exposure. Remedy: restore a regular `0600` key file at the
path (`chmod 600`, or replace the link with the original file) and restart.

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
