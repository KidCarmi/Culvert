# Certificates and CA lifecycle — the FE-6B.0 backend contract

This runbook describes how the inspection Root CA, the admin-UI certificate,
the upstream mTLS client certificate and the OCSP posture are read and changed
through the admin API after the FE-6B.0 backend-truth gate, and how a lost
response, a persistence fault or a restart is recovered. The React pages that
will consume this contract are FE-6B.1/6B.2; the legacy console already speaks
it.

Everything on this surface is **node-local**: nothing here is synced CP→DP
(only the cluster CA fingerprint travels in the ConfigSnapshot), nothing is on
the config-version rollback surface, and `GET /api/certificates` says so
(`scope: node-local`).

## 1. Identities and fences

| Object | Revision token | Read from | Echoed on |
|---|---|---|---|
| Root CA | `caRevision` = `car1:<sha256 hex of the live CA DER>` (`car1:none` without a CA) | `GET /api/ca/status`, `GET /api/certificates`, `GET /api/ca-cert` (JSON) | `?caRevision=` on the rotation challenge, the rotation confirm and a MITM import |
| Admin-UI certificate pair | `uiCertRevision` = `uic1:<sha256 hex of the persisted cert file>` (`uic1:none` when nothing is persisted; `uic1:incomplete` when only one of the two files exists; `uic1:unavailable` when the pair cannot be examined or read — the certificate or the private key is not readable, or a path is a directory; a present but unreadable key is unavailable evidence, never an invalid pair) | `GET /api/certificates` (`uiCert.revision`, with `uiCert.pairState` = `complete` / `absent` / `incomplete` / `unavailable`), the dry run's `current` | `?uiCertRevision=` on a UI replace and a UI delete (a mutation against `uic1:unavailable` is `503 evidence_unavailable`) |
| OCSP desired posture | `ocspRevision` = `ocr1:<hex>` over the durable posture AND its generation (a toggle never returns to an earlier token) | `GET /api/ocsp`, `GET /api/certificates` | `?ocspRevision=` on `POST /api/ocsp` |

A fenced mutation without its token is `428 precondition_required` (the
current token under its own name in `current`); a moved token is `409 stale`
with the current one. The comparison happens **inside** the serialized
mutation boundary, never as a check followed by an unlocked write.

## 2. Operations, replay and the lookup

Every mutation — rotation, MITM import, UI replace, UI delete, OCSP set —
requires a client-generated UUID `?operationId=` (`428 operation_id_required`
without one). Before the first irreversible write the node records the intent
durably in `<dataDir>/certificate_operations.json` (256 slots; unresolved
intents are never evicted; a corrupt or unreadable file is fail-closed
`503 operation_ledger_degraded` with the file left in place as evidence).

- Re-sending the **same operationId with the same candidate** answers the
  recorded result with `replayed: true` — also after a restart — and mutates
  nothing.
- The same operationId with a **different action or candidate** is
  `409 operation_mismatch`.
- `GET /api/ca/operations/{operationId}` (admin) is the authoritative lookup:
  `pending`, `committed`, `aborted` or `outcome_unknown`. A pending intent is
  **settled by the lookup, at boot, or by the next writer of the same object
  before it writes** (§8) from the object's own evidence — the live CA or the
  bundle on disk carrying the candidate fingerprint, the persisted UI
  certificate carrying the candidate digest, the durable OCSP posture at the
  intent's generation naming the intent as its writer — never from a guess.
  A recovered commit carries the **complete action-bound `result`** the
  client would have received (rotation: `rotated`, `ca`, `previous`; import:
  `imported`, `target`, `ca`, `previous`; UI replace/delete: `replaced` /
  `deleted`, `activation`, `uiCert`, `candidate`; OCSP: `ok`, `enabled`,
  `durable`, `revision`, `desired`, `runtime`), rebuilt from the non-secret
  facts recorded with the intent.
- **A post-rename synchronisation failure is not a refusal.** When the
  bundle (or a UI pair file) was renamed into place but the data directory
  could not be synchronised afterwards, the replacement IS on disk: the node
  installs it (a split live/disk state is never published), keeps the intent
  **pending**, and answers the non-terminal `500 outcome_unknown` with
  `current.detail: durability_unproven` and `current.state: pending`. Do not
  re-send with a new operationId — poll the lookup (or re-send the SAME
  operationId): the settlement re-synchronises the directory, and only then
  credits, audits and reports the durable success. A UI pair transition that
  reached its commit point but could not be finished answers
  `current.detail: transition_incomplete` the same way and is completed by
  the next settlement.
- **Unavailable evidence is never absence.** A pending intent whose evidence
  cannot be read — the bundle path is unreadable or is a directory, the
  bundle cannot be decrypted under the passphrase the node booted with, the
  UI pair's path cannot be examined — is settled as the recoverable
  `outcome_unknown` with `code: <why>_evidence_unavailable`, re-decided by
  every later settlement (the lookup, a boot, a recovered CA load, a later
  writer), and it **blocks every writer of that object** (`503
  operation_unsettled`) so the evidence is not destroyed before it decides.
  Restore access (the passphrase, the path, the permissions) without
  changing the bytes and the next settlement commits or aborts from the
  real evidence. A bundle that reads but is not a CA bundle is
  `<why>_evidence_invalid` (recoverable, does not block a repairing writer —
  but the repairing writer never decides the earlier intent: before it
  writes, the intent is recorded durably as `writer_evidence_superseded`
  with `supersededBy` naming the writer (its operationId, or
  `auto_rotation` / `ca_recovery`), a terminal `outcome_unknown` that no
  lookup, boot or later writer re-decides — the same candidate imported by
  the repair is NOT a commit of the earlier intent, and a different one is
  NOT its refusal; a superseding record that cannot be persisted refuses the
  repair with `503 operation_unsettled` and nothing written);
  `<why>_durability_unproven` and `<why>_cleanup_incomplete` are the same
  recoverable, writer-blocking shape for a directory that could not be
  re-synchronised and a UI cleanup that could not be finished. Only a
  **positively absent** bundle, or one carrying something else, aborts.
- A refusal is **terminal only once it is durable**: `500 persist_failed` is
  answered only after the operation's aborted record landed. If that record
  cannot be written, the answer is the non-terminal `500 outcome_unknown`
  with `current.detail: refusal_not_durable` and `current.state: pending` —
  nothing was changed, the intent stays pending, and the next settlement
  records the refusal (`code: persist_failed` in the same process,
  `reconciled_absent` after a restart). A repeat of the same operationId
  then answers `409 operation_aborted` and executes nothing.
- The success audit (`ca.rotate`, `ca.import`, `cert.ui.replace`,
  `cert.ui.delete`, `ocsp.set`) is **operation-keyed and emitted exactly once
  after the durable terminal record**. A refused, aborted or ambiguous
  operation emits none. When the terminal record or the audit could not be
  made durable, the response says so (`recordState: pending_reconciliation`,
  `auditState: pending`) and the lookup completes it.

## 3. Root CA rotation (the bound challenge)

1. `GET /api/ca/status` → `revision`.
2. Generate a UUID `operationId`.
3. `POST /api/ca/rotate/challenge?operationId=…&caRevision=…` → `challenge`
   (64 hex), `fingerprint` of the CA being replaced, `expiresInSeconds` (120).
   The challenge is bound to the requesting actor, the operationId, the
   revision and the expiry, is single-use, and is consumed **only by a fully
   valid confirm**. Audited `ca.rotate_requested`.
4. `POST /api/ca/rotate?operationId=…&caRevision=…` with `{"challenge":"…"}`.
   Another actor, another operation, a moved revision, a wrong value or an
   expired challenge is `409 challenge_stale` with `current.changed` naming the
   bounded class(es) (`actor`, `operation`, `ca_revision`, `challenge`,
   `expired`) and the challenge is **not** consumed; a malformed body is
   `400 invalid_input`; no challenge is `428 challenge_required`.
5. **Persist before publish.** The new bundle is written atomically to the
   configured `-ca-path` first; only then is the candidate installed. A write
   failure is `500 persist_failed` (bounded `current.class`) with the current
   CA unchanged and the operation aborted. No bundle path configured is
   `503 persistence_not_configured`, refused before anything is minted.
6. The result carries `rotated: true`, `persisted: true`, `ca.revision` (the
   new fence), `previous.fingerprint`, `operationId`, `recordState`.

Auto-rotation (30 days before expiry, checked every 24 h) follows the same
rule: a bundle write failure leaves the current CA active, logs the class,
fires `cert_expiry`, and retries at the next check. Nothing is ever installed
unpersisted.

## 4. Importing a MITM CA and replacing the admin-UI certificate

`POST /api/certs/upload` (multipart `cert`, `key`, `target`):

- The **complete candidate is validated first** — `400 candidate_invalid` with
  a bounded `current.reason`: `malformed_pem`, `chain_invalid`,
  `key_mismatch`, `not_ca` (mitm), `unsupported_key` (the MITM signer needs an
  ECDSA key), `encrypted_key_unsupported`, `expired`, `not_yet_valid`. Nothing
  is written; no key material, parser text or path is echoed.
- `?dryRun=1` answers the candidate's public facts (`fingerprint`, `subject`,
  `isCA`, `keyAlgorithm`, `notBefore`/`notAfter`; for a UI pair also
  `dnsNames`, `chainLength`) plus the fence to echo — the T2 review material —
  without a fence, an operationId or a write.
- `target=mitm`: fenced on `caRevision`, persist-before-publish as in §3;
  the installed CA's own certificate is `409 candidate_duplicate`. Audited
  `ca.import`.
- `target=ui`: fenced on `uiCertRevision`; the pair is written as a
  **staged, marker-committed transition** under `<dataDir>`: the certificate
  and the key (0600) are staged as `ui_tls_cert.pem.next` /
  `ui_tls_key.pem.next`, the transition marker `ui_tls_transition.json`
  (kind, operationId, certificate digest — never a key digest) is the commit
  point, then the staged files are renamed over `ui_tls_cert.pem` +
  `ui_tls_key.pem`, the directory is synchronised (**barrier 1**: the
  completed pair is durable), only then is the marker removed, and the
  directory is synchronised again (**barrier 2**: the marker's removal is
  durable). The marker is the recovery evidence and is deleted only once what
  it describes is durable: a crash after barrier 1 leaves a marker beside a
  complete pair, which the next boot or settlement completes idempotently
  and consumes; a failed barrier keeps the marker and answers
  `durability_unproven`; a marker that reappears after a crash is harmless.
  The live pair is therefore only ever the previous complete pair or the new
  complete pair — a process killed at any instant is repaired at the next
  boot and at the next settlement from the marker (a committed transition
  is completed; staged files without a marker are abandoned, the previous
  pair untouched). A failure before the commit point changes nothing
  (`500 persist_failed`). The appliance reports `activation:
  restart_required`: the running listener is unaffected, and what the NEXT
  start serves depends on the startup configuration — an explicit
  `-tls-cert`/`-tls-key` pair or `-ui-no-tls` takes precedence over the
  persisted pair, so a replace proves only that the persisted material
  changed. A replace is credited only for a
  **complete, valid pair whose certificate is the candidate** (the key is
  proven by the pair parsing). Audited `cert.ui.replace`.
- `DELETE /api/certs/ui?operationId=…&uiCertRevision=…` removes the pair
  through the same committed transition (marker first, then key, then
  certificate, then the same two barriers). `404 not_found` when nothing is persisted. The result and
  the recovered record state the cleanup fact: `cleanup: complete` (the
  delete removed both files) or `cleanup: completed_at_settlement` (the
  process died after one removal — a remnant of one file — and the
  settlement finished the cleanup before crediting the intent). A remnant
  without a delete intent is left in place and reported as
  `uiCert.pairState: incomplete` / `uic1:incomplete` (delete or replace it
  with that fence). The running listener keeps what it loaded at boot
  (`uiCert.active`, `activation`); what the next start serves depends on the
  startup configuration (an explicitly configured pair, the automatic
  certificate, or no TLS under `-ui-no-tls`) — the deletion selects no
  replacement. Audited `cert.ui.delete`.

Passphrases and private keys are write-only: never echoed, logged, audited or
recorded in the ledger.

## 5. OCSP posture

`GET /api/ocsp` (viewer) reports the DESIRED posture (`desired.enabled`,
`desired.source` ∈ default / yaml / admin), the RUNTIME posture, `durable`,
`revision`, `scope`, the counters, and — for the upstream mTLS client
certificate — `mtlsClientCertConfigured`, `mtlsClientCertLoaded` and, when not
loaded, a bounded `mtlsClientCertReason` (`cert_file_missing`,
`key_file_missing`, `load_failed`). The file path and the loader's text never
appear on this response.

`POST /api/ocsp?operationId=…&ocspRevision=…` `{"enabled": bool}` persists
the desired posture in `admin_settings.json` first and flips the checker only
after the write landed: a `200` (`durable: true`) survives a restart and wins
over `proxy.ocsp_check`; a persist failure is `500 persist_failed` with the
running posture unchanged. Audited `ocsp.set`.

## 6. Bounded classes, not raw errors

`GET /api/ca/status` and `GET /api/certificates` publish every fault as a
class — `unusableClass` (`expired`, `not_yet_valid`, `no_ca`),
`rotationPersistClass`, `loadFailureClass`, `loadRecoveryClass`
(`permission_denied`, `not_found`, `read_only`, `no_space`, `not_a_file`,
`io_error`, `write_failed`, `decrypt_failed`, `bundle_malformed`,
`load_failed`, `init_failed`, `expired`). The bundle path and the exact OS or
decrypt error stay in the process log. Every refusal on this surface is typed
JSON `{error, code[, current]}` with a closed `code` vocabulary; no route here
answers plain text.

## 7. Backup, restore, rollback, downgrade

See [`docker-compose-backup-restore.md` §13](docker-compose-backup-restore.md#13-certificates-the-ca-and-ocsp-in-a-backup):
the CA bundle is archived (Tier 1), the UI pair and the operation ledger are
not, the OCSP posture travels inside the sanitized settings file, none of them
is on the config-version rollback surface, and a pre-FE-6B.0 binary ignores
the new settings keys and the ledger.

## 8. Who may change a certificate object, and in which order

Every writer of a lifecycle target — the admin handlers, the automatic CA
rotation round and the CA recovery loop — runs under one boundary
(`certOpsMu`, then `caMutationMu` for the CA) and **settles every pending
intent on that target durably before it writes**. Current content proves an
operation's commit only while nobody has written the object since, so the
settlement happens first, and a competitor is refused (`503
operation_unsettled`, `current.reason` a bounded ledger class) or deferred
(rotation: the round is skipped and retried at the next check; recovery:
the attempt is retried by the campaign) when a settlement cannot be made
durable — nothing is written. Consequences an operator can rely on:

- an operation that committed but could not record its terminal state stays
  `committed` — exactly once, with its success audit — even after a later
  rotation, import or replace changed the object;
- an operation that never wrote is never credited with a later writer's
  identical content or with the object's absence;
- the automatic rotation round takes the writer posture (settle, supersede,
  then write) **only when a rotation is due**; a round that would write
  nothing leaves the operation ledger untouched, so a boot with a load
  failure never strips a pending repair of its recoverable state;
- the OCSP posture in `admin_settings.json` records the operationId that
  wrote it (`ocsp_settings_write_id`) in the same atomic write; a posture
  written by anyone else is a refusal for the intent, and a posture without a
  writer is unproven;
- while the operation ledger is corrupt, unreadable or unwritable, no writer
  changes a certificate object — the automatic rotation round logs one line
  per check and waits; repair the ledger (or move it aside to start empty)
  and restart;
- while an intent's evidence is unavailable (an unreadable bundle,
  certificate or private key), its durability unproven or its cleanup
  incomplete (§2), no writer changes that object either: restore access to
  the evidence and the next settlement decides it. A writer that repairs an
  object whose evidence is INVALID is admitted, but only after the waiting
  intent is durably recorded as superseded by that writer (§2) — the
  repair's content never becomes the earlier intent's verdict. The CA
  recovery loop's LOAD branch is the one exception by design — reading the
  bundle is what makes the evidence available again, so the load runs first
  and the waiting intents are settled from the recovered bundle right after
  it; the loop's writing branches (minting a root, re-persisting a loaded
  one) still settle first;
- a commit that the lookup or the boot decided from the **bundle on disk**
  (the process died between the durable write and its record) names that
  bundle's CA in its `result.ca` and `committedRevision` — never a different
  CA the live manager happens to hold at settlement time.

**Boot order is explicit.** The auto-rotation loop's first round waits for
the certificate-lifecycle boot gate; `LoadAdminSettings` reconciles the
operation ledger on every load path (missing, unreadable, quarantined or
readable settings file) and releases the gate afterwards. A pending intent is
therefore classified before anything can replace its evidence, whatever the
startup timing.

## 9. The admin console (React) ceremonies — FE-6B.2

`/app/security/certificates` (tab **Certificates**) exposes every mutation
of §3–§5 to an **admin** signed in to the new console; viewers and operators
see the same facts and no mutation control. The console speaks exactly the
contract above — it invents no token, refreshes no fence on its own and
retries nothing:

- **Rotate Root CA…** — the console mints the `operationId`, obtains the
  server challenge (§3 step 3; the ceremony shows the CA being replaced and
  the challenge's expiry — the challenge is not a mutation and writes no
  recovery marker), records the recovery marker at the confirm and confirms
  only after the operator types `ROTATE`. An expired challenge (`409
  challenge_stale`, `changed: [expired]`) offers a **new challenge for the
  same operation**; a moved revision (`409 stale`) is rendered with the
  current revision and the ceremony ends — refresh, review, start again.
- **Import CA…** / **Replace UI certificate…** — the operator pastes the PEM
  pair; **Review candidate** runs the `?dryRun=1` validation (a bounded
  `candidate_invalid` reason is shown; nothing is written); the reviewed
  facts and the fence to echo are displayed, and **Import** / **Replace**
  commits the same pair under that fence. The pair is sent once, as
  byte-exact multipart file parts, and dropped with the dialog. A replace is
  **not** activation: the result states that the persisted material changed,
  that the running listener is unaffected, and that what the next start
  serves depends on the startup configuration (it never promises that the
  new pair will be served).
- **Delete UI certificate…** — a typed ceremony: the operator types the
  persisted certificate's first eight fingerprint bytes exactly as shown.
  The dialog states the persisted identity **and** the fact about the
  running listener from its bind evidence (it serves this pair, an
  explicitly configured pair, plain HTTP, or is not observed); the delete
  does not stop the listener, and neither the dialog nor the result promises
  a self-signed fallback or what the next start serves.
- **Set OCSP posture…** — states the desired posture, the runtime posture,
  the node-local scope and the checker's coverage limit (§5 / CHAOS-65
  OCSP-8) before **Apply**; the result renders desired and runtime as the
  appliance states them, never merged.

**A lost or unverifiable answer.** Every mutation is dispatched only after a
NON-secret, subject-bound recovery marker (operation id, intent, the fence
carried, the candidate's public identity) is stored in the browser session;
if it cannot be stored, nothing is sent. When the answer is lost, malformed,
or the non-terminal `outcome_unknown`, the ceremony closes (dropping the
typed material), the marker is kept and every mutation control stays
disabled. The **Unresolved certificate operation** card offers:

- **Recover** — `GET /api/ca/operations/{id}` (§2). `committed` clears the
  marker and shows the recorded result; `pending` and a recoverable
  `outcome_unknown` keep it (recover again later); `aborted` states that
  nothing was written; `writer_evidence_superseded` and an unproven
  `outcome_unknown` are **terminal unknown** — never shown as a success, a
  failure or a safe retry. A record under the id that is not bound to the
  dispatched intent (another action, fence or candidate) is reported as
  such and the marker is kept.
- **A `404` lookup is UNKNOWN.** The appliance retains no record of the
  operation — a write that never started and a decided record that was
  evicted from the 256-slot ledger are the same `404` — so whether it
  committed cannot be known, and nothing the node holds now is evidence
  about it. The card offers **no re-send**: a re-sent operation is safe only
  while the ledger still retains its record (replay by id) or the fence has
  moved (`409 stale`); after an eviction plus an identical reinstall of the
  same object the original content-derived fence matches again and the
  re-sent operation would execute a **second time** (proved on the real
  handlers by `fe6b2c_red_test.go`). A new intent is a new operation, after
  the marker is abandoned.
- **Abandon** — a typed ceremony that discards **this browser's marker
  only**; it cancels or reverses nothing on the appliance, whose ledger
  record stays visible through the operation lookup.

Signing out purges the marker; a marker stored under another admin's
session is never inherited.

**Limitations.** Recovery and replay are node-local (§7: the ledger is not
archived, so after a restore a pre-restore operation is `404` — UNKNOWN, as
above; the current object state is not evidence about it). The console does not restart
the appliance and does not distribute the CA to clients or nodes. The
rotation challenge is process-local: a restart between challenge and
confirm is `409 challenge_stale`, and the console asks for a new one.
