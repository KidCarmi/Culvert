# Request-history store — corruption, encryption and recovery

**Applies to:** any node with request-history saving switched on (Logs →
Retention in the admin UI). The setting is durable, so it survives restarts.

**Register item:** CHAOS-57.

---

## What this store is

Culvert records request activity in three independent places:

| Surface | What it is | Survives restart | Affected by this store |
|---|---|---|---|
| In-memory ring | the live tail / SSE feed | no | no |
| Request log (`internal/reqlog`) | the durable JSONL record | yes | no |
| Audit log (`internal/audit`) | the durable compliance record | yes | no |
| **History store (BadgerDB)** | the **queryable, paginated** history | yes | **this document** |

The history store is a searchable view — deep pagination, retention by age and
size. Losing it does not affect traffic, policy enforcement, the request log, or
the audit log. That is why every failure below **degrades** rather than stopping
the gateway.

---

## What happens when the store is damaged

An unclean stop (`docker kill`, OOM, host power loss, a failing volume) can
leave the BadgerDB directory in a state it cannot be opened from. Culvert
detects this and recovers automatically:

1. the damaged directory is **moved aside** to `<dir>.corrupt.<timestamp>` —
   never deleted;
2. an empty store is created in its place and history resumes;
3. the incident is reported once, on every surface listed below.

Only one quarantined copy is kept. A host that keeps producing corruption must
not fill the volume with evidence, and the newest copy is the useful one.

> **Your history from before the incident is in the quarantined copy.** If the
> store is encrypted, that copy is still decryptable with the existing
> `<dir>.salt` sidecar, which is deliberately left in place — so keep the
> sidecar until you have finished with the copy.

### Where you see it

| Surface | Signal |
|---|---|
| `GET /api/diagnostics` | the `request_history` row (`warn`, with an operator action) |
| `/metrics` | `culvert_logstore_available`, `culvert_logstore_recovered`, `culvert_logstore_quarantined_copies` |
| Alerts | `state_file_corrupt` (source `storage`) |
| Server log | one `LogStore:` line naming the cause and the quarantine path |

`culvert_logstore_available` is `0` **both** when history saving is off and when
the store failed to open. Use the `request_history` diagnostics row to tell them
apart; alert on the metric only if you know the fleet has the feature on.

### What to do

1. Confirm the data volume is healthy (space, permissions, mount state). A
   quarantine that keeps recurring is a disk problem, not a Culvert problem.
2. Retrieve anything you need from `<dir>.corrupt.<timestamp>` (see below).
3. Delete that directory to reclaim disk. The `request_history` row keeps
   warning until you do — that is the point.

---

## Encryption: three conditions that look identical

If a history passphrase is configured, the store is encrypted at rest with a key
derived from `(passphrase, salt)`, where the salt lives in a sidecar file next
to the store directory: `<dir>.salt`.

BadgerDB reports the following three conditions **with the same error**, so
Culvert deliberately does **not** guess between them and never quarantines any
of them — quarantining a store whose data is perfectly intact would destroy
history over a configuration change.

| Condition | Is the data intact? | Remedy |
|---|---|---|
| The passphrase changed | yes | restore the original passphrase, or purge |
| The `.salt` sidecar is missing/damaged | yes | **restore the sidecar** (below), or purge |
| The store's KEYREGISTRY is corrupt | no | purge |

The admin UI reports the first as *"saved logs use a different encryption
key — purge saved logs, then enable again"* and the second as its own message
naming the sidecar, because **the remedies are different and only one of them
is reversible.**

### If the `.salt` sidecar is missing or damaged

Culvert **refuses to mint a replacement** when history already exists on disk,
and leaves the existing sidecar untouched. This is deliberate: the key is a pure
function of `(passphrase, salt)`, so writing a fresh salt would replace the only
value that could ever decrypt your history — silently, as a side effect of
failing to read a file.

So the recovery order matters:

1. **Restore `<dir>.salt` from a backup first, if you have one.** Nothing else
   is needed — enable history again and the store opens with all its data.
2. Only if you cannot: purge saved logs (Logs → Retention → Purge) and enable
   again. **This discards the saved history and is irreversible.**

> The salt sidecar is key material, so it is deliberately excluded from support
> bundles and archives — the same rule that excludes `.kek` files. If you want
> to be able to recover from this case, back it up yourself, separately from the
> store it unlocks.

### Reading a quarantined encrypted copy

The quarantine renames only the store directory, so `<dir>.salt` stays where it
was and continues to apply to the quarantined copy. Point a tool at
`<dir>.corrupt.<timestamp>` with the same passphrase and the same sidecar. Do
**not** purge (which removes the sidecar) until you are finished with the copy.

---

## What is NOT affected

- Traffic. The proxy serves normally throughout; the history store is opened and
  closed independently of the data path.
- `/ready` and `/readyz`. A node with history degraded is fully able to serve, so
  it is deliberately **not** failed out of a load-balancer rotation over a query
  convenience.
- The request log and the audit log. Both are separate, durable, and unaffected.

---

## Related

- `docs/operator/category-store-recovery.md` — the same mechanism for the
  Layer-2 community category store (CHAOS-50). Both stores share
  `internal/storeguard`.
- `docs/engineering/CHAOS-ENGINEERING-REVIEW-2026-08-29.md` — the sweep that
  produced this behaviour, including what was deliberately left.
