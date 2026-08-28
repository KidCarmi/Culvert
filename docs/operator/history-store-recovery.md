# Request-history store: damage, recovery and reconciliation

**Applies to:** the saved-log (request history) store — the BadgerDB directory
Culvert uses to make request history *searchable*.
**Related:** [`category-store-recovery.md`](category-store-recovery.md), which
covers the other Badger store on the data volume and shares this mechanism.

---

## What this store is — and what it is not

The history store is an **index**, not the record.

Every proxied request is written to the durable **request log (JSONL)** first;
the same entry is *then* handed to the history store so the admin UI can search
and page through it. If the history store is empty, damaged, or switched off,
the durable request log is unaffected and so is the in-memory ring the dashboard
reads.

This matters because it decides what a recovery costs you: **saved-log search is
reset; your request record is not.**

The store is off by default. It is enabled either by setting `log_store_path` in
config, or — far more commonly — from **Settings → Log Retention** in the admin
UI, which persists the decision to `admin_settings.json` and re-applies it on
every start.

---

## Why damage here used to be serious

A BadgerDB directory that has been torn by an unclean kill (`docker kill`, an
OOM, a host power loss, a volume yanked mid-write) can fail in two ways:

1. it returns an error — always handled: history stays off, the proxy serves
   normally, and the reason is logged; or
2. **it panics from a goroutine BadgerDB itself starts.** No error is returned
   and no caller can catch it. The process dies.

Case 2 was the problem, because this store is opened from two places:

- at **startup**, replaying the saved "history enabled" setting, and
- at **runtime**, when an admin turns history on in the UI.

So a damaged store could kill a serving gateway the moment someone toggled
history on, and — once the setting was saved — kill it again on every restart,
with the admin UI never coming up to let you turn it back off.

Culvert now detects this **before** handing the directory to BadgerDB, using a
marker file it arms for the duration of every open attempt. A marker left behind
by a process that never returned is the one reliable signal that the previous
open died inside it, so the damaged directory is moved aside first.

---

## What Culvert does automatically

On a damaged store, in a single start:

1. the damaged directory is **renamed** to `<store>.corrupt.<timestamp>` beside
   itself — **it is never deleted**;
2. a fresh, empty store is created and history resumes;
3. the incident is reported on every operator surface (below).

Culvert deliberately **refuses** to move a store aside when:

- another process is using it (renaming a live store is destructive);
- the volume is full, read-only, unmounted, or permission-denied — none of those
  are fixed by a rename;
- the failure is not positively recognised as damage. The safe default is to
  leave your disk alone and degrade.

In every one of those cases history stays off, the proxy keeps serving, and the
reason is logged and alerted.

At most **one** quarantined copy is kept, so a repeatedly-failing disk cannot
fill the volume with evidence.

---

## Where you will see it

| Surface | What to look for |
|---|---|
| `GET /api/diagnostics` | the `history_store` row |
| `/metrics` | `culvert_logstore_recovered`, `culvert_logstore_quarantines_total`, `culvert_logstore_quarantined_copies` |
| Alerts | the existing `state_file_corrupt` event, source `storage` |
| Audit log | `logstore.quarantine` — history was reset, with the reason and the quarantine path |
| Server log | lines prefixed `LogStore:` |

**Suggested alerting rule:** page on
`culvert_logstore_quarantined_copies > 0`. That series is read live from the
volume, so it clears by itself the moment you reclaim the disk — it is the
"there is still something to reconcile" signal.
`culvert_logstore_quarantines_total` is the cumulative "did this ever happen in
this process" counter and does **not** clear; use it for history, not for
paging.

---

## Reconciling an incident

1. **Confirm the volume is healthy.** A quarantine is a symptom. Check free
   space, mount state, permissions, and the host's kernel log for I/O errors.
   Recovering onto a dying disk just repeats the incident.

2. **Decide whether you need the quarantined copy.** It is a BadgerDB directory
   at `<store>.corrupt.<timestamp>`. It is damaged by definition, but a partial
   read with BadgerDB tooling is sometimes possible. Remember the durable
   request log (JSONL) still holds the underlying entries — that is usually the
   better source.

3. **Reclaim the disk.** Delete the `.corrupt.*` directory. The
   `history_store` diagnostics row and
   `culvert_logstore_quarantined_copies` both clear on their own once it is
   gone — you do not need to restart Culvert to clear them.

---

## The case that is *not* damage: a changed passphrase

If history was encrypted (`CULVERT_LOGSTORE_PASSPHRASE`) and the passphrase
changed, or the `<store>.salt` sidecar was lost or restored from a different
host, the store cannot be decrypted. Culvert reports:

> saved logs use a different encryption key — purge saved logs, then enable
> again

**This is not treated as damage and nothing is moved aside or deleted.** The
store is left exactly where it is, so the correct first move is to *restore the
original passphrase and salt* if you still have them — history then reopens
untouched.

Only if the key is genuinely unrecoverable should you use **Purge saved logs**
in the retention panel and re-enable history. That deletes the store and starts
a new one under the current passphrase.

> Because an encrypted store cannot be told apart from a wrongly-keyed one from
> the outside, a store that is genuinely *damaged* **and** encrypted may report
> the same message and will not self-heal. The purge-and-re-enable path above is
> the remedy for both.

---

## If history will not come back on

Work down this list; each step is visible in the `history_store` diagnostics row
or the server log.

1. **Volume problems** — space, permissions, read-only mount, or the path being
   a file rather than a directory. Culvert never renames in these cases; fix the
   volume.
2. **Another process holds the store** — usually a second Culvert against the
   same volume, or a container that has not fully exited. Only one may hold it.
3. **Encryption** — see the section above.
4. **Last resort** — purge saved logs and re-enable. You lose the search index;
   you do not lose the durable request log.

Turning history off is always safe and never affects proxy traffic, policy
enforcement, or the durable request log.
