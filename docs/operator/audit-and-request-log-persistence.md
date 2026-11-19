# Audit and request log persistence

Who this is for: operators who run Culvert with a durable audit log or request
log file and need to confirm it is being written, or bring it back when it is
not. The SIEM/syslog copy of the same streams is covered separately in
[`siem-feed-delivery.md`](siem-feed-delivery.md). The Badger-backed request
**history** store (Monitor view, retention) is a different store, covered in
[`request-history-recovery.md`](request-history-recovery.md).

---

## What is persisted, and where

| Stream | Flag | `config.yaml` key | Rotation | In-memory ring |
|---|---|---|---|---|
| Audit log (who changed what on the admin plane) | `-audit-log <path>` | `audit_log_file` | 50 MB, fixed | newest 500 entries |
| Request log (one line per proxied request) | `-request-log <path>` | `request_log_file` | `-request-log-max-mb` / `request_log_max_mb`, default 100 MB | newest 5000 entries |

- Both files are append-only JSONL. The flag wins over the `config.yaml` key.
- Rotation keeps **one** archive: the full file is renamed to `<path>.1` and any
  earlier `<path>.1` is deleted. Older data survives only if you collect it
  (SIEM forwarding, or an external log shipper).
- Neither is on by default in the binary: with no path set, both streams live
  only in the in-memory ring and are lost on restart. The shipped
  `Dockerfile` and `docker-compose.yml` set `-audit-log /data/audit.jsonl` and
  `-request-log /data/requests.jsonl`; `docker-compose.ha.yml` sets only
  `-audit-log`.
- Both paths are read at startup only. Changing the path needs a restart.
- At startup the audit log's existing lines are loaded into the ring, so the
  admin UI shows recent history across a restart. `GET /api/audit?source=file`
  (and the CSV/JSON export, which defaults to the file) reads the file itself.

---

## How to tell whether the file is being written

| Surface | Audit log | Request log |
|---|---|---|
| Operator-contract row (`GET /api/diagnostics`, Diagnostics panel) | `audit_log_persistence` | `request_log_persistence` |
| `GET /api/stats` | `auditLogConfigured`, `auditLogPersisted`, `auditLogPath` | `requestLogConfigured`, `requestLogPersisted`, `requestLogPath` |
| Write failures after a successful open (Prometheus) | `culvert_audit_write_errors_total` | `culvert_reqlog_write_errors_total` |

What the row says:

- `ok` "not configured" — no path is set. This is the in-memory-only setup,
  not a fault. For any deployment with compliance requirements, set
  `-audit-log`.
- `ok` "persisting to the configured log file" — healthy.
- `fail` "configured but failed to open" — a path is set but could not be
  opened at startup (missing directory, wrong ownership, read-only or not yet
  mounted volume). `Configured: true` with `Persisted: false` in `/api/stats`
  means the same thing.

---

## Recovery: the configured path could not be opened at startup

**No restart is needed.** Culvert keeps the configured path as your intent and
re-attempts the **same** path in the background:

- First retry after 10 s, doubling to a 2-minute cap, plus up to 25% jitter,
  so the slowest cadence is about one attempt every 2.5 minutes. There is no
  attempt limit. Both logs use the same schedule.
- Culvert never chooses another path and never changes a setting or creates a
  configuration version.

Steps:

1. Find the cause in the process log. The startup line is
   `Audit: log file error (...)` or `RequestLog: file error (...)`. While
   retrying, a failed attempt is logged on the first attempt and every tenth
   after it.
2. Fix the path: create the directory, correct ownership/permissions for the
   container user, or mount the volume.
3. Wait for the next attempt, then confirm the row is back to `ok`. The log
   shows `Audit: the configured audit log "..." became writable` or
   `RequestLog: the configured request log "..." became writable`.

What happens to entries recorded while the file was unavailable:

- **Audit log:** they are written to the file **before** any newer entry, up
  to the newest 500. Entries evicted from the ring before the open are lost;
  their number is in the "became writable" log line and is added to
  `culvert_audit_write_errors_total`. Culvert then appends a system-attributed
  `audit.persistence.auto_open` audit entry that marks where the recovered gap
  ends and states how many entries were written and how many were evicted.
- **Request log:** entries recorded before the open are **not** written to
  the file. They stay in the in-memory ring only. The file starts with the
  first request after the open.

A restart still works and is the right step only if you need a **different**
path: edit the flag or `audit_log_file` / `request_log_file` and restart.

The one-shot prepare-downgrade command does not retry: it still refuses to run
when its audit log cannot be opened.

---

## When writes fail after the file was opened

The background retry covers the startup open only. A failure later (disk full,
read-only remount, I/O error, a failed reopen after rotation) leaves the row
`ok`, because the file is still open, and is counted instead:

- Audit log: every failed write increments `culvert_audit_write_errors_total`
  and feeds the storage-health plane, which raises the `storage_write_failed`
  alert. The first failure is logged.
- Request log: every failed write increments
  `culvert_reqlog_write_errors_total`. The first failure is logged.

Alert on a non-zero rate of either counter. Fix the volume; the next
successful write resumes persistence. Entries whose write failed are not
retried and exist only in the ring and, if configured, the SIEM feed.

---

## Recommendations

- Set `-audit-log` on every production node and keep the file on the
  persistent `/data` volume.
- Forward both streams to a SIEM. The local file keeps at most one rotated
  archive; the SIEM is the long-term record.
- Scrape and alert on `culvert_audit_write_errors_total`,
  `culvert_reqlog_write_errors_total` and the two persistence rows.
- Size the volume for the active file plus one archive: 100 MB for the audit
  log and twice `request_log_max_mb` for the request log.
