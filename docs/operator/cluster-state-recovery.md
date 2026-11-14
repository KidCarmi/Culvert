# Cluster state file (`cluster.json`) — damage, dropped records and recovery

**Applies to:** a Control Plane, or an HA standby, started with `-cluster-db`
(for example `-cluster-db /data/cluster.json`).

**Register items:** CHAOS-07 (corrupt file), CHAOS-117 (null records).

---

## What this file is

`cluster.json` is the Control Plane's cluster state: the enrolled-node roster
(node ID and certificate serial per node), the enrollment tokens (stored as
SHA-256 hashes) and the revoked-certificate list. The Control Plane checks a
Data Plane node against it on the node's authenticated RPCs: the mTLS
certificate serial must match the serial recorded for the node ID, and a node
ID with no record is refused as `not enrolled`.

Unlike a cache, this state cannot be re-downloaded. What the file loses, an
administrator has to restore from a backup or re-create by re-enrolling nodes.

## What happens when the file is damaged

The file is read once, at startup. Four outcomes are possible:

| Damage | What Culvert does | State in effect |
|---|---|---|
| The file is not valid JSON | Renames it aside to `<path>.corrupt.<unixnano>` (quarantine) and starts with an empty store | **No** nodes, tokens or revocations |
| The quarantine rename itself fails | Leaves the corrupt file in place and starts with an empty store | Same — and the next cluster-state save **overwrites** the corrupt file |
| The file is valid JSON but a node or token record is `null` (`{"nodes":{"dp-1":null}}`) | Drops only the null records. The file is **not** quarantined, moved or modified at load | Every other node, token and the whole revocation list |
| The file exists but cannot be read (permissions, I/O error) | Starts with an empty store. The file is not touched at load | **No** nodes, tokens or revocations |

A fifth case applies to HA: a standby that receives a cluster state containing
null records from the leader drops them before adopting and persisting the
state. The damaged file is the **leader's**, not the standby's.

Quarantined copies left by an earlier start are re-detected on every later
start, until they are removed. This matters because after a quarantine the node
saves a fresh, valid, **empty** `cluster.json`; without the re-detection the
next restart would look healthy while the roster and revocation list are still
missing.

**In no case does a damaged `cluster.json` stop the gateway from starting.**

## What you will see

**Logs**

```
StateCorruption: "cluster state file /data/cluster.json is corrupt (…) — quarantined to
 /data/cluster.json.corrupt.<unixnano>; running with an EMPTY cluster store until the
 quarantined file or a backup is repaired, moved back, and the node restarted"
ClusterDB: load error: parse cluster state: … — starting fresh
```

```
Enrollment: cluster state "/data/cluster.json" contained 1 unusable null record(s) —
 dropped 1 node(s) "dp-1" and 0 token(s); …
```

```
HA: replicated cluster state contained 1 unusable null record(s) — dropped 1 node(s)
 "dp-1" and 0 token(s); the leader's state file is likely damaged
```

The dropped-record lines are the **only** place the affected node IDs are
named. Dropped tokens are counted, never named.

An unreadable file produces only `ClusterDB: load error: read cluster state: …
— starting fresh`. It raises no alert and no Diagnostics or `/ready` row, so
check the startup log if the roster is unexpectedly empty.

**Alert** — `state_file_corrupt` (source `storage`) fires for a quarantine, a
failed quarantine, leftover quarantined copies and dropped records. On an HA
standby the dropped-record alert fires **once per process**, however many
replication rounds repeat it. It carries the full detail, including the path.

**Diagnostics** — `GET /api/diagnostics`, row `state_file_cluster`. The row is
absent when the file loaded cleanly.

| Situation | Status |
|---|---|
| Corrupt file, quarantined | `warn` |
| Corrupt file, quarantine failed | `fail` |
| Quarantined copies left from an earlier start | `warn` |
| Null records dropped from this node's own file | `warn` |

The row is recorded when **this node's own file** is loaded. Null records
dropped from a state replicated by the HA leader do not create it; use the
alert, the log line and the metric on the standby instead.

One record is kept per state file. A dropped-record entry never replaces a
quarantine, a failed quarantine or leftover quarantined copies recorded in the
same start, so the row shows the more severe state. The log line and the metric
still carry the dropped records.

**`/ready`** — an informational `state_file_cluster: fail` row appears for a
quarantine, a failed quarantine or leftover quarantined copies. It does not
change the default verdict; it returns `503` only under `/ready?strict=1`.
Dropped null records do **not** add a `/ready` row: the rest of the file is in
effect, so the node is not held out of service.

**Metric**

```
culvert_cluster_state_nil_entries_dropped_total   # null node/token records dropped, at load or on replication
```

It counts dropped null records only. A quarantine does not move it.

## What you should do

### Corrupt file (quarantined, or quarantine failed)

1. **If the row is `fail`** (quarantine failed), copy `cluster.json` off the
   volume by hand first. The next cluster-state save will overwrite it.
2. **Stop the node, restore the state, then start it.** Repair the quarantined
   copy and move it back to the `-cluster-db` path, or restore `cluster.json`
   from a backup (see
   [`docker-compose-backup-restore.md`](docker-compose-backup-restore.md)).
   Replace the file only while the node is **stopped**: a running node writes
   its in-memory state on the next cluster-state save, and that state is the
   empty one it started with, so it would overwrite the file you restored.
   **On an HA standby, fix the leader first.** A standby imports and saves the
   leader's full cluster state every few seconds, so restoring only the standby
   lasts until its next sync. Make sure the leader's roster and revocation
   list are correct (restore them there first if the leader is affected too)
   before you start the standby again.
3. **Remove the leftover `cluster.json.corrupt.*` files** once reconciled. The
   `warn` row, the `/ready` row and the alert return on every start until they
   are gone.
4. **If no good copy exists**, the roster and revocation list are lost. Every
   Data Plane node is refused as `not enrolled` and must be re-enrolled with a
   fresh token (see the enrollment steps in
   [`deployment-guide.md`](../deployment-guide.md)). Data Plane nodes keep
   serving their last-known-good configuration in the meantime; see the
   `cp_poll` row in [`OPERATIONS.md`](../OPERATIONS.md).

### Null records dropped

1. **Read the node IDs from the log line.** They are not in the Diagnostics
   row, and the affected nodes no longer appear in the node list.
2. **Re-enroll each dropped node** with a fresh enrollment token. Until then
   the node is refused as `not enrolled`.
3. **Re-issue any pending enrollment token** that was dropped; a dropped token
   can no longer be consumed.
4. **On an HA standby, inspect the leader.** The standby already dropped the
   records; the leader's `cluster.json` is the file to check.
5. **Find out why the file was damaged.** A null record is evidence of a
   hand-edit or a damaged volume, not of normal operation.

The row and the record of which node IDs were dropped are held in memory for
the life of the process. The file is not rewritten at load, but the next
cluster-state save writes the state without the null records, so a later
restart no longer reports them. Act on the row while it is showing.

### Confirm a re-enrollment over a dropped record

A dropped record carried that node's certificate serial, so the serial is lost
with it. The predecessor certificate **cannot be added to the revocation list**
and stays valid until it expires.

Because of this, when a node enrolls under a node ID whose record was dropped
earlier in the same process, Culvert records the enrollment as an identity
replacement rather than a first enrollment:

- audit entry `cluster.node.reenroll-dropped` (actor: the enrolling peer's
  address, object: the node ID);
- alert `cluster_node_reenrolled` (source `cluster`).

Both are written only after the enrollment succeeds. Confirm that each one
matches a re-enrollment you performed. The admission decision itself is
unchanged: a valid, single-use, administrator-issued token is still required.

## What it will not do

- It will **not** quarantine a file that parsed. Dropping one null record keeps
  every healthy node and the whole revocation list in effect.
- It will **not** replace a null record with an empty node or token.
- It will **not** revoke the certificate of a dropped node; the serial is gone.
- It will **not** carry the dropped-record evidence across a restart.

## Related

- [`cluster-ca-expiry.md`](cluster-ca-expiry.md) — cluster CA expiry, and
  re-enrolling nodes whose certificate has expired.
- [`docker-compose-backup-restore.md`](docker-compose-backup-restore.md) —
  backing up and restoring `cluster.json` with the cluster CA pair.
- [`support-bundles-and-diagnostics.md`](support-bundles-and-diagnostics.md) —
  reading the Diagnostics rows.
- [`OPERATIONS.md`](../OPERATIONS.md) — the `/ready` checks map and strict
  verdict.
