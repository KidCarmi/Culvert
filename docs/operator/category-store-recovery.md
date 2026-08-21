# Community category store — corruption and recovery

**Applies to:** any node started with `-cat-feed-db` (the shipped
`docker-compose.yml` sets `-cat-feed-db /data/catfeeddb`, so this is most
Docker deployments).

**Register item:** CHAOS-50.

---

## What this store is

Culvert categorises hosts in two tiers:

| Tier | Store | Source of truth | Loss impact |
|---|---|---|---|
| Layer 1 | `catStore` (`categories.json`) | admin-managed, authoritative | policy-relevant |
| Layer 2 | community store (BadgerDB, `-cat-feed-db`) | a **cache** of the downloadable UT1 feed | none — it re-syncs |

Layer 2 holds no authoritative state. Everything in it came from a feed the
node can download again, and the syncer performs an immediate sync when it
finds the store empty. That is why the recovery below is safe: re-creating the
store costs one feed sync, not data.

## What happens when the store is damaged

An unclean stop (`docker kill`, OOM, host power loss, a failing volume) can
leave the BadgerDB directory in a state it cannot be opened from. Culvert
detects this at startup and recovers automatically:

| Damage | Detected as | Recovery |
|---|---|---|
| Torn `MANIFEST`, missing table, damaged `KEYREGISTRY`, value log needing truncation | badger returns an error Culvert classifies as corruption | **Same boot.** The directory is quarantined and re-created; the feed re-syncs. |
| Corrupt table (`.sst`) | badger **panics** during open — the process dies before it can report anything | **Next boot.** A marker left beside the store tells the next start that the previous one died inside the open, so the directory is quarantined *before* badger is touched. Under `restart: unless-stopped` this is automatic and takes seconds. |
| Two Culvert processes racing on one data directory | the loser is refused by the store lock | **No quarantine, no interference.** A store another process is opening or using is never renamed, and its recovery breadcrumb is never cleared. The loser degrades to Layer 1 for that boot. |
| Volume missing, wrong mount, no permission, read-only, full, or another process holding the store | classified as environmental | **No quarantine** — renaming fixes none of these, and on the lock case it would damage a live store. The node boots and serves with **Layer 1 only**. |

**In no case does a damaged Layer-2 store stop the gateway from starting.**
Before CHAOS-50 it did, permanently, with no admin UI to recover from.

## What you will see

**Logs**

```
CatFeedDB: "community category store at /data/catfeeddb was damaged
 (poison_marker: a previous start entered the store open and never returned …)
 — quarantined to /data/catfeeddb.corrupt.1787005493693306866 and re-created
 empty; the feed re-syncs automatically. Delete the quarantined copy once
 reconciled to reclaim disk"
```

or, when the store simply could not be opened:

```
CatFeedDB: cannot open the community store at /data/catfeeddb: <cause>
 — continuing with admin-managed categories only (Layer 1)
```

**Alert** — the existing `state_file_corrupt` event fires (queued at startup and
delivered once the webhook store loads). It carries the full detail, including
the path and cause.

**Diagnostics** — `GET /api/diagnostics`, row `category_feed_db`:

| Situation | Status |
|---|---|
| `-cat-feed-db` not set | `ok` |
| store loaded, nothing quarantined | `ok` |
| store re-created this boot | `warn` |
| quarantined copies still on the volume | `warn` |
| store unavailable, running Layer-1 only | `warn` |

The row never reports `fail`: a node on Layer-1-only categorisation is fully
able to serve traffic — it is the same posture as a node started without
`-cat-feed-db` — so failing it would pull a healthy gateway out of a
load-balancer rotation. For the same reason the row is **not** wired into
`/readyz`.

**Metrics**

```
culvert_catfeeddb_available            0|1   # 0 = unconfigured OR failed to open
culvert_catfeeddb_recovered            0|1   # 1 = quarantined + re-created at this startup
culvert_catfeeddb_quarantined_copies   N     # .corrupt.* directories still on the volume
```

A useful alert is `culvert_catfeeddb_quarantined_copies > 0` **for more than a
day** — that is disk nobody has reclaimed and an incident nobody has looked at.

## What you should do

1. **Nothing urgent.** The gateway is serving. Category rules that depend on
   the community feed will not match until the next sync completes (default
   cadence 24 h; a re-created empty store syncs immediately on start).

2. **Find out why the volume was damaged.** A quarantine is evidence of an
   unclean stop or a sick disk, not of a Culvert bug. Check the host for OOM
   kills of the proxy container, abrupt power loss, and filesystem errors
   (`dmesg`, the storage backend's own health).

3. **Reclaim the disk.** The quarantined copy is kept for inspection and can be
   large. Once you have finished with it:

   ```bash
   docker compose exec proxy sh -c 'ls -d /data/catfeeddb.corrupt.*'
   docker compose exec proxy sh -c 'rm -rf /data/catfeeddb.corrupt.*'
   ```

   Culvert keeps only the newest copy, so this never grows without bound — but
   one copy of a multi-gigabyte store is still worth reclaiming.

4. **If the row says the store is unavailable** (not recovered), the fault is
   environmental. Check, in this order: is the volume mounted; is it read-only;
   is it full; is a second container running against the same data directory.
   Fix it and restart — Culvert re-creates the store on the next boot.

## What it will not do

- It will **not delete** a damaged store. Recovery always moves it aside first.
- It will **not touch** a store another process holds open, and it holds that
  lock for the whole rename rather than checking and letting go. A concurrent
  boot that loses the race degrades instead of quarantining, and it leaves the
  other process's recovery breadcrumb alone.
- It will **not** quarantine on an error it does not positively recognise as
  corruption. Anything unclassified degrades and leaves the disk alone.

## Related

- `docs/operator/root-ca-expiry.md` — the same fail-visible posture for the CA.
- `docs/operator/support-bundles-and-diagnostics.md` — reading the operator
  contract rows.
- `roadmap/CHAOS-ENGINEERING-REVIEW.md` §17 — the finding and its evidence.
