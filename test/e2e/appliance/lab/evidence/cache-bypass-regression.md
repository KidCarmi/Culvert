# Cache-bypass regression: red on 72c827b7, green on bad788e5

Owner review 5478346473 (P1) and follow-up 6097484537 item 1. Lab run
38052333202 (lab commit `cc9687d3`), one disposable QEMU guest per RETAINED
OVA. ASTRA's controller, OVA and guest are not touched.

| candidate | OVA sha256 | result |
|---|---|---|
| `72c827b7` (pre-fix) | `76769f86fe1193768cd67d4829ef66749f970acb67d6306ad6d0b1082cb9dbb5` | **FAILS** `CB cached-clean-in-quarantine` and `CB rescan-before-recache`: the cache-bypass reason |
| `bad788e5` (fix) | `87c8ae617f9a802f6a046627043c5609d0cb3fe260ce9b845409918c8bbe855c` | **passes** every `CB` row |

## Why the old pressure judge could not see it

`p_enforced` (appliance-lab.sh) accepts an allowed `200` at any moment, so a
body delivered from a pre-fault cache and a healthy delivery look the same.
It judges enforcement under pressure and still does; it is not a cache test.
The `CB` leg is: it establishes the fault state first, then judges.

## The predicate (cmd_cachebypass)

1. **CB1 warm:** clean body X answered 200 twice with ONE clamd stream (the
   second answer is a cache hit); EICAR body Y blocked twice with one stream.
2. **CB2 fault:** new TCP connections to clamd are reset from inside its
   network namespace; a fresh body is refused and `stat_clam_scan_error`
   moves (an engine fault). The reset is lifted. A fresh clean body then
   reaches clamd, is answered OK, and is REFUSED with
   `stat_clam_clean_quarantined` moving: the quarantine is ACTIVE.
3. **CB3 inside the window:** X must be refused `av_unavailable`. **200
   fails.** Y must stay the ClamAV block.
4. **CB4 after the window:** X must be re-scanned (one more clamd stream)
   before it is served 200, and the next request must be a cache hit.

Streams are attributed by size and judged by count, never by time (the tap
stamps with the guest clock). Healthy 200s outside the established fault
state stay valid (CB1).

## Rows

| row | 72c827b7 | bad788e5 |
|---|---|---|
| warm-clean | pass (1 stream) | pass (1 stream) |
| warm-block | pass | pass |
| fault-inject | pass (scan_error 0→1) | pass (scan_error 0→1) |
| quarantine-active | pass (quarantined 0→1) | pass (quarantined 0→1) |
| **cached-clean-in-quarantine** | **FAIL — X delivered 200 at +6.2 s, still 1 stream (never re-scanned)** | pass — refused at +6.5 s, 2 streams (re-scanned, refused by the window), stale 0→1 |
| cached-block-in-quarantine | pass | pass |
| **rescan-before-recache** | **FAIL — after the window X still served from the pre-fault cache (1 stream)** | pass — streams 2→3 then a cache hit |
| cached-block-after | pass | pass |
| scan-spanning-fault | info | info |

Scan-spanning-fault is not judged on the appliance: a scan that starts
before a fault and answers inside the 60 s window is refused by the window
on both builds; only a scan longer than the window separates them. That
case is pinned by `TestScanSpanningAFaultIsNotHonoured` (internal/secscan),
mutation-checked.

Per-candidate files: `cache-bypass-<candidate>/` (CB checks, per-step
records, clamd tap streams, proxy log, OVA hash, identities).
