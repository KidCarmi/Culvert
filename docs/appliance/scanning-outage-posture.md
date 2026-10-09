# Malware-scanning outage: what the appliance does, and the pilot policy

Scope: the ClamAV sidecar (`clamav` service, `clamd` on the compose
network) that the proxy uses to scan response bodies. The appliance ships
the `av_unavailable=closed` posture: a body clamd cannot scan because clamd is
down is **refused**, not forwarded unscanned. A generic (non-appliance) install
keeps the historical `open` posture unless an operator chooses otherwise. The
posture is documented in `docs/operator/scan-capacity-and-timeouts.md` §6.2.

## 1. Behaviour by phase

| When ClamAV is unavailable | What happens to traffic | Evidence |
|---|---|---|
| **While the proxy runs** (clamd crashed, OOM, restarted, unreachable) — appliance (`closed`) | Each body clamd cannot scan is **refused** (HTTP 403 "antivirus scanning is currently unavailable"); the refusal is never cached, so the first request after clamd recovers is scanned and delivered (or blocked as `clamav`) on its merits | `av_unavailable_integration_test.go` (real proxy path against a stopped, resetting and stalled clamd stand-in, then recovery); log `SecurityScan: refused host=… AV is unavailable (av_unavailable=closed)` |
| Same, generic install / `open` posture | Each body clamd cannot scan is **forwarded UNSCANNED** (owner decision WK-1b); a body already scanned is still blocked from the verdict cache | `evidence/clamav-image-qualify.*.jsonl` check `clamd-down-posture-is-fail-open` — that harness runs the image WITHOUT `CULVERT_AV_UNAVAILABLE`, i.e. the `open` default (fresh EICAR → HTTP 200) |
| A scan that does not finish in time | **Blocked** (403, fail-closed) — a timeout is not an outage | `internal/secscan` `ScanBodyTimeout`; `scan_timeout` alert |
| **At boot** (first boot, reboot, `docker compose up`) | The proxy is **not started** until `clamav` is healthy (`depends_on: service_healthy`); explicit-proxy clients have no gateway until it is | `docker-compose.yml`; `first-boot.md` troubleshooting |
| **During an application upgrade / image rollback** | The agent **refuses** (`preflight_dependencies`, nothing changed) while `clamav` is unhealthy, because `compose up` would remove the running proxy and leave the new one stopped (measured) | `cmd/culvert-maint` `preflight_deps.go`; `upgrade-runbook.md` |
| ClamAV was already unhealthy before an upgrade that did run | The agent's health gate tolerates the pre-existing 503 (nothing the upgrade broke) | `upgrade-runbook.md` "What the upgrade succeeded means" |

## 2. How the degradation is surfaced

* `/ready` (proxy port) — the `clamav` row fails and `/ready` answers **503**
  while clamd is unreachable (non-strict; it is a gating row). Detail is a
  fixed string; the live cause is on the admin Security Scanning page
  (`/api/security-scan/status`, `clamav_status`).
* `culvert_scan_av_unavailable_refused_total` — every body refused because
  clamd was down (`closed`); `culvert_scan_av_unavailable_closed 1` confirms
  the posture. `culvert_clamav_scan_errors_total` counts the clamd faults in
  both postures (under `open`, every body forwarded unscanned).
* `/ready` turns its `clamav` row `fail` on the next read after a request
  first hits the outage (the cached daemon status is invalidated), not up to
  30 s later.
* `/ready` also fails the `clamav` row when clamd **answers but cannot scan**
  (detail: "ClamAV answers but cannot scan"). The status read sends PING and
  then scans a fixed, tiny, clean probe body through the same INSTREAM path a
  request uses. PING alone needs no temporary file, so before this a daemon
  whose temporary directory was out of space or inodes answered PONG while
  every scan failed: on the appliance under inode exhaustion every scanned
  body was refused (`closed`) for the whole phase while `/ready` reported
  `clamav ok` (lab run 37957097250). `/health` keeps its public enum (this
  state reads `unreachable` there); the cause (`scan_failing: …`) is on
  `GET /api/security-scan/status`. The row recovers on the first status read
  whose probe gets a clean verdict (at most the 30 s status cache after the
  daemon can scan again).
* Admin UI → Security Scanning shows the posture (*When ClamAV Is
  Unavailable*) and the *Refused: AV unavailable* counter;
  `GET /api/security-scan/status` carries `av_unavailable`.
* Alert event `scan_clam_error` — fired per scan error with a bounded reason
  class. **It fires only if a webhook subscribes to it** (producers on the
  request path check for a subscriber first); with no webhook configured
  the counter and the log are the only record.
* `docker compose ps` / `sudo culvert-status` — the sidecar's `unhealthy`
  health state.

## 3. Recommended appliance policy for the pilot

1. **Subscribe the scanning alerts at onboarding** (admin, Alerts →
   Webhooks, or `POST /api/alerts/webhooks` with
   `"events":["scan_clam_error","scan_timeout"]`). Without a subscriber an
   outage is visible only on `/ready`, the metric and the log.
2. **Monitor `/ready`** from the customer's monitoring (503 ⇒ look at the
   `clamav` row). Do NOT wire a single-node pilot's `/ready` into a load
   balancer that would remove the only gateway: the proxy keeps serving
   everything clamd is not needed for while `/ready` is 503.
3. **Block risky file types by policy, independently of ClamAV.** File
   filtering on the allow rules (`FileFiltering` with the `Executables`
   and/or `Archives` profile) is decided by extension/MIME in the proxy
   (`internal/fileblock`) and does not depend on clamd, so a ClamAV outage
   does not reopen those downloads. Under the `closed` posture it is defence
   in depth; under `open` it is the compensating control for the fail-open
   window.
4. **Restore the sidecar before maintenance.** An upgrade is refused while
   it is unhealthy; `culvert-os-update docker|reboot` stops the stack and
   the proxy will not start again until ClamAV is healthy (signature
   download needs outbound HTTPS to `database.clamav.net` on first start).

## 4. Choosing `open` instead

`closed` has a real cost: every clamd restart (signature reload, OOM,
upgrade of the sidecar) is a download outage for content not already in the
verdict cache. An operator who prefers availability sets *When ClamAV Is
Unavailable* to `open` in the admin UI (or `PUT /api/security-scan/av-settings`
`{"av_unavailable":"open"}`); the choice is durable and wins over the
first-boot default. Scans that run out of time are refused in both postures.
