# Malware-scanning outage: what the appliance does, and the pilot policy

Scope: the ClamAV sidecar (`clamav` service, `clamd` on the compose
network) that the proxy uses to scan response bodies. This page states the
behaviour as **measured**, not as intended. Nothing here claims fail-closed
scanning: on a clamd failure the appliance forwards content unscanned.

## 1. Behaviour by phase

| When ClamAV is unavailable | What happens to traffic | Evidence |
|---|---|---|
| **While the proxy runs** (clamd crashed, OOM, restarted, unreachable) | Each body clamd cannot scan is **forwarded UNSCANNED** (fail-open, owner decision WK-1b); a body already scanned is still blocked from the verdict cache | `evidence/clamav-image-qualify.*.jsonl` check `clamd-down-posture-is-fail-open` (fresh EICAR → HTTP 200, log `ClamAV error (connect_failed) … forwarding UNSCANNED (fail-open)`) |
| A scan that does not finish in time | **Blocked** (403, fail-closed) — a timeout is not an outage | `internal/secscan` `ScanBodyTimeout`; `scan_timeout` alert |
| **At boot** (first boot, reboot, `docker compose up`) | The proxy is **not started** until `clamav` is healthy (`depends_on: service_healthy`); explicit-proxy clients have no gateway until it is | `docker-compose.yml`; `first-boot.md` troubleshooting |
| **During an application upgrade / image rollback** | The agent **refuses** (`preflight_dependencies`, nothing changed) while `clamav` is unhealthy, because `compose up` would remove the running proxy and leave the new one stopped (measured) | `cmd/culvert-maint` `preflight_deps.go`; `upgrade-runbook.md` |
| ClamAV was already unhealthy before an upgrade that did run | The agent's health gate tolerates the pre-existing 503 (nothing the upgrade broke) | `upgrade-runbook.md` "What the upgrade succeeded means" |

## 2. How the degradation is surfaced

* `/ready` (proxy port) — the `clamav` row fails and `/ready` answers **503**
  while clamd is unreachable (non-strict; it is a gating row). Detail is a
  fixed string; the live cause is on the admin Security Scanning page
  (`/api/security-scan/status`, `clamav_status`).
* `culvert_clamav_scan_errors_total` — every body forwarded unscanned.
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
   (unscanned) while `/ready` is 503.
3. **Block risky file types by policy, independently of ClamAV.** File
   filtering on the allow rules (`FileFiltering` with the `Executables`
   and/or `Archives` profile) is decided by extension/MIME in the proxy
   (`internal/fileblock`) and does not depend on clamd, so a ClamAV outage
   does not reopen those downloads. This is the available compensating
   control for the fail-open window.
4. **Restore the sidecar before maintenance.** An upgrade is refused while
   it is unhealthy; `culvert-os-update docker|reboot` stops the stack and
   the proxy will not start again until ClamAV is healthy (signature
   download needs outbound HTTPS to `database.clamav.net` on first start).

## 4. Owner decision, not taken in this PR

A "block when the scanner errors" option (fail-closed on clamd failure)
does not exist. Whether the pilot needs one is a product decision with a
real cost — every clamd restart becomes a gateway-wide download outage —
and is recorded as a follow-up, not implemented or implied here.
