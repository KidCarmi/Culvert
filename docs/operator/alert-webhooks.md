# Alert webhooks

**Applies to:** the **Alert Webhooks** panel (**Settings** view), `/api/alerts/webhooks`, `internal/alerts`.

An alert webhook is an HTTP(S) endpoint that Culvert posts a small JSON document to when
a subscribed event occurs. It is how a node reports a condition that no client will:
scanning that stopped, a stale feed, an HA node that fenced itself. None is configured
by default, and with none configured no alert is sent. What each event means and how to
respond is in its subsystem guide, linked from the [event catalog](#event-catalog).

## Facts to know before you rely on it

- **The receiver must have a public address.** Delivery refuses to connect to loopback,
  RFC 1918, carrier-grade NAT (`100.64.0.0/10`), link-local and IPv6 unique-local
  addresses, and no setting allows them. The URL is accepted when saved, because only
  its shape is checked then; the refusal happens at delivery and appears in the delivery
  history as `refusing … dial to private address`. A collector, chat relay or SIEM on
  your internal network cannot receive alerts directly.
- **Webhooks belong to one node.** They are not distributed from the Control Plane to
  Data Plane nodes. An event fires on the node that observed it, so configure each node.
- **The body has one fixed shape.** There is no per-receiver template. A receiver that
  requires its own JSON schema needs a relay in front of it.
- **Delivery is best effort.** Three attempts, then the alert is dropped and counted.

## Configuring a webhook

In the admin UI: **Settings → Alert Webhooks → + Add Webhook**. The Settings view is
shown to the `admin` role only. The API accepts the `operator` role, so an operator
manages webhooks through the API.

| Method and path | Role | Behavior |
|---|---|---|
| `GET /api/alerts/webhooks` | viewer | Lists webhooks. The signing secret is never returned. Below `operator`, `url` is reduced to `scheme://host`, because a receiver URL usually carries a token. |
| `POST /api/alerts/webhooks` | operator | Creates a webhook. `url` is required. The webhook is created **enabled** whatever `enabled` says. Audit action `alert.webhook.create`. |
| `PUT /api/alerts/webhooks?id=<id>` | operator | Replaces the webhook. Audit action `alert.webhook.update`. |
| `DELETE /api/alerts/webhooks?id=<id>` | operator | Deletes it. Audit action `alert.webhook.delete`. |
| `POST /api/alerts/webhooks/test?id=<id>` | operator | Sends one test alert (`event` and `source` are `test`) and returns `{"ok":…,"delivered":…}`. One attempt, no retry, not audited. |
| `GET /api/alerts/webhooks/history` | viewer | Delivery history and the counters in [Monitoring delivery](#monitoring-delivery). |

The request fields are `name`, `url`, `events` (array), `enabled` and `secret`.

- **`PUT` replaces `name`, `events` and `enabled`.** A request that omits `events` leaves
  the webhook subscribed to nothing, and one that omits `enabled` disables it. Only an
  empty `url` and an empty `secret` keep the stored value. Send the whole webhook.
- **A stored secret cannot be cleared.** To stop signing, delete the webhook and create
  it again without a secret.
- **`url`** must be `http://` or `https://` with a host. Anything else is a `400`.
- **`events`** entries are lowercase letters, digits and underscores, at most 64
  characters, or the single name `*`, which subscribes to every event including ones
  added by a later release. Names are checked for shape only: a misspelled name is
  accepted and never fires. The panel has no checkbox for `*`, and saving a webhook from
  the panel replaces its event list with the checked boxes.
- A node holds at most **100** webhooks; the next create is a `400`. Changes apply at once.

## What is delivered

A `POST` with `Content-Type: application/json` and `User-Agent: Culvert-Alerts/1.0`:

```json
{"event":"policy_block","timestamp":"2026-11-23T10:15:00Z","actor":"203.0.113.7",
 "host":"example.com","detail":"block-social","source":"policy"}
```

| Field | Content |
|---|---|
| `event` | The event name. |
| `timestamp` | UTC, RFC 3339, set when the alert is dispatched. |
| `actor` | The client address or user name the event concerns. Empty for node conditions. |
| `host` | The destination or component the event concerns. May be empty. |
| `detail` | Text describing the occurrence, for example the rule or signature name. |
| `source` | The subsystem that raised it. |

For `threat_detected` and `policy_block`, `host` follows the
[destination-privacy setting](traffic-log-destination-privacy.md): with it on, the
receiver gets the pseudonym, not the destination name.

Any final response status below 400 counts as delivered. The request is sent directly
from the node, with a 5 second limit per attempt.

**Signature.** When the webhook has a secret, each request carries
`X-Culvert-Signature: sha256=<hex>`, the HMAC-SHA256 of the exact request body keyed
with the secret. Compute it over the raw bytes received, before any JSON parsing. The
signature covers the body only, and there is no delivery identifier or nonce: a receiver
that must reject replays has to compare `timestamp` itself.

## Suppression, retries and limits

| Behavior | Value |
|---|---|
| Duplicate suppression | An alert with the same `event` and `detail` as one dispatched in the last 30 seconds on this node is not sent. |
| Concurrent deliveries | 10 for the node. An alert that finds all 10 busy is queued and first attempted 5 to 15 seconds later. |
| Attempts | 3 in total. After a failed attempt the next is due 15 seconds later, then 45 seconds later; the queue is examined every 10 seconds. |
| Retry queue | 500 entries for all webhooks, stored in `<dataDir>/alert_retry_queue.json` and resumed after a restart. |
| Queue full | The alert is dropped, counted in `retry_dropped_total`, and logged as `Alert retry queue full`. |
| Attempts used up | The alert is dropped, counted in `retry_exhausted_total`, and logged as `Alert retry exhausted for webhook`. |
| Webhook deleted or disabled | Its queued retries are discarded. |

A failure is a connection error, a timeout, or a status of 400 or above. No alert is
raised about failed alert delivery; use the signals below.

## Monitoring delivery

- **Delivery history.** The panel's **Delivery History** section and
  `GET /api/alerts/webhooks/history` return the node's last 200 attempts with status
  code, attempt number and error. The history is in memory and empty after a restart.
  The response also carries `retry_queue_depth`, `retry_exhausted_total`,
  `retry_dropped_total`, `dedup_tracked` and `dedup_evictions_total`, counted from start.
- **Diagnostics row `alert_delivery`.** A warning when the most recent attempt of an
  enabled webhook failed. It clears on that webhook's next successful delivery or on a
  restart. A webhook never attempted produces no row, so test a new webhook once.
- **Diagnostics row `alert_webhook_signing`.** A warning when a stored signing secret
  cannot be decrypted; that webhook's alerts go out unsigned and the panel marks it.
- **Metrics.** `culvert_alert_dedup_tracked` and `culvert_alert_dedup_evictions_total`.
  A rising eviction count means more than 4096 distinct alerts arrived inside 30
  seconds and some duplicates were delivered again. No alert is lost that way.

## Backup, export and import

Webhooks are stored in `<dataDir>/alert_webhooks.json`. Signing secrets in that file are
encrypted with a key in `<dataDir>/.alert_webhook_key`, which exists only on the node.
Webhook changes create no configuration version and are not affected by a rollback.

- **Backup and restore.** The backup contains `alert_webhooks.json` and never the key.
  Restored without the original key, the webhooks deliver unsigned until the key is put
  back or the secrets are re-entered. The order of those remedies matters; follow
  [Docker Compose backup and restore](docker-compose-backup-restore.md).
- **Configuration export** (`section=alerts` or `all`) includes the webhooks with their
  full URLs and without secrets.
- **Configuration import** adds every webhook in the file as a new one with a new `id`
  and no signing secret. Merge mode duplicates a webhook that already exists; replace
  mode deletes the existing ones first, but only when the file contains at least one. An
  import that would exceed 100 webhooks, or has an invalid URL or event name, is refused.

## Event catalog

The names are the panel's checkbox values. `—` means the event has no guide yet.

| Events | Raised when | Guide |
|---|---|---|
| `threat_detected` | ClamAV, YARA or the DPI / threat-feed scanner blocked a request. | — |
| `policy_block` | A policy rule blocked or dropped a request. | — |
| `auth_lockout` | An admin login was refused because the account or client is locked out. | [lockout](admin-api-credential-lockout.md) |
| `auth_verify_saturated` | Credential verification has been refusing attempts for a sustained period. | [verification cost](credential-verification-cost.md) |
| `identity_backend_unreachable` | An LDAP or OIDC backend cannot be reached; authentication fails closed. | [identity backends](identity-backend-availability.md) |
| `cert_expiry` | A CA is near expiry or was renewed. | [root CA](root-ca-expiry.md), [cluster CA](cluster-ca-expiry.md) |
| `ca_load_failed` | The root CA could not be loaded at startup; SSL inspection is off. | [operations](../OPERATIONS.md) |
| `decryption_autoexclude`, `decryption_autoexclude_rescue`, `decryption_autoexclude_surge` | Adaptive decryption exclusions were learned, rescued a live connection, or surged. | [auto-exclusions](decryption-auto-exclusions.md) |
| `scan_timeout`, `scan_skipped`, `scan_clam_error`, `scan_svc_down` | A body was not scanned, or a scan did not finish. | [scan capacity](scan-capacity-and-timeouts.md) |
| `scan_svc_listener_down` | This node's scan sidecar listener cannot serve. | [scan listener](scan-svc-listener-health.md) |
| `yara_degraded` | The YARA engine is degraded; bodies are forwarded without a YARA verdict. | — |
| `clamav_signature_stale` | The ClamAV definitions are more than 48 hours old. | [ClamAV freshness](clamav-definition-freshness.md) |
| `cdr_unavailable` | The CDR sidecar could not be called. | [CDR](cdr-content-disarm-reconstruction.md) |
| `threat_feed_stale` | Threat intelligence has not synced. | [threat feeds](threat-feed-freshness.md) |
| `blocklist_feed_stale` | An auto-synced remote blocklist feed has not synced. | [blocklist feeds](blocklist-feed-freshness.md) |
| `dns_failure` | Destination lookups are failing. | [DNS health](dns-resolution-health.md) |
| `upstream_pool_down` | All parent proxies are down; egress goes direct. | [upstream proxies](upstream-proxies.md) |
| `pac_profile_degraded` | A PAC profile was published with warnings. | [PAC steering](pac-traffic-steering.md) |
| `socks5_listener_down` | The SOCKS5 listener is not accepting connections. | [SOCKS5 listener](socks5-listener-health.md) |
| `admin_ui_unavailable` | The admin UI listener is down; the proxy keeps serving. | [admin UI listener](admin-ui-listener-recovery.md) |
| `cp_grpc_listener_down`, `config_snapshot_rejected` | The Control Plane cannot serve nodes, or refused to publish an over-size configuration. | [gRPC listener](cp-grpc-listener-recovery.md), [config capacity](cluster-config-capacity.md) |
| `cluster_node_reenrolled` | A node whose certificate had expired re-enrolled with a fresh token. | [cluster state](cluster-state-recovery.md) |
| `state_file_corrupt` | A corrupt state file was quarantined at startup. | [cluster state](cluster-state-recovery.md), [categories](category-store-recovery.md), [request history](request-history-recovery.md), [sessions](session-revocation.md) |
| `ha_self_fenced`, `ha_lease_reacquired`, `ha_resume_unfenced` | HA fencing-lease transitions. | [lease recovery](ha-lease-recovery.md) |
| `ha_manual_failover_required` | The leader is unreachable and automatic failover is off; the standby stays read-only. | [HA failover](ha-lease-failover.md) |
| `ha_sync_panic` | A standby's sync round faulted; replication from the leader is stalled. | — |
| `storage_write_failed` | A write to the data directory failed; the change is not on disk. | [log persistence](audit-and-request-log-persistence.md), [admin roster](admin-roster-durability.md) |
| `disk_critical` | The log disk is critically full; access logs are no longer recorded. | — |
| `syslog_feed_down` | The SIEM / syslog feed is not delivering. | [SIEM feed](siem-feed-delivery.md) |
| `release_catalog_stale`, `release_catalog_refresh_failing`, `release_catalog_recovered` | Release-catalog freshness changed. | [catalog re-sign](catalog-resign-runbook.md) |
| `mcp_gateway_down` | MCP was enabled but is not serving. | — |
| `panic_contained` | A component panicked and was recovered. One alert per component per hour. | — |

The retired name `idp_unreachable` is read as `identity_backend_unreachable`. Conditions
found during startup, such as `ca_load_failed` and `state_file_corrupt`, are held until
the webhooks have been loaded and are delivered then.
