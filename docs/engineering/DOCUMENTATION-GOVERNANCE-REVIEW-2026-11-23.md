# Documentation governance review 2026-11-23

Scope: checked-out `main` at `46b4ffa`. Point-in-time record; not a source of truth for
behavior.

## Finding (High): alert webhooks have no operator guide, and four texts name a menu that does not exist

- **Problem.** Alert webhooks are the only channel through which a node reports its own
  degraded controls. They have a GUI panel, an admin API, 42 subscribable events, two
  Diagnostics rows and two metrics; their operator text was one README bullet naming
  three event kinds. Two Diagnostics remedies, `docs/deployment-guide.md` and
  `docs/operator/docker-compose-backup-restore.md` sent the reader to
  **Security → Alert Webhooks**; the panel is in the **Settings** view and no view is
  named Security. A comment on `alerts.ValidateURL` said private receiver addresses
  "remain usable"; delivery refuses them. The event catalog was debt from 2026-11-20.
- **Implementation evidence.** `internal/alerts/store.go` and `secret.go`,
  `internal/ssrf/ssrf.go` (`privateRanges`, `Control`; the only override is a test seam),
  `ui_security.go` (the three `apiAlerts*` handlers, `webhooksForRole`), `ui_config.go`
  (export, `importAlertWebhooksRejected`, the import apply step), `config_surfaces.go`
  (`alert_webhooks`: not cluster-synced, excluded from rollback), `backup.go`,
  `diagnostics_alert_delivery.go`, `diagnostics.go` (`checkAlertWebhookSigning`),
  `events.go`, `alerts.go`, `static/index.html` (panel in `view-settings`, nav item
  `data-min-role="admin"`).
- **Why it matters.** The panel does not say that a receiver on a private network never
  receives anything, that webhooks set on the Control Plane do not reach Data Plane
  nodes, that a partial `PUT` unsubscribes and disables the webhook, that an alert is
  dropped after three attempts, or that an import yields unsigned duplicates. Each ends
  in alerts that silently do not arrive.
- **Who is affected.** Administrators integrating Culvert with paging, chat or a SIEM;
  on-call staff reading the two Diagnostics rows.
- **Canonical source.** The code above. `docs/operator/alert-webhooks.md` owns the
  delivery contract and the event names; each event's remedy stays in its subsystem
  guide, and signing-key recovery in the backup guide.
- **Change.** The new page; index entry; README bullet; the menu name in four places;
  the `ValidateURL` comment; `alerts_docs_catalog_test.go`, which fails when the catalog
  and the panel's checkboxes differ. No behavior change. Effort: medium. Risk: low.

## Checks performed

- Every limit, status code, field, file name, log line and metric in the new page was
  read from the files above at this revision.
- Reproduced with a throwaway test (not committed): deliveries to `127.0.0.1`, `10.1.2.3`
  and `192.168.1.10` failed with `refusing tcp4 dial to private address` and the listener
  received nothing; an `Update` carrying only `name` left `events` empty and `enabled`
  false while keeping the URL and secret; backoff is 5 s, 15 s, 45 s.
- The catalog test failed in both directions with one event renamed in the page;
  `go build ./...`, `go vet`, `go test ./internal/alerts`, focused root tests, `check.py`.

## Not assessed / documentation debt

- **Medium, product behavior, for the owner:** the panel is reachable only by `admin`
  while the API grants `operator`; `POST` ignores `enabled: false`; a partial `PUT`
  clears `events` and `enabled`; a stored secret cannot be cleared. The panel hint says
  "Supports any HTTP endpoint" and names three event kinds.
- **Ambiguity:** whether refusing private receivers is intended for an on-premises
  gateway. The code enforces it with no override, so the guide states it as the
  contract. The same question is open for OTLP (2026-11-22).
- **Low:** seven events have no subsystem guide; the catalog marks them with `—`.
- Not verified, so not documented: how `host` is filled for events other than the two
  stated, and receiver-specific formats.
- Carried: `CULVERT_MCP_LIVE_CREDENTIAL_KEK`; no environment-variable reference; no
  catalog of Diagnostics codes; GAP-PKI-05; the `auth_cr_no_credential_provider` message;
  the kill-switch route metadata; `otlp-flush` in the shutdown guide.
