# Culvert Product Terminology

Status: Phase 3 deliverable of the GUI redesign program
Date: 2026-07-11

Canonical vocabulary for UI labels, docs, and new code. Backend identifiers
(JSON fields, endpoint paths, Go symbols) are **not** renamed — this governs
what the administrator reads. Where the UI diverges today, the current wording
is listed under "replaces".

| Term | Definition (backed by) | Replaces / notes |
|---|---|---|
| **Policy** | A whole evaluation domain: Access policy (Stage-2, `/api/policy`), Authentication policy (Stage-1, `/api/authpolicy`) | "Policy" used loosely for both a domain and a single rule |
| **Rule** | One ordered entry inside a policy (`PolicyRule`) | "policy rule", "policy" for single rules |
| **Action** | What a rule does to a matching request: **Allow / Deny / Redirect** (Stage-2), **Exempt / Credential Required / SSO Required** (Stage-1 outcomes) | Keep "outcome" for Stage-1 (matches backend `defaultAuthOutcome` and the tester's careful Exempt≠Allow distinction) |
| **Default action** | The Stage-2 decision when no rule matches (`/api/default-action`; default deny) | — |
| **Default authentication behavior** | The Stage-1 decision when no auth rule matches (`default-auth-outcome`: Default = require auth, Exempt = open) | "unauth mode" (retired backend term — never surface it) |
| **Decision** | The evaluated result for one request (tester output, log `ruleMatched`) | "result", "verdict" (reserve "verdict" for Diagnostics checks) |
| **Event** | One row in a monitoring feed (request log entry, audit entry) | — |
| **Alert** | A condition Culvert fires to webhooks (`fireAlert`, `/api/alerts/webhooks`) | Today "alert" only appears as "Alert Webhooks"; keep "Alert" for the condition, "Webhook" for the delivery channel |
| **Incident** | *Not a general product concept* — there is no incident-tracking/ticketing entity (no incident list, ID, or lifecycle) and none should be invented | the Support Bundle's `IncidentScope` (`internal/support`, `?scope=`, GUI "Scope" field: `tls`/`upstream`/`policy`/`storage`/`dns`/`cluster`/`scan`) is a distinct, already-shipped concept — a bundle-focus selector, not the forbidden entity — and MAY keep using "incident" adjectivally (e.g. the Support panel's "Incident scope" tooltip, `resolveSupportBundlesPostParams`'s "unknown incident scope" error) |
| **Engine** | A scanning/enforcement subsystem: ClamAV, YARA, DPI, Threat Feeds, CDR, GeoIP | "scanner", "threat engine" (keep "Threat engine breakdown" as a chart title is fine) |
| **Backup** | A disaster-recovery archive of the data directory, created on demand from the Support panel ("Backup Now") or by the CLI; distinct from a configuration export (T-14). Audit action **`backup.trigger`** (stable wire identifier, shipped since v1.0.254; SIEM rules match it); the maintenance agent names the same event with operation kind `backup.create`, which is recorded here as an **alias** of `backup.trigger`, never emitted as a second audit action (T-71 of the 2026-10-09 review) | `.trigger` is deprecated for NEW audit actions (use `<noun>.create`); `backup.trigger` itself is grandfathered and is not renamed |
| **Object** | A reusable referenced entity: URL category, category group, file profile, rewrite rule, identity provider | new umbrella (nav section) |
| **Profile** | A named object bundle (file profile — `Executables`, `Archives`; IdP profile) | — |
| **Steering profile** | A PAC traffic-steering ruleset assigning client networks to proxy pools (`internal/pac`, `/api/pac/profiles`, GUI "Steering Profiles") | the fourth distinct "Profile" concept alongside file/decryption/CDR profiles — always say "steering profile," never bare "profile," on this screen |
| **Proxy pool** (PAC) | The ordered `PROXY a; PROXY b` failover chain a steering profile hands to a client browser (`internal/pac.Pool`, GUI "Proxy Pools") | distinct from **Upstream Proxies** — Culvert's own server-side outbound egress chain (`/api/upstream`); never call the latter a "proxy pool" outside its own screen |
| **Provider** | An identity provider profile (OIDC/SAML/LDAP; `/api/idp`) | "IdP" acceptable in dense tables |
| **Appliance** | One deployed Culvert system as the operator addresses it ("restart the appliance", "this appliance"): a standalone gateway, or one cluster member viewed from its own console. Used in the legacy GUI, operator runbooks and `/metrics` HELP text; the cross-repo contracts (`CONTRACTS-OWNERSHIP.md`) use it for the Culvert side of the TAC boundary | Do not use for a cluster member as seen from the Control Plane or fleet views — that is **Node**. Do not mass-rename existing uses to "node" or "instance" |
| **Node** | An enrolled cluster member (`EnrolledNode`) | — |
| **Cluster** | The CP/DP deployment (`/api/cluster/*`) | "Cluster Nodes" nav label → "Cluster" |
| **Control Plane / Data Plane (CP/DP)** | Node roles per `controlplane.go` | spell out on first use per screen |
| **Leader / Standby** | HA roles (`/api/cluster/ha`) | — |
| **Health** | A component's operational state: **Healthy / Degraded / Down / Unknown** | unify: today "connected/disconnected", "ok", "live/stale" are mixed. Wire states ("connected") remain in tables where they are the literal backend status; roll-ups use the Health scale |
| **Status** | The lifecycle state of an entity (node: connected/draining/revoked; rule: enabled/disabled; release: available/installed; upgrade: dispatch status) | do not use "status" for health roll-ups |
| **Blocklist / Allowlist** | The host list and its mode (`/api/blocklist`, `/mode`) | never "blacklist/whitelist" (already clean) |
| **Exception** | A never-blocked host (`/api/blocklist/exceptions`) | keep — but see Bypass below |
| **Bypass** | Skipping an *inspection* step for matching traffic: SSL-inspection bypass, content-scan bypass | today: "bypass", "exclusion", "allowlist", "exception" all mean skip-something. Rule: **Exception** = not blocked; **Bypass** = not inspected/scanned; **Feed allowlist** = never blocked *by feeds* |
| **Traffic** | The request stream (Monitor section) | "Live Feed", "Live Request Log", "Recent Requests" → "Traffic" (nav), "Live traffic" (panel), "Recent requests" (dashboard card) |
| **Audit Log** | Admin configuration-change history (`/api/audit`) | never mix with request logs |
| **Configuration versions** | Automatic config snapshots + rollback (`/api/config/versions`) | "Config Versions" ok in dense UI |
| **Update** | Retired term. It named the legacy Docker self-update path; the `updater` sidecar and its `/api/update/*` endpoints no longer exist | do not use it for a current surface, and do not surface "self-update"; say **Release** for the signed catalog and **Upgrade** for applying one |
| **Upgrade** | Applying a release to a node: dispatched from Release management (the console action is **Dispatch**) and performed by the host Maintenance Agent | replaces "Update" / "self-update" |
| **Release** | Signed-catalog release management (`/api/releases*`) | keep distinct from Upgrade (applying a release) until the M3 "Software" merge |
| **Administrator** | A console account (admin/operator/viewer role) | "Users & Roles" → "Administrators" (avoids collision with proxy users/identities) |
| **Admin roster** | The persisted set of Administrator accounts and their roles (`ui_users.json`, flag `-ui-users-file`; metrics `culvert_admin_roster_*`). Say **admin roster file** for the file. The flag `-ui-users-file`, the file name and Go names such as `UIUsers` are wire/code names that stay; the screen that manages the roster is **Administrators** | "admin users file" in Diagnostics operator actions (retired); "UI roster" (T-64 of the 2026-10-15 review; metric alias kept) |
| **Revocation refusal** | A session-revocation entry the appliance declines to retain (`session.Refused`, log `SESSION_REVOKE_REFUSED`; metrics `culvert_session_revoke_refusals_total{reason}` and, for logout cookies it could not verify, `culvert_session_revoke_unverifiable_total`) | "rejected" for the same concept; `culvert_session_revoke_rejected_total{reason}` and `culvert_session_revoke_refused_total` are deprecated metric aliases until v1.1.0 (T-70 of the 2026-10-25 review), and neither name is ever reused |
| **Identity** | An authenticated proxy user (from IdP/local auth; `identity.go`) | never "user" alone when it could mean console account |
| **Inspection** | TLS MITM (SSL inspect) | "SSL inspection" acceptable; be consistent per screen |
| **Setup window** | The period before a first-run setup is durably recorded (any admin roster account, whatever its role, or open mode), during which the setup wizard is reachable without credentials (`bootstrapWindowOpen`, `setup_bootstrap_window.go`; `/api/setup/*`). Say **first-run setup window** in operator-visible text (logs, runbooks, UI) | "bootstrap window" is the internal/code and CHANGELOG term; do not surface it to operators. Not the "Backup" or any upgrade flow |
| **Kill switch** | *Not a single concept — three distinct, unrelated safety mechanisms share this bare name and MUST always carry a qualifier in UI/docs:* **Authentication kill switch** (Stage-1 Exempt-outcome fail-safe when no credential-capable backend is configured, `authExemptKillSwitchEngaged`/`CULVERT_AUTHBYPASS_DISABLE`, Auth Policy Simulator); **C2 enforcement override** (`CULVERT_C2_ENFORCE` revert-to-shadow, Governance panel — already self-qualifies by showing the env var name); **MCP emergency kill switch** (per-capability admission stop, `EngageKillSwitch`/`ClearKillSwitch`, MCP Command Center — already self-qualifies as "Emergency kill switch ... on gateway/management") | none of the three should ever be renamed away from "kill switch" (each is an established, tested, domain-specific fail-safe name) — the fix is always a qualifier, never a rename |

## Casing & style

- Sentence case for all labels, headings, buttons ("Add rule", not "Add Rule");
  product nouns capitalized only when proper (ClamAV, YARA, SAML).
- Verbs on buttons name the object: "Delete rule", "Rotate CA" — never bare
  "OK"/"Yes" on destructive confirms.
- Time: absolute timestamps in tables (`2026-07-11 14:02:11`), relative ("3m
  ago") only with a `title` tooltip carrying the absolute value.
- Numbers: `fmt()` thousands-separators everywhere; bytes via `fmtBytes`.
