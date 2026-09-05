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
| **Object** | A reusable referenced entity: URL category, category group, file profile, rewrite rule, identity provider | new umbrella (nav section) |
| **Profile** | A named object bundle (file profile — `Executables`, `Archives`; IdP profile) | — |
| **Steering profile** | A PAC traffic-steering ruleset assigning client networks to proxy pools (`internal/pac`, `/api/pac/profiles`, GUI "Steering Profiles") | the fourth distinct "Profile" concept alongside file/decryption/CDR profiles — always say "steering profile," never bare "profile," on this screen |
| **Proxy pool** (PAC) | The ordered `PROXY a; PROXY b` failover chain a steering profile hands to a client browser (`internal/pac.Pool`, GUI "Proxy Pools") | distinct from **Upstream Proxies** — Culvert's own server-side outbound egress chain (`/api/upstream`); never call the latter a "proxy pool" outside its own screen |
| **Provider** | An identity provider profile (OIDC/SAML/LDAP; `/api/idp`) | "IdP" acceptable in dense tables |
| **Appliance** | *Not used.* Culvert deploys as binary/container; the UI says **node** or **instance** | avoid inventing appliance language |
| **Node** | An enrolled cluster member (`EnrolledNode`) | — |
| **Cluster** | The CP/DP deployment (`/api/cluster/*`) | "Cluster Nodes" nav label → "Cluster" |
| **Control Plane / Data Plane (CP/DP)** | Node roles per `controlplane.go` | spell out on first use per screen |
| **Leader / Standby** | HA roles (`/api/cluster/ha`) | — |
| **Health** | A component's operational state: **Healthy / Degraded / Down / Unknown** | unify: today "connected/disconnected", "ok", "live/stale" are mixed. Wire states ("connected") remain in tables where they are the literal backend status; roll-ups use the Health scale |
| **Status** | The lifecycle state of an entity (node: connected/draining/revoked; rule: enabled/disabled; update: available/current) | do not use "status" for health roll-ups |
| **Blocklist / Allowlist** | The host list and its mode (`/api/blocklist`, `/mode`) | never "blacklist/whitelist" (already clean) |
| **Exception** | A never-blocked host (`/api/blocklist/exceptions`) | keep — but see Bypass below |
| **Bypass** | Skipping an *inspection* step for matching traffic: SSL-inspection bypass, content-scan bypass | today: "bypass", "exclusion", "allowlist", "exception" all mean skip-something. Rule: **Exception** = not blocked; **Bypass** = not inspected/scanned; **Feed allowlist** = never blocked *by feeds* |
| **Traffic** | The request stream (Monitor section) | "Live Feed", "Live Request Log", "Recent Requests" → "Traffic" (nav), "Live traffic" (panel), "Recent requests" (dashboard card) |
| **Audit Log** | Admin configuration-change history (`/api/audit`) | never mix with request logs |
| **Configuration versions** | Automatic config snapshots + rollback (`/api/config/versions`) | "Config Versions" ok in dense UI |
| **Update** | Legacy Docker self-update path (`/api/update/*`) | — |
| **Release** | Signed-catalog release management (`/api/releases*`) | keep distinct from Update until the M3 "Software" merge |
| **Administrator** | A console account (admin/operator/viewer role) | "Users & Roles" → "Administrators" (avoids collision with proxy users/identities) |
| **Identity** | An authenticated proxy user (from IdP/local auth; `identity.go`) | never "user" alone when it could mean console account |
| **Inspection** | TLS MITM (SSL inspect) | "SSL inspection" acceptable; be consistent per screen |

## Casing & style

- Sentence case for all labels, headings, buttons ("Add rule", not "Add Rule");
  product nouns capitalized only when proper (ClamAV, YARA, SAML).
- Verbs on buttons name the object: "Delete rule", "Rotate CA" — never bare
  "OK"/"Yes" on destructive confirms.
- Time: absolute timestamps in tables (`2026-07-11 14:02:11`), relative ("3m
  ago") only with a `title` tooltip carrying the absolute value.
- Numbers: `fmt()` thousands-separators everywhere; bytes via `fmtBytes`.
