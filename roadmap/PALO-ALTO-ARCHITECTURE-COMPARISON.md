# Palo Alto (PAN-OS / Prisma Access) ↔ Culvert Architecture Comparison

**Status:** Reference (living). **Date:** 2026-07-16.
**Purpose:** Ground Culvert's architecture decisions in the closest mature reference design (Palo
Alto's NGFW + SASE forward proxy), especially for the SSL-decryption / decryption-exclusion surface.
Derived from a four-track research pass (PAN-OS SSL decryption, PAN-OS core pipeline, Prisma Access
SASE forward proxy, and a Culvert code audit).

## How to read the claims in this document — sourcing discipline

Every non-trivial claim is tagged so the reader can tell verified fact from inference:

- **[PAN-DOC]** — behavior stated in Palo Alto's own public documentation (URL cited). NOTE: this
  session's egress policy returns HTTP 403 for automated fetches of `docs.paloaltonetworks.com` and
  `paloaltonetworks.com`, so these facts were gathered via search-index extraction of those exact
  pages plus corroborating community/KB/vendor secondaries. Treat single-sourced numbers (e.g. cache
  size) as "documented but not re-fetched here."
- **[PAN-INFER]** — a reasonable inference about PAN-OS/Prisma behavior that is **not** explicitly
  documented (or where public docs are thin). Flagged as inference, not fact.
- **[CULVERT]** — a Culvert implementation fact verified in the current tree (file/symbol cited).
- **[CULVERT?]** — a statement about Culvert that is **plausible but not fully verified in code**; an
  open item to confirm before relying on it.

**On "better than PAN-OS":** this document does **not** assert Culvert "surpasses PAN-OS" as an
unqualified fact. Where Culvert is stricter or more isolated, the claim is scoped to a **specific,
observable behavior** and tagged accordingly. PAN-OS and Culvert are also different product classes
(a hardware/cloud NGFW+SASE platform vs a single-binary self-hosted forward proxy), so many
differences are class differences, not quality differences.

---

## 1. The decryption-exclusion cache (the subsystem Culvert clones)

This is the closest one-to-one comparison and the reason for the study.

| Property | PAN-OS Local SSL Decryption Exclusion Cache | Culvert `internal/autoexclude` |
|---|---|---|
| Auto-learned on handshake breakage | **[PAN-DOC]** yes — pinned certs, client/mutual auth, unsupported version/cipher | **[CULVERT]** yes — but only 3 narrow classes (see §1.1) |
| Gated on a fail-open profile opt-in | **[PAN-DOC]** yes — only populates if the decryption profile *allows* the unsupported mode | **[CULVERT]** yes — `resolveFailOpen` gates BOTH learn and read on `OnInspectError=="fail-open"` (`autoexclude_resolve.go`) |
| TTL | **[PAN-DOC]** 12h | **[CULVERT]** 12h default; 1h for `client_pinned` (`DefaultTTL`/`DefaultPinnedTTL`, `autoexclude.go:83`) |
| Capacity | **[PAN-DOC]** 1,024 entries | **[CULVERT]** 4,096 (`DefaultMaxEntries`, `autoexclude.go:87`) |
| Locality | **[PAN-DOC]** dataplane-local, per-firewall, per-vsys; not synced | **[CULVERT]** in-memory, per-node, never persisted, never synced CP→DP (confirmed: no `autoexclude` reference in `controlplane*.go`) |
| Manual add | **[PAN-DOC]** no (firewall-populated only) | **[CULVERT]** no (only the classifier promotes; operators evict/clear only) |
| Operator surface | **[PAN-DOC]** `show/clear ssl-decrypt exclude-cache` CLI | **[CULVERT]** `/api/decryption-exclusions` (GET list+Stats / DELETE evict-one / clear-all) + SPA panel |

### 1.1 Where Culvert's behavior is demonstrably stricter (scoped claims)

Each is a **specific observable-behavior** claim, not a blanket "better":

1. **Narrower learn surface.** **[PAN-DOC]** PAN-OS learns on a broad set of breakage signals.
   **[CULVERT]** Culvert's classifier (`classifyOriginInspectFailure`/`classifyClientInspectFailure`)
   learns on **only** `client_cert_required`, `unsupported_params`, and `client_pinned`, and
   **explicitly refuses** to learn on cert-verify failures (untrusted/expired/mismatch) or any
   generic/origin-emitted alert. Observable consequence: a misclassification can only ever keep
   inspecting (fail closed), never wrongly bypass.
2. **Per-policy isolation on the key.** **[PAN-DOC]** PAN-OS entries are scoped by server + vsys +
   profile context. **[CULVERT]** Culvert keys strictly on `(profileID, host)` and gates the read on
   the matched profile, so a host learned under one fail-open profile is **never** consulted for a
   different profile's sessions. This is a tighter, explicitly-tested isolation boundary
   (`TestResolveSSLAction_CrossScopeContamination`).
3. **Anti-poison confirm-count with identity gating.** **[PAN-INFER]** public PAN-OS docs do not
   describe a distinct-client confirm-count before an entry is trusted. **[CULVERT]** Culvert requires
   `ConfirmN` distinct client-evidence tokens within a window, and (ADR-0008) requires **authenticated
   identity** for the spoofable `client_pinned` class — IP-only evidence cannot promote it. This is an
   anti-poisoning control with no documented PAN-OS equivalent (absence of documentation is not proof
   of absence — tagged accordingly).
4. **Conservative default posture.** **[PAN-DOC]** every PAN-OS decryption-profile `block-*` toggle
   ships **OFF** (fail-open) out of the box. **[CULVERT]** Culvert is default-deny / fail-close and
   requires an explicit per-profile `fail-open` opt-in before anything is ever learned or bypassed.

### 1.2 Where PAN-OS has capabilities Culvert lacks (honest gaps)

1. **Two curated exclusion tiers.** **[PAN-DOC]** PAN-OS ships a **predefined** exclusion list
   (pinned/mutual-auth sites) delivered via Applications-and-Threats **content updates**, auto-removed
   when a site becomes decryptable, plus an **admin custom/global** list (wildcards, custom > predefined
   precedence). **[CULVERT]** Culvert has only the learned/volatile tier; a feed-delivered predefined
   list is on Culvert's own "planned" list (`docs/operator/decryption-auto-exclusions.md`).
2. **Exclusion match against server-cert CN (not just SNI).** **[PAN-DOC]** PAN-OS matches an exclusion
   entry against both the client-hello SNI and the server-cert CN. **[CULVERT]** Culvert keys on the
   CONNECT authority / host only. *(This is analysed as a design question in ADR-0011 — CN alone is not
   authoritative identity; do not treat this gap as an obvious win to close.)*
3. **Flush-on-profile-change.** **[PAN-DOC]** PAN-OS flushes the local cache when the decryption rule
   or profile changes (to avoid stale reclassification). **[CULVERT?]** Culvert's read-gate re-reads the
   *current* profile so a flip to fail-close immediately stops bypass, and a delete→recreate orphans old
   entries via a new ID — but a **same-ID profile edit that stays fail-open while changing a
   security-relevant field** (e.g. TLS floor) may leave semantically-stale entries until TTL. *(Analysed
   as an investigation in ADR-0011; needs its own change/ADR.)*

---

## 2. Core security pipeline

| Concept | PAN-OS | Culvert |
|---|---|---|
| Processing model | **[PAN-DOC]** Single-Pass Parallel Processing (SP3): classify once, scan one decoded stream once against a uniform signature format | **[CULVERT]** chained stages (`handleRequest`, `proxy.go:700`): auth → pre-policy blocks → policy → SSL decision → per-response buffered scan (`scanInspectBody`). Discrete Go engines, not one stream |
| Application identity | **[PAN-DOC]** App-ID: port-independent, continuous re-identification, policy re-lookup on app-shift, bounded ID budget (~4 packets / ~2 KB) | **[CULVERT]** classifies by FQDN / URL-category / GeoIP (destination-based), verdict latched at CONNECT; no continuous re-classification |
| Content inspection | **[PAN-DOC]** Content-ID: IPS + AV + URL + file + DLP in one stream-based pass, stream-first (scans before full buffering) | **[CULVERT]** URL-cat (policy-time) + file-block + DPI + ClamAV + YARA + CDR + threat-feed as discrete stages; buffer-then-forward (true prevention) capped at `maxScanBufferBytes` |
| Identity → policy | **[PAN-DOC]** User-ID: many IP→user mapping sources; consumed uniformly as Source-User in policy | **[CULVERT]** inline-auth / captive-portal (proxy-auth 407, SSO redirect); local/LDAP/OIDC/SAML; `defaultAuthOutcome`; no passive IP→user mapping table |
| Policy structure | **[PAN-DOC]** separate ordered rulebases (Security vs **Decryption** vs NAT…), most-specific-first, implicit intrazone-allow/interzone-deny | **[CULVERT]** single forward-proxy rulebase (`policy.go`), first-match priority order, default-deny; SSL-bypass matching fused into policy, not a separate decryption rulebase |
| Config distribution | **[PAN-DOC]** candidate→validate→commit→**diff-push** to dataplane; Panorama device-groups/templates; per-DG and per-admin push scope | **[CULVERT]** CP→DP full `ConfigSnapshot` push (`controlplane_snapshot.go`), fail-closed `validateConfigSnapshot`, 50-version rollback, `Epoch` fencing; no diff-push, no push-scoping |

**Transferable ideas (not claims of deficiency):** SP3's "decode once, fan one stream to all scanners";
App-ID's "bounded identification budget then fall through"; the **separate ordered decryption rulebase**;
and **diff-push** for CP→DP config. These are recorded here and in the roadmap; several are **explicit
non-goals** of the current observability slice (see ADR-0011 §Non-goals).

---

## 3. Decryption observability — the highest-leverage transferable concept

| | PAN-OS | Culvert (today) |
|---|---|---|
| Structured decryption log | **[PAN-DOC]** dedicated Decryption Log (PAN-OS 10.x+): TLS version, key-exchange, cipher, ALPN-era fields, cert chain/root status, proxy type, policy name, **Error + Error-Index** taxonomy, cert metadata | **[CULVERT]** the request/tunnel `Entry` (`internal/logstore`) has `SSLAction` ("inspect"/"bypass") + a `TUNNEL_CLOSED` accounting entry (bytes/duration) + `ActionTaken` (used for the rescue reason); **no** per-session TLS/cipher/cert/failure-category fields |
| Outcome tri-state | **[PAN-DOC]** Decrypted / No-Decrypt / excluded flag | **[CULVERT]** inspect vs bypass exists on the entry, but "manually bypassed vs learned-excluded vs live-rescued vs failed" is **not** a first-class categorical outcome |
| Error taxonomy | **[PAN-DOC]** eight Error-Index classes (Certificate, Protocol, Version, Cipher, Feature, HSM, Resource, …) + cipher/version bitmasks | **[CULVERT]** `classify*InspectFailure` produces narrow reason tokens internally, but they are **not** surfaced as a normalized failure category on any record/metric |
| Dashboard | **[PAN-DOC]** ACC "SSL Activity" widgets (decrypted vs failed vs excluded, top failure reasons) | **[CULVERT]** `culvert_decrypt_autoexclude_*` metrics + the Decryption Exclusions panel (list + Stats + blast-radius), but no decryption-health/coverage dashboard |

**This is the gap ADR-0011 addresses.** Culvert already emits the *inputs* (classifier reasons, autoexclude
metrics, per-rule attribution, the `auth_*` SIEM block precedent on `Entry`); what is missing is a
**single canonical decryption-outcome model** that unifies them across the request feed, audit, alerts,
Prometheus, API, GUI, and future SIEM export.

---

## 4. SASE / fleet-scale (Prisma Access) — selected parallels

- **[PAN-DOC]** Prisma Explicit Proxy uses a PAC + central **Authentication Cache Service** (token→cookie
  handoff), and **requires** decryption for the auth-cookie model (explicitly to prevent open-proxy/DoS
  abuse). **[CULVERT]** analogous to Culvert's captive/SSO portal + HMAC session cookie
  (`proxy_portal.go`, `session.go`); the CP→DP-synced `SessionHMAC` is Culvert's shared-secret analog.
- **[PAN-DOC]** management HA is Panorama active/passive; dataplane is hot-standby SPN pairs per AZ,
  <15s failover. **[CULVERT]** ADR-0005 etcd fencing lease (single-writer CP, epoch = etcd
  `create_revision`). **Scoped claim:** Culvert's epoch-fencing prevents split-brain more strictly than a
  documented Panorama active/passive pair **[PAN-INFER on the split-brain comparison]**; Culvert lacks
  per-node dataplane hot-standby (a scale difference, not a correctness one).
- **[PAN-DOC]** Cloud Identity Engine decouples authN (IdP redirect) from group resolution (Directory
  Sync), so **policy keeps enforcing on cached group mappings when the IdP is down**. **[CULVERT?]**
  Culvert resolves groups at LDAP-bind / token time; an IdP-independent synced group cache is a
  capability Culvert does not appear to have — worth confirming.

---

## 5. What to keep, what to build (pointer to the roadmap)

**Keep (scoped strengths):** the fail-closed classifier, the `(profileID, host)` isolation boundary, the
identity-gated confirm-count, the conservative fail-open opt-in, and the etcd epoch-fencing lease.

**Build next (this study's recommendation):** the **Decryption Observability** surface — a canonical
outcome model + metrics + dashboard — specified in **ADR-0011**. It closes qualification findings
**F6** (per-scope hit/active labels) and **F7** (SIEM-queryable bypass reason) and turns the
already-hardened autoexclude machinery into something a SOC can operate.

**Deferred / investigate (own ADRs):** feed-delivered predefined exclusion tier; server-cert
identity as an exclusion signal (CN/SAN/SPKI — see ADR-0011 investigation); cluster-wide transient
evict (F8); a separate decryption rulebase; SP3-style single-stream scanning; continuous
re-classification; IdP-independent group cache. None are in the observability slice.

---

## Appendix — primary sources (as gathered; see sourcing note in the header)

PAN-OS SSL decryption: SSL Forward Proxy, decryption-profile (server-cert/unsupported-mode/failure
checks), Local SSL Decryption Exclusion Cache, predefined/custom exclusions, TLS 1.3 decryption
support, decryption best practices (all `docs.paloaltonetworks.com/pan-os/*` + `/best-practices/*`).
PAN-OS core: SP3 architecture, App-ID overview, Content-ID tech brief, User-ID map-IP-to-users, policy
rulebases, candidate/running config, Decryption Log fields + Error-Index. Prisma Access: Explicit Proxy
(how-it-works / PAC / Kerberos), commit-push-revert, multitenancy, HA, Cloud Identity Engine. Exact
URLs are recorded in the research task transcripts backing this document.
