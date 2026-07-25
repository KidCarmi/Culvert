# Tool Discovery, Fingerprinting and Drift Classification

This document defines how the MCP Security Gateway (Capability B) identifies MCP tools, canonicalizes
their fingerprints, classifies changes observed between discovery cycles, and gates each change class to
a policy action. It expands [`BLUEPRINT.md`](BLUEPRINT.md) §12 ("Discovery, Risk and Drift") into a
normative design artifact with requirement- and threat-ID traceability. It applies **only** to Capability
B (MCP Security Gateway); Capability A (Culvert Management MCP Server) does not discover or proxy
third-party MCP tools and is out of scope for this document (see
[`README.md`](README.md) doctrine on keeping the two capabilities separate).

**Status: PR-0 design artifact (Proposed).** Nothing in this document is implemented. All schemas,
thresholds and lifecycle states are design targets pending PR-1/PR-2 (Protocol kernel; Registry &
catalog), a numbered ADR, and the PR-0 review gate in
[`PR0-REVIEW-CHECKLIST.md`](PR0-REVIEW-CHECKLIST.md) / [`GO-NO-GO-CHECKLIST.md`](GO-NO-GO-CHECKLIST.md).

---

## 1 · Tool Identity

A tool is not identified by name alone. Name-only identity is exactly what makes tool shadowing
(MCP-T-012) and silent capability changes (schema drift MCP-T-013, description drift MCP-T-014, rug pull
MCP-T-015) possible. Per [`BLUEPRINT.md`](BLUEPRINT.md) §12 and **MCP-TOOL-001**
([`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md)), every tool the Gateway discovers **MUST** be
fingerprinted as the composite:

```
server_registry_id
+ TLS / workload identity
+ tool name
+ canonical input schema hash
+ canonical output schema hash (when available)
+ description hash
+ credential profile
+ observed destination class
```

| Field | Purpose |
|---|---|
| `server_registry_id` | Binds the tool to a specific entry in the server allowlist/registry (MCP-SERVER-001), not to a bare hostname or free-text label. |
| TLS / workload identity | The verified, pinned identity of the upstream MCP server (MCP-SERVER-002). A tool fingerprint is meaningless if the server behind it can be silently swapped. |
| Tool name | Human-facing identifier only — never the sole disambiguator (defeats MCP-T-012 shadowing). |
| Canonical input schema hash | Deterministic hash of the tool's declared input JSON Schema. |
| Canonical output schema hash (when available) | Deterministic hash of the declared output schema. MCP tool definitions are not guaranteed to publish an output schema, so this field may be absent; its absence is itself recorded (a tool that later starts declaring an output schema, or changes one, is a drift event, not a null diff). |
| Description hash | Deterministic hash of the tool's natural-language description/annotations, so semantic/behavioral claim changes are detectable even when the schema is untouched (MCP-T-014). |
| Credential profile | The scoped upstream credential class the tool is invoked with (links to [`AUTH-AND-CREDENTIAL-MODEL.md`](AUTH-AND-CREDENTIAL-MODEL.md)) — a privilege expansion is only meaningful in the context of what credential power is behind the call. |
| Observed destination class | The empirically observed network/resource destination breadth of the tool's calls (see Risk Signals, §3), not merely the declared one — closes the gap between what a tool *says* it does and what it *is seen doing*. |

### Canonicalization

Hashing is only a trustworthy drift signal if it is **deterministic and insensitive to cosmetic
variation**. The canonical form for each hashed field:

- **Whitespace-insensitive**: schema and description text is normalized (collapsed/stripped whitespace)
  before hashing, so re-formatting a JSON Schema document or re-wrapping a description string does not
  register as a change.
- **Order-insensitive** where the underlying structure has no defined order: JSON object keys are sorted
  before serialization; schema `enum`/`required`/`anyOf` member lists are sorted before hashing (a
  cosmetic re-ordering of an enum's members is not a "no material change" if it silently narrows the
  meaning below the diff visibility of a naive text compare, so the *sorted* representation is compared,
  never a raw string diff).
- **Semantically stable serialization**: the same schema/description, re-serialized identically on every
  discovery cycle, must always hash to the same value — the fingerprint pipeline itself needs
  determinism tests (see §6) before it can be trusted as an evidence source.

A hash comparing equal after canonicalization is the **"no material change"** class (§2, row 1). A hash
that differs only because of the transformations above (i.e., would have compared equal under
canonicalization but the raw bytes changed) still resolves to "no material change" — canonicalization is
computed *before* the comparison, not as an exception applied after a raw-diff flags a change.

This tool-identity definition is normatively required by **MCP-TOOL-001**.

---

## 2 · Drift and Change Classes

Every discovery cycle re-fingerprints every known tool and diffs the result against the last-recorded
fingerprint. The diff is classified into exactly one of the following classes (mirrors
[`BLUEPRINT.md`](BLUEPRINT.md) §12); each class maps to a mandatory action, a normative requirement, and
the threat(s) it defends against:

| Change class | Example | Action | Requirement | Threat(s) |
|---|---|---|---|---|
| No material change | Whitespace or key-order difference only, resolved by canonicalization. | Continue; record the observation (no policy effect). | MCP-TOOL-001 | — (canonicalization pre-empts false positives) |
| Safe narrowing | An enum narrows, or a declared destination becomes more restrictive. | Notify; **optional**, policy-controlled auto-accept only for narrowing that a configured policy explicitly opts into. | MCP-TOOL-003 | MCP-T-013 (schema drift, benign direction) |
| Privilege expansion | A new field permits admin action, delete, branch selection, or an arbitrary URL/destination parameter. | **QUARANTINE + human approval.** Never auto-allow. | MCP-TOOL-004 | MCP-T-015 (rug pull), MCP-T-019 (privilege expansion) |
| Semantic drift | The description or a behavioral claim changes without a matching schema change (or vice versa). | Re-score risk; route to human review. | MCP-TOOL-005 | MCP-T-014 (description drift) |
| Identity change | The upstream TLS/workload identity, endpoint owner, or server binding changes. | **Disable the server until re-verified.** This is a server-level control, not a per-tool one — every tool behind that server is affected. | MCP-SERVER-003 | MCP-T-016 (server identity change), MCP-T-021 (compromised approved server) |
| Unknown tool | A tool name/fingerprint the registry has never recorded appears in a discovery response. | **QUARANTINE. Never automatic allow.** | MCP-TOOL-006 | MCP-T-017 (unknown-tool auto-allow, **Critical**) |

Supporting classification and disambiguation requirements that apply across every row above:

- **MCP-TOOL-002** — duplicate or shadowing tool names **MUST** be detected and disambiguated by
  fingerprint, not by name alone (defends MCP-T-012, tool shadowing). A same-named tool from a different
  `server_registry_id`/TLS identity is never treated as "the same tool re-observed."
- Tool poisoning (MCP-T-011, High) is a discovery-time concern addressed by capturing the fingerprint
  (including description hash and destination class) at first sight, before the tool is ever eligible for
  ALLOW — a poisoned description/schema at initial registration is caught by the same canonicalized-hash
  discipline defined in §1, combined with the human review gate implied by an unrecognized fingerprint
  (it enters as "unknown tool" per the last row above, not as an implicit trust grant).

### HARD RULE — never automatic allow

> **Unknown tools (MCP-TOOL-006 / MCP-T-017, Critical) and privilege-expansion drift (MCP-TOOL-004 /
> MCP-T-019, High) MUST NEVER receive an automatic ALLOW decision, under any policy configuration,
> auto-accept setting, or operating mode (including shadow/canary rollout stages).** These two classes are
> QUARANTINE-only; the nine policy actions
> ([`MCP-POLICY-MODEL.md`](MCP-POLICY-MODEL.md)) do not offer a configuration path that resolves either
> class to `ALLOW`, `ALLOW_ONCE`, or `ALLOW_FOR_SESSION` without an intervening human approval decision.
> This is the same red line [`BLUEPRINT.md`](BLUEPRINT.md) §12 states directly ("Quarantine; never
> automatic allow") and it is load-bearing for the MCP-T-017 Critical rating — any implementation, test,
> or configuration surface that appears to auto-resolve either class is a defect, not a feature.

---

## 3 · Risk Signals

Drift classification determines *whether something changed*; risk signals determine *how dangerous the
tool is*, independent of whether it just drifted. Per [`BLUEPRINT.md`](BLUEPRINT.md) §12, each
fingerprinted tool carries the following risk-signal dimensions, evaluated both at discovery time (from
declared schema/description) and continuously (from observed call behavior):

| Signal | Examples |
|---|---|
| Intent | read, write, destructive, administrative, financial |
| Input surface | free-form text, URLs, SQL, shell, file paths, credentials |
| Destination breadth | single approved service vs. arbitrary network |
| Credential power | read-only token vs. tenant administrator |
| Resource scope | single repository vs. all production |
| Reversibility | easy rollback vs. irreversible deletion |
| Observed behavior | destinations, volume, errors, schema mismatch |
| Human review | owner classification and accepted residual risk |

Risk signals feed the policy engine's ([`MCP-POLICY-MODEL.md`](MCP-POLICY-MODEL.md)) decision alongside
the drift class from §2 — a privilege-expansion drift on an already high-risk tool (destructive intent,
tenant-administrator credential power, all-production resource scope) does not receive a lighter-weight
review path than the same drift on a low-risk tool; the QUARANTINE + approval action in §2 is a floor, not
a ceiling that risk signals can raise but never bypass downward.

---

## 4 · Discovery Lifecycle

Discovery is the process by which the Gateway learns about, re-verifies, and re-fingerprints tools behind
registered MCP servers. It is the feed that populates — and, on drift, quarantines entries in — the
Registry & Catalog described in [`RECOMMENDED-ARCHITECTURE.md`](RECOMMENDED-ARCHITECTURE.md):

1. **Server allowlist gate (MCP-SERVER-001).** Discovery only ever runs against a server already present
   on the registered allowlist. An unregistered destination is never discovered from, let alone
   fingerprinted — this is the outermost gate; tool-level drift handling in §2 assumes the server itself
   is already trusted at the point discovery runs.
2. **Server identity verification (MCP-SERVER-002/003).** Before (re-)running discovery against a server,
   its TLS/workload identity is verified against the identity pinned in the registry entry. A mismatch is
   an identity-change event (§2, "Identity change" row) and disables the server — discovery does not
   proceed against an unverified identity, so a server-identity failure can never be laundered into a
   tool-level "safe narrowing" or "no material change" verdict.
3. **Per-tool fingerprint capture.** For each tool the (now-identity-verified) server advertises, the
   Gateway computes the §1 canonical fingerprint.
4. **Catalog lookup and diff.** The fingerprint is looked up against the catalog's last-recorded
   fingerprint for that `(server_registry_id, tool name)` pair:
   - No prior record → **unknown tool** (§2) → the entry is written to the catalog in a
     **quarantined** state; it is never inserted as directly usable.
   - Prior record found → the two fingerprints are diffed field-by-field and classified into one of the
     §2 rows.
5. **Catalog update.** The diff outcome, the new fingerprint, the risk-signal snapshot (§3), and (for
   quarantine-eligible classes) the pending-approval state are written back to the catalog as the new
   "last known" record for the next discovery cycle. Quarantine is a catalog-visible state, not merely a
   policy-engine-transient one — a quarantined tool stays quarantined across discovery cycles and
   restarts until a human approval action explicitly clears it.
6. **Continuous re-observation.** "Observed destination class" and "Observed behavior" (§3) are not
   discovery-cycle-only signals — they accumulate from actual call traffic between discovery cycles, so a
   tool that behaves outside its declared destination class can surface a semantic-drift or risk-rescore
   event even without a schema/description change at the next discovery cycle.

This lifecycle is deliberately layered so that a compromise at one layer cannot be laundered through a
lighter-weight verdict at another: a server-identity failure (step 2) cannot present as a mere tool
schema change (step 4), and an unknown tool (step 4) is never inserted into the catalog in a state that
policy evaluation could resolve to `ALLOW` (§2 HARD RULE).

---

## 5 · Compatibility, Fixtures and Test Evidence

The classification scheme in §2 and the canonicalization rules in §1 are only as trustworthy as the tests
that pin them. As of this PR-0 package:

- **No canonicalization tests exist in the current repository CI baseline.** There is no MCP tool
  fingerprinting code yet (no MCP listener exists in inspected paths — VERIFIED EVIDENCE), so there is
  necessarily no test proving the whitespace-/order-insensitivity behavior described in §1.
- **No malicious or non-compliant MCP server fixtures exist today.** `pr-fast-gate.yml`/`pr-deep-gate.yml`
  do not run any MCP-specific suite. **On CodeQL, note the correction (finding M-1):** `codeql.yml` is PR
  path-scoped, but its filter **already includes `internal/**`**, which matches `internal/mcp/**` — so MCP Go
  code **will be analyzed on PRs with no path-filter change**. What CodeQL does *not* do is **block**: it is
  not a branch-protection-required check, so making it gate MCP PRs is a **repo-settings choice, not a
  workflow edit**. Do **not** schedule a CodeQL path-glob change as MCP work. A malicious-MCP-server test corpus is explicitly listed as **MISSING FOR MCP** in the current CI
  evidence, alongside the OAuth-negative matrix, DNS-rebinding lab, inbound Origin/Host tests,
  SSE-exhaustion tests, and mixed-version/stale-epoch/corrupt-snapshot MCP gates.
- **No drift-classification fixtures (per-row §2 test cases: no-change, safe-narrowing, privilege
  expansion, semantic drift, identity change, unknown tool) exist today.** `NOT VERIFIED` — these are
  design-stage requirements (MCP-TOOL-001..006) with no corresponding executable test yet; the
  requirement-to-test binding is tracked in
  [`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md) and the CI-gate classification
  (Existing/Insufficient/Proposed) for each is recorded in [`CI-GATES.md`](CI-GATES.md).
- Building this fixture/test set (canonicalization determinism tests, the six drift-class fixtures, and a
  malicious/non-compliant server harness) is scoped to **PR-2 (Registry & catalog)**, per the
  requirement-to-PR mapping in [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md), with the
  privilege-expansion/unknown-tool enforcement tests (MCP-TOOL-004/006) gated at **PR-6 (Policy engine)**
  where the QUARANTINE action is actually enforced.

**Risk statement:** Low for the read-only Phase 1 investigation, but the current repository test baseline
remains unverified in this session. This is not a claim that discovery/drift risk is zero or low in an
absolute sense — only that no MCP-specific test evidence exists yet to measure it, which is itself the gap
this section records.

---

## Cross-references

- [`BLUEPRINT.md`](BLUEPRINT.md) §12 — source narrative this document formalizes.
- [`SECURITY-REQUIREMENTS.md`](SECURITY-REQUIREMENTS.md) — MCP-TOOL-001..006, MCP-SERVER-001..003 full
  normative text, verification method, and owning PR.
- [`THREAT-MODEL.md`](THREAT-MODEL.md) — MCP-T-011..017 (tool threats), MCP-T-019 (privilege expansion),
  MCP-T-020/021 (malicious/compromised server), risk ratings and STRIDE mapping.
- [`RECOMMENDED-ARCHITECTURE.md`](RECOMMENDED-ARCHITECTURE.md) — the Registry & Catalog component this
  discovery lifecycle feeds, and the package/interface boundary that isolates it from the SWG policy
  engine (policy.go has no MCP action verbs — VERIFIED EVIDENCE — and this discovery/catalog surface is
  additive, never wired into it).
- [`MCP-POLICY-MODEL.md`](MCP-POLICY-MODEL.md) — the nine policy actions, reason-code taxonomy
  (`MCP.TOOL` prefix), and how a QUARANTINE verdict from §2 is represented as a policy decision.
- [`TEST-TRACEABILITY-MATRIX.md`](TEST-TRACEABILITY-MATRIX.md) — threat → requirement → control → test →
  evidence → owner → gate rows for MCP-T-011..017 / MCP-TOOL-001..006.
- [`CI-GATES.md`](CI-GATES.md) — classification (Existing/Insufficient/Proposed) of the CI gates this
  document's §5 identifies as missing.
- [`IMPLEMENTATION-SLICES.md`](IMPLEMENTATION-SLICES.md) — PR-2 (Registry & catalog) and PR-6 (Policy
  engine) slice contracts that implement this document.
