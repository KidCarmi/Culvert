# Product contracts: registry, gate and governance

Status: **proposal, not ratified.** Every registry entry is `owner_approved: false`.
Nothing here becomes a rule until the product owner approves it.

## 1. The problem

A change can compile, pass the existing tests and pass every scanner while altering
behavior customers rely on. PR #1854 is the worked example: automatic CA rotation
replaced an imported enterprise CA with a self-signed one. No test failed, because
no test stated who is allowed to renew a CA.

The goal is narrow: **a critical product invariant cannot change unnoticed.** Either
an executable test fails, or the change is surfaced for a person who is not its
author to approve. The goal is not more review of ordinary changes.

## 2. What is in this change

| Piece | Path | Role |
|---|---|---|
| Registry | `contracts/registry.yaml` | Machine-readable list of invariants, code paths, tests |
| Checker | `internal/contracts`, `cmd/contractcheck` | Validates the registry; compares base against head |
| Always-on test | `TestRegistry_IsSoundAgainstThisTree` | Runs in the existing race lane; no new workflow needed |
| Gate | `.github/workflows/product-contracts.yml` | Detects weakening; requires independent approval |
| Ownership | `.github/CODEOWNERS` | Registry, checker and this document |
| Agent guidance | `AGENTS.md` route to `docs/agent-context/workflows/product-contracts.md` | Six steps before changing contract code |

No new dependency. The checker uses the YAML library already in `go.mod`.

### Registry entry

Each entry carries: `id`, `area`, `invariant`, `authority` (ownership boundary),
`code` (path globs), `configs`, `transitions.permitted` / `transitions.forbidden`,
`tests` (file + function), `validation` (unit, integration, e2e), `compatibility`,
`status` and `owner_approved`.

`status` is one of two values:

- **`enforced`**: the named tests exist, cannot skip themselves, and guard the invariant.
- **`open`**: the behavior matters but is contradictory, undecided or pending. It
  carries a `question` for the owner. An open entry is a recorded gap, **not** a rule.

A documentation-only contract cannot be registered as enforced: the checker rejects
an enforced entry with no test.

### What the checker does

`validate` (also run by the Go test) fails when:

- an enforced contract names no test, a missing test, or a test containing `t.Skip`;
- a code path matches no file;
- a field name is misspelled (unknown fields are errors);
- an `open` entry claims owner approval.

`impact -base <rev>` compares the **base revision's** registry with the head tree:

| Finding | Meaning | Result |
|---|---|---|
| Touched | The change edits a contract's code paths; its tests are intact | Pass. Listed in the job summary for the reviewer |
| Weakened | A base contract was removed, downgraded, reworded, lost a code path, or a base-registered test is gone or skippable, with no new record | **Fail** |
| Needs approval | The same, but with a new `amended` / `retired` record; or an edit to a protected path | **Fail until** a listed approver who is not the author approves the current commit |

The base registry is the reference. Deleting a test and removing it from the registry
in the same change still fails, because the base list is what gets checked
(`TestAssess_BaseRegistryIsTheReference`). Approvers and protected paths are also
read from the base, so a change cannot add its own approver.

### Risk tiers

| Change | Friction |
|---|---|
| Touches no contract code | None. The job passes in seconds |
| Touches contract code, tests intact | None. Affected IDs are listed for review |
| Adds a contract | None. Additions to the registry need no approval |
| Changes a contract on purpose | One record in the registry plus one approval |
| Edits the checker, the gate workflow, CODEOWNERS, the approver list | One approval |

## 3. Coverage matrix

Derived from a read-only audit of `main` at `ac4e223`. "Enforced" entries name tests
whose existence the checker verifies; the invariant wording is a candidate awaiting
owner approval. Audit limits are in §8.

| Area | Enforced | Open (owner decision) | Not yet covered |
|---|---|---|---|
| SWG enforcement | SWG-001, SWG-002 | SWG-900 plain-HTTP SSRF gap; SWG-901 SOCKS5 skips policy | Gate ordering; WebSocket SSRF guard has no test found |
| Policy evaluation | POL-001 to POL-004 | POL-900 default action at runtime; POL-901 empty action allows | Restored empty default action becomes deny on one path only |
| Authn / authz | AUTH-001 to AUTH-004 | none recorded | OIDC/SAML/LDAP assertion validation, cookie attributes, lockout: not audited |
| TLS inspection | TLS-001, TLS-002 | TLS-900 unloaded CA forwards uninspected; TLS-901 OCSP scope | SSL-bypass precedence over Inspect has no test found |
| PKI | none on `main` | PKI-900 pending PR #1854; PKI-901 no golden vector for the bundle format | Cluster CA; key-at-rest |
| Upgrades | UPG-001, UPG-002 | UPG-900 `min_upgrade_from` parsed, never enforced; UPG-901 health gate uses non-strict `/ready` | Image downgrade policy |
| Backup / restore | BKP-001 to BKP-003 | none recorded | Backup envelope bytes have no golden vector; no schema-2 migration path |
| Agent lifecycle | AGT-001 | AGT-900 crash reconcile decided but not wired | Journal corruption refusal |
| Config compatibility | CFG-001, CFG-002 | CFG-900 no skew or downgrade policy | Config-version files carry no format version |
| Cluster sync | CLU-001, CLU-002 | (CFG-900) | Data-plane behavior during a control-plane outage |
| Failure / recovery | REC-001, REC-002 | (TLS-900, UPG-901) | none recorded |

The 12 open entries are the audit's most useful output: three contradictions between
documentation and code (SWG-900, POL-900, UPG-900/901) and several behaviors nobody
has decided.

## 4. Can it be bypassed?

| Path | Closed by | Residual |
|---|---|---|
| Skip the required check | Repository ruleset marking `Gate · product contracts` required | **Owner action.** Not configurable from the tree |
| Weaken a contract test | Base-registered tests must exist and not skip | A test can be gutted while keeping its name. Review of the listed IDs is the only defense |
| Edit the registry with the implementation | Base registry is the reference | None for removal or rewording |
| Edit the workflow or the checker in the PR | `pull_request_target`: both come from the base branch; PR content is read, never executed | A later maintainer adding a step that runs PR code would reopen it |
| Edit `AGENTS.md` | Existing guidance gate, plus CODEOWNERS | Guidance is advisory by nature |
| Critical code no contract maps | Nothing mechanical | **Largest gap.** Unmapped paths are invisible; see §7 |
| Self-approval or agent approval | Approver must differ from the PR author and approve the head commit | **See below** |

**The identity problem.** Agents in this repository open pull requests as the owner's
own account. GitHub does not let an author approve their own pull request, so today
the owner cannot approve an agent-authored contract change, and any agent holding the
owner's credentials can do whatever the owner can. Independent approval is only real
if agents author through a separate identity (a GitHub App or bot account) with no
ruleset bypass. Until then the gate still detects and blocks silent weakening, but
the approval step can only be satisfied by an administrator override.

I have not confirmed how GitHub resolves the workflow file for `pull_request_review`
events, which is one reason that trigger is not used.

## 5. Vendor comparison (Workstreams A and C)

**Evidence quality:** the vendor documentation hosts were not reachable from this
environment. The points below come from search-result excerpts of the cited pages,
not from reading the pages. Treat them as leads to re-verify, not as citations.

| Practice | AD CS | AWS Private CA | Vault PKI | PAN-OS |
|---|---|---|---|---|
| Same-key CA renewal documented | Yes | Yes ("reissue") | Yes ("reissuance") | Not found |
| New-key rotation documented | Yes | Yes (new CA) | Yes (root rotate) | Not found |
| Externally issued sub-CA renewal | Parent re-issues | External parent signs a CSR | Parent signs a CSR | External CA signs a CSR |
| Product replaces it with a self-signed CA | Not found | Not found; API rejects a self-signed subordinate | Not found | Not found |
| Overlap mechanism | Cross-certificates on root re-key | Two CAs side by side | Multiple issuers, cross-signing | Not found |
| CA expiry signal | Enterprise PKI view | Not found | `pki health-check` thresholds | System-log warning; incident |

Sources: `learn.microsoft.com/.../ad-cs/renew-root-ca-certificate`,
`docs.aws.amazon.com/privateca/latest/userguide/ca-lifecycle.html`,
`developer.hashicorp.com/vault/docs/secrets/pki/rotation-primitives`,
`docs.paloaltonetworks.com/.../decryption/configure-ssl-forward-proxy`.

What this supports for PR #1854:

- **Supported by all four (as far as the excerpts go):** a CA issued by another
  authority is renewed by that authority. None documents replacing it automatically
  with a self-signed certificate.
- **Supported by three:** same-key renewal and new-key rotation are distinct
  operations with different trust consequences.
- **Not matched:** AWS recommends rotating to a new key; Vault and AD CS handle
  re-key overlap with cross-signing. Culvert's same-key renewal is the simpler of
  the documented options and does not rotate the key.
- **Culvert-specific:** a provenance record stored in the bundle, and the "unknown"
  class for bundles that predate it. No vendor excerpt describes an equivalent
  flag; PAN-OS and AWS get the same effect by branching on who signed the CA.

## 6. Independent challenge

1. **Backed by documented practice:** external authority renews an externally issued
   CA; renewal and re-key are separate; expiry is alerted before it happens.
   Required status checks, CODEOWNERS and rulesets are standard GitHub controls.
2. **Culvert-specific choices:** the registry format; using the base revision as
   reference; the `open` status; the provenance PEM block; `CULVERT_CA_PROVENANCE`.
3. **Executable safeguards:** registry validation; base-versus-head weakening
   detection; the skip check; the approver-is-not-author check; the contract tests
   themselves.
4. **Documentation or human review only:** the wording of each invariant; whether a
   test truly asserts its invariant; `transitions` and `compatibility` (free text,
   not checked); the six-step agent procedure; everything in an `open` entry.
5. **Realistic bypass paths:** unmapped code; a test hollowed out under its old
   name; credentials shared between agents and the owner; a ruleset that was never
   configured.
6. **Maintenance cost:** one registry entry per new invariant; one record per
   intentional change. The registry will rot if entries are added for behavior
   nobody would defend, so it should stay small. 36 entries is near the upper end
   of what one owner can keep honest.
7. **Does it scale without bottlenecking?** Approval is needed only for a contract
   change or a protected-path edit. The risk is the opposite: too many code globs
   make "touched" lists noise that reviewers stop reading. Globs should stay narrow.
8. **Migration for deployed appliances:** the gate changes nothing at runtime. For
   PR #1854, existing bundles load as unknown provenance and stop auto-renewing
   until classified; the record is skipped by older builds, so a downgrade loads.

## 7. Rollout

1. **Owner review of this proposal** and of the 24 candidate invariants. Flip
   `owner_approved` only for wording you would defend to a customer.
2. **Decide the 12 open entries**, contradictions first (SWG-900, POL-900,
   UPG-900, UPG-901).
3. **Merge**, then make `Gate · product contracts` a required check in a ruleset.
4. **Separate agent identity**, so approval is independent (§4).
5. **Promote PKI-900** to enforced once PR #1854 merges, naming its tests.
6. **Close the unmapped-code gap**: add golden-vector tests for the two frozen
   on-disk formats (PKI-901 and the backup envelope), then extend coverage area by
   area. A "critical path with no contract" detector is possible later but needs
   an owner-agreed list of critical paths first.

## 8. Residual risks and limits of this work

- The audit was read-only and partial. Authentication protocol handling, cookie
  attributes and lockout were not examined. Several documentation sections were
  not opened.
- The checker proves a test **exists and does not skip**. It does not prove the
  test asserts the invariant. I confirmed existence mechanically for all 24; I did
  not re-read every assertion.
- The gate workflow uses `pull_request_target` and therefore **has not run**: it
  only exists once merged. Its logic is unit-tested; its wiring is not.
- POL-900 was not verified end to end.
- A registry is only as good as its upkeep. Without an owner who prunes it, it
  becomes a second source of stale claims.

## 9. Owner decisions

1. Approve, reword or drop each of the 24 candidate invariants.
2. Answer the 12 open questions.
3. Configure the ruleset: required check, code-owner review, no bypass for agents.
4. Give agents a separate GitHub identity, or accept administrator override as the
   approval path.
5. Decide whether `amended` records should be pruned after release or kept as history.
