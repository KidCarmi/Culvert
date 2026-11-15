# Documentation governance review 2026-11-12

Scope: checked-out `main` at `3b09cff`, focused on product changes merged since the
2026-11-10 review (`ac4e223..3b09cff`, 28 non-merge commits). Point-in-time record; not a
source of truth for behavior.

## Finding (Medium): the `cdr` Diagnostics state lists omitted the two new WARN states

- **Problem.** `142b959` added `enabled-reduced` and `enabled-recovering` to the `cdr`
  Diagnostics row. `docs/OPERATIONS.md` §6 still said the row "surfaces four states beyond
  `disabled`", and the state list in `docs/operator/cdr-content-disarm-reconstruction.md`
  (Observability) ended at `enabled-healthy`. Neither named the new states.
- **Implementation evidence.** `checkCDR` → `checkCDRCapacity` (`diagnostics.go`) uses
  `cdrPool.trippedCount` (`cdr_pool.go`, breaker state not closed). It reports WARN
  `enabled-recovering` when every breaker has tripped but one is still available for a probe,
  and WARN `enabled-reduced` when some, but not all, have tripped. `enabled-dark` (none
  available) and `enabled-broken` (empty pool) stay FAIL.
- **Why it matters.** An operator who sees a WARN state in Diagnostics and checks the recovery
  section finds nothing about it. The "four states" count contradicts the product.
- **Who is affected.** Operators running a multi-instance Sluice pool.
- **Canonical source.** The CDR operator page is the reference. `OPERATIONS.md` §6 is the
  recovery list. Both already listed the states, so each was corrected in place and no new
  page was added.
- **Change.** Both lists now include the two states and their severities. Effort: small.
  Risk: low (prose only).

## Checks performed

- Commits since the previous review were read for operator-visible changes. The CA same-key
  renewal and imported-CA changes were documented in their own commits (`0681278`, `40084c0`).
  The cluster null-record fix (CHAOS-117) and the ClamAV probe changes need no operator page
  change.
- The sourceIP API validation (`263f5e9`) is recorded in `CHANGELOG.md`. The README's
  "Source IP / CIDR" condition does not contradict it, so no change was made.

## Not assessed / documentation debt

- No single catalog lists Diagnostics row codes. A search of tracked Markdown (excluding the
  changelog and review records) for each `OperatorContractCheck` code found several rows with no
  operator documentation, including the new `upstream_pool_config`, `memory_backstop`,
  `config_versions_integrity` and `ui_tls_fallback_http`. A catalog belongs in
  `docs/operator/support-bundles-and-diagnostics.md` and needs its own scoped change.
- Per-option configuration-reference completeness was not re-audited.
