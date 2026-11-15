# Documentation governance review 2026-11-10

Scope: checked-out `main` at `ac4e223`, focused on product changes merged since the
2026-11-09 review (`d11ed3a..ac4e223`). Point-in-time record; not a source of truth for behavior.

## Finding (Medium): README Policy Model omitted category groups and their matching semantics

- **Problem.** `README.md` § Policy Model listed "URL category" as condition 6 with no mention
  of category groups and no statement of how category conditions match. `149dd1a` changed
  category-group rules from single-winner classification to membership; the operator-facing
  contract was recorded only in `CHANGELOG.md` and the edge-case lab.
- **Implementation evidence.** `matchDestNorm` (`policy.go`) ANDs `destCategory` and
  `destCategoryGroup`; both use membership (`hostCatScratch.matchesCategory`,
  `categoryGroupMatchesHostScratch` in `categorygroup.go`). An uncategorized host or an
  unresolved group returns no match (`internal/catgroup` `MatchesMemberKey`). The URL Lookup API
  (`apiURLCatLookup`) and the Policy Tester report the single winner from `lookupHostCategory`,
  resolved admin → signed feed view → community (`policy_hostcat.go` `resolveFusion`).
- **Why it matters.** An administrator who checks a host in URL Lookup sees one category and can
  wrongly conclude that a rule on another category (or a group containing it) will not match.
- **Canonical source.** `README.md` § Policy Model. `docs/enterprise/POLICY-ROLLOUT-GUIDE.md`
  already lists "URL category / category group" and does not contradict the new text.
- **Change.** Condition 6 now names category groups; one paragraph states the membership rule,
  the no-match cases and the single reported category. Effort: small. Risk: low (prose only).

## Checks performed

- Commits since the previous review were read for operator-visible changes: the scan-sidecar
  concurrency bound (CHAOS-115) is already documented in `docs/operator/scan-capacity-and-timeouts.md`
  and `scan-svc-listener-health.md`; the admin-UI plain-HTTP diagnostic and the pseudonymizer
  extraction need no operator documentation change.

## Not assessed

- `docs/operator/category-store-recovery.md` describes "two tiers" (admin `catStore`, community
  store); the signed-feed effective view is a third classification source. That page is scoped to
  community-store recovery, so this was left for a dedicated category-architecture review.
- Per-option configuration-reference completeness was not re-audited.
