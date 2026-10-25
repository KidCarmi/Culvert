# Receipt notes — 642409f0 (tree 0c3a81f3)

- A delta receipt on top of `95a1f8a5`. The only code change is `internal/storeguard/storeguard.go`: `recoverBeforeOpen`'s post-quarantine marker clearing moves verbatim into `clearActedMarkers` (cyclop 17 → under 15; the finding came from the reviewdog lint on PR #1705).
- All 6 commands exit 0; the tree was clean before and after. They cover build + vet, whole-package cyclop/gocognit/funlen on storeguard, diff-scoped lint, the storeguard/catdb/logstore/feedsync race tests at `-shuffle -count=2`, and the root category-feed/storeguard/request-history tests.
- CI on the previous head `ff6b22be`: all 103 check runs passed or were skipped, including Fast + Deep PR Gate APPROVED.
