# Receipt notes — 95a1f8a5 (tree 06880381)

- A delta receipt on top of the full `52463785` receipt (`../52463785/`, `../52463785-saml-supplement/`). Code changed since then:
  - the merge of main c319d2a5 (#1706, test isolation in `access_cidr_diag_test.go` / `ui_access_policy_startup_test.go`);
  - `access_cidr_diag_failclosed_test.go`, which now uses `resetUIAccessPolicyGlobals`.
- All 6 commands exit 0; the tree was clean before and after. They cover build + vet, the access-list/diagnostics tests at `-race -shuffle=on -count=3`, the full root package, diff-scoped lint from c319d2a5, and gitleaks.
- The sub-modules, the frontend and the sidecar are unchanged since `52463785` and were not re-run.
- Main moved to 7bac2df6 (#1563, `internal/admission` only; CHANGELOG merges clean) after this receipt. CI's merge-ref run covers that combination; no local receipt is claimed for it.
