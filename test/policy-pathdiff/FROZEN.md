# Freeze record — cross-path policy differential

Frozen in the commit that adds this file, **before** the held-out seed was run.

| Item | Frozen value |
|---|---|
| Product revision | `155df09` (main) |
| Generator | `internal/pathdiffgen/gen.go`, `Version = pathdiffgen/1` |
| Reference | `internal/pathdiffgen/ref.go`, clauses D1–D4, POL-001 literal fragment, publication transitions |
| Comparison semantics | `pdClassify` in `policy_pathdiff_test.go` |
| Held-out seed | `heldout-1`, scale 1 (2,600 cases) |
| Reviewer predictions | `review_predictions.jsonl`, written by an independent agent that read source only and saw no harness, case or result |

## What had been seen before the freeze

Only the `dev` seed at scale 0.1 (260 cases), used to make the harness work. Three things changed
because of it, all recorded here so nothing is silently tuned:

1. **Harness:** the fake identity provider is installed only for requests that carry credentials.
   With it installed globally every anonymous request was challenged (407).
2. **Reference:** `[1.2.3.4]` (a bracketed IPv4) was wrongly treated as an alias of `1.2.3.4`.
   Brackets are for IPv6 literals only (RFC 3986 §3.2.2).
3. **Reference:** a bare rule destination `example.org` covers `sub.example.org`. The first draft
   said exact match only; the product's documented matcher contract (`internal/hostutil`
   `MatchFQDN`) says a bare name covers its subdomains on a label boundary. The reference was
   wrong, not the product.

The dev seed showed no cross-path decision split. The action-dispatch and dial-alias suites and the
reviewer's predictions were also executed before the freeze; they are fixed tables, not seeded
campaigns, so there is nothing held out about them.

## Frozen expectations for the held-out run

- **E1** Controls pass: two identical runs agree; a fault injected into one path is detected.
- **E2** No stratum is vacuous.
- **E3** The literal-fragment oracle (`plain`, `publish`) reports 0 mismatches.
- **E4** Aliases the reference calls *Same* (D1–D4) decide alike on every path: 0 `alias-split`.
- **E5** No `decision-split` between paths that decide. This is the prediction most likely to be
  wrong, and the one whose failure would matter most.
- **E6** `tester-answers-unroutable` and `tester-refuses-routable` occur; they are compatibility
  differences, reported and baselined, not defects.

A result with zero new findings is an acceptable outcome and will be reported as such.
