# Gitleaks full-history findings: classification (2026-11-13)

This follows the procedure of `gitleaks-history-20261030.md` and
`gitleaks-history-20261108.md`, under the same owner direction (PR #1528,
30 Oct):
- every finding is classified independently;
- exceptions are exact `commit:path:rule:line` fingerprints only;
- no rule, path or commit-wide suppression;
- `.gitleaks.toml` is unchanged;
- no secret value is reproduced beyond what identifies a public constant;
- ASTRA reviews.

**Verdict: neither finding is a credential.** Two fingerprints are appended to
`.gitleaksignore` (group H).

## How they surfaced

The Fast PR Gate dispatched on the R10 candidate `47a2b0e9` (run
43496558390) failed its gitleaks job with 2 findings over 7,334 commits. A
dispatch scans `git log --full-history --all` over every fetched ref, not only
the candidate line. Both findings come from commits on `main` made after the
last green dispatch on this line (`a2b722c0`, run 42653709058, 9 Nov
16:20Z). Neither commit is in the candidate line's history (`git merge-base
--is-ancestor` is false for both).

## Method

1. **Reproduce locally.**
   - gitleaks v8.30.0 (the gate's version), with this line's `.gitleaks.toml`
     and `.gitleaksignore` as of `47a2b0e9`.
   - `--log-opts="--full-history --all"`, `--redact`, on a clone of
     `review/1528-m1-engine-pins` with every remote branch fetched (919 refs).
   - Result: exactly the same **2** fingerprints as CI, and no other finding.
     The local run reports 2,292 commits scanned, against CI's 7,334. Why the
     counts differ is not established; this reproduction does not claim to
     have scanned the CI runner's exact ref set, only that it finds the same
     two fingerprints and nothing else.
2. **Inspect each finding in its exact commit.**

## Findings

| Fingerprint | Commit / branch | What the matched value is | Class |
|---|---|---|---|
| `62aa116ca3778dcff4dc83ed368cf00ed2a06bb7:proxy_tunnel_inspectbuf_test.go:generic-api-key:296` | `main`, 10 Nov (tunnel inspect-buffer test corpus) | `Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==` in a request fixture. It base64-decodes to "the sample nonce": the example key from RFC 6455 §1.3, published in the standard. The rule matched the word "Key" in the header name. | public test vector |
| `e9283034790031d77983224445c039f359504991:internal/pseudonym/pseudonym_test.go:generic-api-key:14` | `main`, 9 Nov (pseudonymizer tests) | `const testKey = "<the hex digits 0-f, twice>" // 32 bytes`. It is a synthetic HMAC key for unit tests, the literal digit sequence. The rule matched the identifier `testKey`. | synthetic test fixture |

**Effect.** After the two fingerprints are added, `check_gitleaks_policy.py`
passes (five canary checks), and the line's own history is unchanged. The
two suppressions name exact commits on `main`. They do not cover any future
finding in those files.
