# Gitleaks full-history findings: classification (2026-11-17)

This follows the procedure of `gitleaks-history-20261030.md`,
`gitleaks-history-20261108.md` and `gitleaks-history-20261113.md`, under the
same owner direction (PR #1528, 30 Oct):
- every finding is classified independently;
- exceptions are exact `commit:path:rule:line` fingerprints only;
- no rule, path or commit-wide suppression;
- `.gitleaks.toml` is unchanged;
- no matched value is reproduced;
- ASTRA reviews.

**Verdict: none of the six findings is a credential.** Six fingerprints are
appended to `.gitleaksignore` (group I).

## How they surfaced

The Fast PR Gate dispatched on the R10 replacement source `c3e24c2a` (run
44138808940, job 134235722167) failed its gitleaks job: `leaks found: 6`. All
six are in one file that commit added,
`docs/appliance/evidence/combined/r10-engine-pins/raw/go-version-m.txt`, the
`go version -m` output of the Docker engine binaries before and after the R10
pin change (the before/after record of `r10-engine-pins/README.md`).

## Method

1. **Reproduce locally.** gitleaks v8.30.0 (the gate's version; release
   tarball checked against the release's `checksums.txt`), this line's
   `.gitleaks.toml` and `.gitleaksignore`, `--redact`, over
   `2f01acc5..c3e24c2a`. Result: exactly the same six fingerprints.
2. **Inspect each line in its exact commit.**

## Findings

Each matched line is a `dep` row of Go build information:
`dep <module path> <version> h1:<checksum>`. The `h1:` value is the Go module
checksum: a base64 SHA-256 over the module's files, published for every
public module version by the Go checksum database (sum.golang.org) and
recorded in every `go.sum` that requires that module. It is not secret and
grants nothing. The rule matched the high-entropy checksum after a module path
containing the word `api` or `credential`.

| Fingerprint (commit `c3e24c2ab488f90ce7b143c36f1867db2a6b9969`, rule `generic-api-key`) | Binary (package) | Module | Class |
|---|---|---|---|
| `…/raw/go-version-m.txt:656` | `docker-compose` (docker-compose-plugin 5.6.1) | `github.com/containerd/containerd/api` v1.12.0 | public Go module checksum |
| `…/raw/go-version-m.txt:669` | `docker-compose` (5.6.1) | `github.com/docker/docker-credential-helpers` v0.9.9 | public Go module checksum |
| `…/raw/go-version-m.txt:695` | `docker-compose` (5.6.1) | `github.com/moby/moby/api` v1.56.1 | public Go module checksum |
| `…/raw/go-version-m.txt:1435` | `docker-compose` (docker-compose-plugin 5.7.1) | `github.com/containerd/containerd/api` v1.12.0 | public Go module checksum |
| `…/raw/go-version-m.txt:1448` | `docker-compose` (5.7.1) | `github.com/docker/docker-credential-helpers` v0.9.9 | public Go module checksum |
| `…/raw/go-version-m.txt:1476` | `docker-compose` (5.7.1) | `github.com/moby/moby/api` v1.56.1 | public Go module checksum |

(`…` = `docs/appliance/evidence/combined/r10-engine-pins`.) Lines 656/1435,
669/1448 and 695/1476 are the same three modules in the old and the new
Compose binary.

**Effect.** The six suppressions name exact lines of one commit; none covers
any future finding in that file. The file is evidence and stays as recorded.
