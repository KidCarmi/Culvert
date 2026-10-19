# Secret scanner policy verification

The previous `.gitleaks.toml` defined an allowlist without extending the built-in
rules. A local Gitleaks 8.30.0 comparison reproduced the gap: the same vendored
module returned zero findings with that configuration and 42 with default rules.
`[extend] useDefault = true` now keeps the default detection rules enabled.

A read-only snapshot of 3,798 tracked and nonignored untracked files (about
68 MB) produced 74 indicators with the restored defaults. This snapshot excluded
ignored local tooling, private qualification material and Git history. It was a
working-tree scan, not an artifact scan or a historical-commit clearance.

The 42 SAML indicators comprise 13 public private-key fixtures, 15 signed/XML
fixture indicators and 14 hash-inventory matches. The complete upstream module
and hashes are documented in `third_party/crewjam-saml/CULVERT-PROVENANCE.json`.
Exceptions name exact files and the relevant detection rule only. CI must also
run `appliance/artifact-audit/verify_saml_patch.py`: any changed or additional
upstream fixture fails byte verification even if its existing filename has a
scanner exception. Runtime binaries have a separate known-key absence check.

The 32 remaining indicators were reviewed as public test canaries, documentation
placeholders and variable names, public build fingerprints/evidence hashes, or
literal source expressions (including a minified frontend local-variable
expression). Their exceptions require both the exact path and exact matched
value. The provenance exception accepts only the reviewed public hashes, not an
arbitrary hexadecimal value. No directory-wide vendor, frontend, test or
documentation exception was added. No unexplained operational credential was
identified in this bounded working-tree scan. Repeating the scan after these
exceptions returned zero remaining indicators.

Run the scanner regression with an installed Gitleaks executable:

```text
python appliance/artifact-audit/check_gitleaks_policy.py --gitleaks /absolute/path/to/gitleaks
```

Five synthetic checks require the known fixture to be accepted, a different value
in that same file to be detected, the known value in another file to be detected,
a public private-key fixture in a new vendor file to be detected, and an arbitrary
hexadecimal token in provenance to be detected. The command never reports canary
values or finding contents. These checks complement the upstream byte verifier;
they must not replace the actual repository or built-artifact scans.

## Historical findings exposed by restoring the defaults

The pinned Gitleaks action scans all fetched refs on `workflow_dispatch`, using
`git log --full-history --all`; PR events instead use the PR commit range. The
first manual run at `a1354270` scanned 5,705 commits and reported 24 additional
historical indicators. The policy canaries and upstream byte check both passed.
Each of these findings was inspected in its exact historical commit:

- One local ESXi evidence value is the public SSH host-key SHA-256 at
  `baseline.ssh_public_key_identity.public_host_key_sha256`. It is not a bootstrap
  password, password hash or retired lab credential.
- Six predecessor-upgrade evidence matches are public upstream-entry resource IDs
  in API route paths ending in `/credential`, not credential values.
- Four private-key-rule matches are fake PEM markers in unit-test source. The
  detector spans escaped strings and adjacent Go code; these are not parseable
  private keys.
- Twelve matches are synthetic authentication/redaction values in retired
  regression tests; one is a test identity reference in ownership documentation.

`.gitleaksignore` records only these 24 complete
`commit:path:rule:line` fingerprints. It suppresses neither whole historical
commits nor future findings in those files. The policy regression rejects
non-fingerprint entries. Additional historical findings remain subject to review;
this list does not claim that every other local or remote Git ref was audited.
