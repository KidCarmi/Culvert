# Receipt notes — b9105086 (tree b6b80fc5): main cutoff a27cffb2 (owner Option B)

- **All 10 commands exit 0** on `b9105086`, Go `go1.27.3`.
- Command 1 records the parents (`846d606a`, `a27cffb2`) and that every previously reviewed commit is an ancestor. It also lists the three conflict-resolved files.
- Command 3 runs the targeted regressions at `-race -count=2 -shuffle=on`:
  - C2 wildcard RBAC/audit, C1/D0/C4/role metadata;
  - OIDC transport boundary;
  - cluster token revoke audit;
  - support durability;
  - installer/compose secret handling (blank, quoted, CRLF, inline comment, multiline, an already-set value);
  - DP backoff, workflow SHA pins, static artifact evidence;
  - F-B1/F-B2, restore/recover, ClamAV/AV-unavailable, appliance, boot, backup.
- Command 4: `internal/catgroup` and `internal/admission` at race ×2 shuffle. Command 5: benchgate.
- Command 6: Trivy exception validator (0 active), security evidence tests 12/12, candidate promotion cases 59/59.
- Command 7: full `go test ./...`. Command 8: lint `--new-from-rev a27cffb2`, 0 issues. Command 9: `make api-verify`. Command 10: gitleaks, no leaks.
- **`clean_before`/`clean_after` are false** because of ONE untracked directory, `.github/scripts/__pycache__/`. My pre-commit run of `security-evidence-test.py` created it as Python bytecode; it is not part of the git tree and is unread by the Go commands. `../b9105086-py-clean/` is a supplementary run: the cache removed, `PYTHONDONTWRITEBYTECODE=1`, the Python command repeated on the same commit, **clean before and after, exit 0**.
- Three Docker-dependent installer tests skip in this sandbox (no daemon). CI covers them: Install Lifecycle E2E and the Deep appliance lifecycle.
