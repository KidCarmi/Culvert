# Receipt notes — 52463785 (tree db36a9a8)

- 26 of 27 commands exit 0; the tree was clean before and after.
- **Command 12 exited 1 because of how the command was written, not because of the code.** `python3 -I` drops the script's own directory from `sys.path`, so `verify_saml_patch.py` could not import its sibling module `raw_keys.py`. CI runs it without `-I` (`pr-fast-gate.yml`, `appliance-console.yml`). The failed log (`12.log`) is kept as recorded.
- The corrected command (without `-I`), plus the verifier's own unit tests, ran on the same commit and tree in `../52463785-saml-supplement/`. Both exit 0, and the tree was clean before and after: 235 upstream files verified, 8 test-data files, functional delta limited to the gofuzz build constraint.
- Toolchain: every Go command ran under `GOTOOLCHAIN=go1.27.3`, including the sub-modules (cmd/culvert-maint, pkg/releaseproof, third_party/crewjam-saml), which carry no toolchain line of their own.
- The agent lint (command 16) is whole-module, not diff-scoped, matching the CI maint-agent gate.
- Not covered here: Docker image builds. That means the ClamAV sidecar `culvert.3` (brotli-libs 1.2.1-r0) is proven only by CI's Deep gate. F-P2 has not been run on `culvert.3` bytes.
