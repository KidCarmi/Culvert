# Culvert Edge-Case Lab — Product-Bug Candidates

Every apparent divergence is triaged conservatively. A PRODUCT_BUG is asserted only when the scenario is valid, the config was accepted, the expectation is deterministic, the enforcement differs, and it **reproduces in a clean environment**.

## Result: no confirmed product bugs

No divergence survived as a PRODUCT_BUG after triage. Two divergences observed during the campaign were traced to **Oracle modeling gaps** (corrected), not Culvert defects, and are recorded here for transparency:

1. **`.exe` download under inspection** — Culvert correctly blocked the executable via its global file-extension blocklist (`FILE_BLOCKED ... ext=".exe"` in the decision trace). The Oracle initially failed to model Culvert's documented global executable blocklist and mispredicted *allow*. Oracle corrected; scenario now PASS.
2. **`certVerification=skip` decryption profile** — Culvert correctly honored the profile and completed inspection (`SSL_INNER` + HTTP 200 through the MITM leaf). The Oracle initially read the wrong profile key and mispredicted *conn_fail*. Oracle corrected; scenario now PASS.

The most security-relevant *divergence from enterprise expectation* is the SOCKS5 policy bypass, but because it is a **documented architectural choice** in the code (the SOCKS5 handler intentionally does not call `policyStore.Evaluate`), it is classified **MISSING_CAPABILITY** rather than PRODUCT_BUG. See `EDGE-CASE-MISSING-CAPABILITIES.md`.

