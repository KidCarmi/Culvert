# SAML integration follow-up — cd8 superseded

The retained cd8 candidate has a confirmed SAML callback failure: a genuine signed fixture response with an IdP Origin receives **403 and no portal cookie**. The same fixture on `2a82320c746a6d146df19a6f5af9676d76b72286` receives **302 and a portal cookie**, rejects reuse of the response with **401**, and passes all eight cookie-purpose controls. This is source integration evidence; replacement appliance qualification remains **BLOCKED**.

[Opus coordination comment](https://github.com/KidCarmi/Culvert/pull/1528#issuecomment-6049116654) and [run 37703421967](https://github.com/KidCarmi/Culvert/actions/runs/37703421967) bind the follow-up. The run's lab head is `a982a9ccbe0d5a8733e8a88543bf15370875e684`. Its successful pre-fix job intentionally requires the cd8 test to fail with the callback 403. A green workflow therefore does not mean cd8 SAML works.

| Evidence | Artifact | ZIP SHA-256 | Test |
|---|---:|---|---|
| cd8 pre-fix | 11518796591 (2,282 bytes) | `a7f4db8c428aa4d1fd36ddbb7e22a6d77e5f2c28209bb36ab0e97dfe6f6763ad` | Expected FAIL, exit 1 |
| 2a fixed | 11518098791 (2,765 bytes) | `85b4ce6fb4cd7165d649553363130ca559f30a92906c262d5c6cae6f40af6d67` | PASS, exit 0 |

Both archives and their bindings were independently verified. The fixture's raw git-object SHA-256 is `908264ffc1533d68f09bf9ef26d80e975b0d0b2fcf0b7093ef6a3a9cdc64db97`, matching both reports. The workflow verifies each candidate HEAD and runs `go test -count=1 -run '^TestLabSAMLCookiePurposeReplay$' -v .` with Go 1.26.8 on Linux/amd64. No local test rerun was performed in this audit.

The eight retained controls establish proxy denial without a cookie; successful proxy use of the SAML portal cookie; admin API denial without a cookie; successful admin use of its UI cookie; denial of portal-to-UI cookie substitution under both names; and denial of UI-to-proxy substitution under both names. Only the legitimate proxy control reaches the counting upstream. Exact statuses, member hashes and job IDs are in `integration-followup.json`.

The source fix exempts only **POST `/auth/saml/callback`** from the generic Origin guard. The fixture uses production handlers and cookie issuers but an ephemeral synthetic SAML signer, direct in-memory provider registration, an HTTP test server and distinct portal/admin names. It does not qualify browser cookie delivery, a real vendor IdP, OIDC interoperability, same-name identities, viewer-specific cases or an OVA.

**Login-CSRF remains open.** The coordination comment identifies absent browser binding for SAML RelayState and OIDC state. Callback source is consistent with that finding; this audit did not independently reproduce the browser attack. Same-response replay denial is a separate property and does not close login-CSRF. Both protocols need a browser-bound initiation proof and positive/negative browser-flow tests.

This run has exactly two artifacts. The OVA, baked-sidecar scan, console and F-DISK jobs are skipped. No replacement OVA, candidate image or exact adopted-sidecar scan is supplied here. The adopted-image scan and historical encrypted-log export/restore plus rotation-key custody remain unresolved; no risk acceptance is inferred.

The published cd8 ESXi observations remain unchanged historical evidence. They cannot qualify the new source or a future replacement OVA. This additive follow-up changes no existing report, checksum or VM state and publishes no raw logs, credentials, cookie values or signing material.
