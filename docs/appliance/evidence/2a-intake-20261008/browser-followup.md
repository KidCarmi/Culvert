# Browser follow-up: SSO identity transport remains blocked

The fixed artifact in [run 37704245895](https://github.com/KidCarmi/Culvert/actions/runs/37704245895) contains a **real Chromium cookie-scope observation**, not an end-to-end Culvert/IdP browser test. Chromium stores the portal-shaped cookie and sends it to `ui.test`, but sends it on **none** of the two ordinary HTTP `dest.test` requests or the `CONNECT dest.test:443` request.

This adds a source-backed **P1 functional blocker for browser SSO proxy traffic** beyond the Origin defect and open login-CSRF finding. At product `2a82320c746a6d146df19a6f5af9676d76b72286`, `session.go:147` sets a host-only UI-origin cookie, while `proxy.go:355` obtains SSO identity from the destination request's Cookie header. Without that cookie or a separate credential, traffic follows no-credential handling. A portal login therefore cannot by itself authenticate ordinary other-origin browser proxy traffic. Policy may challenge, redirect or classify it as unauthenticated; this evidence does not demonstrate an authorization bypass or cookie leak.

Alternate-path inspection found that both successful callbacks (`ui_auth.go:974`, `ui_auth.go:1007`) issue the cookie and redirect without registering an IP/session principal. The complete `resolveRequestAuth` path reads that cookie, then separately supplied Proxy-Authorization Basic credentials, then no-credential handling; it contains no post-login IP-to-principal fallback. Named binding/cache searches found no alternative in the exact production source. This supports the browser-cookie-only limitation as a source inference; it is not a live Culvert browser reproduction. Independently configured proxy credentials are outside this trigger.

The successful earlier Go fixture manually attached a genuine signed session cookie to a proxy request. Its 200 response verifies server-side cookie validation, **not browser delivery of that identity**. The Chromium script uses a synthetic fixed-value cookie and a Node recording proxy, not Culvert or a SAML provider. Its positive UI control and destination observations are useful for this narrow browser behavior. CONNECT intentionally returns 502, so there is no successful HTTPS tunnel/content test. No actual cookie value is reproduced here.

| Artifact | Bytes | ZIP SHA-256 |
|---|---:|---|
| Pre-fix 11519275271 | 2,297 | `8480b3b18e2b69f33cfe14e491b17ea6078b78c0939f0a80200a144e21d43086` |
| Fixed 11518164020 | 3,031 | `177d9e47eaff699f66591a462438a2525247008e1b5544c7c6d3435116f9ac2f` |

Both archives and source bindings verify. Lab head is `fdae20b6924b261eba6f37d77c73ff1b0324dd03`; Playwright is pinned to 1.62.1, but exact Chromium version is not retained in these artifacts. The unchanged Go fixture hash matches both binding files. It again records expected cd8 callback403, fixed callback302, repeated assertion401 and eight cookie-purpose PASS rows. The browser job succeeds because it expects cookies to remain scoped to the UI origin; that success is **not** a successful SSO-to-proxy workflow. The pre-fix browser step is skipped.

Minimum closure requires a supported browser-to-proxy authentication transport, followed by actual browser login through Culvert and authenticated HTTP plus HTTPS/CONNECT traffic to distinct origins, with subject/groups and allow/deny policy checks. Manually injecting Cookie headers does not close this gap. Simply exposing portal cookies to destination origins is not a safe substitute. Browser-bound SAML/OIDC login state also remains unresolved.

No OVA or sidecar scan is produced by this run. A separately reported replacement OVA may be a diagnostic target; this evidence does not justify production readiness or transfer cd8 ESXi results to it. Archive/member hashes, precise source references, workflow jobs and scope limits are in `browser-followup.json`. No new tests or VM calls were made, and the existing report remains unchanged.
