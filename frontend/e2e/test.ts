// Suite-wide test base: every browser context carries a PER-TEST client
// identity (final-qualification correction, 2E-C).
//
// Why. The admin plane refuses more than lockout.Burst (60) mutating API
// requests per lockout.RateWindow (one minute, fixed window) from one real
// client IP — a deliberate, hard-coded security posture that stays fully
// armed here. realClientIP honours X-Forwarded-For only from a trusted
// proxy, and the harness establishes loopback as one (the RISK-019
// deployment shape) through the supported network-settings API. API clients
// in the multi-client specs already present their own identities; every
// BROWSER context, however, presented the bare loopback peer, so that one
// budget was a SUITE-LENGTH shared resource across all page-driven specs.
// Whether it was spent when the policy-learning journey ran depended on how
// fast the preceding specs executed — the order/timing sensitivity the
// full-suite runs exhibited, pinned by admin-budget-isolation.spec.ts.
//
// The identity is DETERMINISTIC per test (derived from Playwright's stable
// testId, so a rerun of one test maps to the same address), private-range,
// and never loopback. It changes nothing on the appliances that do not
// trust a proxy (FRESH, SETUPFAIL ignore the header by construction).
// Sessions are signed cookies, not IP-bound, so the shared storageState
// still authenticates. Playwright applies the same option to every
// browser.newContext() / request.newContext() call in the test that does
// not name extraHTTPHeaders itself; specs that open additional contexts
// still pass the identity explicitly through `identityHeaders(...)` so the
// attribution is visible at the call site, and a client that must be the
// bare loopback peer names `extraHTTPHeaders: {}` (see
// admin-budget-isolation.spec.ts).
import { test as base } from "@playwright/test";
import { createHash } from "node:crypto";

export { expect, request } from "@playwright/test";

export interface IdentityFixtures {
  /** This test's client IP identity as the appliance will attribute it. */
  clientIdentity: string;
}

/** Deterministic private-range identity: 10.a.b.c with c in 1..254. */
export function identityFor(testId: string): string {
  const h = createHash("sha256").update(testId).digest();
  const a = h[0] ?? 0;
  const b = h[1] ?? 0;
  const c = ((h[2] ?? 0) % 254) + 1;
  return `10.${String(a)}.${String(b)}.${String(c)}`;
}

export function identityHeaders(identity: string): Record<string, string> {
  return { "X-Forwarded-For": identity };
}

export const test = base.extend<IdentityFixtures>({
  // eslint-disable-next-line no-empty-pattern -- Playwright fixture signature: no fixture dependencies, testInfo only
  clientIdentity: async ({}, use, testInfo) => {
    await use(identityFor(testInfo.testId));
  },
  // Override the built-in option so the default `context` (and therefore
  // `page` and `page.request`) presents the identity on every request.
  extraHTTPHeaders: async ({ extraHTTPHeaders, clientIdentity }, use) => {
    await use({
      ...(extraHTTPHeaders ?? {}),
      ...identityHeaders(clientIdentity),
    });
  },
});
