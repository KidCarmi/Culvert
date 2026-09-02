// Final-qualification regression (2E-C): a browser-driven admin ceremony is
// ISOLATED from the suite-shared loopback mutation budget.
//
// Root cause it pins. The admin plane refuses more than lockout.Burst (60)
// mutating API requests per lockout.RateWindow (one minute, fixed window)
// from one real client IP — a deliberate, hard-coded security posture. The
// harness trusts loopback as a reverse proxy (RISK-019), so an API client
// can present its own X-Forwarded-For identity — but every BROWSER context
// the suite opened presented the bare loopback peer, so that one budget was
// a SUITE-LENGTH shared resource across every page-driven spec. Whether the
// window was spent by the time the policy-learning journey ran depended on
// how fast the preceding browser-driven specs (policy-2b, policy-2c) had
// executed: the traced full run peaked at 54 loopback mutations inside one
// server window, the faster untraced runs crossed 60, and the journey's
// first page-driven mutation — the enable PUT or the session-start POST,
// exactly the two assertion sites observed — drew a 429 that the page
// rendered truthfully as a refused ceremony while the 5 s assertion waited
// for the success text.
//
// This test manufactures that state deterministically instead of depending
// on suite timing: it spends the loopback budget through the supported login
// endpoint until the appliance refuses (proving the posture is armed), then
// requires a browser-driven ceremony to succeed anyway. A browser context
// must carry its own client identity, never the shared loopback one.
import { expect, request } from "@playwright/test";
import { test } from "./test";
import { AUTH_URL, USERS } from "./fixtures";

const LEARNING_ROUTE = "/app/policies/learning";
const BURST = 60;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

test("a browser-driven admin ceremony succeeds after the loopback mutation budget is spent", async ({
  page,
}) => {
  // Premise, established BEFORE the budget is spent: learning disabled and
  // no inherited active session (SHARED /data — recorded harness debt).
  const st = await page.request.get("/api/policy-learning");
  expect(st.ok()).toBe(true);
  const v: unknown = await st.json();
  if (!isRecord(v)) throw new Error("bad learning status");
  if (isRecord(v["active_session"])) {
    const cancel = await page.request.post("/api/policy-learning/session", {
      data: { action: "cancel" },
    });
    expect(cancel.ok()).toBe(true);
  }
  if (v["enabled"] === true) {
    const off = await page.request.put("/api/policy-learning/config", {
      data: { enabled: false },
    });
    expect(off.ok()).toBe(true);
  }

  // Spend the LOOPBACK budget: a plain API client with no forwarded identity
  // is the loopback peer. Successful logins are ordinary mutations that
  // neither lock the account nor change appliance state. The budget may
  // already be partly spent by the harness seed and the auth-setup login,
  // so spend until refused rather than asserting a fixed count.
  // Playwright applies the test's context options (including the per-test
  // identity header from ./test) to request.newContext() for every option
  // key the call does not name, so the flood client names an EMPTY header
  // set: it must be the bare loopback peer, never this test's identity.
  const loopback = await request.newContext({
    baseURL: AUTH_URL,
    extraHTTPHeaders: {},
  });
  let refused = false;
  for (let i = 0; i <= BURST; i++) {
    const r = await loopback.post("/api/auth/login", {
      data: { user: USERS.admin.user, pass: USERS.admin.pass },
    });
    if (r.status() === 429) {
      refused = true;
      break;
    }
    expect(r.status(), `loopback login ${String(i + 1)}`).toBe(200);
  }
  expect(
    refused,
    "the appliance refuses the loopback client past its budget",
  ).toBe(true);
  // Still exhausted: the posture is a fixed window, not a leaky bucket.
  const again = await loopback.post("/api/auth/login", {
    data: { user: USERS.admin.user, pass: USERS.admin.pass },
  });
  expect(again.status()).toBe(429);
  await loopback.dispose();

  // The browser-driven ceremony — the exact steps of the learning journey —
  // must succeed: the page is a distinct client with its own budget.
  await page.goto(LEARNING_ROUTE);
  await expect(page.getByText("Node-local and advisory")).toBeVisible();
  await page.getByRole("button", { name: "Enable learning…" }).click();
  await expect(page.getByText("Enable Policy Learning")).toBeVisible();
  await page
    .getByRole("button", { name: "Enable learning", exact: true })
    .click();
  await expect(page.getByText("Learning is enabled.")).toBeVisible();
  await expect(page.getByText("Too Many Requests")).toHaveCount(0);

  // Restore the shared premise through the page's own client.
  const off = await page.request.put("/api/policy-learning/config", {
    data: { enabled: false },
  });
  expect(off.ok()).toBe(true);
});
