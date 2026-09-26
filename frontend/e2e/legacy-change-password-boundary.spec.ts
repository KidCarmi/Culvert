// FE-6AR merge-12 correction (record 6ARR-C12b) — the LEGACY console's
// self-service password change RESPONSE BOUNDARY, driven in a real browser on
// the real AUTH appliance as a NON-ADMIN user, with the wire between the
// appliance and the browser rewritten the way an intermediary can rewrite it.
//
// The review found two defects on fd6aae81 and this file is their RED proof:
//
//   (1) A non-2xx does not prove non-commit. The dialog turned EVERY non-2xx
//       into a refusal ("Nothing was changed") and kept the typed secrets in
//       the open dialog. A gateway that replaces a successful appliance answer
//       with a 502/504 AFTER the password committed therefore made the console
//       report non-commit for a change that DID land (rows B1–B4). A refusal
//       is proven ONLY by the endpoint's contracted status + JSON media type +
//       bounded code + required facts; everything else is UNPROVEN — the
//       dialog closes, the secrets are dropped, neither success nor non-commit
//       is claimed, nothing is retried or re-fenced, and no server text is
//       rendered (row B5).
//   (2) Success must reject contradictory facts. The proof accepted `ok`,
//       `selfAffected` and a later generation while ignoring `persisted`,
//       `sessionsRevoked` and `revision` (rows B6–B7).
//
// Controls (rows C1–C2 here; the happy path, the genuine 409 stale refusal,
// the 401 session-loss teardown and the no-authority path stay in
// legacy-change-password.spec.ts): a GENUINE contracted refusal is still
// rendered as one with nothing written and exactly one request.
//
// Wire rewrites use page.route: `route.fetch()` lets the REAL request reach
// the appliance (so a rewritten answer sits on top of a real commit), while
// `route.fulfill()` without a fetch keeps the appliance untouched (so the
// browser's verdict can be checked against an account that did NOT change).
import type { APIRequestContext, Page, Route } from "@playwright/test";
import { expect, request, test } from "./test";
import { AUTH_URL, EMPTY_STATE, USERS } from "./fixtures";

test.use({ storageState: EMPTY_STATE });
// Deliberately NOT serial: every row starts from the same known password
// (reset through the fenced admin roster API in beforeEach), so a RED row
// never hides the verdict of the rows after it and the harness's single
// worker runs them in file order.

const CP_USER = "cp-e2e-boundary";
const PASS_A = "B0undaryPass!a";
const PASS_B = "B0undaryPass!b";
const LEGACY_XFF = "10.71.0.9";
const SERVER_TEXT_MARKER = "SERVER_TEXT_MARKER_7f3a";

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

async function newAdminClient(): Promise<APIRequestContext> {
  const ctx = await request.newContext({
    baseURL: AUTH_URL,
    extraHTTPHeaders: { "X-Forwarded-For": LEGACY_XFF },
  });
  const login = await ctx.post("/api/auth/login", {
    data: { user: USERS.admin.user, pass: USERS.admin.pass },
  });
  expect(login.ok(), await login.text()).toBe(true);
  return ctx;
}

async function rosterRevision(api: APIRequestContext): Promise<number> {
  const r = await api.get("/api/auth/users");
  expect(r.ok(), await r.text()).toBe(true);
  const v: unknown = await r.json();
  if (!isRecord(v) || typeof v["revision"] !== "number")
    throw new Error("roster revision missing");
  return v["revision"];
}

// Each probe presents its OWN client identity: a wrong-password probe is a
// recorded login failure, and lockout's tier-1 pair lock trips after five
// failures from one address against one account — a shared address would
// lock this file's later probes out of a password that IS in effect.
let probeSeq = 0;
async function passwordWorks(user: string, pass: string): Promise<boolean> {
  probeSeq++;
  const ctx = await request.newContext({
    baseURL: AUTH_URL,
    extraHTTPHeaders: { "X-Forwarded-For": `10.71.1.${String(probeSeq)}` },
  });
  try {
    const r = await ctx.post("/api/auth/login", { data: { user, pass } });
    return r.ok();
  } finally {
    await ctx.dispose();
  }
}

async function legacyLogin(
  page: Page,
  user: string,
  pass: string,
): Promise<void> {
  await page.goto(`${AUTH_URL}/`);
  await expect(page.locator("#login-overlay")).toBeVisible();
  await page.locator("#li-user").fill(user);
  await page.locator("#li-pass").fill(pass);
  const loginP = page.waitForResponse(
    (r) =>
      r.url().endsWith("/api/auth/login") && r.request().method() === "POST",
  );
  await page.locator("#li-btn").click();
  const login = await loginP;
  expect(login.status(), await login.text()).toBe(200);
  // Same reload as legacy-change-password.spec.ts: the console's boot fetches
  // predate the session and a late 401 re-shows the overlay (pre-existing).
  const statusP = page.waitForResponse(
    (r) =>
      r.url().endsWith("/api/auth/status") && r.request().method() === "GET",
  );
  await page.reload();
  // The console's own verdict on the fresh session, stated in the failure
  // message so a refused session is diagnosable from the report alone.
  const st = await statusP;
  const stBody = await st.text();
  expect(st.status(), stBody).toBe(200);
  expect(stBody, stBody).toContain('"loggedIn":true');
  await expect(page.locator("#login-overlay")).toBeHidden();
  await expect(page.locator("#topbar-username")).toHaveText(user);
  await expect(page.locator("#change-pw-btn")).toBeVisible();
}

/** Opens the dialog and waits for the authority to be BOUND (Save enabled). */
async function openBoundDialog(page: Page): Promise<number> {
  const statusP = page.waitForResponse(
    (r) =>
      r.url().endsWith("/api/auth/status") && r.request().method() === "GET",
  );
  await page.locator("#change-pw-btn").click();
  const status: unknown = await (await statusP).json();
  await expect(page.locator("#change-password-modal")).toBeVisible();
  await expect(page.locator("#cp-save-btn")).toBeEnabled();
  await expect(page.locator("#cp-save-btn")).toHaveText("Save");
  if (!isRecord(status) || typeof status["securityGeneration"] !== "number")
    throw new Error("auth status carried no securityGeneration");
  return status["securityGeneration"];
}

async function fillDialog(
  page: Page,
  current: string,
  next: string,
): Promise<void> {
  await page.locator("#cp-current").fill(current);
  await page.locator("#cp-new").fill(next);
  await page.locator("#cp-confirm").fill(next);
}

async function expectDialogFieldsEmpty(page: Page): Promise<void> {
  for (const id of ["#cp-current", "#cp-new", "#cp-confirm"]) {
    await expect(page.locator(id)).toHaveValue("");
  }
}

/** Counts change-password POSTs and answers each with `answer`. */
function interceptChangePassword(
  page: Page,
  answer: (route: Route) => Promise<void>,
): { posts: number } {
  const counter = { posts: 0 };
  void page.route("**/api/auth/change-password", async (route) => {
    counter.posts++;
    await answer(route);
  });
  return counter;
}

async function submitAndWait(page: Page): Promise<void> {
  const respP = page.waitForResponse((r) =>
    r.url().endsWith("/api/auth/change-password"),
  );
  await page.locator("#cp-save-btn").click();
  await respP;
}

/**
 * The UNPROVEN posture: the dialog is closed (its secrets dropped with it),
 * the console says the outcome could not be confirmed, and it claims neither
 * a change nor a non-change.
 */
async function expectUnproven(page: Page, counter: { posts: number }) {
  const toast = page.locator("#toasts .toast");
  await expect(toast).toHaveCount(1);
  const text = (await toast.textContent()) ?? "";
  expect(text).toContain("could not be confirmed");
  expect(text).not.toContain("Nothing was changed");
  expect(text).not.toContain("Password changed");
  await expect(page.locator("#change-password-modal")).toBeHidden();
  await expectDialogFieldsEmpty(page);
  // Give a would-be retry every chance to fire, then assert it did not.
  await page.waitForTimeout(500);
  expect(counter.posts).toBe(1);
}

/** A proven REFUSAL: the dialog stays open and states nothing was changed. */
async function expectRefusal(page: Page, counter: { posts: number }) {
  await expect(page.locator("#cp-err")).toBeVisible();
  await expect(page.locator("#cp-err")).toContainText("Nothing was changed");
  await expect(page.locator("#change-password-modal")).toBeVisible();
  await expect(page.locator("#cp-save-btn")).toBeEnabled();
  await expect(page.locator("#toasts .toast")).toHaveCount(0);
  await page.waitForTimeout(500);
  expect(counter.posts).toBe(1);
}

test.beforeAll(async () => {
  // The account is CREATED here and NEVER deleted inside this file. Deleting
  // it would be the natural "idempotent" reset — and it is exactly wrong on
  // this appliance: DELETE /api/auth/users calls RevokeUser, which refuses
  // EVERY session for that username for a full session TTL, re-created
  // account included (the AU-19 residual: user-level revocation is keyed by
  // name, not by record). Playwright recycles its worker after a failed test
  // and re-runs beforeAll, so a delete+create here turned every login after
  // the first RED row into `loggedIn:false` and hid the rows' own verdicts
  // (record 6ARR-C12b). An existing account is therefore RESET, not replaced.
  const api = await newAdminClient();
  try {
    const list = await api.get("/api/auth/users");
    const v: unknown = await list.json();
    const exists =
      isRecord(v) &&
      Array.isArray(v["users"]) &&
      v["users"].some((x) => isRecord(x) && x["username"] === CP_USER);
    const rev = await rosterRevision(api);
    const r = exists
      ? await api.put(`/api/auth/users?revision=${String(rev)}`, {
          data: { username: CP_USER, password: PASS_A, role: "viewer" },
        })
      : await api.post(`/api/auth/users?revision=${String(rev)}`, {
          data: { username: CP_USER, password: PASS_A, role: "viewer" },
        });
    expect(r.ok(), await r.text()).toBe(true);
  } finally {
    await api.dispose();
  }
});

/** Every row starts from PASS_A: an admin resets the viewer's password. */
async function resetViewerPassword(): Promise<void> {
  const api = await newAdminClient();
  try {
    const rev = await rosterRevision(api);
    const r = await api.put(`/api/auth/users?revision=${String(rev)}`, {
      data: { username: CP_USER, password: PASS_A },
    });
    expect(r.ok(), await r.text()).toBe(true);
  } finally {
    await api.dispose();
  }
}

test.beforeEach(async () => {
  await resetViewerPassword();
});

test("B1 — the password commits and an intermediary answers a non-JSON 502: UNPROVEN, secrets dropped, one POST, the NEW password is in effect", async ({
  page,
}) => {
  await legacyLogin(page, CP_USER, PASS_A);
  await openBoundDialog(page);
  let upstreamStatus = 0;
  const counter = interceptChangePassword(page, async (route) => {
    const real = await route.fetch(); // the appliance commits
    upstreamStatus = real.status();
    await route.fulfill({
      status: 502,
      contentType: "text/html",
      body: "<html><body><h1>502 Bad Gateway</h1></body></html>",
    });
  });
  await fillDialog(page, PASS_A, PASS_B);
  await submitAndWait(page);
  expect(upstreamStatus).toBe(200);
  await expectUnproven(page, counter);
  expect(await passwordWorks(CP_USER, PASS_B)).toBe(true);
  expect(await passwordWorks(CP_USER, PASS_A)).toBe(false);
});

test("B2 — a 409 whose body is malformed JSON cannot claim non-commit: UNPROVEN", async ({
  page,
}) => {
  await legacyLogin(page, CP_USER, PASS_A);
  await openBoundDialog(page);
  const counter = interceptChangePassword(page, (route) =>
    route.fulfill({
      status: 409,
      contentType: "application/json",
      body: '{"code": "stale", "current": {"generation": ',
    }),
  );
  await fillDialog(page, PASS_A, PASS_B);
  await submitAndWait(page);
  await expectUnproven(page, counter);
  // Nothing was forwarded, so the appliance still holds PASS_A.
  expect(await passwordWorks(CP_USER, PASS_A)).toBe(true);
  expect(await passwordWorks(CP_USER, PASS_B)).toBe(false);
});

test("B3 — a contracted status with an UNKNOWN refusal code cannot claim non-commit: UNPROVEN", async ({
  page,
}) => {
  await legacyLogin(page, CP_USER, PASS_A);
  await openBoundDialog(page);
  const counter = interceptChangePassword(page, (route) =>
    route.fulfill({
      status: 409,
      contentType: "application/json",
      body: JSON.stringify({ error: "conflict", code: "unenrolled_code" }),
    }),
  );
  await fillDialog(page, PASS_A, PASS_B);
  await submitAndWait(page);
  await expectUnproven(page, counter);
  expect(await passwordWorks(CP_USER, PASS_A)).toBe(true);
});

test("B4 — a status/code MISMATCH (428 carrying `stale`, 409 carrying `precondition_required`) cannot claim non-commit: UNPROVEN, twice", async ({
  page,
}) => {
  await legacyLogin(page, CP_USER, PASS_A);
  await openBoundDialog(page);
  const first = interceptChangePassword(page, (route) =>
    route.fulfill({
      status: 428,
      contentType: "application/json",
      body: JSON.stringify({
        error: "x",
        code: "stale",
        current: { generation: 1 },
      }),
    }),
  );
  await fillDialog(page, PASS_A, PASS_B);
  await submitAndWait(page);
  await expectUnproven(page, first);
  await page.unroute("**/api/auth/change-password");
  // Let the first toast expire so the second verdict is read on its own.
  await expect(page.locator("#toasts .toast")).toHaveCount(0, {
    timeout: 6000,
  });

  await openBoundDialog(page);
  const second = interceptChangePassword(page, (route) =>
    route.fulfill({
      status: 409,
      contentType: "application/json",
      body: JSON.stringify({
        error: "x",
        code: "precondition_required",
        current: { generation: 1 },
      }),
    }),
  );
  await fillDialog(page, PASS_A, PASS_B);
  await submitAndWait(page);
  await expectUnproven(page, second);
  expect(await passwordWorks(CP_USER, PASS_A)).toBe(true);
});

test("B5 — a contracted refusal never renders the server's text; a 400 `invalid_input` is a bounded refusal", async ({
  page,
}) => {
  await legacyLogin(page, CP_USER, PASS_A);
  await openBoundDialog(page);
  const counter = interceptChangePassword(page, (route) =>
    route.fulfill({
      status: 400,
      contentType: "application/json",
      body: JSON.stringify({
        error: `${SERVER_TEXT_MARKER} <b>injected</b>`,
        code: "invalid_input",
      }),
    }),
  );
  await fillDialog(page, PASS_A, PASS_B);
  await submitAndWait(page);
  await expectRefusal(page, counter);
  await expect(page.locator("#cp-err")).not.toContainText(SERVER_TEXT_MARKER);
  await expect(page.locator("#cp-err")).not.toContainText("injected");
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Cancel" })
    .click();
  await expect(page.locator("#change-password-modal")).toBeHidden();
  await expectDialogFieldsEmpty(page);
  expect(await passwordWorks(CP_USER, PASS_A)).toBe(true);
});

test("B6 — the password commits but the visible 2xx says `persisted:false`: UNPROVEN, never success, the NEW password is in effect", async ({
  page,
}) => {
  await legacyLogin(page, CP_USER, PASS_A);
  await openBoundDialog(page);
  const counter = interceptChangePassword(page, async (route) => {
    const real = await route.fetch(); // the appliance commits
    const j: unknown = await real.json();
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(isRecord(j) ? { ...j, persisted: false } : j),
    });
  });
  await fillDialog(page, PASS_A, PASS_B);
  await submitAndWait(page);
  await expectUnproven(page, counter);
  expect(await passwordWorks(CP_USER, PASS_B)).toBe(true);
  expect(await passwordWorks(CP_USER, PASS_A)).toBe(false);
});

test("B7 — an otherwise success-shaped 2xx with `sessionsRevoked:false`, or with no `revision`, cannot claim success: UNPROVEN, twice", async ({
  page,
}) => {
  await legacyLogin(page, CP_USER, PASS_A);
  const bound = await openBoundDialog(page);
  const first = interceptChangePassword(page, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        ok: true,
        revision: 7,
        persisted: true,
        sessionsRevoked: false,
        selfAffected: true,
        securityGeneration: bound + 1,
      }),
    }),
  );
  await fillDialog(page, PASS_A, PASS_B);
  await submitAndWait(page);
  await expectUnproven(page, first);
  await page.unroute("**/api/auth/change-password");
  await expect(page.locator("#toasts .toast")).toHaveCount(0, {
    timeout: 6000,
  });

  const bound2 = await openBoundDialog(page);
  const second = interceptChangePassword(page, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        ok: true,
        persisted: true,
        sessionsRevoked: true,
        selfAffected: true,
        securityGeneration: bound2 + 1,
      }),
    }),
  );
  await fillDialog(page, PASS_A, PASS_B);
  await submitAndWait(page);
  await expectUnproven(page, second);
  // Nothing was forwarded in either cycle: PASS_A still authenticates.
  expect(await passwordWorks(CP_USER, PASS_A)).toBe(true);
  expect(await passwordWorks(CP_USER, PASS_B)).toBe(false);
});

test("C1 — CONTROL: a GENUINE 428 from the appliance (generation stripped on the wire) is a proven refusal with nothing written and one POST", async ({
  page,
}) => {
  await legacyLogin(page, CP_USER, PASS_A);
  await openBoundDialog(page);
  let status = 0;
  const counter = interceptChangePassword(page, async (route) => {
    const body: unknown = route.request().postDataJSON();
    if (!isRecord(body)) return route.continue();
    const real = await route.fetch({
      postData: JSON.stringify({ ...body, generation: 0 }),
    });
    status = real.status();
    await route.fulfill({ response: real });
  });
  await fillDialog(page, PASS_A, PASS_B);
  await submitAndWait(page);
  expect(status).toBe(428);
  await expectRefusal(page, counter);
  await expect(page.locator("#cp-err")).toContainText(
    "did not receive the account state",
  );
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Cancel" })
    .click();
  await expectDialogFieldsEmpty(page);
  expect(await passwordWorks(CP_USER, PASS_A)).toBe(true);
  expect(await passwordWorks(CP_USER, PASS_B)).toBe(false);
});

test("C2 — CONTROL: a GENUINE 403 `invalid_credentials` (wrong current password) is a proven refusal that names the cause and writes nothing", async ({
  page,
}) => {
  await legacyLogin(page, CP_USER, PASS_A);
  await openBoundDialog(page);
  let status = 0;
  const counter = interceptChangePassword(page, async (route) => {
    const real = await route.fetch();
    status = real.status();
    await route.fulfill({ response: real });
  });
  await fillDialog(page, "Wr0ngCurrent!x", PASS_B);
  await submitAndWait(page);
  expect(status).toBe(403);
  await expect(page.locator("#cp-err")).toBeVisible();
  await expect(page.locator("#cp-err")).toContainText(
    "Current password is incorrect",
  );
  await expect(page.locator("#change-password-modal")).toBeVisible();
  await expect(page.locator("#toasts .toast")).toHaveCount(0);
  await page.waitForTimeout(500);
  expect(counter.posts).toBe(1);
  expect(await passwordWorks(CP_USER, PASS_A)).toBe(true);
  expect(await passwordWorks(CP_USER, PASS_B)).toBe(false);
});
