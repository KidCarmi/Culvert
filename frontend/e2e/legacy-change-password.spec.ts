// FE-6AR merge 12 — the LEGACY console's self-service "Change Password"
// dialog (static/index.html, #1425 on main) against this tree's FENCED
// handler (FE-6A.2), driven in a real browser on the real AUTH appliance as a
// NON-ADMIN user.
//
// What is pinned, and why each half exists:
//   1. Non-admin happy path — the dialog binds the subject + server-owned
//      security generation at open (GET /api/auth/status) and sends exactly
//      that generation; the 2xx is credited only when action-bound; the new
//      password is what authenticates afterwards; the typed secrets are gone
//      from the DOM when the dialog closes.
//   2. Stale generation — the appliance refuses (409 `stale`), NOTHING is
//      written, the dialog shows the refusal and stays open, and NO second
//      request is sent (no silent re-fence-and-retry). Cancel then drops the
//      typed secrets.
//   3. Account changed after the dialog bound — the session fence refuses the
//      submit (401), the browser lands on the login overlay with the dialog
//      closed and empty, and the password typed into the dialog did NOT take.
//   4. Missing authority — when the appliance does not state a generation the
//      dialog binds nothing, Save stays disabled, and no change request ever
//      leaves the browser.
//
// The user is created and deleted through the fenced roster API so the
// seeded fixtures are untouched for every other spec.
import type { APIRequestContext, Page } from "@playwright/test";
import { expect, request, test } from "./test";
import { AUTH_URL, EMPTY_STATE, USERS } from "./fixtures";

test.use({ storageState: EMPTY_STATE });
test.describe.configure({ mode: "serial" });

const CP_USER = "cp-e2e-viewer";
const PASS_A = "V1ewerPass!a";
const PASS_B = "V1ewerPass!b";
const PASS_C = "V1ewerPass!c";
const ADMIN_RESET = "Adm1nReset!pw";
const LEGACY_XFF = "10.71.0.7";

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

async function passwordWorks(user: string, pass: string): Promise<boolean> {
  const ctx = await request.newContext({
    baseURL: AUTH_URL,
    extraHTTPHeaders: { "X-Forwarded-For": "10.71.0.8" },
  });
  try {
    const r = await ctx.post("/api/auth/login", { data: { user, pass } });
    return r.ok();
  } finally {
    await ctx.dispose();
  }
}

async function legacyLogin(page: Page, user: string, pass: string): Promise<void> {
  await page.goto(`${AUTH_URL}/`);
  await expect(page.locator("#login-overlay")).toBeVisible();
  await page.locator("#li-user").fill(user);
  await page.locator("#li-pass").fill(pass);
  const loginP = page.waitForResponse(
    (r) => r.url().endsWith("/api/auth/login") && r.request().method() === "POST",
  );
  await page.locator("#li-btn").click();
  const login = await loginP;
  expect(login.status(), await login.text()).toBe(200);
  // The console's boot issues a dozen dashboard fetches BEFORE any session
  // exists; a 401 from one of them that lands after the login succeeded
  // re-shows the overlay and clears the session name (pre-existing console
  // race, observed in this proof's first run). A reload makes every request
  // carry the cookie — what a user's next navigation does — so the proof
  // measures the fenced dialog, not that race.
  await page.reload();
  await expect(page.locator("#login-overlay")).toBeHidden();
  await expect(page.locator("#topbar-username")).toHaveText(user);
  await expect(page.locator("#change-pw-btn")).toBeVisible();
}

/** Opens the dialog and waits for the authority to be BOUND (Save enabled). */
async function openBoundDialog(page: Page): Promise<number> {
  const statusP = page.waitForResponse(
    (r) => r.url().endsWith("/api/auth/status") && r.request().method() === "GET",
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

async function fillDialog(page: Page, current: string, next: string): Promise<void> {
  await page.locator("#cp-current").fill(current);
  await page.locator("#cp-new").fill(next);
  await page.locator("#cp-confirm").fill(next);
}

async function expectDialogFieldsEmpty(page: Page): Promise<void> {
  for (const id of ["#cp-current", "#cp-new", "#cp-confirm"]) {
    await expect(page.locator(id)).toHaveValue("");
  }
}

test.beforeAll(async () => {
  const api = await newAdminClient();
  try {
    // Idempotent: a previous interrupted run may have left the account.
    const list = await api.get("/api/auth/users");
    const v: unknown = await list.json();
    if (isRecord(v) && Array.isArray(v["users"]) &&
        v["users"].some((x) => isRecord(x) && x["username"] === CP_USER)) {
      const del = await api.delete(
        `/api/auth/users?username=${CP_USER}&revision=${String(await rosterRevision(api))}`,
      );
      expect(del.ok(), await del.text()).toBe(true);
    }
    const rev = await rosterRevision(api);
    const created = await api.post(`/api/auth/users?revision=${String(rev)}`, {
      data: { username: CP_USER, password: PASS_A, role: "viewer" },
    });
    expect(created.ok(), await created.text()).toBe(true);
  } finally {
    await api.dispose();
  }
});

test.afterAll(async () => {
  const api = await newAdminClient();
  try {
    const rev = await rosterRevision(api);
    const del = await api.delete(`/api/auth/users?username=${CP_USER}&revision=${String(rev)}`);
    expect(del.ok(), await del.text()).toBe(true);
  } finally {
    await api.dispose();
  }
});

test("1 — a viewer changes their own password: bound generation sent, action-bound 2xx, secrets cleared", async ({ page }) => {
  await legacyLogin(page, CP_USER, PASS_A);
  const bound = await openBoundDialog(page);

  const sent: Array<{ generation: unknown; hasCurrent: boolean; hasNew: boolean }> = [];
  page.on("request", (r) => {
    if (r.url().endsWith("/api/auth/change-password") && r.method() === "POST") {
      const body: unknown = r.postDataJSON();
      sent.push({
        generation: isRecord(body) ? body["generation"] : undefined,
        hasCurrent: isRecord(body) && typeof body["current_password"] === "string",
        hasNew: isRecord(body) && typeof body["new_password"] === "string",
      });
    }
  });

  await fillDialog(page, PASS_A, PASS_B);
  const respP = page.waitForResponse((r) => r.url().endsWith("/api/auth/change-password"));
  await page.locator("#cp-save-btn").click();
  const resp = await respP;
  expect(resp.status()).toBe(200);
  const body: unknown = await resp.json();
  expect(isRecord(body) && body["ok"] === true && body["selfAffected"] === true).toBe(true);
  if (!isRecord(body) || typeof body["securityGeneration"] !== "number") throw new Error("no generation");
  expect(body["securityGeneration"]).toBeGreaterThan(bound);

  await expect(page.locator("#toasts")).toContainText("Password changed.");
  await expect(page.locator("#change-password-modal")).toBeHidden();
  await expectDialogFieldsEmpty(page);

  expect(sent).toHaveLength(1);
  expect(sent[0]).toEqual({ generation: bound, hasCurrent: true, hasNew: true });

  // The session was re-issued at the new generation: the console keeps
  // working without a re-login.
  const st = await page.request.get(`${AUTH_URL}/api/auth/status`);
  const stBody: unknown = await st.json();
  expect(isRecord(stBody) && stBody["loggedIn"] === true && stBody["user"] === CP_USER).toBe(true);

  expect(await passwordWorks(CP_USER, PASS_B)).toBe(true);
  expect(await passwordWorks(CP_USER, PASS_A)).toBe(false);
});

test("2 — a stale generation is refused with nothing written, no retry; Cancel drops the secrets", async ({ page }) => {
  await legacyLogin(page, CP_USER, PASS_B);
  const bound = await openBoundDialog(page);

  // Make the dialog's fence stale ON THE WIRE (the session itself stays at
  // the current generation, so the refusal is the handler's 409, not the
  // session fence's 401).
  let posts = 0;
  await page.route("**/api/auth/change-password", async (route) => {
    posts++;
    const body: unknown = route.request().postDataJSON();
    if (!isRecord(body)) return route.continue();
    await route.continue({ postData: JSON.stringify({ ...body, generation: bound - 1 }) });
  });

  await fillDialog(page, PASS_B, PASS_C);
  const respP = page.waitForResponse((r) => r.url().endsWith("/api/auth/change-password"));
  await page.locator("#cp-save-btn").click();
  const resp = await respP;
  expect(resp.status()).toBe(409);
  const rb: unknown = await resp.json();
  expect(isRecord(rb) && rb["code"] === "stale").toBe(true);

  await expect(page.locator("#cp-err")).toBeVisible();
  await expect(page.locator("#cp-err")).toContainText("Your account changed since this dialog was opened");
  await expect(page.locator("#cp-err")).toContainText("Nothing was changed");
  await expect(page.locator("#change-password-modal")).toBeVisible();
  await expect(page.locator("#cp-save-btn")).toBeEnabled();
  // Give a would-be retry every chance to fire, then assert it did not.
  await page.waitForTimeout(500);
  expect(posts).toBe(1);

  expect(await passwordWorks(CP_USER, PASS_B)).toBe(true);
  expect(await passwordWorks(CP_USER, PASS_C)).toBe(false);

  await page.getByRole("dialog").getByRole("button", { name: "Cancel" }).click();
  await expect(page.locator("#change-password-modal")).toBeHidden();
  await expectDialogFieldsEmpty(page);
  await page.unroute("**/api/auth/change-password");
});

test("3 — the account changed after the dialog bound: refused at the session fence, dialog closed and empty, nothing written", async ({ page }) => {
  await legacyLogin(page, CP_USER, PASS_B);
  await openBoundDialog(page);
  await fillDialog(page, PASS_B, PASS_C);

  // An administrator resets the account while the dialog is open: the
  // security generation advances and every session issued before it — this
  // browser's included — is refused at the fence.
  const api = await newAdminClient();
  try {
    const rev = await rosterRevision(api);
    const reset = await api.put(`/api/auth/users?revision=${String(rev)}`, {
      data: { username: CP_USER, password: ADMIN_RESET },
    });
    expect(reset.ok(), await reset.text()).toBe(true);
  } finally {
    await api.dispose();
  }

  const respP = page.waitForResponse((r) => r.url().endsWith("/api/auth/change-password"));
  await page.locator("#cp-save-btn").click();
  expect((await respP).status()).toBe(401);

  await expect(page.locator("#login-overlay")).toBeVisible();
  await expect(page.locator("#change-password-modal")).toBeHidden();
  await expectDialogFieldsEmpty(page);

  expect(await passwordWorks(CP_USER, ADMIN_RESET)).toBe(true);
  expect(await passwordWorks(CP_USER, PASS_C)).toBe(false);
});

test("4 — no stated authority: nothing is bound, Save stays disabled, no request leaves the browser", async ({ page }) => {
  await legacyLogin(page, CP_USER, ADMIN_RESET);
  // From here the appliance's status answer is stripped of its generation
  // (a build that does not publish one, or a body that cannot be trusted).
  await page.route("**/api/auth/status", async (route) => {
    const r = await route.fetch();
    const j: unknown = await r.json();
    if (!isRecord(j)) return route.fulfill({ response: r });
    const { securityGeneration: _dropped, ...rest } = j;
    void _dropped;
    await route.fulfill({ response: r, body: JSON.stringify(rest), headers: { ...r.headers(), "content-type": "application/json" } });
  });
  let posts = 0;
  page.on("request", (r) => {
    if (r.url().endsWith("/api/auth/change-password")) posts++;
  });

  await page.locator("#change-pw-btn").click();
  await expect(page.locator("#change-password-modal")).toBeVisible();
  await expect(page.locator("#cp-err")).toContainText("authority could not be confirmed");
  await expect(page.locator("#cp-save-btn")).toBeDisabled();
  // Even a forced submit (Enter in a field) cannot send: the handler refuses
  // locally with no bound authority.
  await fillDialog(page, ADMIN_RESET, PASS_C);
  await page.locator("#cp-confirm").press("Enter");
  await page.waitForTimeout(500);
  expect(posts).toBe(0);
  expect(await passwordWorks(CP_USER, ADMIN_RESET)).toBe(true);

  await page.getByRole("dialog").getByRole("button", { name: "Cancel" }).click();
  await expectDialogFieldsEmpty(page);
  await page.unroute("**/api/auth/status");
});
