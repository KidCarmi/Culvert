// FE-3 identity-continuity multi-tab proof (§7): TWO pages in the SAME
// browser context share the real HttpOnly session cookie. Tab B replaces
// the session identity (admin → viewer); Tab A — never reloaded — detects
// the replacement at the approved revalidation boundary (window focus /
// visibility restoration), tears the admin state down, and adopts the
// viewer identity. No production bypass; real appliance, real cookies.
import { expect } from "@playwright/test";
import { test } from "./test";
import type { Page } from "@playwright/test";
import { AUTH_URL, EMPTY_STATE, USERS } from "./fixtures";

test.use({ storageState: EMPTY_STATE });

const ORIGIN = new URL(AUTH_URL).origin;

function watch(page: Page): { errors: string[]; external: string[] } {
  const errors: string[] = [];
  const external: string[] = [];
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    if (/Failed to load resource: .* status of (401|429|500)/.test(m.text()))
      return;
    errors.push(m.text());
  });
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("request", (r) => {
    if (new URL(r.url()).origin !== ORIGIN) external.push(r.url());
  });
  return { errors, external };
}

async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}

test("tab A adopts the replaced viewer identity after teardown — no reload", async ({
  page,
  context,
}) => {
  const wA = watch(page);

  // Tab A: authenticated admin shell.
  await page.goto(`${AUTH_URL}/app/`);
  await login(page, USERS.admin.user, USERS.admin.pass);
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("Administrators")).toBeVisible();
  await expect(page.getByText("admin", { exact: true })).toHaveCount(2); // account user + role chip
  // Reload marker: survives ONLY if tab A is never fully reloaded.
  await page.evaluate(() => {
    document.body.dataset["tabMarker"] = "alive-since-admin";
  });

  // Tab B (same context, same HttpOnly cookie): sees the admin session,
  // signs out, signs in as viewer — the shared cookie now names view-user.
  const pageB = await context.newPage();
  const wB = watch(pageB);
  await pageB.goto(`${AUTH_URL}/app/`);
  await expect(pageB.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(pageB.getByText("admin", { exact: true })).toHaveCount(2);
  await pageB.getByRole("button", { name: "Sign out" }).click();
  await expect(pageB.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await login(pageB, USERS.viewer.user, USERS.viewer.pass);
  await expect(pageB.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(pageB.getByText("viewer", { exact: true })).toBeVisible();

  // Tab A returns to the foreground: the approved revalidation boundary.
  // bringToFront restores focus/visibility; the explicit focus dispatch
  // drives the SAME production listener deterministically in headless runs.
  await page.bringToFront();
  await page.evaluate(() => {
    window.dispatchEvent(new Event("focus"));
  });

  // The frontend detects the viewer identity: the old admin role and its
  // Administration affordances are gone, the viewer chip renders — without
  // any full-page reload.
  await expect(page.getByText("viewer", { exact: true })).toBeVisible();
  await expect(page.getByText("view-user")).toBeVisible();
  await expect(page.getByText("Administrators")).toHaveCount(0);
  await expect(page.getByText("Settings")).toHaveCount(0);
  await expect(page.getByText("admin", { exact: true })).toHaveCount(0);
  const marker = await page.evaluate(() => document.body.dataset["tabMarker"]);
  expect(marker).toBe("alive-since-admin"); // no forced reload happened

  expect(wA.errors).toEqual([]);
  expect(wA.external).toEqual([]);
  expect(wB.errors).toEqual([]);
  expect(wB.external).toEqual([]);
  await pageB.close();
});
