// FE-1B real-binary browser smoke (directive §16): the committed production
// dist, embedded in the real CULVERT Go binary, served under the experimental
// /app preview with the strict nonce-free CSP — rendered by a real Chromium.
import { expect } from "@playwright/test";
import { test } from "./test";

const strictCSP =
  "default-src 'self'; script-src 'self'; script-src-attr 'none'; " +
  "style-src 'self'; style-src-attr 'none'; img-src 'self' data:; " +
  "connect-src 'self'; object-src 'none'; base-uri 'none'; " +
  "form-action 'self'; frame-ancestors 'none'";

function originOf(url: string): string {
  return new URL(url).origin;
}

test("new UI renders under strict CSP with no console errors or external requests", async ({
  page,
  baseURL,
}) => {
  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];
  const requestURLs: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });
  page.on("pageerror", (err) => pageErrors.push(String(err)));
  page.on("request", (req) => requestURLs.push(req.url()));

  await page.emulateMedia({ colorScheme: "dark" }); // deterministic system theme
  const resp = await page.goto("/app/");
  expect(resp?.status()).toBe(200);
  expect(resp?.headers()["content-security-policy"]).toBe(strictCSP);
  expect(resp?.headers()["cache-control"]).toBe("no-store");

  // Shell renders (JS executed): the app shell + overview page are React-drawn.
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await expect(page.getByText("Secure Web Gateway")).toBeVisible();

  // CSS loaded: the token canvas paints the dark background.
  const bg = await page.evaluate(
    () => getComputedStyle(document.body).backgroundColor,
  );
  expect(bg).toBe("rgb(11, 15, 26)");

  // Reload succeeds.
  await page.reload();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();

  // Direct deep-link navigation + reload succeed (SPA fallback → router).
  const deep = await page.goto("/app/no/such/route");
  expect(deep?.status()).toBe(200);
  await expect(page.getByRole("heading", { name: "Not found" })).toBeVisible();
  await page.reload();
  await expect(page.getByRole("heading", { name: "Not found" })).toBeVisible();

  // No CSP violations / console errors / page errors.
  expect(consoleErrors).toEqual([]);
  expect(pageErrors).toEqual([]);

  // Every browser request stayed on the appliance origin — air-gap holds.
  const base = originOf(baseURL ?? "");
  const external = requestURLs.filter((u) => originOf(u) !== base);
  expect(external).toEqual([]);
});

test("legacy root remains the old frontend, separately", async ({
  request,
  baseURL,
}) => {
  const res = await request.get(`${baseURL}/`);
  expect(res.status()).toBe(200);
  const body = await res.text();
  expect(body).toContain("data-view="); // legacy SPA markup
  const csp = res.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("'nonce-"); // legacy nonce policy untouched
  expect(csp).toContain("style-src 'self' 'unsafe-inline'");
  expect(csp).not.toBe(strictCSP);
});
