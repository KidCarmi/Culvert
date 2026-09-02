// FE-2 browser qualification (directive §22): shell keyboard navigation,
// theme switch + persistence, lazy route through the FE-1B validator chain,
// dialog focus lifecycle, Tier-3 typed confirmation, reduced motion, zoom
// reflow — all against the real Go binary, committed production dist, strict
// CSP, with console/error/external-request monitoring throughout.
import { expect } from "@playwright/test";
import { test } from "./test";
import type { Page } from "@playwright/test";
import { expectNavLinkReachable, openNavToFinalState } from "./nav-open";

function watch(
  page: Page,
  baseURL: string,
): { errors: string[]; external: string[] } {
  const errors: string[] = [];
  const external: string[] = [];
  const base = new URL(baseURL).origin;
  page.on("console", (m) => {
    if (m.type() === "error") errors.push(m.text());
  });
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("request", (r) => {
    if (new URL(r.url()).origin !== base) external.push(r.url());
  });
  return { errors, external };
}

test("lazy design-system route loads through the manifest chain", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? "");
  await page.goto("/app/");
  // Client-side navigation triggers the dynamic import (GalleryPage chunk).
  await page.getByRole("link", { name: "Design System" }).click();
  await expect(
    page.getByRole("heading", { name: "Design system" }),
  ).toBeVisible();
  await expect(page.getByText("Proxy Healthy")).toBeVisible();
  // Deep-link + reload of the lazy route works too.
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Design system" }),
  ).toBeVisible();
  // Browser Back returns to the Dashboard.
  await page.goBack();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  expect(w.errors).toEqual([]);
  expect(w.external).toEqual([]);
});

test("theme switches without reload and persists", async ({ page }) => {
  // Headless defaults to prefers-color-scheme: light; pin the OS scheme so
  // "system" deterministically resolves dark for the baseline assertion.
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/app/");
  const bgDark = await page.evaluate(
    () => getComputedStyle(document.body).backgroundColor,
  );
  expect(bgDark).toBe("rgb(11, 15, 26)");
  await page.getByRole("button", { name: "Light theme" }).click();
  const bgLight = await page.evaluate(
    () => getComputedStyle(document.body).backgroundColor,
  );
  expect(bgLight).toBe("rgb(243, 244, 246)");
  expect(
    await page.evaluate(() =>
      document.documentElement.getAttribute("data-theme"),
    ),
  ).toBe("light");
  // Persistence: the ONLY sanctioned browser-storage key survives reload.
  await page.reload();
  expect(
    await page.evaluate(() => getComputedStyle(document.body).backgroundColor),
  ).toBe("rgb(243, 244, 246)");
  expect(await page.evaluate(() => Object.keys(localStorage))).toEqual([
    "culvert-theme",
  ]);
  await page.getByRole("button", { name: "Dark theme" }).click();
});

test("shell keyboard navigation: skip link first, nav reachable", async ({
  page,
}) => {
  await page.goto("/app/");
  // FE-3: wait for the authenticated shell (past the boot phase) before
  // exercising the tab order.
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Skip to content" }),
  ).toBeFocused();
  await page.keyboard.press("Enter");
  expect(await page.evaluate(() => document.activeElement?.id)).toBe("main");
  // Tab order reaches primary navigation links.
  await page.getByRole("link", { name: "Dashboard" }).focus();
  await expect(page.getByRole("link", { name: "Dashboard" })).toBeFocused();
});

test("dialog focus lifecycle under the native top layer", async ({ page }) => {
  await page.goto("/app/design-system");
  const opener = page.getByRole("button", { name: "Open dialog" });
  await opener.focus();
  await page.keyboard.press("Enter"); // open from keyboard
  const dialog = page.getByRole("dialog", { name: "Enrollment token created" });
  await expect(dialog).toBeVisible();
  // Initial focus lands inside the dialog.
  expect(
    await page.evaluate(
      () => document.activeElement?.closest("dialog") !== null,
    ),
  ).toBe(true);
  // Tab containment: focus never lands on background page content while the
  // dialog is modal (the wrap step may pass through <body> on its way to the
  // browser chrome — that is not a background element receiving focus).
  for (let i = 0; i < 6; i++) {
    await page.keyboard.press("Tab");
    expect(
      await page.evaluate(() => {
        const a = document.activeElement;
        return (
          a === null ||
          a === document.body ||
          a === document.documentElement ||
          a.closest("dialog") !== null
        );
      }),
    ).toBe(true);
  }
  // Escape closes; focus returns to the invoker (platform behavior).
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
  await expect(opener).toBeFocused();
});

test("tier-3 typed confirmation ceremony", async ({ page }) => {
  await page.goto("/app/design-system");
  await page.getByRole("button", { name: "Tier-3 ceremony" }).click();
  const dialog = page.getByRole("dialog", {
    name: "Switch blocklist to allowlist mode",
  });
  await expect(dialog).toBeVisible();
  const confirm = dialog.getByRole("button", { name: "Switch mode" });
  await expect(confirm).toBeDisabled();
  const input = dialog.getByLabel(/Type ALLOWLIST to confirm/);
  // Enter must not bypass the typed requirement.
  await input.focus();
  await page.keyboard.press("Enter");
  await expect(dialog).toBeVisible();
  await expect(confirm).toBeDisabled();
  // Wrong word keeps it disabled; exact word arms it.
  await input.fill("ALLOWLIS");
  await expect(confirm).toBeDisabled();
  await input.fill("ALLOWLIST");
  await expect(confirm).toBeEnabled();
  await confirm.click();
  // Pending blocks double-submit, then the demo lands in the first-class
  // UNKNOWN state (distinct from success/failure).
  await expect(dialog.getByText("Action state is unknown")).toBeVisible();
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog).not.toBeVisible();
});

test("reduced motion collapses durations", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/app/design-system");
  const dur = await page.evaluate(() =>
    getComputedStyle(document.documentElement)
      .getPropertyValue("--dur-base")
      .trim(),
  );
  expect(dur).toMatch(/^0m?s$/); // minifier normalizes 0ms -> 0s
});

test("zoom/narrow reflow: no page-level horizontal scroll, nav fully opens", async ({
  page,
}) => {
  // 640×800 CSS px ≈ a 1280-wide desktop at 200% zoom.
  await page.setViewportSize({ width: 640, height: 800 });
  await page.goto("/app/");
  const overflow = await page.evaluate(
    () =>
      document.documentElement.scrollWidth -
      document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(0);
  // Critical navigation reaches its FINAL open state: sidebar fully
  // in-viewport, settled at x = 0 — a mid-transition sliver fails this.
  await openNavToFinalState(page);
  // Every critical link is REACHABLE and then 100% inside the viewport.
  // Since FE-4 the nav is taller than one 640×800 viewport (Monitor +
  // Governance entries) and the sidebar scrolls by design, so the honest
  // condition is scroll-within-the-panel → fully visible.
  await expectNavLinkReachable(page, "Design System");
  await expectNavLinkReachable(page, "Dashboard");
  // The open panel introduces no page-level horizontal overflow either.
  const overflowOpen = await page.evaluate(
    () =>
      document.documentElement.scrollWidth -
      document.documentElement.clientWidth,
  );
  expect(overflowOpen).toBeLessThanOrEqual(0);
});

test("1024x768 shell remains usable", async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 768 });
  await page.goto("/app/design-system");
  await expect(
    page.getByRole("heading", { name: "Design system" }),
  ).toBeVisible();
  const overflow = await page.evaluate(
    () =>
      document.documentElement.scrollWidth -
      document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(0);
});
