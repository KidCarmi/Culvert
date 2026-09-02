// Visual-evidence captures (FE-2 §21). Runs only when CULVERT_EVIDENCE_DIR
// is set (qualification runs); screenshots are evidence artifacts, never
// committed to the repository.
import { test } from "./test";
import { openNavToFinalState } from "./nav-open";

const dir = process.env["CULVERT_EVIDENCE_DIR"];

test.skip(dir === undefined, "evidence captures run only in qualification");

test("capture visual evidence", async ({ page }) => {
  const out = (name: string): string => `${dir ?? "."}/${name}`;
  await page.emulateMedia({ colorScheme: "dark" });

  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/app/design-system");
  await page.waitForSelector("text=Proxy Healthy");
  await page.screenshot({
    path: out("gallery-1440x900-dark.png"),
    fullPage: true,
  });

  await page.goto("/app/");
  await page.screenshot({ path: out("shell-overview-1440x900-dark.png") });

  // The gallery scrolls inside <main>; capture the lower sections too.
  await page.goto("/app/design-system");
  await page.waitForSelector("text=Proxy Healthy");
  await page.getByRole("heading", { name: "Health" }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: out("gallery-health-diagnostics-dark.png") });
  await page
    .getByRole("heading", { name: "Charts", exact: false })
    .scrollIntoViewIfNeeded();
  await page.screenshot({ path: out("gallery-ops-audit-charts-dark.png") });

  await page.getByRole("button", { name: "Light theme" }).click();
  await page.goto("/app/design-system");
  await page.waitForSelector("text=Proxy Healthy");
  await page.screenshot({
    path: out("gallery-1440x900-light.png"),
    fullPage: true,
  });

  // Confirmation dialog (light theme).
  await page.getByRole("button", { name: "Tier-3 ceremony" }).click();
  await page.getByLabel(/Type ALLOWLIST to confirm/).fill("ALLOWLIST");
  await page.screenshot({ path: out("tier3-dialog-light.png") });
  await page.keyboard.press("Escape");

  await page.getByRole("button", { name: "Dark theme" }).click();
  await page.setViewportSize({ width: 1024, height: 768 });
  await page.goto("/app/design-system");
  await page.waitForSelector("text=Proxy Healthy");
  await page.screenshot({ path: out("gallery-1024x768-dark.png") });

  // ≈200% zoom on a 1280 desktop: 640 CSS px viewport. The capture waits on
  // the SAME final-open-state condition as the qualification proof — never a
  // mid-transition frame.
  await page.setViewportSize({ width: 640, height: 800 });
  await page.goto("/app/");
  await openNavToFinalState(page);
  await page.screenshot({ path: out("shell-640w-200pct-zoom-nav.png") });
});
