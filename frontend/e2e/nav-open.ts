// Shared final-open-state condition for the off-canvas sidebar (≤1100px).
// The sidebar slides in over --dur-base; a screenshot or assertion taken
// mid-transition sees only a sliver. Both the qualification proof and the
// visual-evidence capture wait on THIS one condition, so the evidence can
// never again be captured before the panel reaches its resting position.
import { expect } from "@playwright/test";
import type { Page } from "@playwright/test";

export async function openNavToFinalState(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Open navigation" }).click();

  const sidebar = page.getByRole("complementary"); // the <aside> shell sidebar
  const nav = page.getByRole("navigation", { name: "Primary" });

  // Geometric proof, not a sleep: 100% of the primary navigation must be
  // inside the viewport — a partially-slid panel fails the ratio.
  await expect(nav).toBeInViewport({ ratio: 1 });
  await expect(sidebar).toBeInViewport({ ratio: 1 });

  // Settled at the resting position: the sidebar's left edge is exactly at
  // x = 0 (fixed, inset-left 0, final translate 0 0) and its right edge is
  // within the viewport. Polled so the 180ms transition is waited out, and
  // exact so a mid-transition frame can never satisfy it.
  await expect.poll(async () => (await sidebar.boundingBox())?.x).toBe(0);
  const box = await sidebar.boundingBox();
  const viewport = page.viewportSize();
  expect(box).not.toBeNull();
  expect(viewport).not.toBeNull();
  if (box !== null && viewport !== null) {
    expect(box.x).toBe(0);
    expect(box.x + box.width).toBeLessThanOrEqual(viewport.width);
  }
}
