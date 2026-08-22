// Shared final-open-state condition for the off-canvas sidebar (≤1100px).
// The sidebar slides in over --dur-base; a screenshot or assertion taken
// mid-transition sees only a sliver. Both the qualification proof and the
// visual-evidence capture wait on THIS one condition, so the evidence can
// never again be captured before the panel reaches its resting position.
//
// FE-4 note: the primary navigation grew past one 640×800 viewport height
// (Monitor + Governance entries), and the sidebar scrolls vertically by
// design (overflow-y: auto), so "the whole <nav> element is inside the
// viewport" stopped being a valid settledness condition. The settled-open
// proof now rests entirely on the SIDEBAR box (fixed, full-height, final
// translate 0 0): 100% in viewport and left edge exactly at x = 0 — a
// mid-transition frame still fails both. Link reachability is proven
// separately by expectNavLinkReachable (scroll within the sidebar, then
// fully visible), which is the honest condition for a scrollable nav.
import { expect } from "@playwright/test";
import type { Page } from "@playwright/test";

export async function openNavToFinalState(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Open navigation" }).click();

  const sidebar = page.getByRole("complementary"); // the <aside> shell sidebar
  const nav = page.getByRole("navigation", { name: "Primary" });

  // Geometric proof, not a sleep: the sidebar panel (viewport-height by
  // construction) must be 100% inside the viewport — a partially-slid panel
  // fails the ratio. The nav merely has to be rendered inside it.
  await expect(nav).toBeVisible();
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

/** Reachability proof for one nav link inside the (scrollable) sidebar:
 * scrolling within the panel must bring the link 100% into the viewport. */
export async function expectNavLinkReachable(
  page: Page,
  name: string,
): Promise<void> {
  const link = page.getByRole("link", { name });
  await link.scrollIntoViewIfNeeded();
  await expect(link).toBeInViewport({ ratio: 1 });
}
