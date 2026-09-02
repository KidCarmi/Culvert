// Slice 2D-B real-binary browser qualification: URL Categories + signed SaaS
// taxonomy over the actual CULVERT binary and committed dist, on the AUTH
// appliance.
//
// Covers the directive's browser proofs:
//   - category list truth (Admin vs Baseline, UT1 labeling) + operator CRUD
//     with the server-owned semantic revision fence,
//   - two-client stale write → structured 409, never a silent overwrite,
//   - manual lookup ("Uncategorized" is taxonomy truth),
//   - feed status + signed SaaS status rendered from server truth while the
//     feed stays DORMANT (unmanaged ⇒ runtime gate closed) — §31: the browser
//     must never contact the public signed-feed hostname, asserted per test,
//   - settings interval-only save (fenced; enablement untouched ⇒ no network),
//   - overrides full-set replace + clear-all with the override revision.
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page } from "@playwright/test";
import { AUTH_URL, USERS } from "./fixtures";

test.use({ extraHTTPHeaders: { "X-Forwarded-For": "198.51.100.40" } });

const ROUTE = "/app/objects/url-categories";
const FEED_HOST = "feeds.culvertlabs.com";

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}

async function newAdminClient(xff: string): Promise<APIRequestContext> {
  const ctx = await request.newContext({
    baseURL: AUTH_URL,
    extraHTTPHeaders: { "X-Forwarded-For": xff },
  });
  const login = await ctx.post("/api/auth/login", {
    data: { user: USERS.admin.user, pass: USERS.admin.pass },
  });
  expect(login.ok()).toBe(true);
  return ctx;
}

/** §31 guard: collect every request origin; the public feed host must never
 * be contacted by the browser qualification. */
function armFeedHostGuard(page: Page): () => void {
  const offenders: string[] = [];
  page.on("request", (req) => {
    if (req.url().includes(FEED_HOST)) offenders.push(req.url());
  });
  return () => {
    expect(offenders).toEqual([]);
  };
}

async function categoryNames(api: APIRequestContext): Promise<string[]> {
  const resp = await api.get("/api/urlcat/state");
  const v: unknown = await resp.json();
  if (!isRecord(v) || !Array.isArray(v["categories"])) return [];
  return v["categories"].flatMap((c: unknown) =>
    isRecord(c) && typeof c["name"] === "string" ? [c["name"]] : [],
  );
}

async function stateRevision(api: APIRequestContext): Promise<string> {
  const resp = await api.get("/api/urlcat/state");
  const v: unknown = await resp.json();
  if (!isRecord(v) || typeof v["revision"] !== "string") return "";
  return v["revision"];
}

async function deleteCategoryIfPresent(
  api: APIRequestContext,
  name: string,
): Promise<void> {
  const rev = await stateRevision(api);
  await api.delete(
    `/api/urlcat?name=${encodeURIComponent(name)}&ifRevision=${encodeURIComponent(rev)}`,
  );
}

test("url categories: operator CRUD journey with the revision fence", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.41");
  const assertNoFeedContact = armFeedHostGuard(page);
  try {
    await page.goto(ROUTE);
    await expect(page.getByText("URL Categories").first()).toBeVisible();

    // Create (strict, fenced).
    await page.getByRole("button", { name: "Create category" }).click();
    await page.getByLabel("Category name").fill("E2E 2DB Cat");
    await page
      .getByLabel("Hosts / patterns — one per line")
      .fill("e2e-a.example\ne2e-b.example");
    await expect(page.getByText("2 hosts")).toBeVisible();
    await page.getByRole("button", { name: "Create", exact: true }).click();
    await expect(
      page.getByRole("button", { name: "E2E 2DB Cat" }),
    ).toBeVisible();

    // The row carries the Admin type badge (server truth).
    const row = page.getByRole("row").filter({ hasText: "E2E 2DB Cat" });
    await expect(row.getByText("Admin", { exact: true })).toBeVisible();
    await expect(row.getByText("2", { exact: true })).toBeVisible();

    // Edit hosts (fenced replace).
    await row.getByRole("button", { name: "Edit hosts" }).click();
    await page
      .getByLabel("Hosts / patterns — one per line")
      .fill("e2e-a.example");
    await page.getByRole("button", { name: "Save hosts" }).click();
    await expect(row.getByText("1", { exact: true })).toBeVisible();

    // Delete (unreferenced) — T2 ceremony, fenced.
    await row.getByRole("button", { name: "Delete", exact: true }).click();
    await expect(page.getByText("Delete category — E2E 2DB Cat")).toBeVisible();
    await page
      .getByRole("button", { name: "Delete category", exact: true })
      .click();
    await expect(
      page.getByRole("button", { name: "E2E 2DB Cat" }),
    ).toBeHidden();
    expect(await categoryNames(api)).not.toContain("E2E 2DB Cat");
  } finally {
    await deleteCategoryIfPresent(api, "E2E 2DB Cat");
    await api.dispose();
    assertNoFeedContact();
  }
});

test("two-client stale category write is a structured 409 — no silent overwrite", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.42");
  const assertNoFeedContact = armFeedHostGuard(page);
  try {
    // Seed a category the browser will edit.
    let rev = await stateRevision(api);
    const seeded = await api.post(
      `/api/urlcat?ifRevision=${encodeURIComponent(rev)}`,
      { data: { name: "E2E Stale Cat", hosts: ["stale-a.example"] } },
    );
    expect(seeded.ok()).toBe(true);

    // Browser (client A) loads revision R.
    await page.goto(ROUTE);
    const rowA = page.getByRole("row").filter({ hasText: "E2E Stale Cat" });
    await expect(
      rowA.getByRole("button", { name: "Edit hosts" }),
    ).toBeVisible();

    // Client B advances the taxonomy AFTER A's load.
    rev = await stateRevision(api);
    const bWrite = await api.post(
      `/api/urlcat?ifRevision=${encodeURIComponent(rev)}`,
      { data: { name: "E2E B Cat", hosts: ["b.example"] } },
    );
    expect(bWrite.ok()).toBe(true);

    // A's edit against the stale revision → the Not applied notice; B's
    // category survives.
    await rowA.getByRole("button", { name: "Edit hosts" }).click();
    await page
      .getByLabel("Hosts / patterns — one per line")
      .fill("stale-clobber.example");
    await page.getByRole("button", { name: "Save hosts" }).click();
    await expect(page.getByText("Not applied").first()).toBeVisible();
    await expect(page.getByText("stale revision")).toBeVisible();
    const names = await categoryNames(api);
    expect(names).toContain("E2E B Cat");
  } finally {
    await deleteCategoryIfPresent(api, "E2E Stale Cat");
    await deleteCategoryIfPresent(api, "E2E B Cat");
    await api.dispose();
    assertNoFeedContact();
  }
});

test("lookup renders Uncategorized as taxonomy truth", async ({ page }) => {
  const assertNoFeedContact = armFeedHostGuard(page);
  await page.goto(ROUTE);
  await page.getByRole("tab", { name: "Lookup" }).click();
  await page.getByLabel("Hostname").fill("no-such-host-2db.example");
  await page.getByRole("button", { name: "Run lookup" }).click();
  await expect(page.getByText("Uncategorized")).toBeVisible();
  await expect(page.getByText("not an access verdict")).toBeVisible();
  assertNoFeedContact();
});

test("feed status + signed status render server truth while the feed stays dormant", async ({
  page,
}) => {
  const assertNoFeedContact = armFeedHostGuard(page);
  await page.goto(ROUTE);

  await page.getByRole("tab", { name: "Feed Status" }).click();
  await expect(page.getByText("UT1 community feed").first()).toBeVisible();
  await expect(page.getByText("Signed SaaS feed (summary)")).toBeVisible();

  await page.getByRole("tab", { name: "Signed SaaS Feed" }).click();
  await expect(page.getByText("Runtime status")).toBeVisible();
  // The harness appliance is unmanaged ⇒ dormant runtime, disabled state.
  await expect(page.getByText("No (dormant)").first()).toBeVisible();
  await expect(
    page.getByText(
      "https://feeds.culvertlabs.com/v1/url-categories/saas/manifest.sigstore.json",
    ),
  ).toBeVisible();
  await expect(
    page.getByText("no custom URL, no mirror, no unsigned fallback"),
  ).toBeVisible();
  assertNoFeedContact();
});

test("settings: interval-only save round-trips with the settings revision", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.43");
  const assertNoFeedContact = armFeedHostGuard(page);
  try {
    await page.goto(ROUTE);
    await page.getByRole("tab", { name: "Signed SaaS Feed" }).click();
    await expect(
      page.getByRole("heading", { name: "Configuration" }),
    ).toBeVisible();

    // Interval-only change (enablement untouched — both switches stay OFF on
    // the unmanaged harness appliance, so the runtime gate stays closed and
    // nothing dials the public feed).
    await page
      .getByLabel("Refresh interval (minimum 1h, default 24h — e.g. 12h)")
      .fill("12h");
    await page.getByRole("button", { name: "Save configuration" }).click();
    await expect(page.getByText("Settings saved")).toBeVisible();

    const resp = await api.get("/api/saas-feed/settings");
    const v: unknown = await resp.json();
    expect(isRecord(v) && v["refresh_seconds"]).toBe(43200);
    // Runtime stays dormant (managed=false).
    const status = await api.get("/api/saas-feed/status");
    const sv: unknown = await status.json();
    expect(isRecord(sv) && sv["enabled"]).toBe(false);
  } finally {
    // Restore the default interval.
    const resp = await api.get("/api/saas-feed/settings");
    const v: unknown = await resp.json();
    const rev =
      isRecord(v) && typeof v["revision"] === "string" ? v["revision"] : "";
    await api.put(
      `/api/saas-feed/settings?ifRevision=${encodeURIComponent(rev)}`,
      { data: { managed: false, enabled: false } },
    );
    await api.dispose();
    assertNoFeedContact();
  }
});

test("overrides: fenced replace and clear-all with subtree ceremony", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.44");
  const assertNoFeedContact = armFeedHostGuard(page);
  try {
    await page.goto(ROUTE);
    await page.getByRole("tab", { name: "Overrides" }).click();
    await expect(page.getByText("Subtree scope")).toBeVisible();

    // Replace with one addition + one tombstone.
    await page
      .getByLabel(
        "host = category — one per line; inserts a host the feed does not carry",
      )
      .fill("e2e-added.example.com = business");
    await page
      .getByLabel("host — one per line; suppresses that feed subtree entirely")
      .fill("e2e-tomb.example.com");
    await page.getByRole("button", { name: "Replace override set" }).click();
    await expect(page.getByText("Replace override set").nth(1)).toBeVisible();
    await page.getByRole("button", { name: "Replace set" }).click();
    await expect(page.getByText("Overrides replaced")).toBeVisible();

    // Clear-all ceremony with counts.
    await expect(page.getByText("Added (1)")).toBeVisible();
    for (const label of [
      "host = category — one per line; inserts a host the feed does not carry",
      "host = category — one per line; repoints a feed-carried subtree",
      "host — one per line; suppresses that feed subtree entirely",
    ]) {
      await page.getByLabel(label).fill("");
    }
    await page.getByRole("button", { name: "Clear all overrides" }).click();
    await expect(
      page.getByRole("heading", { name: "Clear ALL overrides" }),
    ).toBeVisible();
    await expect(page.getByText("Total to remove")).toBeVisible();
    await page.getByRole("button", { name: "Clear all", exact: true }).click();
    await expect(page.getByText("Overrides replaced")).toBeVisible();

    const resp = await api.get("/api/saas-feed/overrides");
    const v: unknown = await resp.json();
    expect(isRecord(v) && v["revision"]).toBe("none");
  } finally {
    // Ensure a clean override set for later specs.
    const resp = await api.get("/api/saas-feed/overrides");
    const v: unknown = await resp.json();
    const rev =
      isRecord(v) && typeof v["revision"] === "string" ? v["revision"] : "";
    await api.put(
      `/api/saas-feed/overrides?ifRevision=${encodeURIComponent(rev)}`,
      { data: {} },
    );
    await api.dispose();
    assertNoFeedContact();
  }
});
