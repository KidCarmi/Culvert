// Slice 2A-M real-binary qualification (§22): History & Storage against the
// real binary. Read/export flows run on the AUTH appliance (persistent store
// enabled by its harness config; roster has viewer/admin). Mutation flows run
// on the FRESH appliance (root-admin) so the AUTH store's seeded Traffic
// history — evidence other suites depend on — is never disabled or purged.
// Harness-isolation doctrine (§19): every premise (enabled/disabled/specific
// retention) is ESTABLISHED through the supported admin API inside the test,
// never assumed from historical shared-/data state, and FRESH is left
// disabled at the end.
import { expect } from "@playwright/test";
import { test } from "./test";
import type { Page } from "@playwright/test";
import { AUTH_URL, EMPTY_STATE, FRESH_URL, USERS } from "./fixtures";

const TOLERATED = [/Failed to load resource: .* status of (401|403|429|500)/];

interface Watch {
  errors: string[];
  external: string[];
  sse: string[];
}

function watch(page: Page, base: string, extraTolerated: RegExp[] = []): Watch {
  const tolerated = [...TOLERATED, ...extraTolerated];
  const errors: string[] = [];
  const external: string[] = [];
  const sse: string[] = [];
  const origin = new URL(base).origin;
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    const text = m.text();
    if (tolerated.some((re) => re.test(text))) return;
    errors.push(text);
  });
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.origin !== origin && u.origin !== new URL(FRESH_URL).origin)
      external.push(r.url());
    if (u.pathname.startsWith("/api/events")) sse.push(r.url());
  });
  return { errors, external, sse };
}

function assertClean(w: Watch): void {
  expect(w.errors).toEqual([]);
  expect(w.external).toEqual([]);
  expect(w.sse).toEqual([]);
}

async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}

async function loginFresh(page: Page): Promise<void> {
  await page.goto(`${FRESH_URL}/app/monitor/history`);
  await login(page, "root-admin", "StrongPass123");
  await expect(
    page.getByRole("heading", { name: "History & Storage" }).first(),
  ).toBeVisible();
}

/** Establish a FRESH-appliance premise through the supported admin API
 * (§19): the shared absolute /data means historical state can never be
 * assumed. */
async function setFreshRetention(
  page: Page,
  body: Record<string, unknown>,
): Promise<void> {
  const r = await page.request.put(`${FRESH_URL}/api/logs/retention`, {
    data: body,
  });
  expect(r.ok()).toBe(true);
}

// ── AUTH: read surface + roles (flows 1, 2, 22) ───────────────────────────

test("admin reads History & Storage on an enabled appliance (nav + posture + usage)", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.goto("/app/monitor/traffic");
  await page.getByRole("link", { name: "History & Storage" }).click();
  await expect(
    page.getByRole("heading", { name: "History & Storage" }).first(),
  ).toBeVisible();
  // The harness API-enables the AUTH store before seeding (e2e-smoke.sh
  // §19 premise — boot state inherits the SHARED /data admin settings).
  await expect(page.getByText("Enabled", { exact: true })).toBeVisible();
  await expect(page.getByText("Stored size")).toBeVisible();
  await expect(page.getByText("Projected growth")).toBeVisible();
  await expect(page.getByText("Disk guard")).toBeVisible();
  // Admin mutation affordances exist.
  await expect(
    page.getByRole("button", { name: "Edit history settings" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Purge retained history…" }),
  ).toBeVisible();
  assertClean(w);
});

test.describe("viewer posture", () => {
  test.use({ storageState: EMPTY_STATE });
  test("viewer reads status + export exists, and NO mutation controls are mounted", async ({
    page,
    baseURL,
  }) => {
    const w = watch(page, baseURL ?? AUTH_URL);
    await page.goto("/app/monitor/history");
    await login(page, USERS.viewer.user, USERS.viewer.pass);
    await expect(
      page.getByRole("heading", { name: "History & Storage" }).first(),
    ).toBeVisible();
    await expect(page.getByText("Retention days")).toBeVisible();
    await expect(
      page.getByRole("button", { name: /Export recent memory — JSON/ }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Edit history settings" }),
    ).toHaveCount(0);
    await expect(page.getByRole("button", { name: /Purge/ })).toHaveCount(0);
    assertClean(w);
  });
});

// ── AUTH: recent-memory export (flows 15–18) ──────────────────────────────

test("JSON + CSV recent-memory exports download with correct types and truthful scope wording", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.goto("/app/monitor/history");
  await expect(
    page.getByText(
      "current in-memory traffic ring (the newest requests held in memory). It does not export the full persistent history store.",
    ),
  ).toBeVisible();
  // Deliberately NOT presented as a persistent-history export.
  await expect(page.getByText("Export all history")).toHaveCount(0);
  await expect(page.getByText("Export retained logs")).toHaveCount(0);

  const jsonResp = page.waitForResponse((r) =>
    r.url().includes("/api/export?format=json"),
  );
  const jsonDownload = page.waitForEvent("download");
  await page
    .getByRole("button", { name: "Export recent memory — JSON" })
    .click();
  const jr = await jsonResp;
  expect(jr.headers()["content-type"]).toContain("application/json");
  const jd = await jsonDownload;
  expect(jd.suggestedFilename()).toMatch(
    /^culvert-recent-traffic-\d{8}-\d{6}\.json$/,
  );

  const csvResp = page.waitForResponse((r) =>
    r.url().includes("/api/export?format=csv"),
  );
  const csvDownload = page.waitForEvent("download");
  await page
    .getByRole("button", { name: "Export recent memory — CSV" })
    .click();
  const cr = await csvResp;
  expect(cr.headers()["content-type"]).toContain("text/csv");
  const cd = await csvDownload;
  expect(cd.suggestedFilename()).toMatch(
    /^culvert-recent-traffic-\d{8}-\d{6}\.csv$/,
  );
  assertClean(w);
});

test("bad Content-Type and oversized Content-Length are rejected as controlled errors", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.goto("/app/monitor/history");
  await expect(
    page.getByRole("button", { name: "Export recent memory — JSON" }),
  ).toBeVisible();

  await page.route("**/api/export*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "text/html",
      body: "<html>not an export</html>",
    }),
  );
  await page
    .getByRole("button", { name: "Export recent memory — JSON" })
    .click();
  await expect(
    page.getByText(/unexpected download Content-Type/),
  ).toBeVisible();

  await page.unrouteAll();
  await page.route("**/api/export*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "text/csv",
      headers: { "Content-Length": String(1024 * 1024 * 1024) },
      body: "a,b\n",
    }),
  );
  await page
    .getByRole("button", { name: "Export recent memory — CSV" })
    .click();
  await expect(page.getByText(/exceeds the \d+-byte cap/)).toBeVisible();
  await page.unrouteAll();
  assertClean(w);
});

test.describe("export auth boundary", () => {
  test.use({ storageState: EMPTY_STATE });
  test("signing out during an export aborts it; nothing downloads across identities", async ({
    page,
    baseURL,
  }) => {
    const w = watch(page, baseURL ?? AUTH_URL, [/ERR_FAILED/, /ERR_ABORTED/]);
    await page.goto("/app/monitor/history");
    await login(page, USERS.viewer.user, USERS.viewer.pass);
    await expect(
      page.getByRole("heading", { name: "History & Storage" }).first(),
    ).toBeVisible();

    let downloads = 0;
    page.on("download", () => {
      downloads += 1;
    });
    await page.route("**/api/export*", async (route) => {
      await new Promise((r) => setTimeout(r, 8000));
      await route.abort();
    });
    await page
      .getByRole("button", { name: "Export recent memory — JSON" })
      .click();
    await expect(
      page.getByRole("button", { name: "Preparing…" }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();

    await login(page, USERS.operator.user, USERS.operator.pass);
    await expect(
      page.getByRole("heading", { name: "History & Storage" }).first(),
    ).toBeVisible();
    expect(downloads).toBe(0);
    await page.unrouteAll();
    assertClean(w);
  });
});

// ── FRESH: retention mutations (flows 3–6, 11–12, 14) ─────────────────────

test("admin journey: enable with retention → edit retention → purge → disable (truth copy) → purge while disabled", async ({
  page,
}) => {
  const w = watch(page, FRESH_URL);
  await loginFresh(page);
  await setFreshRetention(page, { enabled: false, criticalDiskPct: 99 }); // known baseline (§19)
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByText("Disabled", { exact: true })).toBeVisible();

  // Enable + retention + threshold in one explicit Save (flows 4/5/6).
  await page.getByRole("button", { name: "Edit history settings" }).click();
  await page.getByLabel("Persistent history").selectOption("enabled");
  await page.getByLabel("Retention days").fill("7");
  await page.getByLabel("Max storage GB").fill("1");
  // 99, not the default 90: the dev-machine session disk allowance reads
  // ~90%+ used via statvfs, and a lower threshold engages EMERGENCY minimal
  // logging + retained-history cleanup mid-test (correct product behavior
  // that would destroy every premise here).
  await page.getByLabel("Critical disk threshold %").fill("99");
  await page.getByRole("button", { name: "Save history settings" }).click();
  await expect(page.getByText("Enabled", { exact: true })).toBeVisible();
  await expect(page.getByText("99%", { exact: true })).toBeVisible();
  // Server truth for the numeric values (precise, selector-ambiguity-free).
  const afterEnable: unknown = await (
    await page.request.get(`${FRESH_URL}/api/logs/retention`)
  ).json();
  expect(afterEnable).toMatchObject({
    enabled: true,
    retentionDays: 7,
    retentionMaxGB: 1,
  });

  // Retention-only edit while enabled (flow 5).
  await page.getByRole("button", { name: "Edit history settings" }).click();
  await page.getByLabel("Retention days").fill("14");
  await page.getByRole("button", { name: "Save history settings" }).click();
  await expect(
    page.getByRole("button", { name: "Edit history settings" }),
  ).toBeVisible(); // edit state closed on the confirmed response
  const afterEdit: unknown = await (
    await page.request.get(`${FRESH_URL}/api/logs/retention`)
  ).json();
  expect(afterEdit).toMatchObject({ enabled: true, retentionDays: 14 });

  // Purge while enabled: T2 ceremony (flows 11/12).
  await page.getByRole("button", { name: "Purge retained history…" }).click();
  const dialog = page.getByRole("dialog");
  await expect(
    dialog.getByText("permanently deletes all retained Traffic history", {
      exact: false,
    }),
  ).toBeVisible();
  await expect(
    dialog.getByText("This cannot be undone.", { exact: false }).first(),
  ).toBeVisible();
  await expect(dialog.getByText("Audit Log", { exact: false })).toBeVisible(); // names what is NOT deleted
  await dialog.getByRole("button", { name: "Purge retained history" }).click();
  await expect(page.getByText("Retained history purged")).toBeVisible();

  // Disable: keeps-data truth copy before Save; disabled posture after.
  await page.getByRole("button", { name: "Edit history settings" }).click();
  await page.getByLabel("Persistent history").selectOption("disabled");
  await expect(
    page.getByText("Disabling stops new persistent traffic-history writes."),
  ).toBeVisible();
  await page.getByRole("button", { name: "Save history settings" }).click();
  await expect(page.getByText("Disabled", { exact: true })).toBeVisible();
  await expect(
    page.getByText(
      "Existing retained history remains on disk until it expires or is purged.",
    ),
  ).toBeVisible();

  // Purge while disabled (flow 14): on-disk retained store still deletable.
  await page.getByRole("button", { name: "Purge retained history…" }).click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Purge retained history" })
    .click();
  await expect(page.getByText("Retained history purged")).toBeVisible();
  assertClean(w);
});

test("client-side bounds block a bad Save with no request; server 400/409 pinned at the API (flows 7–9)", async ({
  page,
}) => {
  const w = watch(page, FRESH_URL);
  await loginFresh(page);
  await setFreshRetention(page, { enabled: false, criticalDiskPct: 99 });

  const puts: string[] = [];
  page.on("request", (r) => {
    if (r.url().includes("/api/logs/retention") && r.method() === "PUT")
      puts.push(r.url());
  });
  await page.getByRole("button", { name: "Refresh" }).click();
  await page.getByRole("button", { name: "Edit history settings" }).click();
  await page.getByLabel("Retention days").fill("5000");
  await page.getByRole("button", { name: "Save history settings" }).click();
  await expect(
    page.getByText("Retention days must be an integer between 0 and 3650."),
  ).toBeVisible();
  expect(puts).toHaveLength(0); // UX validation only — nothing was sent
  await page.getByRole("button", { name: "Cancel" }).click();

  // Server 400 (out-of-range) — API-level pin; the UI mirror can't produce it.
  const bad = await page.request.put(`${FRESH_URL}/api/logs/retention`, {
    data: { retentionDays: 999999, enabled: false },
  });
  expect(bad.status()).toBe(400);

  // Retention-only change while the store is OFF → 409 (flow 9). The v2 form
  // cannot produce this state: it always sends an explicit `enabled`, so a
  // disable-with-retention is a valid disable. Pinned here at the API.
  const conflict = await page.request.put(`${FRESH_URL}/api/logs/retention`, {
    data: { retentionDays: 5 },
  });
  expect(conflict.status()).toBe(409);
  expect(await conflict.text()).toContain("history store is off");

  // The page still renders server truth after the refused mutations.
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByText("Disabled", { exact: true })).toBeVisible();
  assertClean(w);
});

test("unknown Save outcome: prior snapshot kept, unconfirmed declared, blocked until Refresh (flow 10)", async ({
  page,
}) => {
  const w = watch(page, FRESH_URL, [/ERR_FAILED/, /ERR_ABORTED/]);
  await loginFresh(page);
  await setFreshRetention(page, { enabled: false, criticalDiskPct: 99 });
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByText("Disabled", { exact: true })).toBeVisible();

  await page.route("**/api/logs/retention", async (route) => {
    if (route.request().method() === "PUT") {
      await new Promise((r) => setTimeout(r, 300));
      await route.abort();
      return;
    }
    await route.continue();
  });
  await page.getByRole("button", { name: "Edit history settings" }).click();
  await page.getByLabel("Retention days").fill("21");
  await page.getByRole("button", { name: "Save history settings" }).click();

  await expect(page.getByText("Save outcome unconfirmed")).toBeVisible();
  await expect(
    page.getByText(
      "The server may have applied the settings before the connection was lost.",
    ),
  ).toBeVisible();
  // Prior snapshot still shown; no success claim; mutations blocked.
  await expect(page.getByText("Disabled", { exact: true })).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Edit history settings" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Purge retained history…" }),
  ).toBeDisabled();

  // A FAILED resolving refresh must NOT clear the latch: fail the retention
  // GET only now — after the unknown state exists, never the initial load.
  await page.unrouteAll();
  await page.route("**/api/logs/retention", async (route) => {
    if (route.request().method() === "GET") {
      await route.abort();
      return;
    }
    await route.continue();
  });
  await page.getByRole("button", { name: "Refresh current state" }).click();
  await expect(
    page.getByText("Refresh failed — showing previous snapshot"),
  ).toBeVisible();
  await expect(page.getByText("Save outcome unconfirmed")).toBeVisible();
  await expect(page.getByText("Disabled", { exact: true })).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Edit history settings" }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: "Purge retained history…" }),
  ).toBeDisabled();

  // Only a fresh SUCCESSFUL GET resolves.
  await page.unrouteAll();
  await page.getByRole("button", { name: "Refresh current state" }).click();
  await expect(page.getByText("Save outcome unconfirmed")).toBeHidden();
  await expect(
    page.getByRole("button", { name: "Edit history settings" }),
  ).toBeEnabled();
  await expect(
    page.getByRole("button", { name: "Purge retained history…" }),
  ).toBeEnabled();
  assertClean(w);
});

test("unknown Purge outcome: dialog closes into the unconfirmed state with the required copy (flow 13)", async ({
  page,
}) => {
  const w = watch(page, FRESH_URL, [/ERR_FAILED/, /ERR_ABORTED/]);
  await loginFresh(page);
  await setFreshRetention(page, { enabled: false, criticalDiskPct: 99 });
  await page.getByRole("button", { name: "Refresh" }).click();

  await page.route("**/api/logs/purge", async (route) => {
    await new Promise((r) => setTimeout(r, 300));
    await route.abort();
  });
  await page.getByRole("button", { name: "Purge retained history…" }).click();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Purge retained history" })
    .click();

  await expect(page.getByText("Purge outcome unconfirmed")).toBeVisible();
  await expect(
    page.getByText(
      "The appliance may have completed the purge before the connection was lost. Refresh History & Storage before taking another destructive action.",
    ),
  ).toBeVisible();
  // Neither "failed" nor "deleted" is claimed.
  await expect(page.getByText("Purge failed")).toBeHidden();
  await expect(page.getByText("Retained history purged")).toBeHidden();
  await expect(
    page.getByRole("button", { name: "Purge retained history…" }),
  ).toBeDisabled();

  // A FAILED resolving refresh keeps the unconfirmed declaration, fabricates
  // no success acknowledgement, and keeps Purge blocked.
  await page.route("**/api/logs/retention", async (route) => {
    if (route.request().method() === "GET") {
      await route.abort();
      return;
    }
    await route.continue();
  });
  await page.getByRole("button", { name: "Refresh current state" }).click();
  await expect(
    page.getByText("Refresh failed — showing previous snapshot"),
  ).toBeVisible();
  await expect(page.getByText("Purge outcome unconfirmed")).toBeVisible();
  await expect(page.getByText("Retained history purged")).toBeHidden();
  await expect(
    page.getByRole("button", { name: "Purge retained history…" }),
  ).toBeDisabled();

  await page.unrouteAll();
  await page.getByRole("button", { name: "Refresh current state" }).click();
  await expect(page.getByText("Purge outcome unconfirmed")).toBeHidden();
  await expect(
    page.getByRole("button", { name: "Purge retained history…" }),
  ).toBeEnabled();
  assertClean(w);
});

test("auth boundary during a Save leaks nothing into the next session (flow 21)", async ({
  page,
}) => {
  const w = watch(page, FRESH_URL, [/ERR_FAILED/, /ERR_ABORTED/]);
  await loginFresh(page);
  await setFreshRetention(page, { enabled: false, criticalDiskPct: 99 });
  await page.getByRole("button", { name: "Refresh" }).click();

  await page.route("**/api/logs/retention", async (route) => {
    if (route.request().method() === "PUT") {
      await new Promise((r) => setTimeout(r, 8000));
      await route.abort();
      return;
    }
    await route.continue();
  });
  await page.getByRole("button", { name: "Edit history settings" }).click();
  await page.getByLabel("Retention days").fill("9");
  await page.getByRole("button", { name: "Save history settings" }).click();
  await expect(page.getByRole("button", { name: "Saving…" })).toBeVisible();

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  await page.unrouteAll();

  await login(page, "root-admin", "StrongPass123");
  await expect(
    page.getByRole("heading", { name: "History & Storage" }).first(),
  ).toBeVisible();
  // Fresh session: no edit form, no unknown latch, no save-state leakage.
  await expect(page.getByText("Save outcome unconfirmed")).toBeHidden();
  await expect(page.getByRole("button", { name: "Saving…" })).toHaveCount(0);
  await expect(
    page.getByRole("button", { name: "Edit history settings" }),
  ).toBeEnabled();
  assertClean(w);
});
