// 2F-E CORRECTION real-binary journeys (external freeze review of 39e2cfdb):
// the failure scenarios the candidate's happy-path recovery journey did not
// cover, each against the actual CULVERT binary on the AUTH appliance.
//
//   R1  BOUNDED HISTORY + SUPERSEDED PUBLICATION: a publish whose response is
//       lost is followed by 25 further publishes through the API (the GET
//       lists 20); Recover must NOT say "did not land" — the appliance's
//       operation lookup proves it committed as history revision 1 and that
//       it is no longer the active revision.
//   R2  NOT RECEIVED: the request never reaches the appliance (aborted before
//       dispatch); the base is unchanged, so Recover keeps the operation
//       UNRESOLVED (not observed) and withholds publish; the explicit
//       re-send carries the SAME operationId and lands.
//   R3  GATEWAY 502 AFTER COMMIT: the appliance commits, an intermediary
//       answers 502; the page stays UNRESOLVED (marker kept) and Recover
//       proves the commit.
//   R4  MALFORMED 200 AFTER COMMIT: the body is not JSON; same posture.
//   R5  WRONG IDENTITY 200 AFTER COMMIT: a well-formed body naming another
//       operation is never "Published"; Recover proves the commit.
//   R6  A → B NAVIGATION + RELOAD: an unresolved operation on profile A
//       withholds publish on profile B (named), survives a reload, and is
//       lifted only once A is resolved.
//   R7  TWO-ADMIN DRAFT: a local edit based on draft revision N, a
//       concurrent API save to N+1, Refresh — Save sends N (409 stale
//       rendered, the server draft untouched); the explicit re-base then
//       saves the local content.
//   R8  LOCAL NAVIGATION GUARD: a dirty editor asks before a tab switch.
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page } from "@playwright/test";
import { AUTH_URL, USERS } from "./fixtures";

const ROUTE = "/app/network/pac";
const KEY = "culvert.pac.lifecycle-recovery.v1";
const SUFFIX = Date.now().toString(36).slice(-6);
const POOL_ID = `e2ecpool${SUFFIX}`;
const PROF_A = `e2ecprofa${SUFFIX}`;
const PROF_B = `e2ecprofb${SUFFIX}`;
const NAME_A = `E2E PAC C-A ${SUFFIX}`;
const NAME_B = `E2E PAC C-B ${SUFFIX}`;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function num(v: Record<string, unknown>, k: string): number {
  const n = v[k];
  if (typeof n !== "number") throw new Error(`missing number ${k}`);
  return n;
}
function str(v: Record<string, unknown>, k: string): string {
  const s = v[k];
  if (typeof s !== "string") throw new Error(`missing string ${k}`);
  return s;
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

async function listing(
  api: APIRequestContext,
): Promise<Record<string, unknown>> {
  const resp = await api.get("/api/pac/profiles");
  expect(resp.ok()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v)) throw new Error("bad profiles listing");
  return v;
}

async function lifecycle(
  api: APIRequestContext,
  id: string,
): Promise<Record<string, unknown>> {
  const resp = await api.get(`/api/pac/profiles/${id}/lifecycle`);
  expect(resp.ok()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v)) throw new Error("bad lifecycle");
  return v;
}

async function seed(api: APIRequestContext, withB: boolean): Promise<void> {
  const l = await listing(api);
  const pool = await api.post("/api/pac/pools", {
    data: {
      id: POOL_ID,
      name: `E2E pool C ${SUFFIX}`,
      endpoints: [{ host: "proxy-c.e2e.test", port: 3128 }],
      collectionEtag: str(l, "collectionEtag"),
    },
  });
  expect(pool.status(), await pool.text()).toBe(200);
  for (const [id, name] of withB
    ? ([
        [PROF_A, NAME_A],
        [PROF_B, NAME_B],
      ] as const)
    : ([[PROF_A, NAME_A]] as const)) {
    const l2 = await listing(api);
    const prof = await api.post("/api/pac/profiles", {
      data: {
        id,
        name,
        description: "2F-E correction fixture",
        enabled: true,
        poolId: POOL_ID,
        rules: [],
        privateNetworks: "proxy",
        availabilityMode: "secure",
        revision: 1,
        collectionEtag: str(l2, "collectionEtag"),
      },
    });
    expect(prof.status(), await prof.text()).toBe(200);
  }
}

function draftFor(id: string, name: string, rules: unknown[]): unknown {
  return {
    id,
    name,
    description: "2F-E correction fixture",
    enabled: true,
    poolId: POOL_ID,
    rules,
    privateNetworks: "proxy",
    availabilityMode: "secure",
    revision: 0,
  };
}

async function saveDraft(
  api: APIRequestContext,
  id: string,
  name: string,
  rules: unknown[],
): Promise<void> {
  const lc = await lifecycle(api, id);
  const resp = await api.post(`/api/pac/profiles/${id}/lifecycle`, {
    data: {
      action: "save_draft",
      draft: draftFor(id, name, rules),
      draftRevision: num(lc, "draftRevision"),
    },
  });
  expect(resp.status(), await resp.text()).toBe(200);
}

async function publishViaApi(
  api: APIRequestContext,
  id: string,
  name: string,
  tag: string,
): Promise<void> {
  const lc = await lifecycle(api, id);
  const resp = await api.post(`/api/pac/profiles/${id}/lifecycle`, {
    data: {
      action: "publish",
      operationId: crypto.randomUUID(),
      draft: draftFor(id, name, [
        {
          kind: "domain",
          pattern: `${tag}.e2e.test`,
          action: "use_pool",
          poolId: POOL_ID,
        },
      ]),
      expectedActiveRevision: num(lc, "activeRevision"),
      collectionEtag: str(lc, "collectionEtag"),
      reason: `api ${tag}`,
    },
  });
  expect(resp.status(), await resp.text()).toBe(200);
}

async function cleanup(api: APIRequestContext): Promise<void> {
  const l = await listing(api);
  const profiles = Array.isArray(l["profiles"]) ? l["profiles"] : [];
  for (const p of profiles) {
    if (isRecord(p) && (p["id"] === PROF_A || p["id"] === PROF_B)) {
      const del = await api.delete(
        `/api/pac/profiles/${String(p["id"])}?revision=${String(p["revision"])}`,
      );
      expect([204, 404]).toContain(del.status());
    }
  }
  const etags = l["poolEtags"];
  if (isRecord(etags) && typeof etags[POOL_ID] === "string") {
    const del = await api.delete(
      `/api/pac/pools/${POOL_ID}?etag=${encodeURIComponent(etags[POOL_ID])}`,
    );
    expect([204, 404]).toContain(del.status());
  }
}

function trackApiRequests(page: Page): Array<{ method: string; path: string }> {
  const calls: Array<{ method: string; path: string }> = [];
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.pathname.startsWith("/api/"))
      calls.push({ method: r.method(), path: u.pathname });
  });
  return calls;
}

async function openProfile(page: Page, name: string): Promise<void> {
  await page.goto(ROUTE);
  await page.getByRole("tab", { name: "Profiles" }).click();
  const row = page.getByRole("row", { name: new RegExp(name) });
  await expect(row).toBeVisible();
  await row.getByRole("button", { name: "Open" }).click();
  await expect(page.getByText("Active revision")).toBeVisible();
}

async function markerRaw(page: Page): Promise<string | null> {
  return page.evaluate((k) => sessionStorage.getItem(k), KEY);
}

async function opIdFromMarker(page: Page): Promise<string> {
  const raw = await markerRaw(page);
  const parsed: unknown = JSON.parse(raw ?? "{}");
  const id = isRecord(parsed) ? String(parsed["operationId"]) : "";
  expect(id).toMatch(/^[0-9a-f-]{36}$/);
  return id;
}

async function clickPublish(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Publish", exact: true }).click();
  await page.getByRole("button", { name: "Publish now" }).click();
}

/** Route the lifecycle POST so the appliance receives it and the browser
 * gets `answer` instead of the real response. */
async function interceptPost(
  page: Page,
  id: string,
  answer: (real: {
    status: number;
    body: string;
  }) => Promise<{ status: number; body: string; contentType: string }>,
): Promise<void> {
  await page.route(`**/api/pac/profiles/${id}/lifecycle`, async (route) => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }
    const real = await route.fetch();
    const a = await answer({ status: real.status(), body: await real.text() });
    await route.fulfill({
      status: a.status,
      body: a.body,
      contentType: a.contentType,
    });
  });
}

// ── R1 ──────────────────────────────────────────────────────────────────────

test("R1 bounded history + superseded publication: Recover proves 'committed as revision 1, no longer active' — never 'did not land'", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.101");
  try {
    await seed(api, false);
    await saveDraft(api, PROF_A, NAME_A, [
      {
        kind: "domain",
        pattern: "first.e2e.test",
        action: "use_pool",
        poolId: POOL_ID,
      },
    ]);
    await openProfile(page, NAME_A);
    await page.route(
      `**/api/pac/profiles/${PROF_A}/lifecycle`,
      async (route) => {
        if (route.request().method() !== "POST") {
          await route.continue();
          return;
        }
        await route.fetch();
        await route.abort("connectionreset");
      },
    );
    await clickPublish(page);
    await expect(page.getByText(/outcome unknown/i).first()).toBeVisible();
    const opId = await opIdFromMarker(page);
    await page.unroute(`**/api/pac/profiles/${PROF_A}/lifecycle`);
    expect(num(await lifecycle(api, PROF_A), "activeN")).toBe(1);
    for (let i = 0; i < 25; i += 1) {
      await publishViaApi(api, PROF_A, NAME_A, `later${String(i)}`);
    }
    const lc = await lifecycle(api, PROF_A);
    expect(num(lc, "activeN")).toBe(26);
    const shown = Array.isArray(lc["operations"]) ? lc["operations"] : [];
    expect(shown).toHaveLength(20);
    expect(shown.some((o) => isRecord(o) && o["operationId"] === opId)).toBe(
      false,
    );
    await page.getByRole("button", { name: "Recover" }).click();
    const outcome = page.getByRole("status").filter({ hasText: /committed/i });
    await expect(outcome).toBeVisible();
    await expect(outcome).toContainText(/no longer/i);
    await expect(page.getByText(/did not land/i)).toHaveCount(0);
    expect(await markerRaw(page)).toBeNull();
  } finally {
    await cleanup(api);
    await api.dispose();
  }
});

// ── R2 ──────────────────────────────────────────────────────────────────────

test("R2 not received: the base is unchanged so Recover keeps the operation unresolved; the explicit re-send reuses the operationId and lands", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.102");
  try {
    await seed(api, false);
    await saveDraft(api, PROF_A, NAME_A, [
      {
        kind: "domain",
        pattern: "never.e2e.test",
        action: "use_pool",
        poolId: POOL_ID,
      },
    ]);
    const calls = trackApiRequests(page);
    await openProfile(page, NAME_A);
    await page.route(
      `**/api/pac/profiles/${PROF_A}/lifecycle`,
      async (route) => {
        if (route.request().method() !== "POST") {
          await route.continue();
          return;
        }
        await route.abort("connectionrefused");
      },
    );
    await clickPublish(page);
    await expect(page.getByText(/outcome unknown/i).first()).toBeVisible();
    const opId = await opIdFromMarker(page);
    await page.unroute(`**/api/pac/profiles/${PROF_A}/lifecycle`);
    expect(num(await lifecycle(api, PROF_A), "activeN")).toBe(0);
    await page.getByRole("button", { name: "Recover" }).click();
    await expect(
      page.getByRole("status").filter({ hasText: /not observed/i }),
    ).toBeVisible();
    expect(await markerRaw(page)).not.toBeNull();
    await expect(
      page.getByRole("button", { name: "Publish", exact: true }),
    ).toBeDisabled();
    await page.getByRole("button", { name: /^Re-send/ }).click();
    await page.getByRole("button", { name: "Re-send now" }).click();
    // the success NOTICE — the history card is captioned "Published revisions"
    await expect(
      page.getByRole("status").filter({ hasText: "Published" }),
    ).toBeVisible();
    expect(await markerRaw(page)).toBeNull();
    const lc = await lifecycle(api, PROF_A);
    expect(num(lc, "activeN")).toBe(1);
    const revs = Array.isArray(lc["revisions"]) ? lc["revisions"] : [];
    expect(revs.some((r) => isRecord(r) && r["operationId"] === opId)).toBe(
      true,
    );
    const posts = calls.filter(
      (c) => c.method === "POST" && c.path.endsWith("/lifecycle"),
    );
    expect(posts).toHaveLength(2);
  } finally {
    await cleanup(api);
    await api.dispose();
  }
});

// ── R3 / R4 / R5 ────────────────────────────────────────────────────────────

for (const variant of [
  {
    name: "R3 gateway 502 after the appliance committed",
    answer: () =>
      Promise.resolve({
        status: 502,
        body: "<html>Bad Gateway</html>",
        contentType: "text/html",
      }),
  },
  {
    name: "R4 malformed 200 after the appliance committed",
    answer: () =>
      Promise.resolve({
        status: 200,
        body: "{not json",
        contentType: "application/json",
      }),
  },
  {
    name: "R5 wrong-identity 200 after the appliance committed",
    answer: () =>
      Promise.resolve({
        status: 200,
        body: JSON.stringify({
          operationId: "2d7c0f5e-9b1a-4c3d-8e2f-6a5b4c3d2e1f",
          activeRevision: 2,
          historyState: "recorded",
          published: true,
          revision: 1,
        }),
        contentType: "application/json",
      }),
  },
]) {
  test(`${variant.name}: the page stays UNRESOLVED (marker kept, never 'Published'); Recover proves the commit`, async ({
    page,
  }) => {
    const api = await newAdminClient("198.51.100.103");
    try {
      await seed(api, false);
      await saveDraft(api, PROF_A, NAME_A, [
        {
          kind: "domain",
          pattern: "gw.e2e.test",
          action: "use_pool",
          poolId: POOL_ID,
        },
      ]);
      await openProfile(page, NAME_A);
      await interceptPost(page, PROF_A, variant.answer);
      await clickPublish(page);
      await expect(page.getByText(/outcome unknown/i).first()).toBeVisible();
      await expect(page.getByText("Published", { exact: true })).toHaveCount(0);
      const opId = await opIdFromMarker(page);
      await page.unroute(`**/api/pac/profiles/${PROF_A}/lifecycle`);
      const lc = await lifecycle(api, PROF_A);
      expect(num(lc, "activeN")).toBe(1);
      const revs = Array.isArray(lc["revisions"]) ? lc["revisions"] : [];
      expect(revs.some((r) => isRecord(r) && r["operationId"] === opId)).toBe(
        true,
      );
      await expect(
        page.getByRole("button", { name: "Publish", exact: true }),
      ).toBeDisabled();
      await page.getByRole("button", { name: "Recover" }).click();
      await expect(
        page.getByRole("status").filter({ hasText: /committed/i }),
      ).toBeVisible();
      expect(await markerRaw(page)).toBeNull();
    } finally {
      await cleanup(api);
      await api.dispose();
    }
  });
}

// ── R6 ──────────────────────────────────────────────────────────────────────

test("R6 A → B navigation and reload: an unresolved operation on A withholds publish on B until A is resolved", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.104");
  try {
    await seed(api, true);
    await saveDraft(api, PROF_A, NAME_A, [
      {
        kind: "domain",
        pattern: "a.e2e.test",
        action: "use_pool",
        poolId: POOL_ID,
      },
    ]);
    await saveDraft(api, PROF_B, NAME_B, [
      {
        kind: "domain",
        pattern: "b.e2e.test",
        action: "use_pool",
        poolId: POOL_ID,
      },
    ]);
    await openProfile(page, NAME_A);
    await page.route(
      `**/api/pac/profiles/${PROF_A}/lifecycle`,
      async (route) => {
        if (route.request().method() !== "POST") {
          await route.continue();
          return;
        }
        await route.fetch();
        await route.abort("connectionreset");
      },
    );
    await clickPublish(page);
    await expect(page.getByText(/outcome unknown/i).first()).toBeVisible();
    await page.unroute(`**/api/pac/profiles/${PROF_A}/lifecycle`);
    // B while A is unresolved
    await page.getByRole("button", { name: /All profiles/ }).click();
    await expect(page.getByText(PROF_A).first()).toBeVisible();
    const rowB = page.getByRole("row", { name: new RegExp(NAME_B) });
    await rowB.getByRole("button", { name: "Open" }).click();
    await expect(page.getByText("Active revision")).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Publish", exact: true }),
    ).toBeDisabled();
    await expect(page.getByText(PROF_A).first()).toBeVisible();
    // survives a reload
    await page.reload();
    await page.getByRole("tab", { name: "Profiles" }).click();
    const rowB2 = page.getByRole("row", { name: new RegExp(NAME_B) });
    await rowB2.getByRole("button", { name: "Open" }).click();
    await expect(page.getByText("Active revision")).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Publish", exact: true }),
    ).toBeDisabled();
    expect(await markerRaw(page)).not.toBeNull();
    // resolve A
    await page.getByRole("button", { name: /All profiles/ }).click();
    const rowA = page.getByRole("row", { name: new RegExp(NAME_A) });
    await rowA.getByRole("button", { name: "Open" }).click();
    await page.getByRole("button", { name: "Recover" }).click();
    await expect(
      page.getByRole("status").filter({ hasText: /committed/i }),
    ).toBeVisible();
    expect(await markerRaw(page)).toBeNull();
    // B is free again
    await page.getByRole("button", { name: /All profiles/ }).click();
    const rowB3 = page.getByRole("row", { name: new RegExp(NAME_B) });
    await rowB3.getByRole("button", { name: "Open" }).click();
    await expect(
      page.getByRole("button", { name: "Publish", exact: true }),
    ).toBeEnabled();
    expect(num(await lifecycle(api, PROF_B), "activeN")).toBe(0);
  } finally {
    await cleanup(api);
    await api.dispose();
  }
});

// ── R7 / R8 ─────────────────────────────────────────────────────────────────

test("R7 two-admin draft: the local edit keeps its base revision across Refresh; the stale save is refused and rendered; re-basing is explicit", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.105");
  try {
    await seed(api, false);
    await saveDraft(api, PROF_A, NAME_A, []);
    await openProfile(page, NAME_A);
    const before = num(await lifecycle(api, PROF_A), "draftRevision");
    await page.getByLabel("Name").fill(`${NAME_A} local`);
    // the other admin saves draft revision N+1
    await saveDraft(api, PROF_A, `${NAME_A} other`, []);
    const after = num(await lifecycle(api, PROF_A), "draftRevision");
    expect(after).toBe(before + 1);
    await page.getByRole("button", { name: "Refresh" }).first().click();
    await expect(
      page.getByText(/Draft changed on the appliance/i),
    ).toBeVisible();
    await expect(page.getByLabel("Name")).toHaveValue(`${NAME_A} local`);
    await page.getByRole("button", { name: "Save draft" }).click();
    await expect(
      page.getByText(`current draft revision ${String(after)}`),
    ).toBeVisible();
    const untouched = await lifecycle(api, PROF_A);
    const serverDraft = untouched["draft"];
    expect(isRecord(serverDraft) && serverDraft["name"]).toBe(
      `${NAME_A} other`,
    );
    await page.getByRole("button", { name: /^Keep my edits/ }).click();
    await page.getByRole("button", { name: "Save draft" }).click();
    await expect(page.getByText("Draft saved")).toBeVisible();
    const saved = await lifecycle(api, PROF_A);
    const d = saved["draft"];
    expect(isRecord(d) && d["name"]).toBe(`${NAME_A} local`);
    expect(num(saved, "draftRevision")).toBe(after + 1);
  } finally {
    await cleanup(api);
    await api.dispose();
  }
});

test("R8 local navigation guard: a dirty editor asks before a tab switch; Cancel keeps the edit", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.106");
  try {
    await seed(api, false);
    await openProfile(page, NAME_A);
    await page.getByLabel("Name").fill(`${NAME_A} dirty`);
    await page.getByRole("tab", { name: "Pools" }).click();
    await expect(page.getByText("Discard unsaved changes?")).toBeVisible();
    await page.getByRole("button", { name: "Cancel" }).click();
    await expect(page.getByLabel("Name")).toHaveValue(`${NAME_A} dirty`);
    await page.getByRole("tab", { name: "Pools" }).click();
    await page.getByRole("button", { name: "Discard and leave" }).click();
    await expect(page.getByRole("tab", { name: "Pools" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
  } finally {
    await cleanup(api);
    await api.dispose();
  }
});
