// 2F-E CORRECTION ROUND 2 real-binary journeys (external freeze review of
// db6f4d35): the continuity and active-truth failure scenarios, each against
// the actual CULVERT binary on the AUTH appliance. Written and executed on
// the UNTOUCHED candidate before any product change; every journey fails
// there for the reason the review names.
//
//   R9   CURRENTLY ACTIVE TRUTH: a publish whose response is lost is
//        followed by a direct profile PUT through the API (the authoritative
//        active store moves, the history pointer does not); Recover must
//        report the commit AND that it is NO LONGER the active revision.
//   R10  DELETE + RECREATE REPRODUCING THE ORIGINAL BASE: the request never
//        reached the appliance; the profile is deleted and recreated under
//        the same id with the same draft. Recover must keep the operation
//        UNRESOLVED (broken history continuity) and WITHHOLD the re-send —
//        the appliance has no decision record for the operationId in the
//        new epoch, so a re-send would run it as a fresh operation.
//   R11  DELETE + RECREATE REACHING A HIGHER REVISION after the operation
//        DID land (502 after commit): Recover must never say "did not land";
//        the operation stays unresolved with broken continuity.
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page } from "@playwright/test";
import { AUTH_URL, USERS } from "./fixtures";

const ROUTE = "/app/network/pac";
const KEY = "culvert.pac.lifecycle-recovery.v1";
const SUFFIX = "r2" + Date.now().toString(36).slice(-5);
const POOL_ID = `e2ec2pool${SUFFIX}`;
const PROF_A = `e2ec2profa${SUFFIX}`;
const PROF_B = `e2ec2profb${SUFFIX}`;
const NAME_A = `E2E PAC C2-A ${SUFFIX}`;
const NAME_B = `E2E PAC C2-B ${SUFFIX}`;

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
      name: `E2E pool C2 ${SUFFIX}`,
      endpoints: [{ host: "proxy-c2.e2e.test", port: 3128 }],
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

/** The direct CRUD path: replace the active spec (name change), revision
 * fenced — the authoritative store advances, the lifecycle history does not. */
async function directPut(
  api: APIRequestContext,
  id: string,
  name: string,
): Promise<number> {
  const cur = await api.get(`/api/pac/profiles/${id}`);
  expect(cur.ok()).toBe(true);
  const p: unknown = await cur.json();
  if (!isRecord(p)) throw new Error("bad profile");
  const resp = await api.put(`/api/pac/profiles/${id}`, {
    data: { ...p, name, revision: num(p, "revision") },
  });
  expect(resp.status(), await resp.text()).toBe(200);
  const after: unknown = await resp.json();
  if (!isRecord(after)) throw new Error("bad profile after PUT");
  return num(after, "revision");
}

async function deleteProfile(
  api: APIRequestContext,
  id: string,
): Promise<void> {
  const cur = await api.get(`/api/pac/profiles/${id}`);
  expect(cur.ok()).toBe(true);
  const p: unknown = await cur.json();
  if (!isRecord(p)) throw new Error("bad profile");
  const del = await api.delete(
    `/api/pac/profiles/${id}?revision=${String(num(p, "revision"))}`,
  );
  expect(del.status(), await del.text()).toBe(204);
}

async function recreateProfileA(api: APIRequestContext): Promise<void> {
  const l = await listing(api);
  const prof = await api.post("/api/pac/profiles", {
    data: {
      id: PROF_A,
      name: NAME_A,
      description: "2F-E correction fixture",
      enabled: true,
      poolId: POOL_ID,
      rules: [],
      privateNetworks: "proxy",
      availabilityMode: "secure",
      revision: 1,
      collectionEtag: str(l, "collectionEtag"),
    },
  });
  expect(prof.status(), await prof.text()).toBe(200);
}

const DRAFT_RULES = [
  {
    kind: "domain",
    pattern: "cont.e2e.test",
    action: "use_pool",
    poolId: POOL_ID,
  },
];

// ── R9 ──────────────────────────────────────────────────────────────────────

test("R9 currently-active truth: publish → lost response → direct profile PUT → Recover reports the commit as NO LONGER active", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.111");
  try {
    await seed(api, false);
    await saveDraft(api, PROF_A, NAME_A, DRAFT_RULES);
    await openProfile(page, NAME_A);
    await interceptPost(page, PROF_A, () =>
      Promise.resolve({
        status: 502,
        body: "<html>bad gateway</html>",
        contentType: "text/html",
      }),
    );
    await clickPublish(page);
    await expect(page.getByText(/outcome unknown/i).first()).toBeVisible();
    const opId = await opIdFromMarker(page);
    await page.unroute(`**/api/pac/profiles/${PROF_A}/lifecycle`);
    // the appliance committed: history revision 1, active store revision 2
    let lc = await lifecycle(api, PROF_A);
    expect(num(lc, "activeN")).toBe(1);
    expect(num(lc, "activeRevision")).toBe(2);
    // the authoritative active store moves WITHOUT the lifecycle
    const putRev = await directPut(api, PROF_A, `${NAME_A} renamed by PUT`);
    expect(putRev).toBe(3);
    lc = await lifecycle(api, PROF_A);
    expect(num(lc, "activeN")).toBe(1);
    expect(num(lc, "activeRevision")).toBe(3);
    await page.getByRole("button", { name: "Recover" }).click();
    const notice = page
      .getByRole("status")
      .filter({ hasText: /committed as history revision 1/i });
    await expect(notice).toBeVisible();
    await expect(notice).toContainText(/no longer the active revision/i);
    await expect(notice).not.toContainText(/It is the active revision/i);
    expect(await markerRaw(page)).toBeNull();
    const revs = Array.isArray(lc["revisions"]) ? lc["revisions"] : [];
    expect(revs.some((r) => isRecord(r) && r["operationId"] === opId)).toBe(
      true,
    );
  } finally {
    await cleanup(api);
    await api.dispose();
  }
});

// ── R10 ─────────────────────────────────────────────────────────────────────

test("R10 delete + recreate reproducing the original base: Recover keeps the operation unresolved (broken continuity) and withholds the re-send", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.112");
  try {
    await seed(api, false);
    await saveDraft(api, PROF_A, NAME_A, DRAFT_RULES);
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
    await opIdFromMarker(page);
    await page.unroute(`**/api/pac/profiles/${PROF_A}/lifecycle`);
    expect(num(await lifecycle(api, PROF_A), "activeN")).toBe(0);
    // the profile is deleted and recreated under the SAME id, back at the
    // reviewed base (revision 1, same spec) with the same draft restored
    await deleteProfile(api, PROF_A);
    await recreateProfileA(api);
    await saveDraft(api, PROF_A, NAME_A, DRAFT_RULES);
    const lc = await lifecycle(api, PROF_A);
    expect(num(lc, "activeRevision")).toBe(1);
    expect(num(lc, "activeN")).toBe(0);
    await page.getByRole("button", { name: "Recover" }).click();
    await expect(
      page.getByRole("status").filter({ hasText: /continuity/i }),
    ).toBeVisible();
    await expect(
      page.getByRole("status").filter({ hasText: /not observed/i }),
    ).toHaveCount(0);
    expect(await markerRaw(page)).not.toBeNull();
    await expect(
      page.getByRole("button", { name: "Publish", exact: true }),
    ).toBeDisabled();
    const resend = page.getByRole("button", { name: /^Re-send/ });
    if ((await resend.count()) > 0) await expect(resend).toBeDisabled();
    // nothing was dispatched beyond the aborted attempt
    const posts = calls.filter(
      (c) => c.method === "POST" && c.path.endsWith("/lifecycle"),
    );
    expect(posts).toHaveLength(1);
    expect(num(await lifecycle(api, PROF_A), "activeN")).toBe(0);
  } finally {
    await cleanup(api);
    await api.dispose();
  }
});

// ── R11 ─────────────────────────────────────────────────────────────────────

test("R11 delete + recreate reaching a higher revision after the operation landed: Recover never says 'did not land'", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.113");
  try {
    await seed(api, false);
    await saveDraft(api, PROF_A, NAME_A, DRAFT_RULES);
    await openProfile(page, NAME_A);
    await interceptPost(page, PROF_A, () =>
      Promise.resolve({
        status: 502,
        body: "<html>bad gateway</html>",
        contentType: "text/html",
      }),
    );
    await clickPublish(page);
    await expect(page.getByText(/outcome unknown/i).first()).toBeVisible();
    await opIdFromMarker(page);
    await page.unroute(`**/api/pac/profiles/${PROF_A}/lifecycle`);
    expect(num(await lifecycle(api, PROF_A), "activeN")).toBe(1);
    // the history that recorded the commit is discarded with the profile;
    // the recreated profile climbs past the reviewed revision
    await deleteProfile(api, PROF_A);
    await recreateProfileA(api);
    await publishViaApi(api, PROF_A, NAME_A, "again1");
    await publishViaApi(api, PROF_A, NAME_A, "again2");
    const lc = await lifecycle(api, PROF_A);
    expect(num(lc, "activeRevision")).toBe(3);
    expect(num(lc, "activeN")).toBe(2);
    await page.getByRole("button", { name: "Recover" }).click();
    await expect(
      page.getByRole("status").filter({ hasText: /continuity/i }),
    ).toBeVisible();
    await expect(
      page.getByRole("status").filter({ hasText: /did not land/i }),
    ).toHaveCount(0);
    expect(await markerRaw(page)).not.toBeNull();
    await expect(
      page.getByRole("button", { name: "Publish", exact: true }),
    ).toBeDisabled();
  } finally {
    await cleanup(api);
    await api.dispose();
  }
});
