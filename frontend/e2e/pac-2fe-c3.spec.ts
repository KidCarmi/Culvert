// 2F-E CORRECTION ROUND 3 real-binary journeys (external freeze review of
// 33f6f21c): the state transitions the round-2 continuity guarantee did not
// survive, each against the actual CULVERT binary on the AUTH appliance.
// Written and executed on the UNTOUCHED candidate before any product change;
// every journey fails there for the reason the review names.
//
//   R12  SAME-REVISION REPLACEMENT UNDER A DELAYED REQUEST (finding 1, case
//        A): the publish is reviewed against epoch E, revision N and spec A
//        and HELD in the browser before it reaches the appliance; a
//        replace-mode config IMPORT installs spec B at the SAME revision N
//        (the epoch is unchanged); the request is then released. The
//        appliance must REFUSE it (it passes the revision fence and the epoch
//        check as shipped) and commit nothing; the page must not report a
//        commit.
//   R13  EVICTED COMMIT + RESTORE OF ITS ORIGINAL BASE (finding 1, case B):
//        a publish commits but its response is lost; enough later operations
//        evict it from both bounded histories; a replace-mode import restores
//        the base it was reviewed against (same revision, same spec) and the
//        same draft is saved again. Recover must keep the operation
//        UNRESOLVED with BROKEN continuity and WITHHOLD the re-send — as
//        shipped it reports "history evidence is bounded" and OFFERS the
//        re-send, which would run the operation a SECOND time.
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page } from "@playwright/test";
import { AUTH_URL, USERS } from "./fixtures";

const ROUTE = "/app/network/pac";
const KEY = "culvert.pac.lifecycle-recovery.v1";
const SUFFIX = "r3" + Date.now().toString(36).slice(-5);
const POOL_ID = `e2ec3pool${SUFFIX}`;
const PROF_A = `e2ec3profa${SUFFIX}`;
const PROF_B = `e2ec3profb${SUFFIX}`;
const NAME_A = `E2E PAC C3-A ${SUFFIX}`;
const NAME_B = `E2E PAC C3-B ${SUFFIX}`;

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
      name: `E2E pool C3 ${SUFFIX}`,
      endpoints: [{ host: "proxy-c3.e2e.test", port: 3128 }],
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

const DRAFT_RULES = [
  {
    kind: "domain",
    pattern: "cont.e2e.test",
    action: "use_pool",
    poolId: POOL_ID,
  },
];

/** Replace-mode config import of exactly these PAC profiles (+ the fixture
 * pool): the path that keeps positive imported revisions verbatim. */
async function importReplace(
  api: APIRequestContext,
  profiles: unknown[],
): Promise<void> {
  const resp = await api.post("/api/config/import?mode=replace", {
    data: {
      version: 2,
      pacProfiles: profiles,
      pacPools: [
        {
          id: POOL_ID,
          name: `E2E pool C3 ${SUFFIX}`,
          endpoints: [{ host: "proxy-c3.e2e.test", port: 3128 }],
        },
      ],
    },
  });
  expect(resp.status(), await resp.text()).toBe(200);
}

function activeSpec(name: string, revision: number): unknown {
  return {
    id: PROF_A,
    name,
    description: "2F-E correction fixture",
    enabled: true,
    poolId: POOL_ID,
    rules: [],
    privateNetworks: "proxy",
    availabilityMode: "secure",
    revision,
  };
}

async function profileOf(
  api: APIRequestContext,
  id: string,
): Promise<Record<string, unknown>> {
  const resp = await api.get(`/api/pac/profiles/${id}`);
  expect(resp.ok()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v)) throw new Error("bad profile");
  return v;
}

// ── R12 ─────────────────────────────────────────────────────────────────────

test("R12 a publish held before the appliance and released after a same-revision replace import is refused and commits nothing", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.121");
  try {
    await seed(api, false);
    await saveDraft(api, PROF_A, NAME_A, DRAFT_RULES);
    await openProfile(page, NAME_A);
    const before = await lifecycle(api, PROF_A);
    expect(num(before, "activeRevision")).toBe(1);
    expect(num(before, "activeN")).toBe(0);
    // hold the dispatch in the browser until the fixture says so
    let held = false;
    let release: () => void = () => {};
    const gate = new Promise<void>((r) => {
      release = r;
    });
    await page.route(
      `**/api/pac/profiles/${PROF_A}/lifecycle`,
      async (route) => {
        if (route.request().method() !== "POST") {
          await route.continue();
          return;
        }
        held = true;
        await gate;
        await route.continue();
      },
    );
    await clickPublish(page);
    await expect.poll(() => held).toBe(true);
    // spec B lands at the SAME revision 1 through the replace import
    await importReplace(api, [activeSpec(`${NAME_A} replaced by import`, 1)]);
    const replaced = await profileOf(api, PROF_A);
    expect(num(replaced, "revision")).toBe(1);
    expect(str(replaced, "name")).toBe(`${NAME_A} replaced by import`);
    expect(str(await lifecycle(api, PROF_A), "activeSpecDigest")).not.toBe(
      str(before, "activeSpecDigest"),
    );
    release();
    // the page reports a refusal, never a commit
    await expect(
      page.getByText(/stale|refused|epoch|continuity/i).first(),
    ).toBeVisible();
    await expect(
      page.getByRole("status").filter({ hasText: /^Published/ }),
    ).toHaveCount(0);
    const after = await lifecycle(api, PROF_A);
    expect(num(after, "activeN")).toBe(0);
    expect(num(after, "activeRevision")).toBe(1);
    expect(str(await profileOf(api, PROF_A), "name")).toBe(
      `${NAME_A} replaced by import`,
    );
    expect(await markerRaw(page)).toBeNull();
  } finally {
    await cleanup(api);
    await api.dispose();
  }
});

// ── R13 ─────────────────────────────────────────────────────────────────────

test("R13 an evicted commit whose original base is restored by a replace import stays unresolved with broken continuity and the re-send is withheld", async ({
  page,
}) => {
  test.setTimeout(240_000);
  const api = await newAdminClient("198.51.100.122");
  // the admin plane allows 60 mutations per minute PER CLIENT IP; the
  // eviction below needs more, so it draws from three further synthetic
  // client identities (the harness trusts loopback as a reverse proxy)
  const evictors = await Promise.all(
    ["198.51.100.123", "198.51.100.124", "198.51.100.125"].map(newAdminClient),
  );
  try {
    await seed(api, false);
    await saveDraft(api, PROF_A, NAME_A, DRAFT_RULES);
    const calls = trackApiRequests(page);
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
    let lc = await lifecycle(api, PROF_A);
    expect(num(lc, "activeN")).toBe(1);
    expect(num(lc, "activeRevision")).toBe(2);
    // evict the commit from BOTH bounded histories
    const cap = num(lc, "operationsCap");
    for (let i = 0; i < cap + 2; i++) {
      const ev = evictors[i % evictors.length];
      if (ev === undefined) throw new Error("no evictor client");
      await publishViaApi(ev, PROF_A, NAME_A, `evict${String(i)}`);
    }
    const look = await api.get(
      `/api/pac/profiles/${PROF_A}/lifecycle?operationId=${opId}`,
    );
    expect(look.ok()).toBe(true);
    const lookBody: unknown = await look.json();
    if (!isRecord(lookBody) || !isRecord(lookBody["operation"]))
      throw new Error("bad lookup");
    expect(lookBody["operation"]["found"]).toBe(false);
    expect(num(lookBody, "operationsRetained")).toBe(cap);
    // the ORIGINAL base (revision 1, the seeded spec) is restored through
    // the replace import; the same draft is saved again
    await importReplace(api, [activeSpec(NAME_A, 1)]);
    await saveDraft(api, PROF_A, NAME_A, DRAFT_RULES);
    lc = await lifecycle(api, PROF_A);
    expect(num(lc, "activeRevision")).toBe(1);
    await page.getByRole("button", { name: "Recover" }).click();
    await expect(
      page.getByRole("status").filter({ hasText: /continuity is broken/i }),
    ).toBeVisible();
    await expect(
      page.getByRole("status").filter({ hasText: /evidence is bounded/i }),
    ).toHaveCount(0);
    await expect(page.getByRole("button", { name: /^Re-send/ })).toHaveCount(0);
    expect(await markerRaw(page)).not.toBeNull();
    await expect(
      page.getByRole("button", { name: "Publish", exact: true }),
    ).toBeDisabled();
    // nothing was dispatched from the page beyond the lost attempt
    const posts = calls.filter(
      (c) => c.method === "POST" && c.path.endsWith("/lifecycle"),
    );
    expect(posts).toHaveLength(1);
    expect(num(await lifecycle(api, PROF_A), "activeRevision")).toBe(1);
  } finally {
    await cleanup(api);
    await api.dispose();
    for (const ev of evictors) await ev.dispose();
  }
});
