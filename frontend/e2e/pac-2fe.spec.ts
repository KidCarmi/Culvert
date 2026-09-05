// 2F-E real-binary browser journeys: the PAC surface at /app/network/pac
// over the actual CULVERT binary on the AUTH appliance (never a mock).
//
// Directive §5 proofs:
//   1. Viewer inspects every tab; ZERO write controls mount; ZERO non-GET
//      requests; the lifecycle/exception surfaces say node-local.
//   2. Admin lifecycle: publish a reviewed draft (proven commit, history
//      revision 1), publish a second revision, roll back to 1 through the
//      Tier-2 ceremony — every step against the real intent state machine.
//   3. STALE WRITE: a concurrent publish through the API moves the active
//      revision; the page's publish carries the revision it reviewed and the
//      appliance refuses 409 stale; the page renders the server's current
//      token and issues exactly one POST (no auto-retry).
//   4. DIRECT CHALLENGE INVALIDATION: a draft introducing a DIRECT rule
//      draws the bound challenge; the referenced pool is changed underneath
//      it; the typed confirmation is refused challenge_stale naming
//      poolDigest; after a refresh a FRESH challenge is issued and the
//      publish lands.
//   5. LOST RESPONSE: the publish POST reaches the appliance but its
//      response is dropped; the page latches UNKNOWN with the operation
//      identity it persisted BEFORE dispatch; "Recover" resolves LANDED
//      from the lifecycle GET (the decided operation carries our id) and
//      only then is a fresh dispatch allowed.
//   6. The journey stays on its own surface (no cross-surface API calls).
//
// Everything created is removed in finally blocks through the fenced API
// (profile then pool), so the shared appliance ends the spec unchanged.
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page } from "@playwright/test";
import { AUTH_URL, EMPTY_STATE, USERS } from "./fixtures";

const ROUTE = "/app/network/pac";
const SUFFIX = Date.now().toString(36).slice(-6);
const POOL_ID = `e2epool${SUFFIX}`;
const PROFILE_ID = `e2eprof${SUFFIX}`;
const PROFILE_NAME = `E2E PAC ${SUFFIX}`;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
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
): Promise<Record<string, unknown>> {
  const resp = await api.get(`/api/pac/profiles/${PROFILE_ID}/lifecycle`);
  expect(resp.ok()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v)) throw new Error("bad lifecycle");
  return v;
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

async function seedPoolAndProfile(api: APIRequestContext): Promise<void> {
  const l = await listing(api);
  const pool = await api.post("/api/pac/pools", {
    data: {
      id: POOL_ID,
      name: `E2E pool ${SUFFIX}`,
      endpoints: [{ host: "proxy-a.e2e.test", port: 3128 }],
      collectionEtag: str(l, "collectionEtag"),
    },
  });
  expect(pool.status(), await pool.text()).toBe(200);
  const l2 = await listing(api);
  const prof = await api.post("/api/pac/profiles", {
    data: {
      id: PROFILE_ID,
      name: PROFILE_NAME,
      description: "2F-E browser journey fixture",
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

async function saveDraft(
  api: APIRequestContext,
  rules: unknown[],
  availabilityMode = "secure",
): Promise<void> {
  const lc = await lifecycle(api);
  const draft = {
    id: PROFILE_ID,
    name: PROFILE_NAME,
    description: "2F-E browser journey fixture",
    enabled: true,
    poolId: POOL_ID,
    rules,
    privateNetworks: "proxy",
    availabilityMode,
    revision: 0,
  };
  const resp = await api.post(`/api/pac/profiles/${PROFILE_ID}/lifecycle`, {
    data: {
      action: "save_draft",
      draft,
      draftRevision: num(lc, "draftRevision"),
    },
  });
  expect(resp.status(), await resp.text()).toBe(200);
}

async function publishViaApi(api: APIRequestContext): Promise<void> {
  const lc = await lifecycle(api);
  const draft = lc["draft"];
  const resp = await api.post(`/api/pac/profiles/${PROFILE_ID}/lifecycle`, {
    data: {
      action: "publish",
      operationId: crypto.randomUUID(),
      draft,
      expectedActiveRevision: num(lc, "activeRevision"),
      collectionEtag: str(lc, "collectionEtag"),
      reason: "concurrent admin",
    },
  });
  expect(resp.status(), await resp.text()).toBe(200);
}

async function cleanup(api: APIRequestContext): Promise<void> {
  const l = await listing(api);
  const profiles = Array.isArray(l["profiles"]) ? l["profiles"] : [];
  for (const p of profiles) {
    if (isRecord(p) && p["id"] === PROFILE_ID) {
      const del = await api.delete(
        `/api/pac/profiles/${PROFILE_ID}?revision=${String(p["revision"])}`,
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

async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}

function trackApiRequests(page: Page): Array<{ method: string; path: string }> {
  const calls: Array<{ method: string; path: string }> = [];
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.pathname.startsWith("/api/")) {
      calls.push({ method: r.method(), path: u.pathname });
    }
  });
  return calls;
}

const ALLOWED_PREFIXES = [
  "/api/pac/",
  "/api/pac-config",
  "/api/auth/",
  "/api/setup/",
  "/api/session",
];
function assertNoCrossSurface(
  calls: ReadonlyArray<{ method: string; path: string }>,
): void {
  for (const c of calls) {
    expect(
      ALLOWED_PREFIXES.some((p) => c.path.startsWith(p)),
      `unexpected cross-surface call ${c.method} ${c.path}`,
    ).toBe(true);
  }
}

const MUTATION_WORDS = [
  "Publish",
  "Save draft",
  "New profile",
  "New pool",
  "Delete",
  "Roll back",
  "Acknowledge",
  "Repair",
  "Save",
  "Clear",
  "Recover",
];

async function openProfile(page: Page): Promise<void> {
  await page.goto(ROUTE);
  await expect(
    page.getByRole("heading", { name: "PAC", exact: false }),
  ).toBeVisible();
  await page.getByRole("tab", { name: "Profiles" }).click();
  const row = page.getByRole("row", { name: new RegExp(PROFILE_NAME) });
  await expect(row).toBeVisible();
  await row.getByRole("button", { name: "Open" }).click();
  await expect(page.getByText("Active revision")).toBeVisible();
}

// ── 1 + 6: viewer ───────────────────────────────────────────────────────────
test.describe("viewer posture", () => {
  test.use({ storageState: EMPTY_STATE });
  test("viewer reads every tab; zero mutation controls; zero non-GET requests; node-local labels", async ({
    page,
  }) => {
    const api = await newAdminClient("198.51.100.90");
    try {
      await seedPoolAndProfile(api);
      const calls = trackApiRequests(page);
      await page.goto(ROUTE);
      await login(page, USERS.viewer.user, USERS.viewer.pass);
      await expect(
        page.getByRole("heading", { name: "PAC", exact: false }),
      ).toBeVisible();
      await page.getByRole("tab", { name: "Profiles" }).click();
      const row = page.getByRole("row", { name: new RegExp(PROFILE_NAME) });
      await expect(row).toBeVisible();
      await row.getByRole("button", { name: "Open" }).click();
      await expect(page.getByText("Active revision")).toBeVisible();
      await expect(page.getByText(/node-local/i).first()).toBeVisible();
      for (const tab of [
        "Pools",
        "DIRECT Exceptions",
        "Legacy PAC",
        "Profiles",
      ]) {
        await page.getByRole("tab", { name: tab }).click();
      }
      const texts = await page.getByRole("button").allTextContents();
      const offending = texts.filter((t) =>
        MUTATION_WORDS.some((w) => t.includes(w)),
      );
      expect(offending).toEqual([]);
      const mutating = calls.filter(
        (c) => c.method !== "GET" && !c.path.startsWith("/api/auth/"),
      );
      expect(mutating).toEqual([]);
      assertNoCrossSurface(calls);
    } finally {
      await cleanup(api);
      await api.dispose();
    }
  });
});

// ── 2: admin lifecycle — publish, second revision, rollback ────────────────
test("admin: publish (revision 1), publish again (revision 2), roll back to 1 through the T2 ceremony", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.91");
  try {
    await seedPoolAndProfile(api);
    const calls = trackApiRequests(page);
    await openProfile(page);
    await page.getByRole("button", { name: "Publish", exact: true }).click();
    await page.getByRole("button", { name: "Publish now" }).click();
    await expect(
      page.getByText("Published", { exact: false }).first(),
    ).toBeVisible();
    await expect.poll(async () => num(await lifecycle(api), "activeN")).toBe(1);
    // second revision: a use_pool rule saved through the API, reviewed and published in the browser
    await saveDraft(api, [
      {
        kind: "domain",
        pattern: "app.e2e.test",
        action: "use_pool",
        poolId: POOL_ID,
      },
    ]);
    await page.getByRole("button", { name: "Refresh" }).first().click();
    await expect(page.getByText("app.e2e.test")).toBeVisible();
    await page.getByRole("button", { name: "Publish", exact: true }).click();
    await page.getByRole("button", { name: "Publish now" }).click();
    await expect.poll(async () => num(await lifecycle(api), "activeN")).toBe(2);
    // roll back to revision 1
    await page.getByRole("button", { name: "Roll back to 1" }).click();
    await page.getByRole("button", { name: "Roll back now" }).click();
    await expect(
      page.getByText("Rolled back", { exact: false }).first(),
    ).toBeVisible();
    await expect.poll(async () => num(await lifecycle(api), "activeN")).toBe(3);
    const lc = await lifecycle(api);
    const active = lc["active"];
    // `rules` is omitempty on the wire: an absent key IS the empty list.
    expect(
      isRecord(active)
        ? Array.isArray(active["rules"])
          ? active["rules"].length
          : active["rules"] === undefined
            ? 0
            : -1
        : -1,
    ).toBe(0);
    assertNoCrossSurface(calls);
  } finally {
    await cleanup(api);
    await api.dispose();
  }
});

// ── 3: stale write ──────────────────────────────────────────────────────────
test("admin: a concurrent publish makes the page's reviewed revision stale; 409 stale is rendered with the current token and never auto-retried", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.92");
  try {
    await seedPoolAndProfile(api);
    await saveDraft(api, [
      {
        kind: "domain",
        pattern: "one.e2e.test",
        action: "use_pool",
        poolId: POOL_ID,
      },
    ]);
    const calls = trackApiRequests(page);
    await openProfile(page);
    const reviewed = num(await lifecycle(api), "activeRevision");
    // the OTHER admin publishes first
    await publishViaApi(api);
    const moved = num(await lifecycle(api), "activeRevision");
    expect(moved).toBe(reviewed + 1);
    await page.getByRole("button", { name: "Publish", exact: true }).click();
    await page.getByRole("button", { name: "Publish now" }).click();
    await expect(
      page.getByText(`current revision ${String(moved)}`),
    ).toBeVisible();
    const posts = calls.filter(
      (c) => c.method === "POST" && c.path.endsWith("/lifecycle"),
    );
    expect(posts).toHaveLength(1);
    expect(num(await lifecycle(api), "activeRevision")).toBe(moved);
    assertNoCrossSurface(calls);
  } finally {
    await cleanup(api);
    await api.dispose();
  }
});

// ── 4: DIRECT challenge invalidation ────────────────────────────────────────
test("admin: the bound DIRECT challenge is invalidated by a pool change underneath it; a fresh challenge then lands", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.93");
  try {
    await seedPoolAndProfile(api);
    await saveDraft(
      api,
      [{ kind: "domain", pattern: "intranet.e2e.test", action: "direct" }],
      "balanced",
    );
    const calls = trackApiRequests(page);
    await openProfile(page);
    await page.getByRole("button", { name: "Publish", exact: true }).click();
    await page.getByRole("button", { name: "Publish now" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByText("intranet.e2e.test")).toBeVisible();
    const word = await dialog.getByTestId("pac-confirm-value").textContent();
    expect(word).toMatch(new RegExp(`^${PROFILE_ID}:[0-9a-f]{8}$`));
    // the referenced pool changes underneath the reviewed challenge
    const pools = await api.get("/api/pac/pools");
    const list: unknown = await pools.json();
    const mine: unknown = Array.isArray(list)
      ? list.find((p: unknown) => isRecord(p) && p["id"] === POOL_ID)
      : undefined;
    if (!isRecord(mine)) throw new Error("pool missing");
    const upd = await api.put(`/api/pac/pools/${POOL_ID}`, {
      data: {
        id: POOL_ID,
        name: `E2E pool ${SUFFIX}`,
        endpoints: [{ host: "proxy-b.e2e.test", port: 3128 }],
        etag: str(mine, "etag"),
      },
    });
    expect(upd.status(), await upd.text()).toBe(200);
    await dialog.getByLabel(/Type/).fill(word ?? "");
    await dialog.getByRole("button", { name: "Publish bypass" }).click();
    await expect(page.getByText("poolDigest")).toBeVisible();
    await expect(page.getByText(/changed/).first()).toBeVisible();
    expect(num(await lifecycle(api), "activeN")).toBe(0);
    // fresh review: refresh, publish again, a NEW challenge is issued
    await page.getByRole("button", { name: "Refresh" }).first().click();
    await page.getByRole("button", { name: "Publish", exact: true }).click();
    await page.getByRole("button", { name: "Publish now" }).click();
    const dialog2 = page.getByRole("dialog");
    const word2 = await dialog2.getByTestId("pac-confirm-value").textContent();
    expect(word2).toMatch(new RegExp(`^${PROFILE_ID}:[0-9a-f]{8}$`));
    await dialog2.getByLabel(/Type/).fill(word2 ?? "");
    await dialog2.getByRole("button", { name: "Publish bypass" }).click();
    await expect(
      page.getByText("Published", { exact: false }).first(),
    ).toBeVisible();
    await expect.poll(async () => num(await lifecycle(api), "activeN")).toBe(1);
    assertNoCrossSurface(calls);
  } finally {
    await cleanup(api);
    await api.dispose();
  }
});

// ── 5: lost response → authoritative recovery ───────────────────────────────
test("admin: a publish whose response is lost latches UNKNOWN with the persisted operation id; Recover resolves LANDED from the lifecycle GET", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.94");
  try {
    await seedPoolAndProfile(api);
    await saveDraft(api, [
      {
        kind: "domain",
        pattern: "lost.e2e.test",
        action: "use_pool",
        poolId: POOL_ID,
      },
    ]);
    const calls = trackApiRequests(page);
    await openProfile(page);
    // the request reaches the appliance; its response never reaches the page
    await page.route(
      `**/api/pac/profiles/${PROFILE_ID}/lifecycle`,
      async (route) => {
        if (route.request().method() !== "POST") {
          await route.continue();
          return;
        }
        await route.fetch();
        await route.abort("connectionreset");
      },
    );
    await page.getByRole("button", { name: "Publish", exact: true }).click();
    await page.getByRole("button", { name: "Publish now" }).click();
    await expect(page.getByText(/unknown/i).first()).toBeVisible();
    const marker = await page.evaluate(() =>
      sessionStorage.getItem("culvert.pac.lifecycle-recovery.v1"),
    );
    expect(marker).not.toBeNull();
    const parsed: unknown = JSON.parse(marker ?? "{}");
    const opId = isRecord(parsed) ? String(parsed["operationId"]) : "";
    expect(opId).toMatch(/^[0-9a-f-]{36}$/);
    await page.unroute(`**/api/pac/profiles/${PROFILE_ID}/lifecycle`);
    // the appliance decided it: the operation is in the lifecycle's decided ring
    const lc = await lifecycle(api);
    const ops = Array.isArray(lc["operations"]) ? lc["operations"] : [];
    expect(ops.some((o) => isRecord(o) && o["operationId"] === opId)).toBe(
      true,
    );
    await expect(
      page.getByRole("button", { name: "Publish", exact: true }),
    ).toBeDisabled();
    await page.getByRole("button", { name: "Recover" }).click();
    await expect(page.getByText(/landed/i).first()).toBeVisible();
    expect(
      await page.evaluate(() =>
        sessionStorage.getItem("culvert.pac.lifecycle-recovery.v1"),
      ),
    ).toBeNull();
    await expect(
      page.getByRole("button", { name: "Publish", exact: true }),
    ).toBeEnabled();
    const posts = calls.filter(
      (c) => c.method === "POST" && c.path.endsWith("/lifecycle"),
    );
    expect(posts).toHaveLength(1);
    expect(num(await lifecycle(api), "activeN")).toBe(1);
    assertNoCrossSurface(calls);
  } finally {
    await cleanup(api);
    await api.dispose();
  }
});
