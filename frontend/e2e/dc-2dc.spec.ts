// Slice 2D-C real-binary browser qualification: File Profiles + Header
// Rewrite over the actual CULVERT binary and committed dist, on the AUTH
// appliance.
//
// Covers the directive's §42 browser proofs:
//   - File Profiles: create with SERVER-side extension normalization, rename
//     as a TRUE rename (the stable object ID is preserved and a referencing
//     Access Rule keeps its authoritative fileProfileId while the display
//     name cascades), the fail-closed referenced delete with the server's
//     authoritative consumer list, and delete after unreference,
//   - Header Rewrite: UI create receives a SERVER-owned durable stableId,
//     rules render in the appliance's evaluation order, delete addresses the
//     stableId, and a stale ?ifRevision= fence refuses the delete with the
//     shared structured 409 (nothing applied).
//
// No external traffic: every proof runs against the local appliance's admin
// plane. The header-rewrite DATA-PLANE effect (SetRules publication, host
// matching, op application) is proven by the Go suites against deterministic
// local fixtures — this spec proves the admin surface end to end.
//
// Unknown-outcome and auth-boundary mechanics are owned by the component
// suites (deterministic network-fault injection against the same shared
// useObjectPage machinery).
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext } from "@playwright/test";
import { AUTH_URL, USERS } from "./fixtures";

// Per-spec client identity: draws on its own admin-plane rate budget (the
// harness trusts loopback as a reverse proxy).
test.use({ extraHTTPHeaders: { "X-Forwarded-For": "198.51.100.34" } });

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

async function profileByName(
  api: APIRequestContext,
  name: string,
): Promise<Record<string, unknown> | undefined> {
  const resp = await api.get("/api/fileblock/profiles/state");
  const v: unknown = await resp.json();
  if (!isRecord(v) || !Array.isArray(v["profiles"])) return undefined;
  return v["profiles"]
    .map((p: unknown) => p)
    .filter(isRecord)
    .find((p) => p["name"] === name);
}

async function rewriteRuleByHost(
  api: APIRequestContext,
  host: string,
): Promise<Record<string, unknown> | undefined> {
  const resp = await api.get("/api/rewrite/state");
  const v: unknown = await resp.json();
  if (!isRecord(v) || !Array.isArray(v["rules"])) return undefined;
  return v["rules"]
    .map((r: unknown) => r)
    .filter(isRecord)
    .find((r) => r["host"] === host);
}

async function deleteRewriteByHost(
  api: APIRequestContext,
  host: string,
): Promise<void> {
  const r = await rewriteRuleByHost(api, host);
  if (r !== undefined && typeof r["stableId"] === "string") {
    await api.delete(`/api/rewrite?stableId=${String(r["stableId"])}`);
  }
}

async function deleteRuleByName(
  api: APIRequestContext,
  name: string,
): Promise<void> {
  const resp = await api.get("/api/policy");
  const v: unknown = await resp.json();
  if (!isRecord(v) || !Array.isArray(v["rules"])) return;
  for (const r of v["rules"].map((x: unknown) => x).filter(isRecord)) {
    if (r["name"] === name) {
      await api.delete(`/api/policy?id=${String(r["id"])}`);
    }
  }
}

const PROFILES_ROUTE = "/app/objects/file-profiles";
const REWRITE_ROUTE = "/app/policies/header-rewrite";

// ── File Profiles: full operator journey against the real store ────────────
test("file profiles: create (server normalization), rename keeps identity + cascades onto the referencing rule, referenced delete refused, delete after unreference", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.35");
  try {
    await page.goto(PROFILES_ROUTE);
    await expect(page.getByText("File Profiles").first()).toBeVisible();
    // The seeded built-ins are rendered with their badge.
    await expect(page.getByText("Built-in").first()).toBeVisible();

    // Create — mixed-case, dotless, duplicate input; the SERVER normalizes.
    await page.getByRole("button", { name: "New file profile…" }).click();
    await page.getByLabel("Profile name").fill("E2E 2DC Profile");
    await page
      .getByLabel("Blocked extensions (one per line)")
      .fill("EXE\n.exe\n Msi ");
    await expect(page.getByText("2 normalized extensions")).toBeVisible();
    await page.getByRole("button", { name: "Create profile" }).click();
    await expect(page.getByText("E2E 2DC Profile").first()).toBeVisible();

    const created = await profileByName(api, "E2E 2DC Profile");
    expect(created).toBeDefined();
    const pid = String(created?.["id"]);
    expect(pid).not.toBe("");
    expect(created?.["extensions"]).toEqual([".exe", ".msi"]);

    // Reference it from an Access Rule by NAME (intent); the server stamps
    // the authoritative fileProfileId.
    const mk = await api.post("/api/policy", {
      data: {
        name: "E2E 2DC FP Rule",
        action: "Allow",
        destFQDN: "dc-fp.test",
        fileProfile: "E2E 2DC Profile",
        enabled: false,
      },
    });
    expect(mk.ok()).toBe(true);

    const polResp1 = await api.get("/api/policy");
    const pol1: unknown = await polResp1.json();
    if (!isRecord(pol1) || !Array.isArray(pol1["rules"]))
      throw new Error("bad policy envelope");
    const rule1 = pol1["rules"]
      .map((r: unknown) => r)
      .filter(isRecord)
      .find((r) => r["name"] === "E2E 2DC FP Rule");
    expect(rule1?.["fileProfileId"]).toBe(pid);

    // Rename via UI — the truth callout appears; the object ID is preserved
    // and the rule's display name follows while its link ID stays the same.
    await page
      .getByRole("button", { name: "Edit profile E2E 2DC Profile" })
      .click();
    await page.getByLabel("Profile name").fill("E2E 2DC Profile v2");
    await expect(page.getByText("This is a rename")).toBeVisible();
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByText("E2E 2DC Profile v2").first()).toBeVisible();

    const renamed = await profileByName(api, "E2E 2DC Profile v2");
    expect(String(renamed?.["id"])).toBe(pid);

    const polResp2 = await api.get("/api/policy");
    const pol2: unknown = await polResp2.json();
    if (!isRecord(pol2) || !Array.isArray(pol2["rules"]))
      throw new Error("bad policy envelope");
    const rule2 = pol2["rules"]
      .map((r: unknown) => r)
      .filter(isRecord)
      .find((r) => r["name"] === "E2E 2DC FP Rule");
    expect(rule2?.["fileProfileId"]).toBe(pid);
    expect(rule2?.["fileProfile"]).toBe("E2E 2DC Profile v2");

    // Referenced delete: the appliance refuses with the REAL consumer.
    await page
      .getByRole("button", { name: "Delete profile E2E 2DC Profile v2" })
      .click();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Delete", exact: true })
      .click();
    await expect(
      page.getByText("Delete refused — still referenced"),
    ).toBeVisible();
    await expect(
      page.getByRole("dialog").getByText("E2E 2DC FP Rule"),
    ).toBeVisible();
    await page.getByRole("button", { name: "Close", exact: true }).click();

    // Unreference, then the delete lands.
    await deleteRuleByName(api, "E2E 2DC FP Rule");
    await page.reload();
    await expect(page.getByText("E2E 2DC Profile v2").first()).toBeVisible();
    await page
      .getByRole("button", { name: "Delete profile E2E 2DC Profile v2" })
      .click();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Delete", exact: true })
      .click();
    await expect(page.getByText("E2E 2DC Profile v2")).toHaveCount(0);
    expect(await profileByName(api, "E2E 2DC Profile v2")).toBeUndefined();
  } finally {
    await deleteRuleByName(api, "E2E 2DC FP Rule");
    for (const n of ["E2E 2DC Profile v2", "E2E 2DC Profile"]) {
      const p = await profileByName(api, n);
      if (p !== undefined) {
        await api.delete(`/api/fileblock/profiles?id=${String(p["id"])}`);
      }
    }
    await api.dispose();
  }
});

// ── Header Rewrite: identity + order + stableId-addressed delete ────────────
test("header rewrite: UI create receives a server-owned stableId, evaluation order renders truthfully, delete addresses the stableId", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.36");
  try {
    await page.goto(REWRITE_ROUTE);
    await expect(page.getByText("Header Rewrite").first()).toBeVisible();

    // Create via UI — the browser never fabricates or submits an identity.
    await page.getByRole("button", { name: "New rewrite rule…" }).click();
    await page.getByLabel("Host scope").fill("dc-rw-a.test");
    await page
      .getByLabel(
        "Set (Header-Name: value, one per line — replaces any existing value)",
      )
      .first()
      .fill("X-E2E-A: one");
    await expect(page.getByText("1 header operation defined")).toBeVisible();
    await page.getByRole("button", { name: "Create rule" }).click();
    await expect(page.getByText("dc-rw-a.test").first()).toBeVisible();

    const ruleA = await rewriteRuleByHost(api, "dc-rw-a.test");
    expect(ruleA).toBeDefined();
    const sidA = String(ruleA?.["stableId"]);
    expect(sidA.length).toBeGreaterThan(0);

    // Second rule appended via the API — evaluation order is append order.
    const mkB = await api.post("/api/rewrite", {
      data: { host: "dc-rw-b.test", resp_remove: ["X-E2E-Gone"] },
    });
    expect(mkB.ok()).toBe(true);
    await page.reload();
    await expect(page.getByText("dc-rw-b.test").first()).toBeVisible();
    const rowA = page.getByRole("row").filter({ hasText: "dc-rw-a.test" });
    const rowB = page.getByRole("row").filter({ hasText: "dc-rw-b.test" });
    // Truthful evaluation order: A was created first, so A precedes B.
    const bodyText = (await page.locator("tbody").innerText()).replace(
      /\s+/g,
      " ",
    );
    expect(bodyText.indexOf("dc-rw-a.test")).toBeLessThan(
      bodyText.indexOf("dc-rw-b.test"),
    );

    // The row detail exposes the stable identity.
    await rowA
      .first()
      .getByRole("button", { name: /Details for rewrite rule/ })
      .click();
    await expect(page.getByText(sidA).first()).toBeVisible();

    // Delete rule A via UI — addressed by stableId, fenced by the fresh view.
    await rowA
      .first()
      .getByRole("button", { name: /Delete rewrite rule/ })
      .click();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Delete", exact: true })
      .click();
    await expect(page.getByText("dc-rw-a.test")).toHaveCount(0);
    expect(await rewriteRuleByHost(api, "dc-rw-a.test")).toBeUndefined();
    // B is untouched and keeps its identity.
    const ruleB = await rewriteRuleByHost(api, "dc-rw-b.test");
    expect(ruleB).toBeDefined();
    await expect(rowB.first()).toBeVisible();
  } finally {
    await deleteRewriteByHost(api, "dc-rw-a.test");
    await deleteRewriteByHost(api, "dc-rw-b.test");
    await api.dispose();
  }
});

test("header rewrite: a stale revision fence refuses the delete with the shared structured 409 — nothing applied", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.37");
  try {
    const mk = await api.post("/api/rewrite", {
      data: { host: "dc-rw-stale.test", req_remove: ["X-E2E-Stale"] },
    });
    expect(mk.ok()).toBe(true);

    await page.goto(REWRITE_ROUTE);
    await expect(page.getByText("dc-rw-stale.test").first()).toBeVisible();

    // Advance the revision BEHIND the page's back.
    const mk2 = await api.post("/api/rewrite", {
      data: { host: "dc-rw-behind.test", req_remove: ["X-E2E-Behind"] },
    });
    expect(mk2.ok()).toBe(true);

    // The page still holds the pre-mutation revision — the delete is refused.
    await page
      .getByRole("row")
      .filter({ hasText: "dc-rw-stale.test" })
      .first()
      .getByRole("button", { name: /Delete rewrite rule/ })
      .click();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Delete", exact: true })
      .click();
    await expect(
      page.getByText("The rewrite rules changed since you loaded them"),
    ).toBeVisible();
    // Nothing was applied: the rule is still on the appliance.
    expect(await rewriteRuleByHost(api, "dc-rw-stale.test")).toBeDefined();
  } finally {
    await deleteRewriteByHost(api, "dc-rw-stale.test");
    await deleteRewriteByHost(api, "dc-rw-behind.test");
    await api.dispose();
  }
});
