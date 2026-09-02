// Slice 2D-A real-binary browser qualification: the shared-object management
// surfaces (Category Groups + Decryption Profiles) over the actual CULVERT
// binary and committed dist, on the AUTH appliance.
//
// Covers the directive's §28 browser proofs:
//   - viewer read posture + operator CRUD journeys on both object kinds,
//   - rename by STABLE object ID: referencing Access Rules keep the same
//     authoritative link ID while the display name follows (server cascade),
//   - Where Used + the fail-closed referenced delete with the server's
//     authoritative consumer list,
//   - decryption enum/inherit fidelity (tri-state HTTP/2, no "permissive",
//     the pre-save fail-open adaptive-exclusion warning),
//   - active-draft interaction: a draft-only reference follows a rename and
//     commits cleanly to the SAME object ID; a rename cascading onto RUNNING
//     rules truthfully stales the draft base (the implementation's actual
//     behavior — commit is fenced until review),
//   - auth boundary: signing out clears open object-editor state.
//
// Unknown-outcome mechanics are owned by the component suites (deterministic
// network-fault injection); the page-level latch is proven there.
//
// Staging/cleanup mutations run through dedicated API clients with distinct
// X-Forwarded-For identities (the harness trusts loopback as a reverse
// proxy), so this spec's API traffic draws on its own admin-plane rate
// budgets instead of the suite-shared 127.0.0.1 budget.
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page } from "@playwright/test";
import { AUTH_URL, EMPTY_STATE, USERS } from "./fixtures";

// This spec's BROWSER traffic carries its own client identity (the harness
// trusts loopback as a reverse proxy), so its mutation burst draws on a
// per-spec admin-plane rate budget instead of the suite-shared 127.0.0.1
// budget (the deliberate 60-mutations/min posture stays armed per identity).
test.use({ extraHTTPHeaders: { "X-Forwarded-For": "198.51.100.30" } });

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

async function groupByName(
  api: APIRequestContext,
  name: string,
): Promise<Record<string, unknown> | undefined> {
  const resp = await api.get("/api/category-groups");
  const v: unknown = await resp.json();
  if (!isRecord(v) || !Array.isArray(v["groups"])) return undefined;
  return v["groups"]
    .map((g: unknown) => g)
    .filter(isRecord)
    .find((g) => g["name"] === name);
}

async function profileByName(
  api: APIRequestContext,
  name: string,
): Promise<Record<string, unknown> | undefined> {
  const resp = await api.get("/api/decryption-profiles");
  const v: unknown = await resp.json();
  if (!isRecord(v) || !Array.isArray(v["profiles"])) return undefined;
  return v["profiles"]
    .map((p: unknown) => p)
    .filter(isRecord)
    .find((p) => p["name"] === name);
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

async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}

const GROUPS_ROUTE = "/app/objects/category-groups";
const PROFILES_ROUTE = "/app/objects/decryption-profiles";

// ── Category Groups: full operator journey (create → edit → rename →
// unreferenced delete), all live against the real store ────────────────────
test("category groups: operator CRUD journey — create, edit membership, rename (same object ID), delete", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.20");
  try {
    await page.goto(GROUPS_ROUTE);
    await expect(page.getByText("Category Groups").first()).toBeVisible();

    // Create.
    await page.getByRole("button", { name: "New category group…" }).click();
    await page.getByLabel("Group name").fill("E2E 2D Group");
    await page.getByRole("checkbox", { name: "News", exact: true }).check();
    await page.getByRole("button", { name: "Create group" }).click();
    await expect(page.getByText("E2E 2D Group")).toBeVisible();

    const created = await groupByName(api, "E2E 2D Group");
    expect(created).toBeDefined();
    const gid = String(created?.["id"]);
    expect(gid.length).toBeGreaterThan(0);

    // Edit membership (stable-ID addressed server-side).
    await page.getByRole("button", { name: "Edit group E2E 2D Group" }).click();
    await page.getByRole("checkbox", { name: "Finance" }).check();
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(
      page.getByRole("button", { name: "Edit group E2E 2D Group" }),
    ).toBeVisible();
    const edited = await groupByName(api, "E2E 2D Group");
    expect(edited?.["id"]).toBe(gid);
    expect(edited?.["categories"]).toEqual(
      expect.arrayContaining(["news", "finance"]),
    );

    // Rename — same stable ID, rename truth surfaced.
    await page.getByRole("button", { name: "Edit group E2E 2D Group" }).click();
    await page.getByLabel("Group name").fill("E2E 2D Group Renamed");
    await expect(page.getByText("This is a rename")).toBeVisible();
    await expect(page.getByText("stable object ID is preserved")).toBeVisible();
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByText("E2E 2D Group Renamed")).toBeVisible();
    const renamed = await groupByName(api, "E2E 2D Group Renamed");
    expect(renamed?.["id"]).toBe(gid);
    expect(await groupByName(api, "E2E 2D Group")).toBeUndefined();

    // Unreferenced delete (T1 ceremony; preflight shows no references).
    await page
      .getByRole("button", { name: "Delete group E2E 2D Group Renamed" })
      .click();
    await expect(page.getByText("No references were found")).toBeVisible();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Delete", exact: true })
      .click();
    await expect(
      page.getByRole("button", { name: "Delete group E2E 2D Group Renamed" }),
    ).toBeHidden();
    expect(await groupByName(api, "E2E 2D Group Renamed")).toBeUndefined();
  } finally {
    const leftoverRenamed = await groupByName(api, "E2E 2D Group Renamed");
    if (leftoverRenamed !== undefined) {
      await api.delete(
        `/api/category-groups?id=${String(leftoverRenamed["id"])}`,
      );
    }
    const leftover = await groupByName(api, "E2E 2D Group");
    if (leftover !== undefined) {
      await api.delete(`/api/category-groups?id=${String(leftover["id"])}`);
    }
    await api.dispose();
  }
});

// ── Reference integrity across rename + fail-closed delete (§27/§28) ───────
test("group referenced by an access rule: Where Used finds it, delete is refused with the real consumer, rename keeps the rule's object link", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.21");
  try {
    // Stage: group + running access rule referencing it BY NAME (the server
    // stamps the authoritative ID — the browser never chooses link IDs).
    const cg = await api.post("/api/category-groups", {
      data: { name: "E2E 2D RefGroup", categories: ["news"] },
    });
    expect(cg.ok()).toBe(true);
    const gid = String((await groupByName(api, "E2E 2D RefGroup"))?.["id"]);
    const rule = await api.post("/api/policy", {
      data: {
        name: "E2E 2D RefRule",
        action: "Allow",
        destCategoryGroup: "E2E 2D RefGroup",
        enabled: false,
      },
    });
    expect(rule.ok()).toBe(true);

    await page.goto(GROUPS_ROUTE);
    // Where Used (explicit interest) lists the referencing rule.
    await page
      .getByRole("button", { name: "Details for group E2E 2D RefGroup" })
      .click();
    await page
      .getByRole("button", { name: /Where used: Category group/ })
      .click();
    await expect(page.getByText("E2E 2D RefRule")).toBeVisible();

    // Referenced delete → the server's authoritative 409 with the consumer.
    await page
      .getByRole("button", { name: "Delete group E2E 2D RefGroup" })
      .click();
    await expect(page.getByText("Currently referenced")).toBeVisible();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Delete", exact: true })
      .click();
    await expect(
      page.getByText("Delete refused — still referenced"),
    ).toBeVisible();
    await page.getByRole("button", { name: "Close", exact: true }).click();

    // Rename via UI; the RULE follows the SAME object by ID, new display name.
    await page
      .getByRole("button", { name: "Edit group E2E 2D RefGroup" })
      .click();
    await page.getByLabel("Group name").fill("E2E 2D RefGroup v2");
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(page.getByText("E2E 2D RefGroup v2").first()).toBeVisible();

    const polResp = await api.get("/api/policy");
    const pol: unknown = await polResp.json();
    if (!isRecord(pol) || !Array.isArray(pol["rules"]))
      throw new Error("bad policy envelope");
    const refRule = pol["rules"]
      .map((r: unknown) => r)
      .filter(isRecord)
      .find((r) => r["name"] === "E2E 2D RefRule");
    expect(refRule).toBeDefined();
    expect(refRule?.["destCategoryGroupId"]).toBe(gid);
    expect(refRule?.["destCategoryGroup"]).toBe("E2E 2D RefGroup v2");
  } finally {
    await deleteRuleByName(api, "E2E 2D RefRule");
    for (const n of ["E2E 2D RefGroup v2", "E2E 2D RefGroup"]) {
      const g = await groupByName(api, n);
      if (g !== undefined) {
        await api.delete(`/api/category-groups?id=${String(g["id"])}`);
      }
    }
    await api.dispose();
  }
});

// ── Decryption Profiles: enum/inherit fidelity + fail-open warning + rename ─
test("decryption profiles: create keeps tri-state inherit; fail-open warns before save; rename keeps the stable ID; permissive is never offered", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.22");
  try {
    await page.goto(PROFILES_ROUTE);
    await expect(page.getByText("Decryption Profiles").first()).toBeVisible();

    // Create with everything inherited; the cert select must not offer the
    // retired permissive value.
    await page.getByRole("button", { name: "New decryption profile…" }).click();
    await page.getByLabel("Profile name").fill("e2e-2d-prof");
    const certOptions = await page
      .getByLabel("Certificate verification")
      .locator("option")
      .allTextContents();
    expect(certOptions.join(" ")).not.toContain("permissive");
    // Selecting fail-open surfaces the adaptive-exclusion warning BEFORE save.
    await page.getByLabel("On inspect error").selectOption("fail-open");
    await expect(
      page.getByText("Fail-open enables adaptive decryption exclusion"),
    ).toBeVisible();
    await page.getByLabel("On inspect error").selectOption("fail-close");
    await page.getByRole("button", { name: "Create profile" }).click();
    await expect(
      page.getByRole("button", { name: "Edit profile e2e-2d-prof" }),
    ).toBeVisible();

    // Server truth: tri-state inherit was OMITTED (absent), not false.
    const created = await profileByName(api, "e2e-2d-prof");
    expect(created).toBeDefined();
    const pid = String(created?.["id"]);
    expect("inspectHttp2" in (created ?? {})).toBe(false);
    expect(created?.["onInspectError"]).toBe("fail-close");
    // The UI renders the inherit truth.
    await expect(
      page.getByText("inherit (strip → HTTP/1.1)").first(),
    ).toBeVisible();

    // Rename — same stable ID; the exclusion-scope truth is stated.
    await page
      .getByRole("button", { name: "Edit profile e2e-2d-prof" })
      .click();
    await page.getByLabel("Profile name").fill("e2e-2d-prof-renamed");
    await expect(page.getByText("This is a rename")).toBeVisible();
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(
      page.getByRole("button", { name: "Edit profile e2e-2d-prof-renamed" }),
    ).toBeVisible();
    const renamed = await profileByName(api, "e2e-2d-prof-renamed");
    expect(renamed?.["id"]).toBe(pid);

    // Unreferenced delete.
    await page
      .getByRole("button", { name: "Delete profile e2e-2d-prof-renamed" })
      .click();
    await expect(page.getByText("No references were found")).toBeVisible();
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Delete", exact: true })
      .click();
    await expect(
      page.getByRole("button", { name: "Delete profile e2e-2d-prof-renamed" }),
    ).toBeHidden();
  } finally {
    for (const n of ["e2e-2d-prof-renamed", "e2e-2d-prof"]) {
      const p = await profileByName(api, n);
      if (p !== undefined) {
        await api.delete(`/api/decryption-profiles?id=${String(p["id"])}`);
      }
    }
    await api.dispose();
  }
});

// ── Active draft interaction (§9/§28) ───────────────────────────────────────
test("rename with an active draft: a draft-only reference follows and commits to the SAME object ID; a running-reference cascade truthfully stales the draft base", async ({
  page,
}) => {
  const api = await newAdminClient("198.51.100.23");
  const draftState = async (): Promise<{
    active: boolean;
    baseStale: boolean;
    requireCommit: boolean;
  }> => {
    const resp = await api.get("/api/policy/draft");
    const v: unknown = await resp.json();
    if (!isRecord(v)) throw new Error("bad draft payload");
    return {
      active: v["active"] === true,
      baseStale: v["baseStale"] === true,
      requireCommit: v["requireCommit"] === true,
    };
  };
  const resetDraft = async (): Promise<void> => {
    const d = await draftState();
    if (d.active) await api.post("/api/policy/draft/revert");
    if (d.requireCommit) {
      await api.put("/api/policy/draft", { data: { require_commit: false } });
    }
  };
  try {
    await resetDraft();
    // Profile referenced ONLY by a staged candidate rule.
    const prof = await api.post("/api/decryption-profiles", {
      data: { name: "e2e-2d-draftprof", onInspectError: "fail-close" },
    });
    expect(prof.ok()).toBe(true);
    const pid = String((await profileByName(api, "e2e-2d-draftprof"))?.["id"]);
    await api.put("/api/policy/draft", { data: { require_commit: true } });
    const staged = await api.post("/api/policy", {
      data: {
        name: "E2E 2D DraftRef",
        action: "Allow",
        sslAction: "Inspect",
        decryptionProfile: "e2e-2d-draftprof",
        enabled: false,
      },
    });
    expect(staged.ok()).toBe(true);
    expect((await draftState()).active).toBe(true);

    // Rename through the UI while the draft is active.
    await page.goto(PROFILES_ROUTE);
    await page
      .getByRole("button", { name: "Edit profile e2e-2d-draftprof" })
      .click();
    await page.getByLabel("Profile name").fill("e2e-2d-draftprof-v2");
    await page.getByRole("button", { name: "Save changes" }).click();
    await expect(
      page.getByRole("button", { name: "Edit profile e2e-2d-draftprof-v2" }),
    ).toBeVisible();

    // Draft-only reference: the candidate followed (same ID, new name) and
    // running never moved, so the draft base is NOT stale — commit stays valid.
    const afterRename = await draftState();
    expect(afterRename.active).toBe(true);
    expect(afterRename.baseStale).toBe(false);
    const commit = await api.post("/api/policy/draft/commit", {
      data: { comment: "2D-A draft-ref rename proof" },
    });
    expect(
      commit.ok(),
      `commit refused: ${String(commit.status())} ${await commit.text()}`,
    ).toBe(true);
    const polResp = await api.get("/api/policy");
    const pol: unknown = await polResp.json();
    if (!isRecord(pol) || !Array.isArray(pol["rules"]))
      throw new Error("bad policy envelope");
    const committed = pol["rules"]
      .map((r: unknown) => r)
      .filter(isRecord)
      .find((r) => r["name"] === "E2E 2D DraftRef");
    expect(committed?.["decryptionProfileId"]).toBe(pid);
    expect(committed?.["decryptionProfile"]).toBe("e2e-2d-draftprof-v2");

    // Now the RUNNING-reference shape: the committed rule references the
    // profile in RUNNING; open a fresh draft with an unrelated staged rule and
    // rename again — the running cascade advances the running generation, so
    // the draft truthfully reads base-stale (commit fenced until review).
    await api.put("/api/policy/draft", { data: { require_commit: true } });
    const unrelated = await api.post("/api/policy", {
      data: { name: "E2E 2D Unrelated", action: "Allow", enabled: false },
    });
    expect(unrelated.ok()).toBe(true);
    const rename2 = await api.put(`/api/decryption-profiles?id=${pid}`, {
      data: { name: "e2e-2d-draftprof-v3", onInspectError: "fail-close" },
    });
    expect(rename2.ok()).toBe(true);
    const afterRunningCascade = await draftState();
    expect(afterRunningCascade.baseStale).toBe(true);
    // Recovery: revert clears the stale draft (2B/2C ceremony).
    await api.post("/api/policy/draft/revert");
    await api.put("/api/policy/draft", { data: { require_commit: false } });
  } finally {
    await resetDraft();
    await deleteRuleByName(api, "E2E 2D DraftRef");
    await deleteRuleByName(api, "E2E 2D Unrelated");
    for (const n of [
      "e2e-2d-draftprof-v3",
      "e2e-2d-draftprof-v2",
      "e2e-2d-draftprof",
    ]) {
      const p = await profileByName(api, n);
      if (p !== undefined) {
        await api.delete(`/api/decryption-profiles?id=${String(p["id"])}`);
      }
    }
    await api.dispose();
  }
});

// ── Viewer posture + auth boundary ──────────────────────────────────────────
test("viewer reads both object surfaces without mutation controls; signing out clears open editor state", async ({
  browser,
}) => {
  const ctx = await browser.newContext({
    storageState: EMPTY_STATE,
    extraHTTPHeaders: { "X-Forwarded-For": "198.51.100.31" },
  });
  const page = await ctx.newPage();
  try {
    await page.goto(`${AUTH_URL}${GROUPS_ROUTE}`);
    await login(page, USERS.viewer.user, USERS.viewer.pass);
    await expect(page.getByText("Category Groups").first()).toBeVisible();
    await expect(
      page.getByRole("button", { name: "New category group…" }),
    ).toBeHidden();
    await page.goto(`${AUTH_URL}${PROFILES_ROUTE}`);
    await expect(
      page.getByRole("button", { name: "New decryption profile…" }),
    ).toBeHidden();
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.getByLabel("Username")).toBeVisible();

    // Operator: open the editor, then sign out — the boundary clears it.
    await page.goto(`${AUTH_URL}${GROUPS_ROUTE}`);
    await login(page, USERS.operator.user, USERS.operator.pass);
    // The route intent returns to the requested page after sign-in.
    await page.getByRole("button", { name: "New category group…" }).click();
    await expect(page.getByLabel("Group name")).toBeVisible();
    await page.keyboard.press("Escape"); // dialog closes; dirty state cleared
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.getByLabel("Username")).toBeVisible();
  } finally {
    await ctx.close();
  }
});
