// Slice 2B real-binary browser qualification: the Policy WRITE surface over
// the actual CULVERT binary + committed dist, on the AUTH appliance (502
// Stage-2 access rules incl. 500 bulk rules + 2 Stage-1 auth rules).
//
// Covers the directive's browser proofs: §35 write interactions at 500+
// rules (edit / stage / discard / apply reorder), §36 multi-admin two-client
// fencing (live edit conflict, shared-draft actor warning + stale draft
// mutation conflict, commit-review version fence), §37 durability at browser
// level (live edit survives reload; staged draft survives reload; committed
// running survives reload), role posture, delete ceremony, and the
// default-action immediate-live ceremony.
//
// Harness isolation (§19): every premise is established through supported
// admin APIs; every test that arms Require Commit, stages a draft, reorders,
// or flips the default action restores the appliance state it found (the
// AUTH policy fixture is regenerated per harness run, and RequireCommit
// persists in the SHARED /data admin settings — leaving it armed would leak
// into later specs and later runs).
import { expect } from "@playwright/test";
import { identityHeaders, test } from "./test";
import type { Browser, Page } from "@playwright/test";
import { AUTH_URL, EMPTY_STATE, USERS } from "./fixtures";

const TOLERATED = [
  /Failed to load resource: .* status of (401|403|409|429|500)/,
];

interface Watch {
  errors: string[];
  external: string[];
  sse: string[];
}

function watch(page: Page, base: string): Watch {
  const errors: string[] = [];
  const external: string[] = [];
  const sse: string[] = [];
  const origin = new URL(base).origin;
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    const text = m.text();
    if (TOLERATED.some((re) => re.test(text))) return;
    errors.push(text);
  });
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.origin !== origin) external.push(r.url());
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

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

interface ApiRule {
  id: string;
  name: string;
  priority: number;
  comment: string;
}

interface ApiPolicy {
  rules: ApiRule[];
  version: number;
  draft: boolean;
}

function readPolicy(v: unknown): ApiPolicy {
  if (!isRecord(v)) throw new Error("bad /api/policy payload");
  const rulesRaw = v["rules"];
  const version = v["version"];
  const draft = v["draft"];
  if (
    !Array.isArray(rulesRaw) ||
    typeof version !== "number" ||
    typeof draft !== "boolean"
  ) {
    throw new Error("bad /api/policy envelope");
  }
  const rules: ApiRule[] = rulesRaw.map((r: unknown) => {
    if (!isRecord(r)) throw new Error("bad rule row");
    const id = r["id"];
    const name = r["name"];
    const priority = r["priority"];
    const comment = r["comment"];
    return {
      id: typeof id === "string" ? id : "",
      name: typeof name === "string" ? name : "",
      priority: typeof priority === "number" ? priority : 0,
      comment: typeof comment === "string" ? comment : "",
    };
  });
  return { rules, version, draft };
}

async function apiPolicy(page: Page): Promise<ApiPolicy> {
  const resp = await page.request.get("/api/policy");
  expect(resp.ok()).toBe(true);
  return readPolicy(await resp.json());
}

interface ApiDraft {
  requireCommit: boolean;
  active: boolean;
  actor: string;
}

async function apiDraft(page: Page): Promise<ApiDraft> {
  const resp = await page.request.get("/api/policy/draft");
  expect(resp.ok()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v)) throw new Error("bad draft payload");
  return {
    requireCommit: v["requireCommit"] === true,
    active: v["active"] === true,
    actor: typeof v["actor"] === "string" ? v["actor"] : "",
  };
}

/** Reset the write-mode premises through supported APIs: no draft, live
 * mode. Run at the start AND end of every mode-touching test. */
async function resetDraftMode(page: Page): Promise<void> {
  const d = await apiDraft(page);
  if (d.active) {
    await page.request.post("/api/policy/draft/revert");
  }
  if (d.requireCommit) {
    await page.request.put("/api/policy/draft", {
      data: { require_commit: false },
    });
  }
}

const RULES_ROUTE = "/app/policies/access-rules";

// ── §35: write interactions at 500+ rules ───────────────────────────────────

test("500-rule scale: open editor, edit a bulk rule, save; create + T1 delete ceremony (live wording)", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await resetDraftMode(page);
  await page.goto(RULES_ROUTE);
  await expect(page.getByText("502 of 502 access rules")).toBeVisible();

  // Edit a deep bulk rule: filter to it, open the editor, change the comment.
  await page.getByLabel("Filter").fill("Bulk rule 250");
  await expect(page.getByText("1 of 502 access rules")).toBeVisible();
  await page.getByRole("button", { name: "Edit rule Bulk rule 250" }).click();
  await expect(page.getByText("Edit rule: Bulk rule 250")).toBeVisible();
  await expect(page.getByText("LIVE immediately after saving")).toBeVisible();
  await page.getByLabel("Comment").fill("edited at 500-rule scale");
  await page.getByRole("button", { name: "Save rule" }).click();
  await expect(page.getByText("Edit rule: Bulk rule 250")).toBeHidden();
  const edited = (await apiPolicy(page)).rules.find(
    (r) => r.name === "Bulk rule 250",
  );
  expect(edited?.comment).toBe("edited at 500-rule scale");

  // Create a rule, then delete it through the T1 ceremony.
  await page.getByLabel("Filter").fill("");
  await page.getByRole("button", { name: "New rule…" }).click();
  await expect(page.getByText("New access rule")).toBeVisible();
  await page.getByLabel("Rule name").fill("E2E 2B Created Rule");
  await page.getByRole("button", { name: "Create rule" }).click();
  await expect(page.getByText("New access rule")).toBeHidden();
  await expect(page.getByText("503 of 503 access rules")).toBeVisible();
  const created = (await apiPolicy(page)).rules.find(
    (r) => r.name === "E2E 2B Created Rule",
  );
  expect(created).toBeDefined();

  await page.getByLabel("Filter").fill("E2E 2B Created Rule");
  await page
    .getByRole("button", { name: "Delete rule E2E 2B Created Rule" })
    .click();
  await expect(page.getByText("Delete access rule")).toBeVisible();
  await expect(page.getByText("E2E 2B Created Rule").nth(1)).toBeVisible();
  await expect(page.getByText("The delete is LIVE immediately.")).toBeVisible();
  await page.getByRole("button", { name: "Delete rule", exact: true }).click();
  await expect(page.getByText("Delete access rule")).toBeHidden();
  expect(
    (await apiPolicy(page)).rules.some((r) => r.name === "E2E 2B Created Rule"),
  ).toBe(false);
  assertClean(w);
});

test("500-rule scale: stage, discard, and apply a reorder with deterministic controls; then restore", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await resetDraftMode(page);
  await page.goto(RULES_ROUTE);
  await expect(page.getByText("502 of 502 access rules")).toBeVisible();

  // Stage: swap two adjacent deep bulk rules (leaves every other slot
  // untouched, incl. the priority-1 match rule other specs depend on).
  await page.getByRole("button", { name: "Reorder rules…" }).click();
  await expect(page.getByLabel("Filter")).toBeDisabled();
  await page
    .getByRole("button", { name: "Move rule Bulk rule 251 up" })
    .click();
  await expect(page.getByText("Reorder staged")).toBeVisible();

  // Discard first: server order untouched.
  const before = await apiPolicy(page);
  await page.getByRole("button", { name: "Discard reorder" }).click();
  await expect(page.getByText("Reorder staged")).toBeHidden();
  const afterDiscard = await apiPolicy(page);
  expect(afterDiscard.version).toBe(before.version);

  // Stage again and APPLY.
  await page.getByRole("button", { name: "Reorder rules…" }).click();
  await page
    .getByRole("button", { name: "Move rule Bulk rule 251 up" })
    .click();
  await page.getByRole("button", { name: "Apply reorder" }).click();
  await expect(page.getByText("Reorder staged")).toBeHidden();
  await expect(page.getByRole("button", { name: "New rule…" })).toBeVisible();
  const applied = await apiPolicy(page);
  const names = applied.rules.map((r) => r.name);
  expect(names.indexOf("Bulk rule 251")).toBeLessThan(
    names.indexOf("Bulk rule 250"),
  );

  // Restore the fixture order for later specs.
  await page.getByRole("button", { name: "Reorder rules…" }).click();
  await page
    .getByRole("button", { name: "Move rule Bulk rule 251 down" })
    .click();
  await page.getByRole("button", { name: "Apply reorder" }).click();
  await expect(page.getByText("Reorder staged")).toBeHidden();
  const restored = await apiPolicy(page);
  const rNames = restored.rules.map((r) => r.name);
  expect(rNames.indexOf("Bulk rule 250")).toBeLessThan(
    rNames.indexOf("Bulk rule 251"),
  );
  assertClean(w);
});

// ── §36 A–E: two clients, live mode ─────────────────────────────────────────

async function operatorPage(browser: Browser, identity: string): Promise<Page> {
  const ctx = await browser.newContext({
    storageState: EMPTY_STATE,
    extraHTTPHeaders: identityHeaders(identity),
  });
  const page = await ctx.newPage();
  await page.goto(`${AUTH_URL}${RULES_ROUTE}`);
  await login(page, USERS.operator.user, USERS.operator.pass);
  await expect(page.getByText("of 502 access rules")).toBeVisible();
  return page;
}

test("two clients, same version: A edits, B's stale edit gets the REAL server 409 and is not applied", async ({
  clientIdentity,
  page,
  baseURL,
  browser,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await resetDraftMode(page);
  const pageB = await operatorPage(browser, clientIdentity);

  // Both clients load the same snapshot version.
  await page.goto(RULES_ROUTE);
  await expect(page.getByText("502 of 502 access rules")).toBeVisible();

  // Both open the SAME rule for editing.
  for (const p of [page, pageB]) {
    await p.getByLabel("Filter").fill("Bulk rule 300");
    await p.getByRole("button", { name: "Edit rule Bulk rule 300" }).click();
    await expect(p.getByText("Edit rule: Bulk rule 300")).toBeVisible();
  }

  // A saves first.
  await page.getByLabel("Comment").fill("A won this rule");
  await page.getByRole("button", { name: "Save rule" }).click();
  await expect(page.getByText("Edit rule: Bulk rule 300")).toBeHidden();

  // B's save asserts the stale version → structured 409, nothing applied.
  await pageB.getByLabel("Comment").fill("B must not win silently");
  await pageB.getByRole("button", { name: "Save rule" }).click();
  await expect(
    pageB.getByText("The rulebase changed", { exact: true }),
  ).toBeVisible();
  await expect(pageB.getByRole("button", { name: "Save rule" })).toBeDisabled();
  const rule = (await apiPolicy(page)).rules.find(
    (r) => r.name === "Bulk rule 300",
  );
  expect(rule?.comment).toBe("A won this rule");

  await pageB.context().close();
  assertClean(w);
});

// ── §36 draft + commit fencing: two clients, shared candidate ──────────────

test("shared draft: actor warning for the second operator; stale draft mutation conflicts; commit fence refuses unreviewed changes", async ({
  clientIdentity,
  page,
  baseURL,
  browser,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await resetDraftMode(page);
  const pageB = await operatorPage(browser, clientIdentity);
  try {
    // Admin (page A) arms Require Commit through the ceremony.
    await page.goto(RULES_ROUTE);
    await page
      .getByRole("button", { name: "Require commit for changes…" })
      .click();
    await page
      .getByRole("button", { name: "Require commit", exact: true })
      .click();
    await expect(page.getByText("Commit mode armed")).toBeVisible();

    // A stages the first change → the shared draft opens under actor=admin.
    await page.getByLabel("Filter").fill("Bulk rule 310");
    await page.getByRole("button", { name: "Edit rule Bulk rule 310" }).click();
    await expect(
      page.getByText("STAGED in the shared Policy Draft"),
    ).toBeVisible();
    await page.getByLabel("Comment").fill("staged by admin");
    await page.getByRole("button", { name: "Save rule" }).click();
    await expect(page.getByText("Edit rule: Bulk rule 310")).toBeHidden();
    await expect(
      page.getByText("Editing the shared Policy Draft"),
    ).toBeVisible();
    expect((await apiDraft(page)).actor).toBe(USERS.admin.user);

    // B reloads and sees the SHARED-candidate actor warning (§21).
    await pageB.reload();
    await expect(
      pageB.getByText(
        `This shared draft was opened by ${USERS.admin.user}. Your edits modify the same candidate.`,
      ),
    ).toBeVisible();

    // B opens an edit against the current candidate version…
    await pageB.getByLabel("Filter").fill("Bulk rule 311");
    await pageB
      .getByRole("button", { name: "Edit rule Bulk rule 311" })
      .click();
    await expect(pageB.getByText("Edit rule: Bulk rule 311")).toBeVisible();
    // …then A advances the candidate…
    await page.getByLabel("Filter").fill("Bulk rule 312");
    await page.getByRole("button", { name: "Edit rule Bulk rule 312" }).click();
    await page.getByLabel("Comment").fill("second staged change");
    await page.getByRole("button", { name: "Save rule" }).click();
    await expect(page.getByText("Edit rule: Bulk rule 312")).toBeHidden();
    // …so B's stale staged mutation must conflict (real server 409).
    await pageB.getByLabel("Comment").fill("stale draft edit");
    await pageB.getByRole("button", { name: "Save rule" }).click();
    await expect(
      pageB.getByText("The rulebase changed", { exact: true }),
    ).toBeVisible();
    await pageB.getByRole("button", { name: "Cancel" }).click();

    // Commit fence (§36 third block): B opens the review at candidate vN…
    await pageB.reload();
    await pageB.getByRole("button", { name: "Review & commit…" }).click();
    await expect(pageB.getByText("Review & commit Policy Draft")).toBeVisible();
    // …A stages ANOTHER change B has not reviewed…
    await page.getByLabel("Filter").fill("Bulk rule 313");
    await page.getByRole("button", { name: "Edit rule Bulk rule 313" }).click();
    await page.getByLabel("Comment").fill("unreviewed change");
    await page.getByRole("button", { name: "Save rule" }).click();
    await expect(page.getByText("Edit rule: Bulk rule 313")).toBeHidden();
    // …and B's commit with the reviewed (now stale) version MUST conflict.
    await pageB.getByLabel("Commit comment").fill("commit at stale review");
    await pageB.getByRole("button", { name: "Commit draft" }).click();
    await expect(
      pageB.getByText("The draft changed", { exact: true }),
    ).toBeVisible();
    await expect(pageB.getByText("changes you had not reviewed")).toBeVisible();
    // The unreviewed change was NOT committed: the draft is still active
    // (the /api/policy view is the candidate while engaged, so the running
    // rulebase is untouched by construction — commitActivate never ran).
    expect((await apiDraft(page)).active).toBe(true);
  } finally {
    await pageB.context().close();
    await resetDraftMode(page);
  }
  assertClean(w);
});

// ── Commit success + §37 durability ─────────────────────────────────────────

test("draft → browser reload keeps the candidate; commit ceremony activates it; running survives reload", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await resetDraftMode(page);
  try {
    await page.goto(RULES_ROUTE);
    await page
      .getByRole("button", { name: "Require commit for changes…" })
      .click();
    await page
      .getByRole("button", { name: "Require commit", exact: true })
      .click();
    await expect(page.getByText("Commit mode armed")).toBeVisible();

    // Stage one edit.
    await page.getByLabel("Filter").fill("Bulk rule 320");
    await page.getByRole("button", { name: "Edit rule Bulk rule 320" }).click();
    await page.getByLabel("Comment").fill("committed via ceremony");
    await page.getByRole("button", { name: "Save rule" }).click();
    await expect(page.getByText("Edit rule: Bulk rule 320")).toBeHidden();

    // §37: the staged candidate survives a full browser reload.
    await page.reload();
    await expect(
      page.getByText("Editing the shared Policy Draft"),
    ).toBeVisible();
    await expect(page.getByText("1 pending change")).toBeVisible();

    // Commit through the review ceremony.
    await page.getByRole("button", { name: "Review & commit…" }).click();
    await expect(page.getByText("Review & commit Policy Draft")).toBeVisible();
    await expect(page.getByText("Modified 1")).toBeVisible();
    await expect(page.getByText("Bulk rule 320").first()).toBeVisible();
    await page.getByLabel("Commit comment").fill("e2e 2B commit");
    await page.getByRole("button", { name: "Commit draft" }).click();
    await expect(page.getByText("Draft committed")).toBeVisible();
    await page.getByRole("button", { name: "Close", exact: true }).click();

    // Running truth after commit + §37 reload persistence.
    await page.reload();
    await expect(page.getByText("Commit mode armed")).toBeVisible();
    const committed = (await apiPolicy(page)).rules.find(
      (r) => r.name === "Bulk rule 320",
    );
    expect(committed?.comment).toBe("committed via ceremony");
    expect((await apiDraft(page)).active).toBe(false);
  } finally {
    await resetDraftMode(page);
  }
  assertClean(w);
});

test("live edit survives a full page reload (§37)", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await resetDraftMode(page);
  await page.goto(RULES_ROUTE);
  await page.getByLabel("Filter").fill("Bulk rule 330");
  await page.getByRole("button", { name: "Edit rule Bulk rule 330" }).click();
  await page.getByLabel("Comment").fill("durable live edit");
  await page.getByRole("button", { name: "Save rule" }).click();
  await expect(page.getByText("Edit rule: Bulk rule 330")).toBeHidden();

  await page.reload();
  await page.getByLabel("Filter").fill("Bulk rule 330");
  await page
    .getByRole("button", { name: "Details for rule Bulk rule 330" })
    .click();
  await expect(page.getByText("durable live edit")).toBeVisible();
  assertClean(w);
});

// ── Revert ceremony over the real binary ────────────────────────────────────

test("revert ceremony discards the shared candidate with its impact truth", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await resetDraftMode(page);
  try {
    await page.goto(RULES_ROUTE);
    await page
      .getByRole("button", { name: "Require commit for changes…" })
      .click();
    await page
      .getByRole("button", { name: "Require commit", exact: true })
      .click();
    await page.getByLabel("Filter").fill("Bulk rule 340");
    await page.getByRole("button", { name: "Edit rule Bulk rule 340" }).click();
    await page.getByLabel("Comment").fill("doomed staged edit");
    await page.getByRole("button", { name: "Save rule" }).click();
    await expect(page.getByText("Edit rule: Bulk rule 340")).toBeHidden();

    await page.getByRole("button", { name: "Revert draft…" }).click();
    await expect(
      page.getByText("Discards 1 pending change", { exact: false }),
    ).toBeVisible();
    await page
      .getByRole("button", { name: "Revert draft", exact: true })
      .click();
    await expect(
      page.getByText("Editing the shared Policy Draft"),
    ).toBeHidden();
    expect((await apiDraft(page)).active).toBe(false);
    const rule = (await apiPolicy(page)).rules.find(
      (r) => r.name === "Bulk rule 340",
    );
    expect(rule?.comment).not.toBe("doomed staged edit");
  } finally {
    await resetDraftMode(page);
  }
  assertClean(w);
});

// ── §32: default action immediate-live ceremony ─────────────────────────────

test("default action: T2 ceremony with immediate-live truth; value restored", async ({
  page,
  baseURL,
}) => {
  const w = watch(page, baseURL ?? AUTH_URL);
  await page.goto(RULES_ROUTE);
  await expect(
    page.getByText("Default action for unmatched traffic:"),
  ).toBeVisible();
  await expect(page.getByText("Deny", { exact: true })).toBeVisible();
  try {
    await page.getByRole("button", { name: "Change…" }).click();
    await expect(
      page.getByText("This takes effect LIVE immediately for all traffic."),
    ).toBeVisible();
    await expect(
      page.getByText(
        "It is never staged in the Policy Draft — even while Require Commit is on.",
      ),
    ).toBeVisible();
    await page.getByRole("button", { name: "Set default to allow" }).click();
    await expect(
      page.getByText("Allow", { exact: true }).first(),
    ).toBeVisible();
    const resp = await page.request.get("/api/default-action");
    const v: unknown = await resp.json();
    expect(isRecord(v) && v["defaultAction"]).toBe("allow");
  } finally {
    // Restore the fixture's default (deny) for every later spec.
    await page.request.post("/api/default-action", {
      data: { action: "deny" },
    });
  }
  const resp = await page.request.get("/api/default-action");
  const v: unknown = await resp.json();
  expect(isRecord(v) && v["defaultAction"]).toBe("deny");
  assertClean(w);
});
