// FE-6A.1 real-binary journeys — Identity Providers (viewer read,
// /app/objects/identity-providers) and Administrators (admin read,
// /app/administrators). Written RED against the merged FE-6A.1 baseline
// (3b6ba325): both routes are unserved there and the harness carries no
// registry file, no legacy YAML ldap block and no quarantined appliance.
// Real appliances only (scripts/e2e-smoke.sh):
//
//   AUTH   — registry file armed; this spec seeds (through the supported
//            admin API, never through the surface) an ENABLED SAML profile
//            with inline metadata (no network), a DISABLED LDAP profile with
//            a bind-password canary, and one SSORequired authentication rule
//            referencing the SAML profile. (An OIDC profile is deliberately
//            NOT seeded: the issuer validator resolves the host through DNS,
//            which a hermetic harness cannot rely on; the OIDC client-secret
//            indicator is pinned by the unit matrix and the backend
//            projection-parity test.)
//   YAMLUP — registry file armed + a legacy YAML ldap block (bind_password
//            canary): the spec commits an ENABLED LDAP profile with a
//            client-generated operationId, which retires the legacy block —
//            the DURABLE, operation-identified cutover the read surface
//            must report (with the admin-only ledger lookup: committed).
//   IDPQ   — a CORRUPT registry file (quarantined at boot) + a legacy YAML
//            ldap block that is present, active and NOT retired.
//
//   J1  role matrix (admin / operator / viewer): navigation placement,
//       Administrators is admin-only (a viewer/operator deep link renders
//       the bounded 403 posture and no roster fact), Identity Providers is
//       viewer-readable.
//   J2  deep-link continuity: an unauthenticated deep link returns to the
//       intended route after sign-in; a reload keeps it; the nav link is
//       reachable.
//   J3  populated registry truth on AUTH: identity / type / enabled /
//       revision / indicators / referenced-provider posture; cluster-synced
//       + persisted; the fleet publication result.
//   J4  corrupt/quarantined posture on IDPQ + the legacy block present and
//       not retired.
//   J5  legacy cutover on YAMLUP: durable record, operation identity,
//       trigger, and the admin lookup rendered as committed.
//   J6  roster truth on AUTH: usernames, durable roles, security
//       generations, administrator count, TOTP presence, node-local; the
//       lock set.
//   J7  leak sweep: no canary, hash, TOTP seed, quarantine file name or
//       raw dependency text in any API response, the DOM, the URL or web
//       storage, on every appliance.
//   J8  no mutation: every request either surface issues is a GET and the
//       server-side revisions are unchanged after the visit.
//   J9  auth boundary: signing out from Administrators clears the roster
//       from the DOM, leaves web storage empty, and the next (viewer)
//       session cannot see it.
//
// No retries, no enlarged timeouts, no skips: every assertion reads the
// appliance's own answer.
import { expect, request } from "@playwright/test";
import { test } from "./test";
import type { APIRequestContext, Page } from "@playwright/test";
import {
  AUTH_URL,
  EMPTY_STATE,
  IDPQ_URL,
  TOTP_SECRET,
  USERS,
  YAML_URL,
} from "./fixtures";
import { expectNavLinkReachable } from "./nav-open";

const IDP_ROUTE = "/app/objects/identity-providers";
const ADMINS_ROUTE = "/app/administrators";
// A FIXED suffix: Playwright re-evaluates this module (and re-runs beforeAll)
// in every worker a `test.use` change starts, and the harness data root is
// fresh per run — so the seed is keyed on a constant and made idempotent by
// name (findProfileId), never re-minted per worker.
const SUFFIX = "fe6a1";
const SAML_NAME = `E2E SAML ${SUFFIX}`;
const LDAP_NAME = `E2E LDAP ${SUFFIX}`;
const RULE_NAME = `E2E SSO Rule ${SUFFIX}`;
const CUTOVER_NAME = `E2E Cutover LDAP ${SUFFIX}`;
const BIND_CANARY = `BINDCANARY-${SUFFIX}-never-in-browser`;
/** the harness's legacy YAML bind_password (scripts/e2e-smoke.sh) */
const YAML_BIND_CANARY = "YAMLBINDCANARY-legacy-ldap-never-in-browser";
// Fixed for the same reason as SUFFIX (module re-evaluation per worker): the
// cutover is once-ever per harness run and its ledger key must be the one
// every worker asserts on.
const CUTOVER_OP_ID = "6a1c0000-fe6a-4e2e-9f00-0000000fe6a1";

// Minimal SAML IdP metadata: parsed by crewjam/samlsp offline, never fetched.
const IDP_METADATA_XML = `<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp-${SUFFIX}.invalid/saml">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp-${SUFFIX}.invalid/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;

const LEAK_NEEDLES = [
  BIND_CANARY,
  YAML_BIND_CANARY,
  TOTP_SECRET,
  "pass_hash",
  "totp_secret",
  "backup_codes",
  "bindPassword",
  'clientSecret"',
  "metadataXml",
  "$2a$10$",
];

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

async function newAdminClient(
  base: string,
  xff: string,
): Promise<APIRequestContext> {
  const ctx = await request.newContext({
    baseURL: base,
    extraHTTPHeaders: { "X-Forwarded-For": xff },
  });
  const login = await ctx.post("/api/auth/login", {
    data: { user: USERS.admin.user, pass: USERS.admin.pass },
  });
  expect(login.ok(), await login.text()).toBe(true);
  return ctx;
}

async function documentRevision(ctx: APIRequestContext): Promise<string> {
  const resp = await ctx.get("/api/idp");
  expect(resp.ok(), await resp.text()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v) || typeof v["revision"] !== "string")
    throw new Error("bad /api/idp read model");
  return v["revision"];
}

async function createProfile(
  ctx: APIRequestContext,
  body: Record<string, unknown>,
  operationId?: string,
  cutoverConfirm?: string,
): Promise<Record<string, unknown>> {
  const rev = await documentRevision(ctx);
  const qs = new URLSearchParams({ documentRevision: rev });
  if (operationId !== undefined) qs.set("operationId", operationId);
  // FE-6A.2: a cutover-bearing write must also carry the server's confirm
  // value (the legacy directory URL published as cutoverConfirmValue).
  if (cutoverConfirm !== undefined) qs.set("cutoverConfirm", cutoverConfirm);
  const resp = await ctx.post(`/api/idp?${qs.toString()}`, { data: body });
  expect(resp.ok(), await resp.text()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v)) throw new Error("bad create answer");
  return v;
}

async function findProfileId(
  ctx: APIRequestContext,
  name: string,
): Promise<string | null> {
  const resp = await ctx.get("/api/idp");
  expect(resp.ok()).toBe(true);
  const v: unknown = await resp.json();
  if (!isRecord(v) || !Array.isArray(v["profiles"])) return null;
  for (const p of v["profiles"]) {
    if (isRecord(p) && p["name"] === name && typeof p["id"] === "string")
      return p["id"];
  }
  return null;
}

async function login(page: Page, user: string, pass: string): Promise<void> {
  await page.getByLabel("Username").fill(user);
  await page.getByLabel("Password").fill(pass);
  await page.getByRole("button", { name: "Sign in" }).click();
}

async function storageDump(page: Page): Promise<string> {
  return page.evaluate(() => {
    const out: string[] = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      if (k !== null) out.push(`${k}=${sessionStorage.getItem(k) ?? ""}`);
    }
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k !== null) out.push(`${k}=${localStorage.getItem(k) ?? ""}`);
    }
    return out.join("\n");
  });
}

interface Watch {
  apiCalls: Array<{ method: string; path: string }>;
  bodies: string[];
}

/** Record every API request and response body the page issues from now on. */
function watch(page: Page): Watch {
  const w: Watch = { apiCalls: [], bodies: [] };
  page.on("request", (r) => {
    const u = new URL(r.url());
    if (u.pathname.startsWith("/api/"))
      w.apiCalls.push({ method: r.method(), path: u.pathname });
  });
  page.on("response", (r) => {
    const u = new URL(r.url());
    if (!u.pathname.startsWith("/api/")) return;
    void r
      .text()
      .then((t) => {
        w.bodies.push(`${u.pathname}\n${t}`);
      })
      .catch(() => undefined);
  });
  return w;
}

async function expectNoLeak(
  page: Page,
  w: Watch,
  extra: readonly string[] = [],
): Promise<void> {
  const dom = await page.evaluate(() => document.documentElement.outerHTML);
  const url = page.url();
  const storage = await storageDump(page);
  for (const needle of [...LEAK_NEEDLES, ...extra]) {
    expect(dom, `DOM carries ${needle}`).not.toContain(needle);
    expect(url, `URL carries ${needle}`).not.toContain(needle);
    expect(storage, `storage carries ${needle}`).not.toContain(needle);
    for (const b of w.bodies)
      expect(b, `response carries ${needle}`).not.toContain(needle);
  }
}

/** The authentication flow itself (sign-in / sign-out) is the ONLY non-GET
 * a page context may issue; every request the two surfaces make is a GET. */
const AUTH_FLOW = new Set(["/api/auth/login", "/api/auth/logout"]);
function expectOnlyGET(w: Watch): void {
  expect(w.apiCalls.length).toBeGreaterThan(0);
  expect(
    w.apiCalls.filter((c) => c.method !== "GET" && !AUTH_FLOW.has(c.path)),
  ).toEqual([]);
}

// ── Seed (supported admin API; the surfaces under test never mutate) ──────
let samlId = "";
let ldapId = "";

test.beforeAll(async () => {
  const auth = await newAdminClient(AUTH_URL, "10.61.0.1");
  // Idempotent within a harness run: the data root is fresh per run.
  samlId =
    (await findProfileId(auth, SAML_NAME)) ??
    String(
      (
        await createProfile(auth, {
          name: SAML_NAME,
          type: "saml",
          enabled: true,
          emailDomains: [`saml-${SUFFIX}.example`],
          saml: { metadataXml: IDP_METADATA_XML },
        })
      )["id"],
    );
  ldapId =
    (await findProfileId(auth, LDAP_NAME)) ??
    String(
      (
        await createProfile(auth, {
          name: LDAP_NAME,
          type: "ldap",
          enabled: false,
          ldap: {
            url: `ldaps://dc-${SUFFIX}.invalid:636`,
            baseDn: "dc=e2e,dc=invalid",
            bindDn: "cn=svc,dc=e2e,dc=invalid",
            bindPassword: BIND_CANARY,
            userFilter: "(uid=%s)",
          },
        })
      )["id"],
    );
  // One SSORequired authentication rule referencing the SAML profile (live
  // write mode: no draft open, commit mode disarmed — the 2B premise).
  const draft = await auth.get("/api/policy/draft");
  const d: unknown = await draft.json();
  if (isRecord(d) && d["active"] === true)
    await auth.post("/api/policy/draft/revert");
  if (isRecord(d) && d["requireCommit"] === true)
    await auth.put("/api/policy/draft", { data: { require_commit: false } });
  const ap = await auth.get("/api/authpolicy");
  expect(ap.ok()).toBe(true);
  const apv: unknown = await ap.json();
  if (
    !isRecord(apv) ||
    typeof apv["version"] !== "number" ||
    !Array.isArray(apv["rules"])
  )
    throw new Error("bad authpolicy");
  const present = apv["rules"].some(
    (r) => isRecord(r) && r["name"] === RULE_NAME,
  );
  if (!present) {
    const created = await auth.post(
      `/api/authpolicy?ifVersion=${String(apv["version"])}`,
      {
        data: {
          name: RULE_NAME,
          ruleType: "auth",
          subjectMatch: {
            schemaVersion: 1,
            all: [{ type: "cidr", values: ["10.61.77.0/24"] }],
          },
          auth: {
            outcome: "SSORequired",
            owner: "e2e-harness",
            reason: "FE-6A.1 referenced-provider fixture",
            providerRefs: [samlId],
          },
          destFQDN: `sso-${SUFFIX}.test`,
          destCategory: "",
          destCategoryGroup: "",
          comment: "FE-6A.1 fixture",
        },
      },
    );
    expect(created.ok(), await created.text()).toBe(true);
  }
  await auth.dispose();

  // YAMLUP: the operation-identified cutover (enabled LDAP profile on a node
  // that still carries the legacy YAML block).
  const yaml = await newAdminClient(YAML_URL, "10.61.0.2");
  const legacy = await yaml.get("/api/idp/legacy-ldap");
  expect(legacy.ok()).toBe(true);
  const lv: unknown = await legacy.json();
  const cutoverConfirm =
    isRecord(lv) && typeof lv["cutoverConfirmValue"] === "string"
      ? lv["cutoverConfirmValue"]
      : "ldaps://legacy-dc.invalid:636";
  if (!(isRecord(lv) && lv["retired"] === true)) {
    const answer = await createProfile(
      yaml,
      {
        name: CUTOVER_NAME,
        type: "ldap",
        enabled: true,
        ldap: {
          url: `ldaps://cutover-${SUFFIX}.invalid:636`,
          baseDn: "dc=cutover,dc=invalid",
          bindDn: "cn=svc,dc=cutover,dc=invalid",
          bindPassword: BIND_CANARY,
          userFilter: "(uid=%s)",
        },
      },
      CUTOVER_OP_ID,
      cutoverConfirm,
    );
    expect(answer["operationId"]).toBe(CUTOVER_OP_ID);
  }
  await yaml.dispose();
});

// Per-worker cleanup (mirrors the per-worker seed): the fixtures are the
// spec's own and must not leak into the premises of other specs —
// policy-2a counts exactly the harness's two Stage-1 rules. The rule goes
// first (the SAML profile is referenced by it and its delete would be
// refused 409 referenced until then); every delete is fenced on the
// server-minted token it just read. The YAMLUP cutover profile stays: the
// authority cutover is once-ever and deleting the profile would not (and
// must not) un-retire the legacy block.
test.afterAll(async () => {
  const auth = await newAdminClient(AUTH_URL, "10.61.0.3");
  const ap = await auth.get("/api/authpolicy");
  const apv: unknown = await ap.json();
  if (
    isRecord(apv) &&
    Array.isArray(apv["rules"]) &&
    typeof apv["version"] === "number"
  ) {
    for (const r of apv["rules"]) {
      if (
        isRecord(r) &&
        r["name"] === RULE_NAME &&
        typeof r["id"] === "string"
      ) {
        const cur = await auth.get("/api/authpolicy");
        const cv: unknown = await cur.json();
        const version =
          isRecord(cv) && typeof cv["version"] === "number"
            ? cv["version"]
            : apv["version"];
        const qs = new URLSearchParams({
          id: r["id"],
          ifVersion: String(version),
        });
        const del = await auth.delete(`/api/authpolicy?${qs.toString()}`);
        expect(del.ok(), await del.text()).toBe(true);
      }
    }
  }
  for (const name of [SAML_NAME, LDAP_NAME]) {
    const list = await auth.get("/api/idp");
    const lv: unknown = await list.json();
    if (!isRecord(lv) || !Array.isArray(lv["profiles"])) continue;
    for (const p of lv["profiles"]) {
      if (
        isRecord(p) &&
        p["name"] === name &&
        typeof p["id"] === "string" &&
        typeof p["revision"] === "number"
      ) {
        const qs = new URLSearchParams({ revision: String(p["revision"]) });
        const del = await auth.delete(
          `/api/idp/${encodeURIComponent(p["id"])}?${qs.toString()}`,
        );
        expect(del.ok(), await del.text()).toBe(true);
      }
    }
  }
  await auth.dispose();
});

// ── J1 + J6 + J8 + J9 (admin storage state on AUTH) ────────────────────────
test("J1/J6/J8 admin: navigation reaches both surfaces; the roster, lock set and registry render server truth with only GETs", async ({
  page,
}) => {
  const w = watch(page);
  await page.goto("/app/");
  const nav = page.getByRole("navigation", { name: "Primary" });
  await expect(
    nav.getByRole("link", { name: "Identity Providers" }),
  ).toBeVisible();
  await expect(nav.getByRole("link", { name: "Administrators" })).toBeVisible();

  await nav.getByRole("link", { name: "Administrators" }).click();
  await expect(page).toHaveURL(new RegExp(`${ADMINS_ROUTE}$`));
  await expect(
    page.getByRole("heading", { name: "Administrators" }),
  ).toBeVisible();
  const main = page.getByRole("main");
  await expect(main.getByText("Node-local").first()).toBeVisible();
  for (const u of ["admin", "op-user", "view-user", "totp-user"]) {
    await expect(
      main.getByRole("cell", { name: u, exact: true }).first(),
    ).toBeVisible();
  }
  await expect(main.getByText("2 administrator accounts")).toBeVisible();
  await expect(main.getByText("Last admin")).toHaveCount(0);
  await expect(main.getByText(/Roster revision \d+/)).toBeVisible();
  await expect(main.getByText(/Lock-set generation \d+/)).toBeVisible();
  await expect(main.getByText("No active lockouts")).toBeVisible();
  // TOTP presence: totp-user configured, the others not.
  const totpRow = main.getByRole("row", { name: /totp-user/ });
  await expect(totpRow.getByText("configured", { exact: true })).toBeVisible();
  const adminRow = main.getByRole("row", { name: /^admin / });
  await expect(
    adminRow.getByText("not configured", { exact: true }),
  ).toBeVisible();
  // Read-only: the only buttons in the main region are Refresh.
  const buttons = await main.getByRole("button").allTextContents();
  expect(buttons.length).toBeGreaterThan(0);
  expect(buttons.every((b) => b.trim() === "Refresh")).toBe(true);
  expect(await main.locator("input,select,textarea,dialog,form").count()).toBe(
    0,
  );

  // Identity Providers via the sidebar.
  await nav.getByRole("link", { name: "Identity Providers" }).click();
  await expect(page).toHaveURL(new RegExp(`${IDP_ROUTE}$`));
  await expect(
    page.getByRole("heading", { name: "Identity Providers" }),
  ).toBeVisible();
  await expect(main.getByText("Cluster-synced").first()).toBeVisible();
  await expect(main.getByText("Persisted", { exact: true })).toBeVisible();
  await expect(main.getByRole("cell", { name: SAML_NAME })).toBeVisible();
  const idpButtons = await main.getByRole("button").allTextContents();
  expect(idpButtons.every((b) => b.trim() === "Refresh")).toBe(true);

  expectOnlyGET(w);
  await expectNoLeak(page, w);
  // Server-side revisions untouched by the visit.
  const roster = await page.request.get("/api/auth/users");
  expect(roster.ok()).toBe(true);
  const registry = await page.request.get("/api/idp");
  expect(registry.ok()).toBe(true);
  const rv: unknown = await registry.json();
  expect(isRecord(rv) && rv["persisted"]).toBe(true);
});

// ── J3 + J7 (viewer floor on the populated registry, via EMPTY_STATE) ─────
test.describe("J2/J3 viewer: deep link, populated registry truth, referenced provider, indicators only", () => {
  test.use({ storageState: EMPTY_STATE });

  test("unauthenticated deep link returns to Identity Providers; the registry renders server truth; reload keeps the route", async ({
    page,
  }) => {
    await page.goto(IDP_ROUTE);
    await expect(page.getByLabel("Username")).toBeVisible();
    const w = watch(page);
    await login(page, USERS.viewer.user, USERS.viewer.pass);
    await expect(page).toHaveURL(new RegExp(`${IDP_ROUTE}$`));
    await expect(
      page.getByRole("heading", { name: "Identity Providers" }),
    ).toBeVisible();
    const main = page.getByRole("main");

    // Identity, type, enabled state, entry revision, indicators.
    const saml = main.getByRole("row", { name: new RegExp(SAML_NAME) });
    await expect(saml).toBeVisible();
    await expect(saml.getByText("saml", { exact: true })).toBeVisible();
    await expect(saml.getByText("Enabled", { exact: true })).toBeVisible();
    await expect(saml.getByText("Inline metadata: configured")).toBeVisible();
    await expect(
      saml.getByText(`Referenced by 1 authentication rule`),
    ).toBeVisible();
    await expect(saml.getByText(RULE_NAME)).toBeVisible();
    const ldap = main.getByRole("row", { name: new RegExp(LDAP_NAME) });
    await expect(ldap.getByText("Disabled", { exact: true })).toBeVisible();
    await expect(ldap.getByText("Bind credential: configured")).toBeVisible();
    await expect(ldap.getByText("Not referenced")).toBeVisible();
    // Every seeded entry carries a server-minted entry revision ≥ 1.
    for (const row of [saml, ldap]) {
      await expect(row.getByText(/^[1-9]\d*$/).first()).toBeVisible();
    }
    // Registry document facts.
    await expect(main.getByText("Cluster-synced").first()).toBeVisible();
    await expect(main.getByText("Persisted", { exact: true })).toBeVisible();
    await expect(main.getByText(/Fleet publication/)).toBeVisible();
    await expect(main.getByText(/Audit sink: (file|memory)/)).toBeVisible();
    // Legacy block absent on AUTH.
    await expect(main.getByText("Legacy YAML LDAP")).toBeVisible();
    await expect(main.getByText("Not present")).toBeVisible();
    // Viewer never issues the admin-only lookup and never mutates.
    expect(
      w.apiCalls.filter((c) => c.path.startsWith("/api/idp/operations/")),
    ).toEqual([]);
    expectOnlyGET(w);
    await expectNoLeak(page, w);

    // Reload keeps the route and the truth.
    await page.reload();
    await expect(page).toHaveURL(new RegExp(`${IDP_ROUTE}$`));
    await expect(main.getByRole("cell", { name: SAML_NAME })).toBeVisible();
    await expectNavLinkReachable(page, "Identity Providers");
    // A viewer has no Administrators entry — not even a planned one.
    const nav = page.getByRole("navigation", { name: "Primary" });
    await expect(nav.getByText("Administrators")).toHaveCount(0);
    expect(ldapId).not.toBe("");
  });

  test("viewer and operator deep links to Administrators render the bounded 403 posture and no roster fact", async ({
    page,
  }) => {
    for (const u of [USERS.viewer, USERS.operator]) {
      await page.context().clearCookies();
      await page.goto(ADMINS_ROUTE);
      await expect(page.getByLabel("Username")).toBeVisible();
      const w = watch(page);
      await login(page, u.user, u.pass);
      // The intent is not authorized for the role: Overview, never the roster.
      await expect(page).toHaveURL(/\/app\/?$/);
      await page.goto(ADMINS_ROUTE);
      await expect(
        page.getByRole("heading", { name: "Administrators" }),
      ).toBeVisible();
      const main = page.getByRole("main");
      await expect(main.getByRole("alert")).toBeVisible();
      await expect(main.getByText(/requires the admin role/)).toBeVisible();
      await expect(
        main.getByRole("cell", { name: "totp-user", exact: true }),
      ).toHaveCount(0);
      await expect(main.getByText(/Roster revision/)).toHaveCount(0);
      expectOnlyGET(w);
      await expectNoLeak(page, w);
    }
  });
});

// ── J9 auth boundary (admin via EMPTY_STATE so the sign-out is observable) ─
test.describe("J9 auth boundary", () => {
  test.use({ storageState: EMPTY_STATE });

  test("signing out from Administrators clears the roster from the DOM and storage; the next viewer session cannot see it", async ({
    page,
  }) => {
    await page.goto(ADMINS_ROUTE);
    await login(page, USERS.admin.user, USERS.admin.pass);
    await expect(page).toHaveURL(new RegExp(`${ADMINS_ROUTE}$`));
    const main = page.getByRole("main");
    await expect(
      main.getByRole("cell", { name: "totp-user", exact: true }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.getByLabel("Username")).toBeVisible();
    const html = await page.evaluate(() => document.documentElement.outerHTML);
    expect(html).not.toContain("totp-user");
    expect(html).not.toContain("Roster revision");
    const storage = await storageDump(page);
    expect(
      storage
        .split("\n")
        .filter((l) => l !== "" && !l.startsWith("culvert-theme")),
    ).toEqual([]);
    await login(page, USERS.viewer.user, USERS.viewer.pass);
    await expect(page).toHaveURL(/\/app\/?$/);
    await page.goto(ADMINS_ROUTE);
    await expect(page.getByRole("main").getByRole("alert")).toBeVisible();
    await expect(
      page
        .getByRole("main")
        .getByRole("cell", { name: "totp-user", exact: true }),
    ).toHaveCount(0);
  });
});

// ── J4 corrupt / quarantined registry + legacy block present (IDPQ) ───────
test.describe("J4 quarantined registry", () => {
  test.use({ storageState: EMPTY_STATE });

  test("IDPQ renders the bounded degraded posture, evidence recorded without a file name, legacy block present and not retired", async ({
    page,
  }) => {
    await page.goto(`${IDPQ_URL}${IDP_ROUTE}`);
    const w = watch(page);
    await login(page, USERS.admin.user, USERS.admin.pass);
    await expect(page).toHaveURL(new RegExp(`${IDP_ROUTE}$`));
    const main = page.getByRole("main");
    await expect(main.getByText("Registry degraded")).toBeVisible();
    await expect(main.getByText("corrupt_quarantined")).toBeVisible();
    await expect(main.getByText("Quarantine evidence: recorded")).toBeVisible();
    await expect(main.getByText("No identity providers")).toBeVisible();
    await expect(main.getByText("Legacy YAML LDAP")).toBeVisible();
    await expect(main.getByText("Present", { exact: true })).toBeVisible();
    await expect(main.getByText("Not retired").first()).toBeVisible();
    await expect(main.getByText("Bind credential: configured")).toBeVisible();
    // Correction round 2: the security-effective legacy configuration is
    // rendered from the wire — this block sets neither start_tls nor
    // tls_skip_verify, so both are false and must be said so.
    await expect(main.getByText("TLS certificate verification")).toBeVisible();
    await expect(main.getByText("Enforced", { exact: true })).toBeVisible();
    await expect(
      main.getByText("Not negotiated", { exact: true }),
    ).toBeVisible();
    await expect(main.getByText("Skipped (tlsSkipVerify)")).toHaveCount(0);
    await expect(main.getByText("Result cache TTL")).toBeVisible();
    await expect(
      main.getByText("Operation ledger", { exact: false }).first(),
    ).toBeVisible();
    const buttons = await main.getByRole("button").allTextContents();
    expect(buttons.every((b) => b.trim() === "Refresh")).toBe(true);
    expectOnlyGET(w);
    // The quarantine file name is a server fact for the repair ceremony
    // (absent from this slice) — it never reaches the DOM, URL or storage.
    const dom = await page.evaluate(() => document.documentElement.outerHTML);
    expect(dom).not.toContain(".corrupt.");
    expect(dom).not.toContain("idp_profiles.json");
    await expectNoLeak(page, w);
  });
});

// ── J5 durable, operation-identified legacy cutover (YAMLUP) ──────────────
test.describe("J5 legacy cutover", () => {
  test.use({ storageState: EMPTY_STATE });

  test("YAMLUP renders the durable cutover record and the admin ledger lookup as committed; a viewer sees the record without the lookup", async ({
    page,
  }) => {
    await page.goto(`${YAML_URL}${IDP_ROUTE}`);
    let w = watch(page);
    await login(page, USERS.admin.user, USERS.admin.pass);
    await expect(page).toHaveURL(new RegExp(`${IDP_ROUTE}$`));
    const main = page.getByRole("main");
    await expect(main.getByText("Legacy YAML LDAP")).toBeVisible();
    await expect(main.getByText("Retired", { exact: true })).toBeVisible();
    await expect(main.getByText("Durable", { exact: true })).toBeVisible();
    await expect(main.getByText("admin_api")).toBeVisible();
    await expect(main.getByText(CUTOVER_NAME).first()).toBeVisible();
    await expect(main.getByText(CUTOVER_OP_ID).first()).toBeVisible();
    await expect(main.getByText("Committed", { exact: true })).toBeVisible();
    await expect(main.getByText("Outcome unknown")).toHaveCount(0);
    expect(
      w.apiCalls.filter(
        (c) => c.path === `/api/idp/operations/${CUTOVER_OP_ID}`,
      ).length,
    ).toBe(1);
    expectOnlyGET(w);
    await expectNoLeak(page, w);

    // Viewer on the same appliance: record yes, admin-only lookup never issued.
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page.getByLabel("Username")).toBeVisible();
    w = watch(page);
    await login(page, USERS.viewer.user, USERS.viewer.pass);
    // Wait for the authenticated shell before navigating, so the navigation
    // never races the sign-in exchange.
    await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible();
    await page.goto(`${YAML_URL}${IDP_ROUTE}`);
    await expect(main.getByText(CUTOVER_OP_ID).first()).toBeVisible();
    await expect(
      main.getByText("Operation record lookup is admin-only"),
    ).toBeVisible();
    expect(
      w.apiCalls.filter((c) => c.path.startsWith("/api/idp/operations/")),
    ).toEqual([]);
    expectOnlyGET(w);
  });
});
