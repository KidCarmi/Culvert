// FE-6A.1 RED matrix (pages) — written against the merged FE-6A.1 baseline
// (3b6ba325) BEFORE the Identity Providers / Administrators surfaces exist;
// fails at import resolution there. Pins the browser-side guarantees of the
// FE-6A.1 directive against the frozen FE-6A.0 backend read models,
// rendered from STRUCTURED server facts (never prose, never frontend
// wording that compensates for the appliance):
//
//   P1  viewer, populated registry: every profile renders its identity,
//       type, enabled state, ENTRY revision and provenance; the document
//       revision, the cluster-synced scope, the fleet publication result
//       and the ledger posture are shown; write-only secrets appear ONLY as
//       configured/not-configured indicators; the referenced-provider
//       posture names the blocking authentication rules; the page mounts
//       ZERO controls other than Refresh and issues ZERO non-GET requests
//       and ZERO admin-only lookups.
//   P2  degraded registry: the bounded reason renders, the quarantine
//       evidence is reported as RECORDED without its file name, and the
//       empty registry is an empty state — never a guessed "healthy".
//   P3  legacy-LDAP cutover: admin sees the record (operation identity,
//       trigger, actor), the bounded durability word, and the authoritative
//       operation lookup rendered as its server state — outcome_unknown
//       stays "unknown", never success or failure; viewer/operator never
//       issue the admin-only lookup and are told it is admin-only.
//   P4  a raw server error body never reaches the DOM; the surface shows a
//       bounded error state.
//   P5  admin, Administrators: username / durable role / security
//       generation / TOTP presence per account, roster revision, node-local
//       scope, administrator count + last-admin posture, active lockouts
//       with their generation; ZERO mutation controls; ZERO non-GET.
//   P6  viewer / operator on Administrators: the 403 is a bounded error
//       state, no roster fact is rendered.
//   P7  the roster and the lock set are INDEPENDENT snapshots: a failed
//       lockouts read leaves the roster rendered and the lockouts in an
//       error state (never blank success).
//   P8  the operation lookup's bounded refusals: 404 not_found renders "no
//       retained record"; 503 operation_ledger_degraded renders the refusal
//       code — neither is converted into an outcome.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { IdentityProvidersPage } from "../features/objects/IdentityProvidersPage";
import { AdministratorsPage } from "../features/administration/AdministratorsPage";
import { AppShell } from "../layouts/AppShell";
import { ToastProvider } from "../design-system/toast";

const OP_ID = "0b6f9a1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b";
const SECRET_CANARY = "SECRET-CANARY-never-rendered";
const RAW_CANARY = "RAWCANARY-/srv/never/render";
const EVIDENCE = "idp_profiles.json.corrupt.1757600000000000000";

const OIDC = {
  id: "oidc-corp",
  name: "Corp OIDC",
  type: "oidc",
  emailDomains: ["corp.example"],
  enabled: true,
  priority: 10,
  revision: 3,
  operationId: OP_ID,
  oidc: {
    issuer: "https://issuer.example",
    clientId: "client-a",
    clientSecretConfigured: true,
  },
};
const CUTOVER_ID = "HBVfpgASPQEYE1ZaJo8H1g"; // the cutover's OWN server-minted identity
const LDAP = {
  id: "ldap-dc",
  name: "DC LDAP",
  type: "ldap",
  emailDomains: null,
  enabled: false,
  priority: 5,
  revision: 2,
  operationId: OP_ID, // create provenance = the ledger key
  ldap: {
    url: "ldaps://dc.example:636",
    bindDn: "cn=svc,dc=example",
    bindCredentialConfigured: false,
  },
};
const LIST = {
  persisted: true,
  degraded: false,
  revision: "r-abc123",
  profiles: [OIDC, LDAP],
  scope: "cluster-synced",
  cluster: { state: "published", publishedVersion: 42 },
  operations: {
    degraded: false,
    retained: 3,
    unresolved: 1,
    capacity: 256,
    auditSink: "file",
  },
};
const DEGRADED = {
  persisted: true,
  degraded: true,
  degradedReason: "corrupt_quarantined",
  degradedDetail: "moved aside",
  quarantineEvidence: EVIDENCE,
  revision: "r-empty",
  profiles: null,
  scope: "cluster-synced",
  cluster: {
    state: "pending",
    publishedVersion: 41,
    lastRejection: { reason: "snapshot_invalid", at: "2026-09-12T10:00:00Z" },
  },
  operations: {
    degraded: true,
    degradedReason: "corrupt",
    retained: 0,
    unresolved: 0,
    capacity: 256,
    auditSink: "memory",
  },
};
const LEGACY_ABSENT = {
  present: false,
  retired: false,
  scope: "node-local",
  cutoverDurability: "not_retired",
};
const LEGACY_CUTOVER = {
  present: true,
  active: false,
  scope: "node-local",
  retired: true,
  shadowed: true,
  url: "ldaps://legacy.example:636",
  baseDn: "dc=legacy",
  bindDn: "cn=svc,dc=legacy",
  bindCredentialConfigured: true,
  cutoverDurability: "pending_reconciliation",
  cutover: {
    operationId: CUTOVER_ID,
    profileId: "ldap-dc",
    profileName: "DC LDAP",
    registryRevision: "r-abc123",
    actor: "admin@10.0.0.9",
    trigger: "admin_api",
    at: "2026-09-12T09:59:01Z",
    durable: false,
  },
};
const OP_UNKNOWN = {
  operationId: OP_ID,
  state: "outcome_unknown",
  action: "idp.create",
  actor: "admin@10.0.0.9",
  profileId: "ldap-dc",
  registryRevision: "r-abc123",
  cutover: true,
  startedAt: "2026-09-12T09:59:00Z",
  finishedAt: "2026-09-12T09:59:02Z",
  audited: false,
  code: "outcome_unknown",
};
const ROSTER = {
  users: [
    {
      username: "admin",
      role: "admin",
      totpEnabled: false,
      securityGeneration: 4,
    },
    {
      username: "op-user",
      role: "operator",
      totpEnabled: false,
      securityGeneration: 1,
    },
    {
      username: "view-user",
      role: "viewer",
      totpEnabled: true,
      securityGeneration: 2,
    },
  ],
  revision: 7,
  scope: "node-local",
};
const LOCKOUTS = {
  lockouts: [
    { tier: "account", username: "op-user", seconds_remaining: 120 },
    {
      tier: "pair",
      username: "op-user",
      ip: "10.0.0.9",
      seconds_remaining: 30,
    },
  ],
  generation: 9,
  scope: "node-local",
};

function okJSON(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

let container: HTMLDivElement;
let root: Root;
let requests: Array<{ method: string; url: string }>;
let route: (url: string) => Promise<Response>;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  requests = [];
  route = (url) => {
    if (url.includes("/api/idp/legacy-ldap")) return okJSON(LEGACY_ABSENT);
    if (url.includes("/api/idp/operations/")) return okJSON(OP_UNKNOWN);
    if (url.includes("/api/objects/references")) {
      const name = new URL(url, "http://localhost").searchParams.get("name");
      return okJSON({
        object: { type: "idp", name: name ?? "" },
        referencedBy:
          name === "oidc-corp"
            ? [
                {
                  consumerType: "auth-rule",
                  id: "01HRULE",
                  name: "SSO Rule",
                  detail: "auth.providerRefs",
                  view: "authpolicy",
                },
              ]
            : [],
      });
    }
    if (url.includes("/api/idp")) return okJSON(LIST);
    if (url.includes("/api/auth/users")) return okJSON(ROSTER);
    if (url.includes("/api/auth/lockouts")) return okJSON(LOCKOUTS);
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      requests.push({ method: init?.method ?? "GET", url });
      return route(url);
    }),
  );
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  container.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

type RoleName = "viewer" | "operator" | "admin";

function machineFor(role: RoleName, qc: QueryClient): AuthMachine {
  return new AuthMachine(qc, {
    getSetupStatus: () =>
      Promise.resolve({
        needsSetup: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    getAuthStatus: () =>
      Promise.resolve({
        loggedIn: true,
        user: `${role}-user`,
        role,
        bootstrap: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    postLogout: () => Promise.resolve({ ok: true }),
  });
}

async function mount(
  role: RoleName,
  path: "/objects/identity-providers" | "/administrators",
): Promise<void> {
  const router = createMemoryRouter(
    [
      {
        path: "/objects/identity-providers",
        element: <IdentityProvidersPage />,
      },
      { path: "/administrators", element: <AdministratorsPage /> },
    ],
    { initialEntries: [path] },
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const machine = machineFor(role, qc);
  await machine.boot();
  act(() => {
    root = createRoot(container);
    root.render(
      <StrictMode>
        <QueryClientProvider client={qc}>
          <AuthProvider machine={machine}>
            <RouterProvider router={router} />
          </AuthProvider>
        </QueryClientProvider>
      </StrictMode>,
    );
  });
}

async function flushUntil(cond: () => void): Promise<void> {
  await vi.waitFor(async () => {
    await act(async () => {
      await new Promise((r) => {
        setTimeout(r, 0);
      });
    });
    cond();
  });
}

function text(): string {
  return container.textContent ?? "";
}

function buttonTexts(): string[] {
  return Array.from(container.querySelectorAll("button")).map((b) =>
    (b.textContent ?? "").trim(),
  );
}

function nonGET(): Array<{ method: string; url: string }> {
  return requests.filter((r) => r.method !== "GET");
}

// ── P1 ─────────────────────────────────────────────────────────────────────
it("P1 viewer: populated registry renders every server fact, indicators only, no controls, no non-GET, no admin lookup", async () => {
  await mount("viewer", "/objects/identity-providers");
  await flushUntil(() => {
    expect(text()).toContain("Corp OIDC");
    expect(text()).toContain("Referenced by 1 authentication rule");
  });
  const t = text();
  expect(t).toContain("DC LDAP");
  expect(t).toContain("oidc");
  expect(t).toContain("ldap");
  expect(t).toContain("Enabled");
  expect(t).toContain("Disabled");
  expect(t).toContain("r-abc123"); // document revision
  expect(t).toContain("Cluster-synced");
  expect(t).toContain("Published (config version 42)");
  expect(t).toContain(OP_ID); // provenance of the create that produced the entry
  expect(t).toContain("Client secret: configured");
  expect(t).toContain("Bind credential: not configured");
  expect(t).toContain("SSO Rule");
  expect(t).toContain("Not referenced");
  expect(t).toContain("Unresolved intents: 1");
  expect(t).toContain("Retained: 3 of 256");
  expect(t).toContain("Audit sink: file");
  expect(t).not.toContain(SECRET_CANARY);
  // Read-only: the ONLY buttons are Refresh; no create/edit/delete/test/
  // repair/cutover/credential control, not even a disabled one.
  expect(buttonTexts().every((b) => b === "Refresh")).toBe(true);
  expect(buttonTexts().length).toBeGreaterThan(0);
  expect(
    container.querySelectorAll("input,select,textarea,dialog,form").length,
  ).toBe(0);
  expect(nonGET()).toEqual([]);
  expect(requests.some((r) => r.url.includes("/api/idp/operations/"))).toBe(
    false,
  );
  // no persisted-state claim beyond the server's: persisted:true renders as such
  expect(t).toContain("Persisted");
});

// ── P2 ─────────────────────────────────────────────────────────────────────
it("P2 degraded registry: bounded reason, evidence recorded without its name, empty state, pending publication with its rejection", async () => {
  route = (url) => {
    if (url.includes("/api/idp/legacy-ldap")) return okJSON(LEGACY_ABSENT);
    if (url.includes("/api/idp")) return okJSON(DEGRADED);
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("viewer", "/objects/identity-providers");
  await flushUntil(() => {
    expect(text()).toContain("corrupt_quarantined");
  });
  const t = text();
  expect(t).toContain("Registry degraded");
  expect(t).toContain("Quarantine evidence: recorded");
  expect(t).not.toContain(EVIDENCE);
  expect(t).not.toContain(".corrupt.");
  expect(t).toContain("No identity providers");
  expect(t).toContain("Pending publication");
  expect(t).toContain("snapshot_invalid");
  expect(t).toContain("Operation ledger degraded");
  expect(t).toContain("Audit sink: memory");
  expect(buttonTexts().every((b) => b === "Refresh")).toBe(true);
  expect(nonGET()).toEqual([]);
});

// ── P3 ─────────────────────────────────────────────────────────────────────
it("P3 admin: legacy cutover record + pending_reconciliation + the operation lookup rendered as outcome_unknown (never a guess)", async () => {
  route = (url) => {
    if (url.includes("/api/idp/legacy-ldap")) return okJSON(LEGACY_CUTOVER);
    if (url.includes("/api/idp/operations/")) return okJSON(OP_UNKNOWN);
    if (url.includes("/api/objects/references"))
      return okJSON({ object: { type: "idp", name: "x" }, referencedBy: [] });
    if (url.includes("/api/idp")) return okJSON(LIST);
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("admin", "/objects/identity-providers");
  await flushUntil(() => {
    expect(text()).toContain("Outcome unknown");
  });
  const t = text();
  expect(t).toContain("Legacy YAML LDAP");
  expect(t).toContain("Pending reconciliation");
  expect(t).toContain("admin_api");
  expect(t).toContain("admin@10.0.0.9");
  expect(t).toContain("Retired");
  expect(t).toContain("Bind credential: configured");
  expect(t).toContain(CUTOVER_ID); // the cutover's own identity
  expect(t).toContain(OP_ID); // the ledger key (enabling create provenance)
  expect(t).not.toContain("Committed");
  expect(t).not.toContain("succeeded");
  expect(t).not.toContain("failed");
  // The lookup is issued (StrictMode's dev-only double subscription may
  // cancel-and-restart the first fetch; the real-binary journey pins exactly
  // one against the production bundle).
  expect(
    requests.filter((r) => r.url.includes(`/api/idp/operations/${OP_ID}`))
      .length,
  ).toBeGreaterThanOrEqual(1);
  expect(nonGET()).toEqual([]);
  expect(buttonTexts().every((b) => b === "Refresh")).toBe(true);
});

it("P3b viewer: the cutover record renders but the admin-only lookup is never issued", async () => {
  route = (url) => {
    if (url.includes("/api/idp/legacy-ldap")) return okJSON(LEGACY_CUTOVER);
    if (url.includes("/api/objects/references"))
      return okJSON({ object: { type: "idp", name: "x" }, referencedBy: [] });
    if (url.includes("/api/idp")) return okJSON(LIST);
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("viewer", "/objects/identity-providers");
  await flushUntil(() => {
    expect(text()).toContain("Pending reconciliation");
  });
  expect(text()).toContain(OP_ID);
  expect(text()).toContain(CUTOVER_ID);
  expect(text()).toContain("Operation record lookup is admin-only");
  expect(requests.some((r) => r.url.includes("/api/idp/operations/"))).toBe(
    false,
  );
});

// ── P4 ─────────────────────────────────────────────────────────────────────
it("P4 a raw server error body never reaches the DOM", async () => {
  route = (url) => {
    if (url.includes("/api/idp/legacy-ldap")) return okJSON(LEGACY_ABSENT);
    if (url.includes("/api/idp"))
      return okJSON({ error: RAW_CANARY, code: "persist_failed" }, 500);
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("viewer", "/objects/identity-providers");
  await flushUntil(() => {
    expect(container.querySelector('[role="alert"]')).not.toBeNull();
  });
  expect(text()).not.toContain(RAW_CANARY);
  expect(text()).toContain("HTTP 500");
});

// ── P5 ─────────────────────────────────────────────────────────────────────
it("P5 admin: roster facts, last-admin posture, TOTP presence, lockouts; no mutation controls; no non-GET", async () => {
  await mount("admin", "/administrators");
  await flushUntil(() => {
    expect(text()).toContain("view-user");
    expect(text()).toContain("10.0.0.9");
  });
  const t = text();
  expect(t).toContain("Node-local");
  expect(t).toContain("Roster revision 7");
  expect(t).toContain("1 administrator account");
  expect(t).toContain("Last admin: admin");
  expect(t).toContain("operator");
  expect(t).toContain("viewer");
  expect(t).toContain("configured"); // TOTP presence for view-user
  expect(t).toContain("Lock-set generation 9");
  expect(t).toContain("account");
  expect(t).toContain("pair");
  expect(t).toContain("120");
  expect(buttonTexts().every((b) => b === "Refresh")).toBe(true);
  expect(
    container.querySelectorAll("input,select,textarea,dialog,form").length,
  ).toBe(0);
  expect(nonGET()).toEqual([]);
  // security generation per account is rendered (session-binding fact)
  expect(t).toContain("4");
});

// ── P6 ─────────────────────────────────────────────────────────────────────
it("P6 viewer / operator: the 403 is a bounded error state and no roster fact renders", async () => {
  route = (url) => {
    if (url.includes("/api/auth/"))
      return okJSON(
        { error: `forbidden ${RAW_CANARY}`, code: "forbidden" },
        403,
      );
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("operator", "/administrators");
  await flushUntil(() => {
    expect(container.querySelector('[role="alert"]')).not.toBeNull();
  });
  const t = text();
  expect(t).toContain("requires the admin role");
  expect(t).not.toContain("op-user");
  expect(t).not.toContain(RAW_CANARY);
  expect(nonGET()).toEqual([]);
});

// ── P7 ─────────────────────────────────────────────────────────────────────
it("P7 roster and lockouts are independent snapshots", async () => {
  route = (url) => {
    if (url.includes("/api/auth/users")) return okJSON(ROSTER);
    if (url.includes("/api/auth/lockouts"))
      return okJSON({ error: RAW_CANARY }, 500);
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("admin", "/administrators");
  await flushUntil(() => {
    expect(text()).toContain("view-user");
    expect(text()).toContain("Lockouts unavailable");
  });
  expect(text()).not.toContain(RAW_CANARY);
  expect(text()).not.toContain("No active lockouts");
});

// ── P8 ─────────────────────────────────────────────────────────────────────
it("P8 operation lookup refusals stay bounded: 404 → no retained record; 503 → the refusal code", async () => {
  route = (url) => {
    if (url.includes("/api/idp/legacy-ldap")) return okJSON(LEGACY_CUTOVER);
    if (url.includes("/api/idp/operations/"))
      return okJSON({ error: RAW_CANARY, code: "not_found" }, 404);
    if (url.includes("/api/objects/references"))
      return okJSON({ object: { type: "idp", name: "x" }, referencedBy: [] });
    if (url.includes("/api/idp")) return okJSON(LIST);
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("admin", "/objects/identity-providers");
  await flushUntil(() => {
    expect(text()).toContain("No retained operation record");
  });
  expect(text()).not.toContain(RAW_CANARY);
  act(() => {
    root.unmount();
  });
  requests = [];
  route = (url) => {
    if (url.includes("/api/idp/legacy-ldap")) return okJSON(LEGACY_CUTOVER);
    if (url.includes("/api/idp/operations/"))
      return okJSON(
        { error: RAW_CANARY, code: "operation_ledger_degraded" },
        503,
      );
    if (url.includes("/api/objects/references"))
      return okJSON({ object: { type: "idp", name: "x" }, referencedBy: [] });
    if (url.includes("/api/idp")) return okJSON(LIST);
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("admin", "/objects/identity-providers");
  await flushUntil(() => {
    expect(text()).toContain("Lookup refused: operation_ledger_degraded");
  });
  expect(text()).not.toContain(RAW_CANARY);
  expect(text()).not.toContain("Committed");
});

// ── P0 navigation placement (FE-6-0 migration-plan record) ────────────────
// Identity Providers is a REAL Objects entry (viewer floor, uiRoutes GET
// /api/idp = viewer); Administrators is a REAL Administration entry (admin,
// uiRoutes GET /api/auth/users = admin) — no longer "planned". A viewer's
// shell carries no Administrators entry at all.

async function mountShell(role: RoleName): Promise<void> {
  const router = createMemoryRouter(
    [
      {
        path: "/",
        element: <AppShell />,
        children: [{ index: true, element: <div>home</div> }],
      },
    ],
    { initialEntries: ["/"] },
  );
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const machine = machineFor(role, qc);
  await machine.boot();
  act(() => {
    root = createRoot(container);
    root.render(
      <StrictMode>
        <QueryClientProvider client={qc}>
          <ToastProvider>
            <AuthProvider machine={machine}>
              <RouterProvider router={router} />
            </AuthProvider>
          </ToastProvider>
        </QueryClientProvider>
      </StrictMode>,
    );
  });
  await flushUntil(() => {
    expect(text()).toContain("CULVERT");
  });
}

function navLink(label: string): HTMLAnchorElement | null {
  const a = Array.from(container.querySelectorAll("nav a")).find(
    (el) => (el.textContent ?? "").trim() === label,
  );
  return a instanceof HTMLAnchorElement ? a : null;
}

it("P0 admin shell: Identity Providers (Objects) and Administrators (Administration) are real links at the approved paths", async () => {
  route = () => okJSON({});
  await mountShell("admin");
  expect(navLink("Identity Providers")?.getAttribute("href")).toBe(
    "/objects/identity-providers",
  );
  expect(navLink("Administrators")?.getAttribute("href")).toBe(
    "/administrators",
  );
  // Not a planned placeholder any more.
  const planned = Array.from(
    container.querySelectorAll("nav [aria-disabled='true']"),
  ).map((el) => el.textContent ?? "");
  expect(planned.some((t) => t.includes("Administrators"))).toBe(false);
});

it("P0 viewer shell: Identity Providers is present; Administrators is absent entirely", async () => {
  route = () => okJSON({});
  await mountShell("viewer");
  expect(navLink("Identity Providers")?.getAttribute("href")).toBe(
    "/objects/identity-providers",
  );
  expect(navLink("Administrators")).toBeNull();
  expect(text()).not.toContain("Administrators");
});
