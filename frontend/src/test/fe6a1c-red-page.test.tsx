// FE-6A.1 CORRECTION RED matrix (pages) — written against the frozen FE-6A.1
// candidate 6ab24a1e BEFORE any product change:
//
//   CP1 a raw fleet-rejection reason and a raw ledger reason never reach the
//       DOM: the list decoder refuses the response, the page shows a bounded
//       error state and the raw text is absent.
//   CP2 registry failure + successful legacy read: the node-local legacy
//       snapshot (block, authority, cutover record) still renders beside the
//       registry error state.
//   CP3 legacy failure + successful registry read: the registry (providers,
//       document facts) still renders beside the legacy error state.
//   CP4 zero / one / multiple administrators are three distinct postures;
//       zero is never "More than one administrator".
//   CP5 an unknown lookup refusal code renders a bounded refusal without the
//       code text.
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

const RAW = "dial tcp /data/private: permission denied";
const OP_ID = "0b6f9a1e-2c3d-4e5f-8a9b-0c1d2e3f4a5b";
const CUTOVER_ID = "HBVfpgASPQEYE1ZaJo8H1g";

const LDAP = {
  id: "ldap-dc",
  name: "DC LDAP",
  type: "ldap",
  emailDomains: null,
  enabled: true,
  priority: 5,
  revision: 2,
  operationId: OP_ID,
  ldap: {
    url: "ldaps://dc.example:636",
    bindDn: "cn=svc,dc=example",
    bindCredentialConfigured: true,
  },
};
const LIST = {
  persisted: true,
  degraded: false,
  revision: "r-abc123",
  profiles: [LDAP],
  scope: "cluster-synced",
  cluster: { state: "published", publishedVersion: 42 },
  operations: {
    degraded: false,
    retained: 1,
    unresolved: 0,
    capacity: 256,
    auditSink: "file",
  },
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
  cutoverDurability: "durable",
  cutover: {
    operationId: CUTOVER_ID,
    profileId: "ldap-dc",
    profileName: "DC LDAP",
    registryRevision: "r-abc123",
    actor: "admin@10.0.0.9",
    trigger: "admin_api",
    at: "2026-09-12T09:59:01Z",
    durable: true,
  },
};
const LEGACY_ABSENT = {
  present: false,
  retired: false,
  scope: "node-local",
  cutoverDurability: "not_retired",
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
let route: (url: string) => Promise<Response>;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  route = () => Promise.reject(new TypeError("unrouted"));
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown) => route(String(input))),
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

type RoleName = "viewer" | "admin";

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

const text = (): string => container.textContent ?? "";

it("CP1 a raw fleet rejection reason never reaches the DOM (the response is refused as a whole)", async () => {
  route = (url) => {
    if (url.includes("/api/idp/legacy-ldap")) return okJSON(LEGACY_ABSENT);
    if (url.includes("/api/idp"))
      return okJSON({
        ...LIST,
        cluster: {
          state: "pending",
          publishedVersion: 41,
          lastRejection: { reason: RAW, at: "t" },
        },
      });
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("viewer", "/objects/identity-providers");
  await flushUntil(() => {
    expect(container.querySelector('[role="alert"]')).not.toBeNull();
  });
  expect(text()).not.toContain(RAW);
  expect(text()).not.toContain("permission denied");
  expect(text()).not.toContain("DC LDAP"); // nothing of a refused response is rendered
});

it("CP1b a raw ledger degradation reason never reaches the DOM", async () => {
  route = (url) => {
    if (url.includes("/api/idp/legacy-ldap")) return okJSON(LEGACY_ABSENT);
    if (url.includes("/api/idp"))
      return okJSON({
        ...LIST,
        operations: { ...LIST.operations, degraded: true, degradedReason: RAW },
      });
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("viewer", "/objects/identity-providers");
  await flushUntil(() => {
    expect(container.querySelector('[role="alert"]')).not.toBeNull();
  });
  expect(text()).not.toContain(RAW);
  expect(text()).not.toContain("permission denied");
});

it("CP2 registry failure + successful legacy read still renders the legacy snapshot", async () => {
  route = (url) => {
    if (url.includes("/api/idp/legacy-ldap")) return okJSON(LEGACY_CUTOVER);
    if (url.includes("/api/idp"))
      return okJSON({ error: RAW, code: "persist_failed" }, 500);
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("viewer", "/objects/identity-providers");
  await flushUntil(() => {
    expect(text()).toContain("Legacy YAML LDAP");
    expect(text()).toContain("Identity-provider registry unavailable");
  });
  const t = text();
  expect(t).toContain("Present");
  expect(t).toContain("Retired");
  expect(t).toContain("Durable");
  expect(t).toContain(CUTOVER_ID);
  expect(t).toContain("admin_api");
  expect(t).not.toContain(RAW);
});

it("CP3 legacy failure + successful registry read still renders the registry", async () => {
  route = (url) => {
    if (url.includes("/api/idp/legacy-ldap"))
      return okJSON({ error: RAW, code: "persist_failed" }, 500);
    if (url.includes("/api/objects/references"))
      return okJSON({ object: { type: "idp", name: "x" }, referencedBy: [] });
    if (url.includes("/api/idp")) return okJSON(LIST);
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("viewer", "/objects/identity-providers");
  await flushUntil(() => {
    expect(text()).toContain("DC LDAP");
    expect(text()).toContain("Legacy YAML LDAP posture unavailable");
  });
  const t = text();
  expect(t).toContain("r-abc123");
  expect(t).toContain("Published (config version 42)");
  expect(t).not.toContain(RAW);
});

it("CP4 zero, one and multiple administrators are three distinct postures", async () => {
  const roster = (roles: string[]): unknown => ({
    users: roles.map((r, i) => ({
      username: `u${String(i)}`,
      role: r,
      totpEnabled: false,
      securityGeneration: 1,
    })),
    revision: 1,
    scope: "node-local",
  });
  const locks = { lockouts: [], generation: 1, scope: "node-local" };
  route = (url) => {
    if (url.includes("/api/auth/users"))
      return okJSON(roster(["viewer", "operator"]));
    if (url.includes("/api/auth/lockouts")) return okJSON(locks);
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("admin", "/administrators");
  await flushUntil(() => {
    expect(text()).toContain("No administrator accounts");
  });
  expect(text()).not.toContain("More than one administrator");
  expect(text()).not.toContain("Last admin:");
  act(() => {
    root.unmount();
  });
  route = (url) => {
    if (url.includes("/api/auth/users"))
      return okJSON(roster(["admin", "viewer"]));
    if (url.includes("/api/auth/lockouts")) return okJSON(locks);
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("admin", "/administrators");
  await flushUntil(() => {
    expect(text()).toContain("Last admin: u0");
  });
  expect(text()).not.toContain("More than one administrator");
  expect(text()).not.toContain("No administrator accounts");
  act(() => {
    root.unmount();
  });
  route = (url) => {
    if (url.includes("/api/auth/users"))
      return okJSON(roster(["admin", "admin"]));
    if (url.includes("/api/auth/lockouts")) return okJSON(locks);
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("admin", "/administrators");
  await flushUntil(() => {
    expect(text()).toContain("More than one administrator");
  });
  expect(text()).not.toContain("No administrator accounts");
  expect(text()).not.toContain("Last admin:");
});

it("CP5 an unknown lookup refusal code renders a bounded refusal without the code", async () => {
  route = (url) => {
    if (url.includes("/api/idp/legacy-ldap")) return okJSON(LEGACY_CUTOVER);
    if (url.includes("/api/idp/operations/"))
      return okJSON({ error: RAW, code: "made_up_code" }, 503);
    if (url.includes("/api/objects/references"))
      return okJSON({ object: { type: "idp", name: "x" }, referencedBy: [] });
    if (url.includes("/api/idp")) return okJSON(LIST);
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("admin", "/objects/identity-providers");
  await flushUntil(() => {
    expect(text()).toContain("Lookup refused");
  });
  expect(text()).not.toContain("made_up_code");
  expect(text()).not.toContain(RAW);
  expect(text()).not.toContain("Committed");
});
