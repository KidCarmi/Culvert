// FE-6A.1 CORRECTION ROUND 2 — RED matrix (page), written against the frozen
// candidate b9336de0 BEFORE any product change.
//
//   DP1 the Legacy YAML LDAP card renders the security-effective legacy
//       configuration truthfully: user filter and required group verbatim,
//       StartTLS posture, TLS certificate verification posture (a skipped
//       verification is a visible warning, never hidden), the result cache
//       TTL; an empty required group is stated as "(none)".
//   DP2 a lock set whose response lacks the lockouts key is a bounded error
//       state, never "No active lockouts".
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
import { LEGACY_PRESENT } from "./fe6a1d-fixtures";

const LIST = {
  persisted: true,
  degraded: false,
  revision: "r-abc123",
  profiles: [],
  scope: "cluster-synced",
  cluster: { state: "published", publishedVersion: 42 },
  operations: {
    degraded: false,
    retained: 0,
    unresolved: 0,
    capacity: 256,
    auditSink: "file",
  },
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

function machineFor(role: "viewer" | "admin", qc: QueryClient): AuthMachine {
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
  role: "viewer" | "admin",
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

/** the <dd> value rendered beside a KeyValue <dt> label */
function rowValue(label: string): string | null {
  for (const dt of Array.from(container.querySelectorAll("dt"))) {
    if (dt.textContent === label)
      return dt.nextElementSibling?.textContent ?? null;
  }
  return null;
}

it("DP1 the legacy card renders the security-effective configuration truthfully", async () => {
  route = (url) => {
    if (url.includes("/api/idp/legacy-ldap")) return okJSON(LEGACY_PRESENT);
    if (url.includes("/api/idp")) return okJSON(LIST);
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("viewer", "/objects/identity-providers");
  await flushUntil(() => {
    expect(rowValue("User filter")).not.toBeNull();
  });
  expect(rowValue("User filter")).toBe("(uid=%s)");
  expect(rowValue("Required group")).toBe(
    "cn=proxy-users,dc=legacy,dc=example",
  );
  expect(rowValue("StartTLS")).toBe("Negotiated");
  expect(rowValue("TLS certificate verification")).toContain("Skipped");
  expect(rowValue("Result cache TTL")).toBe("300 s");
  expect(rowValue("Base DN")).toBe("dc=legacy,dc=example");
  expect(text()).not.toContain("Enforced");
});

it("DP1b verification enforced, StartTLS off, no required group", async () => {
  route = (url) => {
    if (url.includes("/api/idp/legacy-ldap"))
      return okJSON({
        ...LEGACY_PRESENT,
        startTls: false,
        tlsSkipVerify: false,
        requiredGroup: "",
        cacheTtlSeconds: 0,
      });
    if (url.includes("/api/idp")) return okJSON(LIST);
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("viewer", "/objects/identity-providers");
  await flushUntil(() => {
    expect(rowValue("StartTLS")).not.toBeNull();
  });
  expect(rowValue("StartTLS")).toBe("Not negotiated");
  expect(rowValue("TLS certificate verification")).toBe("Enforced");
  expect(rowValue("Required group")).toBe("(none)");
  expect(rowValue("Result cache TTL")).toBe("0 s");
  expect(text()).not.toContain("Skipped");
});

it("DP2 a lock set without the lockouts key is a bounded error, never an empty state", async () => {
  route = (url) => {
    if (url.includes("/api/auth/users"))
      return okJSON({
        users: [
          {
            username: "admin",
            role: "admin",
            totpEnabled: false,
            securityGeneration: 1,
          },
        ],
        revision: 1,
        scope: "node-local",
      });
    if (url.includes("/api/auth/lockouts"))
      return okJSON({ generation: 1, scope: "node-local" });
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("admin", "/administrators");
  await flushUntil(() => {
    expect(container.querySelector('[role="alert"]')).not.toBeNull();
  });
  expect(text()).not.toContain("No active lockouts");
});
