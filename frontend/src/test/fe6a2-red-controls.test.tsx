// FE-6A.2 RED matrix — CONTROLS that pass on the frozen baseline 98d4a6c8 and
// must keep passing: no mutation control renders below the admin role on
// either surface (the read pages render none by construction today; the
// write pages must keep it that way). They live apart from fe6a2-red-page so
// the import of not-yet-existing product modules cannot mask them.
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
import {
  LEGACY_PRESENT,
  LIST,
  RAW,
  ldapProfileAnswer,
  oidcProfileAnswer,
} from "./fe6a2-fixtures";

let container: HTMLDivElement;
let root: Root;
let route: (url: string, method: string) => Promise<Response>;
const json = (body: unknown, status = 200): Promise<Response> =>
  Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  route = () => Promise.reject(new TypeError("unrouted"));
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) =>
      route(String(input), init?.method ?? "GET"),
    ),
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

async function mount(role: "viewer" | "operator", path: string): Promise<void> {
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
  const machine = new AuthMachine(qc, {
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
const buttons = (name: string): HTMLButtonElement[] =>
  Array.from(container.querySelectorAll("button")).filter(
    (b) => (b.textContent ?? "").trim() === name,
  );

const MUTATION_CONTROLS = [
  "Add provider",
  "Edit",
  "Delete",
  "Import legacy configuration",
  "Repair registry",
  "Recover",
  "Re-send",
  "Abandon",
];
const ADMIN_CONTROLS = [
  "Add account",
  "Edit",
  "Delete",
  "Clear",
  "Change my password",
];

it("C1 a viewer sees no Identity Provider mutation control — even on a degraded registry with a live legacy block", async () => {
  route = (url, method) => {
    if (method !== "GET") return json({ error: RAW, code: "forbidden" }, 403);
    if (url.startsWith("/api/idp/legacy-ldap")) return json(LEGACY_PRESENT);
    if (url.startsWith("/api/objects/references"))
      return json({ object: { type: "idp", name: "x" }, referencedBy: [] });
    if (url === "/api/idp")
      return json({
        ...LIST,
        degraded: true,
        degradedReason: "corrupt_quarantined",
        quarantineEvidence: "idp_profiles.json.corrupt.1",
        profiles: [oidcProfileAnswer(), ldapProfileAnswer()],
      });
    return Promise.reject(new TypeError(`unexpected ${url}`));
  };
  await mount("viewer", "/objects/identity-providers");
  await flushUntil(() => {
    expect(text()).toContain("Legacy YAML LDAP");
    expect(text()).toContain("Registry degraded");
  });
  for (const name of MUTATION_CONTROLS)
    expect(buttons(name), name).toHaveLength(0);
  const nonRefresh = Array.from(container.querySelectorAll("button")).filter(
    (b) => (b.textContent ?? "").trim() !== "Refresh",
  );
  expect(nonRefresh).toHaveLength(0);
});

it("C2 an operator sees no Administrators mutation control (the server refuses the reads)", async () => {
  route = () => json({ error: RAW, code: "forbidden" }, 403);
  await mount("operator", "/administrators");
  await flushUntil(() => {
    expect(text()).toContain("requires the admin role");
  });
  for (const name of ADMIN_CONTROLS)
    expect(buttons(name), name).toHaveLength(0);
});
