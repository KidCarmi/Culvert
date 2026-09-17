// FE-6A.2 CORRECTION ROUND 5 RED — page half, written against the frozen
// corrected candidate a56ac527 BEFORE any product change (Blocker 1: a
// sentinel without its record is rendered as DEGRADED evidence, never as a
// durable cutover).
//
//   DP1  `record_missing` renders the legacy card with a degraded badge that
//        names the missing record, no "Durable" claim, no cutover identity,
//        and issues no non-GET.
//
// On a56ac527 DP1 fails (the decoder refuses the word, so the card cannot
// render the posture).
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { IdentityProvidersPage } from "../features/objects/IdentityProvidersPage";
import { LEGACY_PRESENT, LIST } from "./fe6a2-fixtures";

interface Call {
  url: string;
  method: string;
}
let calls: Call[];
let route: (c: Call) => Response | Promise<Response>;
let container: HTMLDivElement;
let root: Root;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  calls = [];
  sessionStorage.clear();
  Element.prototype.scrollIntoView = vi.fn();
  route = () => Promise.reject(new TypeError("unrouted"));
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const c: Call = { url: String(input), method: init?.method ?? "GET" };
      calls.push(c);
      return Promise.resolve(route(c));
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

async function mount(): Promise<void> {
  const rt = createMemoryRouter(
    [
      {
        path: "/objects/identity-providers",
        element: <IdentityProvidersPage />,
      },
    ],
    { initialEntries: ["/objects/identity-providers"] },
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
        user: "admin-user",
        role: "admin" as const,
        bootstrap: false,
        securityGeneration: 3,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    postLogout: () => Promise.resolve({ ok: true as const }),
  });
  await machine.boot();
  act(() => {
    root = createRoot(container);
    root.render(
      <StrictMode>
        <QueryClientProvider client={qc}>
          <AuthProvider machine={machine}>
            <RouterProvider router={rt} />
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
const buttonTexts = (): string[] =>
  Array.from(container.querySelectorAll("button")).map((b) =>
    (b.textContent ?? "").trim(),
  );

const LEGACY_RECORD_MISSING = {
  ...LEGACY_PRESENT,
  active: false,
  retired: true,
  shadowed: true,
  cutoverDurability: "record_missing",
};

it("DP1 admin: a sentinel without its record renders as degraded evidence, never as a durable cutover", async () => {
  route = (c) => {
    if (c.url.startsWith("/api/idp/legacy-ldap") && c.method === "GET")
      return json(LEGACY_RECORD_MISSING);
    if (c.url.startsWith("/api/objects/references"))
      return json({ object: { type: "idp", name: "x" }, referencedBy: [] });
    if (c.url === "/api/idp" && c.method === "GET") return json(LIST);
    return Promise.reject(new TypeError(`unexpected ${c.method} ${c.url}`));
  };
  await mount();
  await flushUntil(() => {
    expect(text()).toContain("Record missing");
  });
  const t = text();
  expect(t).toContain("Legacy YAML LDAP");
  expect(t).toContain("Retired");
  expect(t).not.toContain("Durable");
  expect(t).not.toContain("Pending reconciliation");
  expect(t).not.toContain("admin_api");
  expect(t).not.toContain("Could not load");
  // The record's identity is not fabricated on the page either.
  expect(t).not.toContain("Cutover operation");
  // (The Import control is gated on `present` alone — pre-existing FE-6A.2
  // behaviour; the server refuses an import on a retired node. Not part of
  // this blocker, so it is deliberately not asserted here.)
  expect(buttonTexts().length).toBeGreaterThan(0);
  expect(calls.filter((c) => c.method !== "GET")).toEqual([]);
});
