// FE-6A.2 CORRECTION ROUND 4 RED — page half, written against the frozen
// corrected candidate 67e2a4a8 BEFORE any product change (Blocker 2: the
// lost-response recovery clears an import marker for ANY committed record
// with the same operationId — action and reviewed source unverified).
//
//   L1  import marker + committed `idp.create` record with the same id ⇒
//       UNPROVEN: the marker is RETAINED, nothing is re-sent, no success
//       is claimed.
//   L2  import marker (token A) + committed import bound to token B ⇒
//       UNPROVEN, marker retained, no re-send, no success claim.
//   L3  (control) token A + committed import bound to token A ⇒ committed
//       and the marker cleared.
//   L4  (control) pending / aborted / outcome_unknown semantics unchanged:
//       the marker stays, no re-send, Abandon only on an aborted record.
//
// On 67e2a4a8 L1 and L2 fail (the marker is cleared and "committed" is
// announced); L3 and L4 pass.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { IdentityProvidersPage } from "../features/objects/IdentityProvidersPage";
import { IDP_RECOVERY_KEY } from "../features/objects/idpRecovery";
import {
  LEGACY_PRESENT,
  OTHER_SOURCE_TOKEN,
  SOURCE_TOKEN,
  LIST,
} from "./fe6a2-fixtures";

interface Call {
  url: string;
  method: string;
  body: unknown;
  markerAtDispatch: string | null;
}
let calls: Call[];
let route: (c: Call) => Response | Promise<Response>;
let container: HTMLDivElement;
let root: Root;

const marker = (): string | null => sessionStorage.getItem(IDP_RECOVERY_KEY);
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
  Object.defineProperty(HTMLDialogElement.prototype, "showModal", {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.open = true;
    },
  });
  Object.defineProperty(HTMLDialogElement.prototype, "close", {
    configurable: true,
    value(this: HTMLDialogElement) {
      this.open = false;
    },
  });
  route = () => Promise.reject(new TypeError("unrouted"));
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const raw = init?.body;
      const c: Call = {
        url: String(input),
        method: init?.method ?? "GET",
        body: typeof raw === "string" ? JSON.parse(raw) : undefined,
        markerAtDispatch: marker(),
      };
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
function buttons(
  name: string,
  scope: ParentNode = document,
): HTMLButtonElement[] {
  return Array.from(scope.querySelectorAll("button")).filter(
    (b) => (b.textContent ?? "").trim() === name,
  );
}
async function click(
  name: string,
  scope: ParentNode = document,
): Promise<void> {
  const b = buttons(name, scope)[0];
  if (b === undefined) throw new Error(`no button "${name}"`);
  await act(async () => {
    b.click();
    await Promise.resolve();
  });
}
const openDialog = (): HTMLDialogElement => {
  const d = document.querySelector("dialog[open]");
  if (!(d instanceof HTMLDialogElement)) throw new Error("no open dialog");
  return d;
};

function idpRoutes(
  over: Partial<Record<string, (c: Call) => Response | Promise<Response>>>,
  legacy: unknown,
  profiles: unknown[] = [],
): void {
  route = (c) => {
    if (c.url.startsWith("/api/idp/legacy-ldap") && c.method === "GET")
      return json(legacy);
    if (c.url.startsWith("/api/objects/references"))
      return json({ object: { type: "idp", name: "x" }, referencedBy: [] });
    if (c.url === "/api/idp" && c.method === "GET")
      return json({ ...LIST, profiles });
    for (const [k, fn] of Object.entries(over)) {
      if (fn !== undefined && c.url.startsWith(k)) return fn(c);
    }
    return Promise.reject(new TypeError(`unexpected ${c.method} ${c.url}`));
  };
}

async function runImportCeremony(): Promise<void> {
  await mount();
  await flushUntil(() => {
    expect(buttons("Import legacy configuration")).toHaveLength(1);
  });
  await click("Import legacy configuration");
  const dlg = openDialog();
  expect(dlg.textContent).toContain("disabled");
  await click("Import", dlg);
}

/** An unproven import (text/plain 2xx) leaves a marker behind; the
 * ledger lookup then answers `op` (or a status) on Recover. */
let lookup: (id: string) => Response;
function importThenLookup(): void {
  idpRoutes(
    {
      "/api/idp/legacy-ldap/import": () =>
        new Response("ok", {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        }),
      "/api/idp/operations/": (c) => lookup(c.url.split("/").pop() ?? ""),
    },
    LEGACY_PRESENT,
  );
}
const committed = (
  id: string,
  action: string,
  extra: Record<string, unknown> = {},
): Record<string, unknown> => ({
  operationId: id,
  state: "committed",
  action,
  actor: "admin@10.0.0.9",
  profileId: "imp000000001",
  registryRevision: "r-doc-1",
  cutover: false,
  startedAt: "2026-09-16T10:00:00Z",
  audited: true,
  finishedAt: "2026-09-16T10:00:02Z",
  committedRevision: "r-doc-2",
  ...extra,
});
const lookups = (): number =>
  calls.filter((c) => c.url.startsWith("/api/idp/operations/")).length;

async function recoverOnce(): Promise<void> {
  await runImportCeremony();
  await flushUntil(() => {
    expect(text()).toContain("Unresolved provider operation");
  });
  expect(marker()).not.toBeNull();
  await click("Recover");
  await flushUntil(() => {
    expect(lookups()).toBe(1);
    expect(text()).not.toContain("Looking the operation up");
  });
}

function expectUnprovenBinding(): void {
  // The marker is kept, nothing is offered for re-send, no success claim.
  expect(marker()).not.toBeNull();
  expect(buttons("Re-send")).toHaveLength(0);
  expect(text()).not.toContain("is committed on the appliance");
  expect(text()).not.toContain("success audit durable");
  expect(text()).not.toContain(
    "Operation resolved from the appliance's ledger",
  );
  expect(text()).toMatch(/not bound|unproven/i);
  expect(text()).toContain("Unresolved provider operation");
}

it("L1 an import marker against a committed idp.create record is UNPROVEN — marker retained", async () => {
  lookup = (id) => json(committed(id, "idp.create"));
  importThenLookup();
  await recoverOnce();
  expectUnprovenBinding();
});

it("L2 an import marker (token A) against a committed import bound to token B is UNPROVEN", async () => {
  lookup = (id) =>
    json(
      committed(id, "idp.import", { importSourceRevision: OTHER_SOURCE_TOKEN }),
    );
  importThenLookup();
  await recoverOnce();
  expectUnprovenBinding();
});

it("L3 (control) token A against a committed import bound to token A is committed and clears the marker", async () => {
  lookup = (id) =>
    json(committed(id, "idp.import", { importSourceRevision: SOURCE_TOKEN }));
  importThenLookup();
  await recoverOnce();
  await flushUntil(() => {
    expect(text()).toContain("Committed");
    expect(marker()).toBeNull();
  });
  expect(text()).not.toMatch(/not bound/i);
});

it("L4 (control) pending / aborted / outcome_unknown keep the marker; Abandon only on aborted", async () => {
  const base = (id: string): Record<string, unknown> => ({
    operationId: id,
    action: "idp.import",
    actor: "admin@10.0.0.9",
    profileId: "imp000000001",
    registryRevision: "r-doc-1",
    cutover: false,
    startedAt: "2026-09-16T10:00:00Z",
    audited: false,
    importSourceRevision: SOURCE_TOKEN,
  });
  lookup = (id) => json({ ...base(id), state: "pending" });
  importThenLookup();
  await recoverOnce();
  expect(text()).toContain("Pending");
  expect(marker()).not.toBeNull();
  expect(buttons("Re-send")).toHaveLength(0);
  expect(buttons("Abandon")).toHaveLength(0);

  lookup = (id) =>
    json({
      ...base(id),
      state: "aborted",
      finishedAt: "2026-09-16T10:00:01Z",
      code: "stale",
    });
  await click("Recover");
  await flushUntil(() => {
    expect(lookups()).toBe(2);
    expect(text()).toContain("Aborted");
  });
  expect(marker()).not.toBeNull();
  expect(buttons("Re-send")).toHaveLength(0);
  expect(buttons("Abandon")).toHaveLength(1);

  lookup = (id) =>
    json({
      ...base(id),
      state: "outcome_unknown",
      finishedAt: "2026-09-16T10:00:01Z",
      code: "outcome_unknown",
    });
  await click("Recover");
  await flushUntil(() => {
    expect(lookups()).toBe(3);
    expect(text()).toMatch(/unknown/i);
  });
  expect(marker()).not.toBeNull();
  expect(buttons("Re-send")).toHaveLength(0);
});
