// FE-6A RECOVERY FOLLOW-UP — page half of record 6AR, written against the
// entry head (frozen FE-6B head df17f835 + the origin/main entry merge)
// BEFORE any product change.
//
// The Go half (fe6ar_resend_red_test.go) proves on the production handlers
// that the IdP operation ledger evicts DECIDED records (256 slots), that a
// 404 lookup therefore proves neither non-commit nor safe retry, and that a
// re-sent operation after eviction EXECUTES AGAIN for every action the
// recovery marker can carry (create, cutover-bearing update, import) — the
// certificate counterexample (6B2C-B1) transfers. The shipped page offers
// "Re-send" after a 404 ("The appliance never recorded this operation: the
// write did not start. The same candidate may be re-sent…"), a claim the
// backend cannot support. These rows pin the corrected posture:
//
//   A1  create marker + Recover ⇒ 404: the view is UNKNOWN — "retains no
//       record", never "never recorded" / "may be re-sent"; NO Re-send
//       control; the marker is kept; every mutation stays blocked; the
//       typed Abandon is offered; nothing further is dispatched.
//   A2  import marker + Recover ⇒ 404: the same UNKNOWN posture (PC3's
//       import re-send is gone).
//   A3  reload: the marker survives a remount, the card returns with every
//       mutation blocked, and a Recover ⇒ 404 after the reload still offers
//       no Re-send.
//   A4  CONTROL — Abandon: Cancel keeps the marker; the typed operationId
//       discards ONLY the browser marker and re-enables mutation.
//   A5  CONTROL — a transport loss on the lookup itself is UNPROVEN: marker
//       kept, no Re-send, no success claim.
//   A6  CONTROL — an aborted record: Abandon offered, no Re-send, no
//       success claim.
//   A7  CONTROL — while a marker is unresolved no NEW operation can be
//       started (Add provider / Import legacy configuration disabled), so a
//       later attempt's refusal can never be mistaken for evidence about
//       the original: nothing else is ever dispatched.
//
// On the entry head A1, A2 and A3 FAIL (Re-send offered, "never recorded"
// claimed); A4–A7 pass.
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
import { isRecord } from "../api/decode";
import { LEGACY_ABSENT, LEGACY_PRESENT, LIST, RAW } from "./fe6a2-fixtures";

const rec = (v: unknown): Record<string, unknown> => {
  if (!isRecord(v)) throw new Error("not a record");
  return v;
};

interface Call {
  url: string;
  method: string;
  body: unknown;
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
const plainOK = (): Response =>
  new Response("ok", {
    status: 200,
    headers: { "Content-Type": "text/plain" },
  });
const posts = (): Call[] => calls.filter((c) => c.method === "POST");

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
async function remount(): Promise<void> {
  act(() => {
    root.unmount();
  });
  container.remove();
  container = document.createElement("div");
  document.body.appendChild(container);
  await mount();
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
function field(label: string, scope: ParentNode): HTMLElement {
  for (const l of Array.from(scope.querySelectorAll("label"))) {
    if ((l.textContent ?? "").trim().startsWith(label)) {
      const el = l.htmlFor
        ? document.getElementById(l.htmlFor)
        : l.querySelector("input,select,textarea");
      if (el instanceof HTMLElement) return el;
    }
  }
  throw new Error(`no field "${label}"`);
}
async function type(
  label: string,
  value: string,
  scope: ParentNode,
): Promise<void> {
  const el = field(label, scope);
  await act(async () => {
    // eslint-disable-next-line @typescript-eslint/unbound-method -- invoked with call()
    const setter = Object.getOwnPropertyDescriptor(
      Object.getPrototypeOf(el),
      "value",
    )?.set;
    setter?.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    await Promise.resolve();
  });
}
const openDialog = (): HTMLDialogElement => {
  const d = document.querySelector("dialog[open]");
  if (!(d instanceof HTMLDialogElement)) throw new Error("no open dialog");
  return d;
};
const noOpenDialog = (): boolean =>
  document.querySelector("dialog[open]") === null;

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

/** The lookup answer (or failure) Recover receives; set per row. */
let lookup: (id: string) => Response | Promise<Response>;
const notFound = (): Response => json({ error: RAW, code: "not_found" }, 404);
const lookups = (): number =>
  calls.filter((c) => c.url.startsWith("/api/idp/operations/")).length;

/** An unproven CREATE (text/plain 2xx) leaves a create marker behind. */
async function createUnproven(): Promise<string> {
  idpRoutes(
    {
      "/api/idp/operations/": (c) => lookup(c.url.split("/").pop() ?? ""),
      "/api/idp?": plainOK,
    },
    LEGACY_ABSENT,
  );
  await mount();
  await flushUntil(() => {
    expect(buttons("Add provider")).toHaveLength(1);
  });
  await click("Add provider");
  const dlg = openDialog();
  await type("Type", "ldap", dlg);
  await type("Name", "Lost LDAP", dlg);
  await type("Directory URL", "ldap://dc.example:389", dlg);
  await type("Base DN", "dc=example", dlg);
  await click("Review and save", dlg);
  await flushUntil(() => {
    expect(text()).toContain("Unresolved provider operation");
  });
  const m = rec(JSON.parse(marker() ?? "null"));
  expect(m["action"]).toBe("create");
  return String(m["operationId"]);
}

/** An unproven IMPORT (text/plain 2xx) leaves an import marker behind. */
async function importUnproven(): Promise<string> {
  idpRoutes(
    {
      "/api/idp/legacy-ldap/import": plainOK,
      "/api/idp/operations/": (c) => lookup(c.url.split("/").pop() ?? ""),
    },
    LEGACY_PRESENT,
  );
  await mount();
  await flushUntil(() => {
    expect(buttons("Import legacy configuration")).toHaveLength(1);
  });
  await click("Import legacy configuration");
  await click("Import", openDialog());
  await flushUntil(() => {
    expect(text()).toContain("Unresolved provider operation");
  });
  const m = rec(JSON.parse(marker() ?? "null"));
  expect(m["action"]).toBe("import");
  return String(m["operationId"]);
}

async function recoverOnce(): Promise<void> {
  await click("Recover");
  await flushUntil(() => {
    expect(lookups()).toBeGreaterThanOrEqual(1);
    expect(text()).not.toContain("Looking the operation up");
  });
}

/** The corrected 404 posture: UNKNOWN, no re-send, marker kept, typed
 * Abandon the only exit, every mutation still blocked. */
function expectAbsentIsUnknown(op: string): void {
  expect(marker()).not.toBeNull();
  expect(String(rec(JSON.parse(marker() ?? "null"))["operationId"])).toBe(op);
  expect(buttons("Re-send")).toEqual([]);
  expect(text()).not.toContain("never recorded");
  expect(text()).not.toContain("may be re-sent");
  expect(text()).not.toContain("the write did not start");
  expect(text()).toContain("retains no record");
  expect(text()).not.toContain("is committed on the appliance");
  expect(buttons("Abandon")).toHaveLength(1);
  const add = buttons("Add provider")[0];
  if (add !== undefined) expect(add.disabled).toBe(true);
  const imp = buttons("Import legacy configuration")[0];
  if (imp !== undefined) expect(imp.disabled).toBe(true);
  expect(noOpenDialog()).toBe(true);
  expect(text()).not.toContain(RAW);
}

// ── A1 create marker, 404 ⇒ UNKNOWN ─────────────────────────────────────────
it("A1 Recover ⇒ 404 on a create marker is UNKNOWN: no Re-send, marker kept, mutations blocked, typed Abandon only", async () => {
  lookup = notFound;
  const op = await createUnproven();
  expect(posts()).toHaveLength(1);
  await recoverOnce();
  expectAbsentIsUnknown(op);
  // Nothing further left the page.
  expect(posts()).toHaveLength(1);
});

// ── A2 import marker, 404 ⇒ UNKNOWN ─────────────────────────────────────────
it("A2 Recover ⇒ 404 on an import marker is UNKNOWN: no Re-send of the import, marker kept, typed Abandon only", async () => {
  lookup = notFound;
  const op = await importUnproven();
  expect(posts()).toHaveLength(1);
  await recoverOnce();
  expectAbsentIsUnknown(op);
  expect(posts()).toHaveLength(1);
});

// ── A3 reload ───────────────────────────────────────────────────────────────
it("A3 the marker survives a reload; the card returns with mutations blocked; a 404 after the reload still offers no Re-send", async () => {
  lookup = notFound;
  const op = await createUnproven();
  await remount();
  await flushUntil(() => {
    expect(text()).toContain("Unresolved provider operation");
    expect(buttons("Add provider")).toHaveLength(1);
  });
  expect(buttons("Add provider")[0]?.disabled).toBe(true);
  expect(String(rec(JSON.parse(marker() ?? "null"))["operationId"])).toBe(op);
  await recoverOnce();
  expectAbsentIsUnknown(op);
  expect(posts()).toHaveLength(1);
});

// ── A4 CONTROL — Abandon ────────────────────────────────────────────────────
it("A4 CONTROL Abandon: Cancel keeps the marker; the typed operationId discards only the browser marker and re-enables mutation", async () => {
  lookup = notFound;
  const op = await createUnproven();
  await recoverOnce();
  await flushUntil(() => {
    expect(buttons("Abandon")).toHaveLength(1);
  });
  await click("Abandon");
  const dlg = openDialog();
  expect(dlg.textContent).toContain("Only this browser's recovery marker");
  await click("Cancel", dlg);
  expect(marker()).not.toBeNull();
  expect(buttons("Add provider")[0]?.disabled).toBe(true);
  await click("Abandon");
  const again = openDialog();
  const input = again.querySelector("input");
  if (!(input instanceof HTMLInputElement)) throw new Error("no typed field");
  await act(async () => {
    // eslint-disable-next-line @typescript-eslint/unbound-method -- invoked with call()
    const setter = Object.getOwnPropertyDescriptor(
      Object.getPrototypeOf(input),
      "value",
    )?.set;
    setter?.call(input, op);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await Promise.resolve();
  });
  await click("Abandon", again);
  await flushUntil(() => {
    expect(marker()).toBeNull();
    expect(buttons("Add provider")[0]?.disabled).toBe(false);
  });
  // Abandon dispatched nothing.
  expect(posts()).toHaveLength(1);
});

// ── A5 CONTROL — transport loss on the lookup ───────────────────────────────
it("A5 CONTROL a transport failure on the lookup is UNPROVEN: marker kept, no Re-send, no success claim", async () => {
  lookup = () => Promise.reject(new TypeError("Failed to fetch"));
  const op = await createUnproven();
  await recoverOnce();
  expect(String(rec(JSON.parse(marker() ?? "null"))["operationId"])).toBe(op);
  expect(buttons("Re-send")).toEqual([]);
  expect(text()).not.toContain("is committed on the appliance");
  expect(text()).not.toContain("retains no record");
  expect(buttons("Add provider")[0]?.disabled).toBe(true);
  expect(posts()).toHaveLength(1);
});

// ── A6 CONTROL — aborted record ─────────────────────────────────────────────
it("A6 CONTROL an aborted record offers Abandon, never Re-send, and claims no success", async () => {
  lookup = (id) =>
    json({
      operationId: id,
      state: "aborted",
      action: "idp.create",
      actor: "admin@10.0.0.9",
      profileId: "",
      registryRevision: "r-doc-1",
      cutover: false,
      startedAt: "2026-09-20T10:00:00Z",
      audited: false,
      finishedAt: "2026-09-20T10:00:01Z",
      code: "stale",
    });
  await createUnproven();
  await recoverOnce();
  expect(buttons("Re-send")).toEqual([]);
  expect(buttons("Abandon")).toHaveLength(1);
  expect(text()).not.toContain("is committed on the appliance");
  expect(marker()).not.toBeNull();
});

// ── A7 CONTROL — no new operation while one is unresolved ───────────────────
it("A7 CONTROL while a marker is unresolved no new operation can start, so a later attempt's refusal can never speak for the original", async () => {
  lookup = notFound;
  await createUnproven();
  expect(buttons("Add provider")[0]?.disabled).toBe(true);
  // Even a direct click on the disabled control opens nothing and sends nothing.
  await act(async () => {
    buttons("Add provider")[0]?.click();
    await Promise.resolve();
  });
  expect(noOpenDialog()).toBe(true);
  expect(posts()).toHaveLength(1);
  expect(marker()).not.toBeNull();
});
