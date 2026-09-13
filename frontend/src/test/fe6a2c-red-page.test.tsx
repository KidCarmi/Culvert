// FE-6A.2 CORRECTION RED — page half, written against the frozen FE-6A.2
// candidate 64da0df0 BEFORE any product change.
//
//   PC1  Import is dispatched under a client operationId with the loaded
//        document fence; the NON-SECRET marker (action import) is persisted
//        BEFORE the POST and cleared on the proven answer.
//   PC2  a 2xx answering an unrelated disabled LDAP profile is UNPROVEN: the
//        ceremony closes, the page latches, the marker is KEPT, the registry
//        is re-read once — never "imported".
//   PC3  Recover settles an unproven import from the ledger (committed
//        idp.import) and clears the marker; a 404 offers a typed re-send of
//        the SAME import operation.
//   PC4  a 422 preflight_failed on an enabled-LDAP save is rendered as the
//        bounded step + reason, never the server's text; nothing is retried
//        and the marker is released (nothing was written).
//   PC5  (found during the correction, verified failing on 64da0df0) a
//        create re-send after a 404 lookup DISPATCHES the same operation:
//        the recorded marker is adopted as-is (immutable evidence), never
//        refused as "another unresolved operation".
//
// On 64da0df0 this file fails at type-check/import resolution together with
// fe6a2c-red-api.test.ts (the import client has no fence/operation), and
// PC1/PC2/PC4 fail behaviourally (no marker, "imported" claimed on an
// unrelated profile, an unknown refusal).
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
import {
  LEGACY_ABSENT,
  LEGACY_PRESENT,
  LEGACY_URL,
  LIST,
  RAW,
  ldapProfileAnswer,
} from "./fe6a2-fixtures";

const rec = (v: unknown): Record<string, unknown> => {
  if (!isRecord(v)) throw new Error("not a record");
  return v;
};

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
async function check(label: string, scope: ParentNode): Promise<void> {
  const el = field(label, scope);
  if (!(el instanceof HTMLInputElement)) throw new Error("not a checkbox");
  if (!el.checked)
    await act(async () => {
      el.click();
      await Promise.resolve();
    });
}
const openDialog = (): HTMLDialogElement => {
  const d = document.querySelector("dialog[open]");
  if (!(d instanceof HTMLDialogElement)) throw new Error("no open dialog");
  return d;
};
const gets = (path: string): number =>
  calls.filter((c) => c.method === "GET" && c.url === path).length;

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

const IMPORTED = (operationId: string | null): Record<string, unknown> => ({
  imported: true,
  id: "imp000000001",
  name: "Imported legacy LDAP",
  type: "ldap",
  enabled: false,
  revision: 1,
  documentRevision: "r-doc-2",
  operationId,
  source: { url: LEGACY_URL },
  cluster: { publication: "published", version: 9 },
});

/** GET /api/idp count at the instant the import is confirmed — the
 * read-back assertions count from here (the mock answers synchronously, so
 * the answer and its read-back can land inside the confirm's act). */
let getsAtConfirm = 0;
async function runImportCeremony(): Promise<void> {
  await mount();
  await flushUntil(() => {
    expect(buttons("Import legacy configuration")).toHaveLength(1);
  });
  await click("Import legacy configuration");
  const dlg = openDialog();
  expect(dlg.textContent).toContain("disabled");
  getsAtConfirm = gets("/api/idp");
  await click("Import", dlg);
}

it("PC1 import: marker (action import) before the fenced, identified POST; cleared on the proven answer", async () => {
  let posted: Call | undefined;
  idpRoutes(
    {
      "/api/idp/legacy-ldap/import": (c) => {
        posted = c;
        const q = new URL(c.url, "http://x").searchParams;
        return json(IMPORTED(q.get("operationId")));
      },
    },
    LEGACY_PRESENT,
  );
  await runImportCeremony();
  await flushUntil(() => {
    expect(posted).toBeDefined();
  });
  const url = new URL(posted?.url ?? "", "http://x");
  expect(url.pathname).toBe("/api/idp/legacy-ldap/import");
  expect(url.searchParams.get("documentRevision")).toBe("r-doc-1");
  const op = url.searchParams.get("operationId") ?? "";
  expect(op).toMatch(/^[0-9a-f-]{36}$/);
  expect(posted?.body).toBeUndefined();
  const m = rec(JSON.parse(posted?.markerAtDispatch ?? "null"));
  expect(m["action"]).toBe("import");
  expect(m["operationId"]).toBe(op);
  expect(m["fence"]).toBe("r-doc-1");
  expect(m["type"]).toBe("ldap");
  expect(JSON.stringify(m)).not.toMatch(/bindPassword|bindDn/);
  await flushUntil(() => {
    expect(document.querySelector("dialog[open]")).toBeNull();
    expect(marker()).toBeNull();
    expect(text()).toContain("imported");
  });
});

it("PC2 an unrelated disabled profile in the 2xx is UNPROVEN: latched, marker kept, one read-back", async () => {
  idpRoutes(
    {
      "/api/idp/legacy-ldap/import": () =>
        json(
          ldapProfileAnswer("imp000000001", 1, {
            name: "Imported legacy LDAP",
          }),
        ),
    },
    LEGACY_PRESENT,
  );
  await runImportCeremony();
  const getsBefore = getsAtConfirm;
  await flushUntil(() => {
    expect(text()).toContain("Outcome unproven");
  });
  expect(document.querySelector("dialog[open]")).toBeNull();
  expect(text()).not.toContain("imported as the disabled provider");
  expect(marker()).not.toBeNull();
  expect(rec(JSON.parse(marker() ?? "null"))["action"]).toBe("import");
  await flushUntil(() => {
    expect(text()).toContain("Unresolved provider operation");
    expect(gets("/api/idp")).toBe(getsBefore + 1);
  });
  expect(buttons("Import legacy configuration")).toHaveLength(0); // latched
});

it("PC3 Recover settles an unproven import from the ledger; a 404 offers the same-operation re-send", async () => {
  let lookupStatus = 404;
  let importCalls = 0;
  idpRoutes(
    {
      "/api/idp/legacy-ldap/import": () => {
        importCalls += 1;
        return new Response("ok", {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        });
      },
      "/api/idp/operations/": (c) => {
        const id = c.url.split("/").pop() ?? "";
        if (lookupStatus === 404)
          return json({ error: RAW, code: "not_found" }, 404);
        return json({
          operationId: id,
          state: "committed",
          action: "idp.import",
          actor: "admin@10.0.0.9",
          profileId: "imp000000001",
          registryRevision: "r-doc-1",
          cutover: false,
          startedAt: "2026-09-13T10:00:00Z",
          audited: true,
          finishedAt: "2026-09-13T10:00:02Z",
          committedRevision: "r-doc-2",
        });
      },
    },
    LEGACY_PRESENT,
  );
  await runImportCeremony();
  await flushUntil(() => {
    expect(text()).toContain("Unresolved provider operation");
  });
  const op = rec(JSON.parse(marker() ?? "null"))["operationId"];
  await click("Recover");
  await flushUntil(() => {
    expect(buttons("Re-send")).toHaveLength(1);
  });
  // The re-send is the SAME import operation, never a new one: the import
  // ceremony is re-opened (the editor re-send shape — the operator confirms
  // the reviewed legacy facts again) bound to the recorded operation.
  await click("Re-send");
  await flushUntil(() => {
    expect(openDialog().textContent).toContain(String(op));
  });
  expect(importCalls).toBe(1);
  await click("Import", openDialog());
  await flushUntil(() => {
    expect(importCalls).toBe(2);
  });
  const again = calls.filter((c) =>
    c.url.startsWith("/api/idp/legacy-ldap/import"),
  );
  const q = new URL(again[1]?.url ?? "", "http://x").searchParams;
  expect(q.get("operationId")).toBe(op);
  expect(marker()).not.toBeNull();
  lookupStatus = 200;
  await flushUntil(() => {
    expect(buttons("Recover")).toHaveLength(1);
  });
  await click("Recover");
  await flushUntil(() => {
    expect(text()).toContain("Committed");
    expect(marker()).toBeNull();
  });
});

it("PC4 preflight_failed renders the bounded step + reason, closes the editor, releases the marker", async () => {
  idpRoutes(
    {
      "/api/idp": () =>
        json(
          {
            error: RAW,
            code: "preflight_failed",
            current: { step: "reachable", reason: "unreachable", detail: RAW },
          },
          422,
        ),
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
  await type("Name", "Live LDAP", dlg);
  await type("Directory URL", "ldap://dc.example:389", dlg);
  await type("Base DN", "dc=example", dlg);
  await check("Enabled", dlg);
  await click("Review and save", dlg);
  // An LDAP candidate without a bind credential carries no secret material,
  // so there is no T2 review step: "Review and save" dispatches directly.
  if (document.querySelector("dialog[open]") !== null)
    await click("Save provider", openDialog());
  await flushUntil(() => {
    expect(text()).toContain("preflight");
    expect(text()).toContain("reachable");
    expect(text()).toContain("unreachable");
  });
  expect(document.querySelector("dialog[open]")).toBeNull();
  expect(text()).not.toContain(RAW);
  expect(text()).not.toContain("Outcome unproven");
  expect(calls.filter((c) => c.method === "POST")).toHaveLength(1);
  expect(marker()).toBeNull();
});

it("PC5 an editor re-send dispatches the SAME create operation under the recorded marker", async () => {
  let posts = 0;
  idpRoutes(
    {
      // prefix-matched in order: the lookup route must precede the create
      "/api/idp/operations/": () =>
        json({ error: RAW, code: "not_found" }, 404),
      "/api/idp?": () => {
        posts += 1;
        return new Response("ok", {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        });
      },
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
  await type("Name", "Resent LDAP", dlg);
  await type("Directory URL", "ldap://dc.example:389", dlg);
  await type("Base DN", "dc=example", dlg);
  await click("Review and save", dlg);
  await flushUntil(() => {
    expect(text()).toContain("Unresolved provider operation");
  });
  const m = rec(JSON.parse(marker() ?? "null"));
  const op = String(m["operationId"]);
  expect(posts).toBe(1);
  await click("Recover");
  await flushUntil(() => {
    expect(buttons("Re-send")).toHaveLength(1);
  });
  await click("Re-send");
  const again = openDialog();
  await click("Review and save", again);
  await flushUntil(() => {
    expect(posts).toBe(2);
  });
  const sent = calls.filter(
    (c) => c.method === "POST" && c.url.startsWith("/api/idp?"),
  );
  expect(sent).toHaveLength(2);
  expect(
    new URL(sent[1]?.url ?? "", "http://x").searchParams.get("operationId"),
  ).toBe(op);
  // The marker is the SAME evidence (same start instant), still unresolved.
  const after = rec(JSON.parse(marker() ?? "null"));
  expect(after["operationId"]).toBe(op);
  expect(after["startedAt"]).toBe(m["startedAt"]);
  expect(text()).not.toContain(
    "Another provider operation is still unresolved",
  );
});
