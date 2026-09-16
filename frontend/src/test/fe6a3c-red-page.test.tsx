// FE-6A.2 CORRECTION ROUND 3 RED — page half, written against the frozen
// corrected candidate eb90ebc5 BEFORE any product change (Blocker 1).
//
//   PB1  the import POST carries the importSourceRevision the ceremony
//        REVIEWED (the legacy read model's token), never nothing.
//   PB2  a 2xx echoing a DIFFERENT source token is UNPROVEN: the ceremony
//        closes, the page latches, the marker is kept — never "imported".
//   PB3  the marker written before dispatch binds the reviewed token
//        (non-secret) through the candidate digest.
//
// On eb90ebc5 PB1–PB3 fail: no token is sent, an unrelated token is read
// as success, the digest ignores the token.
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
  LEGACY_PRESENT,
  LEGACY_URL,
  OTHER_SOURCE_TOKEN,
  SOURCE_TOKEN,
  LIST,
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

it("PB1 the import POST carries the REVIEWED importSourceRevision", async () => {
  let posted: Call | undefined;
  idpRoutes(
    {
      "/api/idp/legacy-ldap/import": (c) => {
        posted = c;
        const q = new URL(c.url, "http://x").searchParams;
        return json({
          ...IMPORTED(q.get("operationId")),
          importSourceRevision: q.get("importSourceRevision"),
        });
      },
    },
    LEGACY_PRESENT,
  );
  await runImportCeremony();
  await flushUntil(() => {
    expect(posted).toBeDefined();
  });
  const q = new URL(posted?.url ?? "", "http://x").searchParams;
  expect(q.get("importSourceRevision")).toBe(SOURCE_TOKEN);
  await flushUntil(() => {
    expect(marker()).toBeNull();
    expect(text()).toContain("imported");
  });
});

it("PB2 a 2xx echoing a different source token is UNPROVEN: latched, marker kept", async () => {
  idpRoutes(
    {
      "/api/idp/legacy-ldap/import": (c) => {
        const q = new URL(c.url, "http://x").searchParams;
        return json({
          ...IMPORTED(q.get("operationId")),
          importSourceRevision: OTHER_SOURCE_TOKEN,
        });
      },
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
  await flushUntil(() => {
    expect(text()).toContain("Unresolved provider operation");
    expect(gets("/api/idp")).toBe(getsBefore + 1);
  });
  expect(buttons("Import legacy configuration")).toHaveLength(0); // latched
});

it("PB3 the marker binds the reviewed token through its candidate digest", async () => {
  let posted: Call | undefined;
  idpRoutes(
    {
      "/api/idp/legacy-ldap/import": (c) => {
        posted = c;
        return new Response("ok", {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        });
      },
    },
    LEGACY_PRESENT,
  );
  await runImportCeremony();
  await flushUntil(() => {
    expect(posted).toBeDefined();
  });
  const m = rec(JSON.parse(posted?.markerAtDispatch ?? "null"));
  expect(m["action"]).toBe("import");
  expect(JSON.stringify(m)).not.toMatch(/bindPassword|bindDn/);
  // The same legacy facts under another token are a different candidate.
  const digestA = m["candidateDigest"];
  const other = { ...LEGACY_PRESENT, importSourceRevision: OTHER_SOURCE_TOKEN };
  const { importCandidateDigest, decodeLegacyLDAP } =
    await import("../api/idp");
  const o = decodeLegacyLDAP(other);
  if (!o.present) throw new Error("fixture");
  expect(importCandidateDigest(o)).not.toBe(digestA);
});
