// 2B.2 — Access Rules write-surface component proofs: role posture (viewer
// mounts NO mutation controls), full-fidelity fenced edit submission, the
// structured 409 flow (form preserved, resubmit blocked until fresh truth),
// and the page-level unknown-outcome latch (2A-M doctrine: only a fresh
// successful refetch of BOTH policy and draft resolves it).
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { AccessRulesPage } from "../features/policy/AccessRulesPage";

const RULE = {
  priority: 4,
  name: "Edit target",
  id: "01J3ZV9E3JD0AAAAAAAAAAAAAA",
  enabled: false,
  sourceIP: "10.1.0.0/16",
  authSource: "okta",
  destFQDN: "*.corp.example",
  destCountry: ["DE"],
  schedule: {
    days: ["Mon"],
    timeStart: "08:00",
    timeEnd: "18:00",
    timezone: "Europe/Berlin",
  },
  sslAction: "Inspect",
  fileFiltering: true,
  fileProfile: "Executables",
  logFullUri: true,
  logTraffic: false,
  stripAlpn: false,
  tlsSkipVerify: true,
  decryptionProfile: "strict",
  action: "Allow",
  comment: "keep me",
  hitCount: 9,
  createdAt: "2026-01-01T00:00:00Z",
  modifiedAt: "2026-02-01T00:00:00Z",
  modifiedBy: "someone",
};

const POLICY_BODY = {
  rules: [RULE],
  count: 1,
  version: 3,
  updatedAt: "2026-08-28T12:00:00Z",
  draft: false,
};
const DRAFT_BODY = {
  requireCommit: false,
  active: false,
  actor: "",
  startedAt: "",
};

function okJSON(body: unknown): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

let container: HTMLDivElement;
let root: Root;
let onPolicyGet: () => Promise<Response>;
let onDraftGet: () => Promise<Response>;
let onPut: (url: string, body: unknown) => Promise<Response>;
let putCalls: Array<{ url: string; body: unknown }>;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  Element.prototype.scrollIntoView = vi.fn();
  // jsdom has no <dialog>.showModal()/close(); model the `open` property.
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
  onPolicyGet = () => okJSON(POLICY_BODY);
  onDraftGet = () => okJSON(DRAFT_BODY);
  onPut = () => okJSON({ ok: true });
  putCalls = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (url.includes("/api/policy/draft")) return onDraftGet();
      if (url.includes("/api/policy") && method === "GET") {
        return onPolicyGet();
      }
      if (url.includes("/api/policy") && method === "PUT") {
        const body: unknown =
          typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
        putCalls.push({ url, body });
        return onPut(url, body);
      }
      if (url.includes("/api/urlcat")) {
        return okJSON([{ name: "News" }]);
      }
      if (url.includes("/api/category-groups")) {
        return okJSON({ groups: [], names: ["Media"] });
      }
      if (url.includes("/api/decryption-profiles")) {
        return okJSON({ profiles: [], names: ["strict"] });
      }
      if (url.includes("/api/fileblock/profiles/state")) {
        // 2D-C: the selector reads the coherent v2 state envelope.
        return okJSON({
          profiles: [{ id: "builtin-executables", name: "Executables" }],
          revision: "fp1",
        });
      }
      return Promise.reject(new TypeError(`unexpected fetch ${method} ${url}`));
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

function machineFor(role: "viewer" | "operator", qc: QueryClient): AuthMachine {
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
        user: role,
        role,
        bootstrap: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    postLogout: () => Promise.resolve({ ok: true }),
  });
}

async function mount(role: "viewer" | "operator"): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/policies/access-rules", element: <AccessRulesPage /> }],
    { initialEntries: ["/policies/access-rules"] },
  );
  const qc = new QueryClient();
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
  await flushUntil(() => {
    expect(container.textContent).toContain("Edit target");
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

function findButton(match: (t: string) => boolean): HTMLButtonElement {
  const b = Array.from(container.querySelectorAll("button")).find((el) =>
    match(el.textContent ?? ""),
  );
  if (b === undefined) throw new Error("button not found");
  return b;
}

function hasButton(match: (t: string) => boolean): boolean {
  return Array.from(container.querySelectorAll("button")).some((el) =>
    match(el.textContent ?? ""),
  );
}

async function click(btn: HTMLButtonElement): Promise<void> {
  await act(async () => {
    btn.click();
    await new Promise((r) => {
      setTimeout(r, 0);
    });
  });
}

it("viewer mounts NO mutation controls (absent, not disabled)", async () => {
  await mount("viewer");
  expect(hasButton((t) => t.includes("New rule"))).toBe(false);
  expect(hasButton((t) => t === "Edit")).toBe(false);
  expect(hasButton((t) => t === "Delete")).toBe(false);
});

it("operator edit submits the FULL preserved definition, fenced with the snapshot version, without server-owned fields", async () => {
  await mount("operator");
  await click(findButton((t) => t === "Edit"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Edit rule: Edit target");
  });
  await click(findButton((t) => t === "Save rule"));
  await flushUntil(() => {
    expect(putCalls.length).toBe(1);
  });

  const call = putCalls[0];
  if (call === undefined) throw new Error("no PUT");
  expect(call.url).toContain(`id=${RULE.id}`);
  expect(call.url).toContain("ifVersion=3");
  const body = call.body;
  expect(body).toMatchObject({
    name: "Edit target",
    enabled: false,
    sourceIP: "10.1.0.0/16",
    authSource: "okta",
    destFQDN: "*.corp.example",
    destCountry: ["DE"],
    schedule: {
      days: ["Mon"],
      timeStart: "08:00",
      timeEnd: "18:00",
      timezone: "Europe/Berlin",
    },
    sslAction: "Inspect",
    fileFiltering: true,
    fileProfile: "Executables",
    logFullUri: true,
    logTraffic: false,
    stripAlpn: false,
    tlsSkipVerify: true,
    decryptionProfile: "strict",
    action: "Allow",
    comment: "keep me",
  });
  expect(body).not.toHaveProperty("id");
  expect(body).not.toHaveProperty("hitCount");
  expect(body).not.toHaveProperty("createdAt");
  expect(body).not.toHaveProperty("modifiedBy");
  expect(body).not.toHaveProperty("priority"); // reorder-owned on edit
});

it("structured 409 preserves the form, blocks resubmit, and clears on fresh server truth", async () => {
  await mount("operator");
  onPut = () =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          error:
            "the rulebase changed since you loaded it (your version 3, current 5) — reload and reapply your change",
          currentVersion: 5,
          yourVersion: 3,
        }),
        { status: 409, headers: { "Content-Type": "application/json" } },
      ),
    );
  await click(findButton((t) => t === "Edit"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Edit rule: Edit target");
  });
  await click(findButton((t) => t === "Save rule"));
  await flushUntil(() => {
    expect(container.textContent).toContain("The rulebase changed");
  });
  // Resubmit is blocked; the form (and its entries) are still mounted.
  expect(findButton((t) => t === "Save rule").disabled).toBe(true);
  expect(container.textContent).toContain("Edit rule: Edit target");

  // Fresh server truth clears the conflict and re-enables deliberate resubmit.
  await click(findButton((t) => t === "Refresh"));
  await flushUntil(() => {
    expect(container.textContent).not.toContain("The rulebase changed");
  });
  expect(findButton((t) => t === "Save rule").disabled).toBe(false);
});

it("unknown outcome latches the page: controls blocked, failed refresh keeps the latch, fresh policy+draft resolves", async () => {
  await mount("operator");
  onPut = () => Promise.reject(new TypeError("network down"));
  await click(findButton((t) => t === "Edit"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Edit rule: Edit target");
  });
  await click(findButton((t) => t === "Save rule"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Save outcome unconfirmed");
  });
  // The editor stays mounted with the operator's entries; submission blocked.
  expect(container.textContent).toContain("Edit rule: Edit target");
  expect(findButton((t) => t === "Save rule").disabled).toBe(true);

  // FAILED refresh must NOT resolve (2A-M correction transposed): fail the
  // draft refetch while policy succeeds.
  onDraftGet = () => Promise.reject(new TypeError("still down"));
  await click(findButton((t) => t === "Refresh rulebase"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Save outcome unconfirmed");
  });
  expect(findButton((t) => t === "Save rule").disabled).toBe(true);

  // Both refetches fresh-successful ⇒ resolved.
  onDraftGet = () => okJSON(DRAFT_BODY);
  await click(findButton((t) => t === "Refresh rulebase"));
  await flushUntil(() => {
    expect(container.textContent).not.toContain("Save outcome unconfirmed");
  });
  expect(findButton((t) => t === "Save rule").disabled).toBe(false);
});

it("delete ceremony names the rule and fences the DELETE with the snapshot version", async () => {
  await mount("operator");
  let deleteURL = "";
  const fetchMock = vi.mocked(globalThis.fetch);
  fetchMock.mockImplementation((input: unknown, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "DELETE") {
      deleteURL = url;
      return Promise.resolve(new Response(null, { status: 204 }));
    }
    if (url.includes("/api/policy/draft")) return onDraftGet();
    if (url.includes("/api/policy")) return onPolicyGet();
    return Promise.reject(new TypeError(`unexpected ${method} ${url}`));
  });

  await click(findButton((t) => t === "Delete"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Delete access rule");
  });
  // The ceremony names rule name, priority, and action, and states liveness.
  expect(container.textContent).toContain("Edit target");
  expect(container.textContent).toContain("priority 4");
  expect(container.textContent).toContain("action Allow");
  expect(container.textContent).toContain("LIVE immediately");

  await click(findButton((t) => t === "Delete rule"));
  await flushUntil(() => {
    expect(deleteURL).not.toBe("");
  });
  expect(deleteURL).toContain(`id=${RULE.id}`);
  expect(deleteURL).toContain("ifVersion=3");
});
