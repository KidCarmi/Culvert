// 2B.6 — default-action proofs (§32): a separate LIVE mutation with
// unmistakable immediate-effect copy (never staged, even with Require Commit
// armed), T2 blast-radius ceremony, server-value rendering, and the local
// unknown latch resolved only by a fresh successful GET.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { AccessRulesPage } from "../features/policy/AccessRulesPage";

const POLICY_BODY = {
  rules: [
    {
      priority: 1,
      name: "Some rule",
      id: "01J3ZV9E3JD0AAAAAAAAAAAAAA",
      action: "Allow",
      sslAction: "Bypass",
      hitCount: 0,
    },
  ],
  count: 1,
  version: 3,
  updatedAt: "2026-08-28T12:00:00Z",
  draft: false,
};
// Require Commit ARMED — the ceremony must still say LIVE immediately.
const ARMED_DRAFT = {
  requireCommit: true,
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
let onDefaultGet: () => Promise<Response>;
let onDefaultPost: (body: unknown) => Promise<Response>;
let defaultPosts: unknown[];

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
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
  onDefaultGet = () => okJSON({ defaultAction: "deny" });
  onDefaultPost = () => okJSON({ defaultAction: "allow" });
  defaultPosts = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (url.includes("/api/default-action")) {
        if (method === "POST") {
          const body: unknown =
            typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
          defaultPosts.push(body);
          return onDefaultPost(body);
        }
        return onDefaultGet();
      }
      if (url.includes("/api/policy/draft")) return okJSON(ARMED_DRAFT);
      if (url.includes("/api/policy")) return okJSON(POLICY_BODY);
      return Promise.reject(new TypeError(`unexpected ${method} ${url}`));
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

async function mount(role: "viewer" | "operator"): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/policies/access-rules", element: <AccessRulesPage /> }],
    { initialEntries: ["/policies/access-rules"] },
  );
  const qc = new QueryClient();
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
        user: role,
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
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "Default action for unmatched traffic",
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

it("viewer sees the current default action with no mutation control", async () => {
  await mount("viewer");
  await flushUntil(() => {
    expect(container.textContent).toContain("Deny");
  });
  expect(hasButton((t) => t === "Change…")).toBe(false);
});

it("the ceremony states LIVE-immediately + never-staged EVEN with Require Commit armed; success renders the returned server value", async () => {
  await mount("operator");
  await flushUntil(() => {
    expect(container.textContent).toContain("Commit mode armed");
  });
  await click(findButton((t) => t === "Change…"));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "This takes effect LIVE immediately for all traffic.",
    );
  });
  expect(container.textContent).toContain(
    "It is never staged in the Policy Draft — even while Require Commit is on.",
  );
  expect(container.textContent).toContain(
    "a fleet-wide loosening of enforcement",
  );
  await click(findButton((t) => t.includes("Set default to allow")));
  await flushUntil(() => {
    expect(defaultPosts.length).toBe(1);
  });
  expect(defaultPosts[0]).toEqual({ action: "allow" });
  // Rendered value is the SERVER's response.
  await flushUntil(() => {
    expect(container.textContent).toContain("Allow");
  });
});

it("an unknown outcome latches THIS control until a fresh successful GET of the default-action truth", async () => {
  await mount("operator");
  onDefaultPost = () => Promise.reject(new TypeError("network down"));
  await click(findButton((t) => t === "Change…"));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "This takes effect LIVE immediately",
    );
  });
  await click(findButton((t) => t.includes("Set default to allow")));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "Default-action change unconfirmed",
    );
  });
  expect(hasButton((t) => t === "Change…")).toBe(false);

  // Failed refresh keeps the latch.
  onDefaultGet = () => Promise.reject(new TypeError("still down"));
  await click(findButton((t) => t.includes("Refresh default action")));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "Default-action change unconfirmed",
    );
  });

  // Fresh successful GET resolves it.
  onDefaultGet = () => okJSON({ defaultAction: "allow" });
  await click(findButton((t) => t.includes("Refresh default action")));
  await flushUntil(() => {
    expect(container.textContent).not.toContain(
      "Default-action change unconfirmed",
    );
  });
  expect(hasButton((t) => t === "Change…")).toBe(true);
});
