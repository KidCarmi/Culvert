// 2A deep-link navigation correction: the ?rule= target must actually become
// visible and focusable. Proves against a mounted AccessRulesPage with
// in-place router navigations (no remount): (1) a NEW valid deep link is
// authoritative over the in-memory filter (filter reset, row exists, focus,
// highlight, announcement ONLY after the row exists); (2) A → B → A locates
// A again; (3) valid → malformed and valid → nonexistent-but-plausible clear
// every previous target state (no stale highlight next to a truthful
// callout).
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { AccessRulesPage } from "../features/policy/AccessRulesPage";

const RULE_A = {
  priority: 1,
  name: "Alpha rule",
  id: "01J3ZV9E3JD0AAAAAAAAAAAAAA",
  destFQDN: "alpha.test",
  action: "Allow",
  sslAction: "",
  sourceIP: "",
  hitCount: 0,
};
const RULE_B = {
  priority: 2,
  name: "Bravo rule",
  id: "01J3ZV9E3JD0BBBBBBBBBBBBBB",
  destFQDN: "bravo.test",
  action: "Block_Page",
  sslAction: "",
  sourceIP: "",
  hitCount: 0,
};

let container: HTMLDivElement;
let root: Root;
let router: ReturnType<typeof createMemoryRouter>;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  // jsdom has no scrollIntoView; the row-focus contract is asserted via
  // document.activeElement.
  Element.prototype.scrollIntoView = vi.fn();
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown) => {
      const url = String(input);
      const body = url.includes("/api/policy/draft")
        ? { requireCommit: false, active: false, actor: "", startedAt: "" }
        : {
            rules: [RULE_A, RULE_B],
            count: 2,
            version: 3,
            updatedAt: "2026-08-22T12:00:00Z",
            draft: false,
          };
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
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

function viewerMachine(qc: QueryClient): AuthMachine {
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
        user: "view-user",
        role: "viewer",
        bootstrap: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    postLogout: () => Promise.resolve({ ok: true }),
  });
}

function mount(initialQuery: string): void {
  router = createMemoryRouter(
    [{ path: "/policies/access-rules", element: <AccessRulesPage /> }],
    { initialEntries: [`/policies/access-rules${initialQuery}`] },
  );
  const qc = new QueryClient();
  const machine = viewerMachine(qc);
  void machine.boot();
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

async function navigate(query: string): Promise<void> {
  await act(async () => {
    await router.navigate(`/policies/access-rules${query}`);
  });
}

function highlightedRows(): Element[] {
  return Array.from(container.querySelectorAll('tr[data-highlight="true"]'));
}

function announceText(): string {
  // The locate announcement is the sr-only role=status region (SnapshotBar's
  // "Updated" stamp is a separate aria-live span).
  const els = Array.from(container.querySelectorAll('[role="status"]'));
  const el = els.find((e) => e.className.includes("srOnly"));
  return el?.textContent ?? "";
}

function filterInput(): HTMLInputElement {
  const el = container.querySelector("input");
  if (!(el instanceof HTMLInputElement)) throw new Error("no filter input");
  return el;
}

function setFilterValue(v: string): void {
  const input = filterInput();
  const desc = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  );
  desc?.set?.call(input, v);
  act(() => {
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

it("a new deep link is authoritative over the active filter: reset → row exists → focus → highlight → announce", async () => {
  mount(`?rule=${RULE_A.id}`);
  await flushUntil(() => {
    expect(announceText()).toContain("Alpha rule");
  });

  // Hide Bravo behind the in-memory filter.
  setFilterValue("Alpha");
  await flushUntil(() => {
    expect(container.textContent).toContain("1 of 2 access rules");
  });
  expect(container.textContent).not.toContain("Bravo rule");

  // In-place navigation to the filter-hidden target (same mounted route).
  await navigate(`?rule=${RULE_B.id}`);
  await flushUntil(() => {
    expect(announceText()).toContain("Bravo rule");
  });
  // Filter was reset by the navigation, the row exists, is highlighted and
  // holds focus; the announcement names B, not A.
  expect(filterInput().value).toBe("");
  const rows = highlightedRows();
  expect(rows).toHaveLength(1);
  expect(rows[0]?.textContent).toContain("Bravo rule");
  expect(document.activeElement).toBe(rows[0]);
  expect(announceText()).not.toContain("Alpha rule");
});

it("A → B → A locates and announces A again", async () => {
  mount(`?rule=${RULE_A.id}`);
  await flushUntil(() => {
    expect(announceText()).toContain("Alpha rule");
  });
  await navigate(`?rule=${RULE_B.id}`);
  await flushUntil(() => {
    expect(announceText()).toContain("Bravo rule");
  });
  await navigate(`?rule=${RULE_A.id}`);
  await flushUntil(() => {
    expect(announceText()).toContain("Alpha rule");
  });
  const rows = highlightedRows();
  expect(rows).toHaveLength(1);
  expect(rows[0]?.textContent).toContain("Alpha rule");
  expect(document.activeElement).toBe(rows[0]);
});

it("valid → malformed clears the previous highlight and announcement", async () => {
  mount(`?rule=${RULE_A.id}`);
  await flushUntil(() => {
    expect(highlightedRows()).toHaveLength(1);
  });
  await navigate("?rule=<img src=x>");
  await flushUntil(() => {
    expect(container.textContent).toContain("Invalid rule reference");
  });
  expect(highlightedRows()).toHaveLength(0);
  expect(announceText()).toBe("");
});

it("valid → nonexistent-but-plausible clears old state and shows the truthful callout", async () => {
  mount(`?rule=${RULE_A.id}`);
  await flushUntil(() => {
    expect(highlightedRows()).toHaveLength(1);
  });
  await navigate("?rule=01AAAAAAAAAAAAAAAAAAAAAAAA");
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "Referenced rule not in this snapshot",
    );
  });
  expect(highlightedRows()).toHaveLength(0);
  expect(announceText()).toBe("");
  // The empty ?rule= transition also clears (param removed entirely).
  await navigate("");
  await flushUntil(() => {
    expect(container.textContent).not.toContain(
      "Referenced rule not in this snapshot",
    );
  });
  expect(highlightedRows()).toHaveLength(0);
});
