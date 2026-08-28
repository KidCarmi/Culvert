// 2B.4 — staged reorder proofs: local staging (no POST per move), the full
// old-priorities-in-new-order permutation on Apply (fenced), create/edit/
// delete blocked while staged, the 409 discard-visibly contract (§23), and
// the unknown-outcome latch.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { AccessRulesPage } from "../features/policy/AccessRulesPage";

function rule(priority: number, name: string, id: string): unknown {
  return {
    priority,
    name,
    id,
    action: "Allow",
    sslAction: "Bypass",
    hitCount: 0,
  };
}

const POLICY_BODY = {
  rules: [
    rule(1, "First rule", "01J3ZV9E3JD0AAAAAAAAAAAAAA"),
    rule(2, "Second rule", "01J3ZV9E3JD0BBBBBBBBBBBBBB"),
    rule(3, "Third rule", "01J3ZV9E3JD0CCCCCCCCCCCCCC"),
  ],
  count: 3,
  version: 7,
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
let onReorderPost: (url: string, body: unknown) => Promise<Response>;
let reorderPosts: Array<{ url: string; body: unknown }>;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  Element.prototype.scrollIntoView = vi.fn();
  onReorderPost = () => okJSON({ ok: true });
  reorderPosts = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (url.includes("/api/policy/reorder") && method === "POST") {
        const body: unknown =
          typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
        reorderPosts.push({ url, body });
        return onReorderPost(url, body);
      }
      if (url.includes("/api/policy/draft")) return okJSON(DRAFT_BODY);
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

async function mount(): Promise<void> {
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
        user: "op-user",
        role: "operator",
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
    expect(container.textContent).toContain("First rule");
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

function findButtonByLabel(label: string): HTMLButtonElement {
  const b = Array.from(container.querySelectorAll("button")).find(
    (el) => el.getAttribute("aria-label") === label,
  );
  if (b === undefined) throw new Error(`button not found: ${label}`);
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

function rowNames(): string[] {
  return Array.from(container.querySelectorAll("tbody tr"))
    .map((tr) => tr.querySelectorAll("td")[2]?.textContent ?? "")
    .filter((t) => t !== "");
}

async function enterReorder(): Promise<void> {
  await mount();
  await click(findButton((t) => t.includes("Reorder rules…")));
}

it("entering reorder mode blocks create/edit/delete and pauses the filter; moves stage locally with NO server mutation", async () => {
  await enterReorder();
  expect(hasButton((t) => t.includes("New rule"))).toBe(false);
  expect(hasButton((t) => t === "Edit")).toBe(false);
  expect(hasButton((t) => t === "Delete")).toBe(false);
  const filter = container.querySelector("input");
  if (!(filter instanceof HTMLInputElement)) throw new Error("no filter");
  expect(filter.disabled).toBe(true);

  await click(findButtonByLabel("Move rule First rule down"));
  expect(rowNames()).toEqual(["Second rule", "First rule", "Third rule"]);
  expect(container.textContent).toContain("Reorder staged");
  expect(reorderPosts.length).toBe(0); // staging is LOCAL
});

it("Apply posts the full old-priorities-in-new-order permutation, fenced with the snapshot version", async () => {
  await enterReorder();
  await click(findButtonByLabel("Move rule Third rule first"));
  expect(rowNames()).toEqual(["Third rule", "First rule", "Second rule"]);
  await click(findButton((t) => t === "Apply reorder"));
  await flushUntil(() => {
    expect(reorderPosts.length).toBe(1);
  });
  const post = reorderPosts[0];
  if (post === undefined) throw new Error("no post");
  expect(post.url).toContain("ifVersion=7");
  expect(post.body).toEqual({ priorities: [3, 1, 2] });
});

it("Discard clears the staged permutation without any server call", async () => {
  await enterReorder();
  await click(findButtonByLabel("Move rule First rule last"));
  expect(rowNames()).toEqual(["Second rule", "Third rule", "First rule"]);
  await click(findButton((t) => t === "Discard reorder"));
  expect(rowNames()).toEqual(["First rule", "Second rule", "Third rule"]);
  expect(reorderPosts.length).toBe(0);
  expect(hasButton((t) => t.includes("New rule"))).toBe(true);
});

it("a 409 on Apply discards the staged permutation VISIBLY and explains — never rebases", async () => {
  await enterReorder();
  onReorderPost = () =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          error:
            "the rulebase changed since you loaded it (your version 7, current 9) — reload and reapply your change",
          currentVersion: 9,
          yourVersion: 7,
        }),
        { status: 409, headers: { "Content-Type": "application/json" } },
      ),
    );
  await click(findButtonByLabel("Move rule First rule down"));
  await click(findButton((t) => t === "Apply reorder"));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "The rulebase changed while you were reordering. Review the current order and try again.",
    );
  });
  // Staging is gone; the view is back to server order and editing works.
  expect(rowNames()).toEqual(["First rule", "Second rule", "Third rule"]);
  expect(hasButton((t) => t.includes("New rule"))).toBe(true);
});

it("an unknown Apply outcome discards the untrustworthy staging and latches all mutations", async () => {
  await enterReorder();
  onReorderPost = () => Promise.reject(new TypeError("network down"));
  await click(findButtonByLabel("Move rule First rule down"));
  await click(findButton((t) => t === "Apply reorder"));
  await flushUntil(() => {
    expect(container.textContent).toContain("outcome unconfirmed");
  });
  expect(hasButton((t) => t.includes("Refresh rulebase"))).toBe(true);
  // Controls blocked while the latch holds.
  expect(findButton((t) => t.includes("New rule")).disabled).toBe(true);
});
