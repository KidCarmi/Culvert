// 2B.5 — Commit review ceremony proofs (§28–§30): fresh capture on open,
// reviewed-version fencing, required comment, shadow advisory, success
// verified against refreshed server truth, conflict and persistence-failure
// postures (draft retained, never cleared client-side).
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { AccessRulesPage } from "../features/policy/AccessRulesPage";

const RUNNING_POLICY = {
  rules: [
    {
      priority: 1,
      name: "Committed rule",
      id: "01J3ZV9E3JD0AAAAAAAAAAAAAA",
      action: "Allow",
      sslAction: "Bypass",
      hitCount: 0,
    },
  ],
  count: 1,
  version: 12,
  updatedAt: "2026-08-28T12:00:00Z",
  draft: false,
};
const DRAFT_POLICY = { ...RUNNING_POLICY, version: 9, draft: true };

const ACTIVE_DRAFT = {
  requireCommit: true,
  active: true,
  actor: "op-user",
  startedAt: "2026-08-28T10:00:00Z",
  diff: {
    added: ["Staged addition"],
    modified: ["Changed rule"],
    removed: [],
  },
  pendingCount: 2,
  version: 9,
  shadows: [{ rule: "Changed rule", shadowedBy: "Committed rule" }],
};
const INACTIVE_DRAFT = {
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
let draftBody: unknown;
let policyBody: unknown;
let onCommitPost: (url: string, body: unknown) => Promise<Response>;
let commitPosts: Array<{ url: string; body: unknown }>;

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
  draftBody = ACTIVE_DRAFT;
  policyBody = DRAFT_POLICY;
  onCommitPost = () => {
    // Successful commit: the server activates the candidate — subsequent
    // reads see running policy and no active draft.
    draftBody = INACTIVE_DRAFT;
    policyBody = RUNNING_POLICY;
    return okJSON({ ok: true, committed: 2, diff: ACTIVE_DRAFT.diff });
  };
  commitPosts = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (url.includes("/api/policy/draft/commit") && method === "POST") {
        const body: unknown =
          typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
        commitPosts.push({ url, body });
        return onCommitPost(url, body);
      }
      if (url.includes("/api/policy/draft")) return okJSON(draftBody);
      if (url.includes("/api/policy")) return okJSON(policyBody);
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
    [
      { path: "/policies/access-rules", element: <AccessRulesPage /> },
      { path: "/policies/tester", element: <div>tester page</div> },
    ],
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
    expect(container.textContent).toContain("Committed rule");
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

async function click(btn: HTMLButtonElement): Promise<void> {
  await act(async () => {
    btn.click();
    await new Promise((r) => {
      setTimeout(r, 0);
    });
  });
}

function setComment(v: string): void {
  const ta = container.querySelector("textarea");
  if (!(ta instanceof HTMLTextAreaElement)) throw new Error("no textarea");
  const desc = Object.getOwnPropertyDescriptor(
    HTMLTextAreaElement.prototype,
    "value",
  );
  desc?.set?.call(ta, v);
  act(() => {
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

async function openReview(): Promise<void> {
  await mount();
  await click(findButton((t) => t.includes("Review & commit…")));
  await flushUntil(() => {
    expect(container.textContent).toContain("Review & commit Policy Draft");
    expect(container.textContent).toContain("Added 1");
  });
}

it("the review shows diff counts + names, every shadow finding with advisory copy, and a tester link; comment is REQUIRED", async () => {
  await openReview();
  expect(container.textContent).toContain("Added 1");
  expect(container.textContent).toContain("Modified 1");
  expect(container.textContent).toContain("Removed 0");
  expect(container.textContent).toContain("Staged addition");
  expect(container.textContent).toContain("Changed rule");
  expect(container.textContent).toContain("is shadowed by");
  expect(container.textContent).toContain("advisory");
  expect(container.textContent).toContain("not a complete semantic analysis");
  const testerLink = Array.from(container.querySelectorAll("a")).find(
    (a) => a.getAttribute("href") === "/policies/tester",
  );
  expect(testerLink).toBeDefined();
  // Comment required: commit disabled until non-empty.
  expect(findButton((t) => t.includes("Commit draft")).disabled).toBe(true);
  setComment("quarterly rule cleanup");
  await flushUntil(() => {
    expect(findButton((t) => t.includes("Commit draft")).disabled).toBe(false);
  });
});

it("commit posts the reviewed candidate version + comment; success is declared only after refreshed truth agrees", async () => {
  await openReview();
  setComment("ship it");
  await click(findButton((t) => t.includes("Commit draft")));
  await flushUntil(() => {
    expect(container.textContent).toContain("Draft committed");
  });
  const post = commitPosts[0];
  if (post === undefined) throw new Error("no commit post");
  expect(post.url).toContain("ifVersion=9"); // the REVIEWED candidate version
  expect(post.body).toEqual({ comment: "ship it" });
  expect(container.textContent).toContain("2 changes are now the running");
  // The stale candidate label is gone after the refetch.
  await flushUntil(() => {
    expect(container.textContent).not.toContain(
      "Editing the shared Policy Draft",
    );
  });
});

it("a commit version conflict warns that unreviewed changes would have been activated, and offers a review reload", async () => {
  await openReview();
  onCommitPost = () =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          error:
            "the draft changed since you loaded it (your version 9, current 11) — review and retry",
          currentVersion: 11,
          yourVersion: 9,
        }),
        { status: 409, headers: { "Content-Type": "application/json" } },
      ),
    );
  setComment("stale commit");
  await click(findButton((t) => t.includes("Commit draft")));
  await flushUntil(() => {
    expect(container.textContent).toContain("The draft changed");
  });
  expect(container.textContent).toContain("changes you had not reviewed");
  expect(container.textContent).toContain("Reload review");
});

it("a persistence failure surfaces the server's draft-retained truth verbatim and clears nothing", async () => {
  await openReview();
  onCommitPost = () =>
    Promise.resolve(
      new Response(
        "running-policy persist failed — draft retained, nothing committed: disk full",
        { status: 500 },
      ),
    );
  setComment("doomed commit");
  await click(findButton((t) => t.includes("Commit draft")));
  await flushUntil(() => {
    expect(container.textContent).toContain(
      "running-policy persist failed — draft retained, nothing committed",
    );
  });
  // The review (diff + comment field) is still mounted; nothing was cleared.
  expect(container.textContent).toContain("Added 1");
});

it("commit success with DISAGREEING refreshed state renders the controlled inconsistency posture", async () => {
  await openReview();
  onCommitPost = () =>
    // Server says ok but the refreshed reads still report the candidate.
    okJSON({ ok: true, committed: 2, diff: ACTIVE_DRAFT.diff });
  setComment("suspicious commit");
  await click(findButton((t) => t.includes("Commit draft")));
  await flushUntil(() => {
    expect(container.textContent).toContain("the refreshed state disagrees");
  });
  expect(container.textContent).not.toContain("Draft committed");
});
