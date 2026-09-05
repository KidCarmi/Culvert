// 2F-E CORRECTION RED matrix (page) — external freeze review of the candidate
// 39e2cfdb (findings 1–4). Written and executed on the UNTOUCHED candidate
// before any product change; every case fails there:
//
//   P7   switching a PAC tab with unsaved draft edits asks first (local
//        state navigation, not a pathname change).
//   P8   "← All profiles" with unsaved edits asks first.
//   P9   an edit is bound to the draft revision it was based on: after a
//        Refresh that reveals a newer server draft, Save sends the OLD base
//        token (the appliance refuses 409 stale, rendered), a conflict is
//        surfaced, and adopting the newer base is an explicit action.
//   P10  ONE outstanding operation across the PAC surface: a marker for
//        another profile withholds publish/rollback here and names it.
//   P11  an UNREADABLE recovery store withholds dispatch (no POST).
//   P12  recovery evidence: absence from a bounded ring keeps the marker;
//        the server-side operation lookup then proves "committed
//        historically, no longer active".
//   P13  a not-observed operation (base unchanged, complete ring) stays
//        unresolved; the explicit re-send carries the SAME operationId and
//        candidate; only its decoded result clears the marker.
//   P14  a 2xx whose body names another operation, or lacks the positive
//        commit flag, is UNRESOLVED — never "Published".
//   P15  an intermediary 502 after dispatch is UNRESOLVED (marker kept).
//   P16  the marker records the reviewed candidate's server digest.
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { PACPage } from "../features/network/pac/PACPage";
import { PAC_RECOVERY_KEY } from "../features/network/pac/pacRecovery";
import { isRecord } from "../api/decode";

function okJSON(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

const RULE = { kind: "domain", pattern: "intranet.example", action: "direct" };
const ACTIVE = {
  id: "hq",
  name: "HQ",
  description: "",
  enabled: true,
  poolId: "p1",
  rules: [],
  privateNetworks: "proxy",
  availabilityMode: "secure",
  revision: 3,
};
const BRANCH = { ...ACTIVE, id: "branch", name: "Branch" };
const POOL = {
  id: "p1",
  name: "Pool One",
  endpoints: [{ host: "proxy.example", port: 8080 }],
};
const LISTING = {
  defaultProfile: {
    id: "default",
    name: "Default (legacy)",
    enabled: true,
    legacyManaged: true,
    availabilityMode: "balanced",
    privateNetworks: "direct",
    proxyHost: "proxy.example",
    proxyPort: 8080,
    exclusions: 2,
    pacPath: "/pac/default.pac",
  },
  profiles: [ACTIVE, BRANCH],
  pools: [POOL],
  collectionEtag: "sha256:coll",
  poolEtags: { p1: "sha256:pool1" },
};
const BINDING = {
  profileId: "hq",
  action: "publish",
  targetN: 0,
  candidateSpecDigest: "sha256:1a2b3c4d5e6f",
  expectedActiveRevision: 3,
  expectedActiveSpecDigest: "sha256:bbbb",
  poolDigest: "sha256:pppp",
  artifactDigest: "sha256:arti",
  newDirectPaths: ["rule: direct domain intranet.example"],
};

let container: HTMLDivElement;
let root: Root;
let requested: string[];
let mutations: Array<{ method: string; url: string; body: unknown }>;
let onMutate: (method: string, url: string, body: unknown) => Promise<Response>;
let lifecycle: Record<string, unknown>;
let lookup: Record<string, unknown> | null;

function baseLifecycle(): Record<string, unknown> {
  return {
    profileId: "hq",
    activeExists: true,
    active: ACTIVE,
    draft: { ...ACTIVE, rules: [RULE], revision: 0 },
    draftDirty: true,
    activeN: 2,
    revisions: [
      {
        n: 1,
        spec: ACTIVE,
        digest: "a1",
        author: "admin",
        ts: "2026-09-04T10:00:00Z",
        specDigest: "sha256:aaaa",
        poolDigest: "sha256:pppp",
      },
      {
        n: 2,
        spec: ACTIVE,
        digest: "a2",
        author: "admin",
        ts: "2026-09-04T11:00:00Z",
        specDigest: "sha256:bbbb",
        poolDigest: "sha256:pppp",
      },
    ],
    draftDiff: {
      rulesAdded: ["rule 1: direct domain intranet.example"],
      rulesReordered: false,
      poolChanged: false,
      newDirectPaths: BINDING.newDirectPaths,
      securitySensitive: true,
    },
    draftRevision: 4,
    activeRevision: 3,
    collectionEtag: "sha256:coll",
    state: "idle",
    historyState: "recorded",
    pendingOp: null,
    ambiguous: null,
    operations: [],
    activeSpecDigest: "sha256:bbbb",
    draftSpecDigest: "sha256:cand",
    operationsRetained: 0,
    operationsCap: 64,
    poolChangedSince: false,
    scope: "node-local",
    previousRevision: 1,
  };
}

beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
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
  requested = [];
  mutations = [];
  sessionStorage.clear();
  lifecycle = baseLifecycle();
  lookup = null;
  onMutate = () => okJSON({ ok: true });
  vi.stubGlobal(
    "fetch",
    vi.fn((input: unknown, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      requested.push(`${method} ${url}`);
      if (method !== "GET") {
        const body: unknown =
          typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
        mutations.push({ method, url, body });
        return onMutate(method, url, body);
      }
      if (url === "/api/pac/profiles") return okJSON(LISTING);
      if (url.startsWith("/api/pac/profiles/hq/lifecycle?operationId="))
        return okJSON(lookup ?? lifecycle);
      if (url === "/api/pac/profiles/hq/lifecycle") return okJSON(lifecycle);
      if (url === "/api/pac/profiles/branch/lifecycle")
        return okJSON({
          ...baseLifecycle(),
          profileId: "branch",
          active: BRANCH,
          draft: { ...BRANCH, revision: 0 },
        });
      if (url === "/api/pac/pools")
        return okJSON([{ ...POOL, etag: "sha256:pool1" }]);
      if (url === "/api/pac/posture/exceptions")
        return okJSON({
          exceptions: [
            {
              profileId: "hq",
              name: "HQ",
              serving: true,
              directCapable: true,
              status: "ungoverned",
              record: null,
            },
          ],
        });
      // Fixture completion (harness, not an assertion): the DIRECT Exceptions
      // tab renders the posture inventory beside the exception records.
      if (url === "/api/pac/posture/inventory")
        return okJSON({
          evidenceClass: "config",
          profiles: [
            {
              profileId: "hq",
              name: "HQ",
              serving: true,
              availabilityMode: "served",
              directCapable: true,
              directPaths: [],
            },
          ],
          totalProfiles: 1,
          directCapableProfiles: 1,
          servingDirectProfiles: 1,
          totalDirectPaths: 0,
          broadDirectPaths: 0,
        });
      if (url === "/api/pac-config")
        return okJSON({
          proxyHost: "proxy.example",
          proxyPort: 8080,
          exclusions: ["*.local", "10.0.0.0/8"],
          revision: 2,
        });
      return Promise.reject(new TypeError(`unexpected ${method} ${url}`));
    }),
  );
});

afterEach(() => {
  act(() => {
    root.unmount();
  });
  globalThis.IS_REACT_ACT_ENVIRONMENT = undefined;
  container.remove();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function machineFor(
  role: "viewer" | "operator" | "admin",
  qc: QueryClient,
): AuthMachine {
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
        user: `${role}-user`,
        role,
        bootstrap: false,
        tlsFallback: false,
        tlsFallbackReason: "",
      }),
    postLogout: () => Promise.resolve({ ok: true }),
  });
}

async function mountPage(role: "viewer" | "operator" | "admin"): Promise<void> {
  const router = createMemoryRouter(
    [{ path: "/network/pac", element: <PACPage /> }],
    {
      initialEntries: ["/network/pac"],
    },
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
    expect(container.textContent).toContain("HQ");
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

function buttons(): string[] {
  return Array.from(container.querySelectorAll("button")).map(
    (b) => b.textContent ?? "",
  );
}

function clickButton(match: (t: string) => boolean): void {
  const b = Array.from(container.querySelectorAll("button")).find((el) =>
    match(el.textContent ?? ""),
  );
  if (b === undefined)
    throw new Error("button not found: " + buttons().join("|"));
  act(() => {
    b.click();
  });
}

async function openTab(name: string, readyText: string): Promise<void> {
  clickButton((t) => t === name);
  await flushUntil(() => {
    expect(container.textContent).toContain(readyText);
  });
}

async function openProfile(): Promise<void> {
  clickButton((t) => t === "Open");
  await flushUntil(() => {
    expect(container.textContent).toContain("Active revision");
  });
}

function typeInto(label: string, value: string): void {
  const el = Array.from(container.querySelectorAll("input")).find((i) => {
    const l = i.labels?.[0]?.textContent ?? "";
    return l.includes(label);
  });
  if (el === undefined) throw new Error("input not found: " + label);
  act(() => {
    const desc = Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    );
    desc?.set?.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

function nonGets(): string[] {
  return requested.filter((r) => !r.startsWith("GET "));
}

const MUTATION_WORDS = [
  "Publish",
  "Save draft",
  "New profile",
  "New pool",
  "Delete",
  "Roll back",
  "Acknowledge",
  "Repair",
  "Save",
  "Clear",
  "Recover",
];

const OTHER_ID = "2d7c0f5e-9b1a-4c3d-8e2f-6a5b4c3d2e1f";

function foreignOps(n: number): unknown[] {
  return Array.from({ length: n }, (_, i) => ({
    operationId: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`,
    action: "publish",
    state: "recorded",
    ts: "t",
    status: 200,
    result: null,
  }));
}

function publishButton(): HTMLButtonElement | undefined {
  return Array.from(container.querySelectorAll("button")).find(
    (b) => b.textContent === "Publish",
  );
}

async function publishAndLoseResponse(): Promise<Record<string, unknown>> {
  onMutate = () => Promise.reject(new TypeError("connection lost"));
  await mountPage("admin");
  await openProfile();
  clickButton((t) => t === "Publish");
  await flushUntil(() => {
    expect(buttons().some((t) => t === "Publish now")).toBe(true);
  });
  clickButton((t) => t === "Publish now");
  await flushUntil(() => {
    expect(container.textContent).toContain("unknown");
  });
  const sent = mutations[0]?.body;
  if (!isRecord(sent)) throw new Error("no dispatch body");
  return sent;
}

function markerRaw(): unknown {
  const raw = sessionStorage.getItem(PAC_RECOVERY_KEY);
  return raw === null ? null : JSON.parse(raw);
}

// ── P7 / P8 ─────────────────────────────────────────────────────────────────

it("P7 admin: a tab switch with unsaved draft edits asks first; Cancel keeps the editor, Discard leaves", async () => {
  await mountPage("admin");
  await openProfile();
  typeInto("Name", "HQ edited locally");
  clickButton((t) => t === "Pools");
  await flushUntil(() => {
    expect(container.textContent).toContain("Discard unsaved changes?");
  });
  expect(container.textContent).not.toContain("Pool One");
  clickButton((t) => t === "Cancel");
  await flushUntil(() => {
    expect(container.textContent).not.toContain("Discard unsaved changes?");
  });
  const name = Array.from(container.querySelectorAll("input")).find((i) =>
    (i.labels?.[0]?.textContent ?? "").includes("Name"),
  );
  expect(name?.value).toBe("HQ edited locally");
  clickButton((t) => t === "Pools");
  await flushUntil(() => {
    expect(container.textContent).toContain("Discard unsaved changes?");
  });
  clickButton((t) => t === "Discard and leave");
  await flushUntil(() => {
    expect(container.textContent).toContain("Pool One");
  });
  expect(nonGets()).toEqual([]);
});

it("P8 admin: '← All profiles' with unsaved draft edits asks first", async () => {
  await mountPage("admin");
  await openProfile();
  typeInto("Name", "HQ edited locally");
  clickButton((t) => t.includes("All profiles"));
  await flushUntil(() => {
    expect(container.textContent).toContain("Discard unsaved changes?");
  });
  expect(container.textContent).toContain("Active revision");
  clickButton((t) => t === "Cancel");
  await flushUntil(() => {
    expect(container.textContent).not.toContain("Discard unsaved changes?");
  });
  expect(container.textContent).toContain("Active revision");
});

// ── P9 ──────────────────────────────────────────────────────────────────────

it("P9 admin: an edit stays bound to its base draft revision across Refresh; the conflict is explicit and never silently re-based", async () => {
  onMutate = (_m, _u, body) => {
    if (isRecord(body) && body["action"] === "save_draft") {
      if (body["draftRevision"] === 4)
        return okJSON(
          {
            error: "stale draftRevision 4 (current 5): reload and retry",
            code: "stale",
            current: { draftRevision: 5 },
          },
          409,
        );
      return okJSON({
        draftDirty: true,
        draft: body["draft"],
        draftRevision: 6,
      });
    }
    return okJSON({ error: "x" }, 400);
  };
  await mountPage("admin");
  await openProfile();
  typeInto("Name", "HQ edited locally");
  // another admin saved draft revision 5 meanwhile; the page refreshes
  lifecycle = {
    ...baseLifecycle(),
    draft: { ...ACTIVE, name: "Server edit", rules: [RULE], revision: 0 },
    draftRevision: 5,
  };
  clickButton((t) => t === "Refresh");
  await flushUntil(() => {
    expect(container.textContent).toContain("Draft changed on the appliance");
  });
  // the local edit is kept, the base token is NOT silently advanced
  const name = Array.from(container.querySelectorAll("input")).find((i) =>
    (i.labels?.[0]?.textContent ?? "").includes("Name"),
  );
  expect(name?.value).toBe("HQ edited locally");
  clickButton((t) => t === "Save draft");
  await flushUntil(() => {
    expect(mutations).toHaveLength(1);
  });
  const first = mutations[0]?.body;
  expect(isRecord(first) && first["draftRevision"]).toBe(4);
  await flushUntil(() => {
    expect(container.textContent).toContain("current draft revision 5");
  });
  // explicit resolution: keep the edits and re-base onto revision 5
  clickButton((t) => t.startsWith("Keep my edits"));
  await flushUntil(() => {
    expect(container.textContent).not.toContain(
      "Draft changed on the appliance",
    );
  });
  clickButton((t) => t === "Save draft");
  await flushUntil(() => {
    expect(mutations).toHaveLength(2);
  });
  const second = mutations[1]?.body;
  expect(isRecord(second) && second["draftRevision"]).toBe(5);
  expect(
    isRecord(second) && isRecord(second["draft"]) && second["draft"]["name"],
  ).toBe("HQ edited locally");
});

// ── P10 / P11 ───────────────────────────────────────────────────────────────

it("P10 admin: an unresolved operation on ANOTHER profile withholds publish here and names it", async () => {
  sessionStorage.setItem(
    PAC_RECOVERY_KEY,
    JSON.stringify({
      version: 1,
      operationId: OTHER_ID,
      action: "publish",
      profileId: "branch",
      expectedActiveRevision: 3,
      expectedActiveSpecDigest: "sha256:bbbb",
      candidateSpecDigest: "sha256:x",
      targetN: 0,
      startedAt: 1,
      subject: "admin-user",
    }),
  );
  await mountPage("admin");
  await openProfile();
  await flushUntil(() => {
    expect(container.textContent).toContain("branch");
  });
  const pub = publishButton();
  expect(pub === undefined || pub.disabled).toBe(true);
  expect(nonGets()).toEqual([]);
  const raw = markerRaw();
  expect(isRecord(raw) && raw["operationId"]).toBe(OTHER_ID);
});

it("P11 admin: an UNREADABLE recovery store withholds dispatch", async () => {
  sessionStorage.setItem(PAC_RECOVERY_KEY, "{not json");
  await mountPage("admin");
  await openProfile();
  await flushUntil(() => {
    expect(container.textContent).toContain("unreadable");
  });
  const pub = publishButton();
  expect(pub === undefined || pub.disabled).toBe(true);
  expect(nonGets()).toEqual([]);
  expect(sessionStorage.getItem(PAC_RECOVERY_KEY)).toBe("{not json");
});

// ── P12 / P13 ───────────────────────────────────────────────────────────────

it("P12 admin: absence from a bounded ring keeps the marker; the operation lookup then proves 'committed, no longer active'", async () => {
  const sent = await publishAndLoseResponse();
  const opId = String(sent["operationId"]);
  // 20 later decisions are shown, ours is not among them; the base moved
  lifecycle = {
    ...baseLifecycle(),
    activeN: 30,
    activeRevision: 31,
    activeSpecDigest: "sha256:zz",
    operations: foreignOps(20),
    operationsRetained: 64,
    operationsCap: 64,
  };
  lookup = {
    ...lifecycle,
    operation: { operationId: opId, found: false, revisionN: 0 },
  };
  clickButton((t) => t === "Recover");
  await flushUntil(() => {
    expect(container.textContent).toContain("bounded");
  });
  expect(container.textContent).not.toContain("did not land");
  expect(isRecord(markerRaw()) && markerRaw()).not.toBeNull();
  const pub1 = publishButton();
  expect(pub1 === undefined || pub1.disabled).toBe(true);
  // the server retains it after all (ring of 64): committed as revision 3
  lookup = {
    ...lifecycle,
    operation: {
      operationId: opId,
      found: true,
      state: "recorded",
      status: 200,
      ts: "t",
      revisionN: 3,
    },
  };
  clickButton((t) => t === "Recover");
  await flushUntil(() => {
    expect(container.textContent).toContain("committed");
    expect(container.textContent).toContain("no longer");
  });
  expect(sessionStorage.getItem(PAC_RECOVERY_KEY)).toBeNull();
  expect(mutations).toHaveLength(1);
});

it("P13 admin: a not-observed operation stays unresolved; the explicit re-send reuses the SAME operationId and candidate", async () => {
  const sent = await publishAndLoseResponse();
  const opId = String(sent["operationId"]);
  lookup = {
    ...baseLifecycle(),
    operationsRetained: 1,
    operationsCap: 64,
    operation: { operationId: opId, found: false, revisionN: 0 },
  };
  clickButton((t) => t === "Recover");
  await flushUntil(() => {
    expect(container.textContent).toContain("not observed");
  });
  expect(markerRaw()).not.toBeNull();
  const pub = publishButton();
  expect(pub === undefined || pub.disabled).toBe(true);
  onMutate = () =>
    okJSON({
      operationId: opId,
      activeRevision: 4,
      activeSpecDigest: "sha256:cand",
      digest: "arti",
      draftRevision: 5,
      historyState: "recorded",
      scope: "node-local-history",
      published: true,
      revision: 3,
    });
  clickButton((t) => t.startsWith("Re-send"));
  await flushUntil(() => {
    expect(buttons().some((t) => t === "Re-send now")).toBe(true);
  });
  clickButton((t) => t === "Re-send now");
  await flushUntil(() => {
    expect(container.textContent).toContain("Published");
  });
  expect(mutations).toHaveLength(2);
  const again = mutations[1]?.body;
  expect(isRecord(again) && again["operationId"]).toBe(opId);
  expect(isRecord(again) && again["draft"]).toEqual(sent["draft"]);
  expect(isRecord(again) && again["expectedActiveRevision"]).toBe(3);
  expect(sessionStorage.getItem(PAC_RECOVERY_KEY)).toBeNull();
});

// ── P14 / P15 / P16 ─────────────────────────────────────────────────────────

it("P14 admin: a 2xx naming another operation, or without the positive commit flag, is UNRESOLVED — never 'Published'", async () => {
  onMutate = () =>
    okJSON({
      operationId: OTHER_ID,
      activeRevision: 4,
      historyState: "recorded",
      published: true,
      revision: 3,
    });
  await mountPage("admin");
  await openProfile();
  clickButton((t) => t === "Publish");
  await flushUntil(() => {
    expect(buttons().some((t) => t === "Publish now")).toBe(true);
  });
  clickButton((t) => t === "Publish now");
  await flushUntil(() => {
    expect(container.textContent).toContain("unknown");
  });
  expect(container.textContent).not.toContain("Published");
  expect(markerRaw()).not.toBeNull();
  const pub = publishButton();
  expect(pub === undefined || pub.disabled).toBe(true);
});

it("P14b admin: published:false on a 200 is not a commit", async () => {
  onMutate = (_m, _u, body) =>
    okJSON({
      operationId: isRecord(body) ? body["operationId"] : "",
      activeRevision: 3,
      historyState: "recorded",
      published: false,
      rolledBack: false,
    });
  await mountPage("admin");
  await openProfile();
  clickButton((t) => t === "Publish");
  await flushUntil(() => {
    expect(buttons().some((t) => t === "Publish now")).toBe(true);
  });
  clickButton((t) => t === "Publish now");
  await flushUntil(() => {
    expect(container.textContent).toContain("unknown");
  });
  expect(container.textContent).not.toContain("Published");
  expect(markerRaw()).not.toBeNull();
});

it("P15 admin: an intermediary 502 after dispatch is UNRESOLVED (marker kept, publish withheld)", async () => {
  onMutate = () =>
    Promise.resolve(
      new Response("<html>Bad Gateway</html>", {
        status: 502,
        headers: { "Content-Type": "text/html" },
      }),
    );
  await mountPage("admin");
  await openProfile();
  clickButton((t) => t === "Publish");
  await flushUntil(() => {
    expect(buttons().some((t) => t === "Publish now")).toBe(true);
  });
  clickButton((t) => t === "Publish now");
  await flushUntil(() => {
    expect(container.textContent).toContain("unknown");
  });
  expect(markerRaw()).not.toBeNull();
  const pub = publishButton();
  expect(pub === undefined || pub.disabled).toBe(true);
});

it("P16 admin: the marker records the reviewed candidate's server digest", async () => {
  await publishAndLoseResponse();
  const raw = markerRaw();
  expect(isRecord(raw) && raw["candidateSpecDigest"]).toBe("sha256:cand");
});
