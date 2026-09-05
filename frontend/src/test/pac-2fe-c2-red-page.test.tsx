// 2F-E CORRECTION ROUND 2 RED matrix (page) — external freeze review of
// the candidate db6f4d35 (findings 1–3). Written and executed on the
// UNTOUCHED candidate before any product change; every P-case fails there
// (P20 is a CONTROL that passes on both sides):
//
//   P17  history continuity: the appliance's history epoch changed since
//        the dispatch (delete/recreate or reset) — Recover keeps the
//        operation UNRESOLVED, names the broken continuity, WITHHOLDS the
//        re-send (the original operationId has no decision record in the
//        new epoch — a re-send would run it again) and keeps the marker.
//   P18  unresolved → re-send → DIRECT challenge → confirmation → 409 stale:
//        the confirmation continues the RE-SEND (its context is carried
//        through the ceremony), so the refusal keeps the marker with its
//        ORIGINAL dispatch time and the authoritative read follows.
//   P19  … → confirmation → transport loss: the marker keeps its original
//        bindings (dispatch time, candidate digest) — never restamped.
//   P20  CONTROL: a reload while the re-send's challenge is open keeps the
//        unresolved operation, its marker and the withheld publish.
//   P21  "currently active" on the page: a committed operation whose spec
//        was replaced by a direct profile PUT is reported as no longer
//        active — from the authoritative active identity, not activeN.
import type { Root } from "react-dom/client";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { StrictMode, act } from "react";
import { createRoot } from "react-dom/client";
import { AuthMachine } from "../auth/machine";
import { AuthProvider } from "../auth/AuthProvider";
import { PACPage } from "../features/network/pac/PACPage";
import { PAC_RECOVERY_KEY } from "../features/network/pac/pacRecovery";
import { isRecord } from "../api/decode";

const INC_A = "a1a1a1a1-0000-4000-8000-000000000001";
const INC_B = "b2b2b2b2-0000-4000-8000-000000000002";

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
    historyIncarnation: INC_A,
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

function notFound(opId: string): Record<string, unknown> {
  return { operationId: opId, found: false, revisionN: 0 };
}

const CHALLENGE = {
  error: "new DIRECT paths",
  code: "confirm_required",
  confirmField: "confirm",
  challenge: "v1:deadbeef",
  confirmValue: "hq:1a2b3c4d",
  binding: BINDING,
};

/** Drive: lost response → Recover (not observed) → Re-send → the appliance
 * answers the DIRECT challenge → the typed confirmation is sent; the
 * confirmed re-send is answered by `confirmed`. Returns the operationId. */
async function resendThroughChallenge(
  confirmed: () => Promise<Response>,
): Promise<{ opId: string; startedAt: number }> {
  const sent = await publishAndLoseResponse();
  const opId = String(sent["operationId"]);
  const marker = markerRaw();
  if (!isRecord(marker) || typeof marker["startedAt"] !== "number")
    throw new Error("no marker after the lost dispatch");
  const startedAt = marker["startedAt"];
  lookup = {
    ...baseLifecycle(),
    operationsRetained: 0,
    operation: notFound(opId),
  };
  clickButton((t) => t === "Recover");
  await flushUntil(() => {
    expect(container.textContent).toContain("not observed");
  });
  let n = 0;
  onMutate = () => {
    n += 1;
    if (n === 1) return okJSON(CHALLENGE, 409);
    return confirmed();
  };
  clickButton((t) => t.startsWith("Re-send"));
  await flushUntil(() => {
    expect(buttons().some((t) => t === "Re-send now")).toBe(true);
  });
  clickButton((t) => t === "Re-send now");
  await flushUntil(() => {
    expect(container.textContent).toContain("hq:1a2b3c4d");
  });
  return { opId, startedAt };
}

// ── P17 ─────────────────────────────────────────────────────────────────────

it("P17 admin: a changed history epoch keeps the operation unresolved, names the broken continuity and withholds the re-send", async () => {
  const sent = await publishAndLoseResponse();
  const opId = String(sent["operationId"]);
  // the appliance's history epoch is not the one the marker was reviewed
  // in (delete + recreate reproduced the base exactly; the ring is empty)
  lookup = {
    ...baseLifecycle(),
    historyIncarnation: INC_B,
    activeN: 0,
    revisions: [],
    operationsRetained: 0,
    operation: notFound(opId),
  };
  clickButton((t) => t === "Recover");
  await flushUntil(() => {
    expect(container.textContent).toContain("continuity");
  });
  expect(container.textContent).not.toContain("not observed");
  expect(markerRaw()).not.toBeNull();
  const resend = Array.from(container.querySelectorAll("button")).find((b) =>
    (b.textContent ?? "").startsWith("Re-send"),
  );
  expect(resend === undefined || resend.disabled).toBe(true);
  const pub = publishButton();
  expect(pub === undefined || pub.disabled).toBe(true);
  expect(mutations).toHaveLength(1);
});

// ── P18 ─────────────────────────────────────────────────────────────────────

it("P18 admin: re-send → challenge → confirmation → 409 stale keeps the marker (original dispatch time) and reads back authoritatively", async () => {
  let nowValue = 1_700_000_000_000;
  vi.spyOn(Date, "now").mockImplementation(() => nowValue);
  const { opId, startedAt } = await resendThroughChallenge(() =>
    okJSON(
      {
        error: "stale",
        code: "stale",
        current: { revision: 4 },
      },
      409,
    ),
  );
  expect(startedAt).toBe(1_700_000_000_000);
  nowValue += 5 * 60 * 1000;
  // the authoritative read after the refusal: the ring is bounded, so the
  // earlier attempt stays unresolved
  lookup = {
    ...baseLifecycle(),
    operationsRetained: 64,
    operation: notFound(opId),
  };
  typeInto("Type", "hq:1a2b3c4d");
  clickButton((t) => t === "Publish bypass");
  await flushUntil(() => {
    expect(mutations).toHaveLength(3);
  });
  const resent = mutations[1]?.body;
  const confirmed = mutations[2]?.body;
  if (!isRecord(resent) || !isRecord(confirmed)) throw new Error("bodies");
  expect(resent["operationId"]).toBe(opId);
  expect(confirmed["operationId"]).toBe(opId);
  expect(confirmed["confirm"]).toEqual({
    challenge: "v1:deadbeef",
    value: "hq:1a2b3c4d",
    binding: BINDING,
  });
  // the refusal of the confirmed RE-SEND must not erase the earlier,
  // still-unresolved attempt: the marker survives with its original
  // dispatch time, and the authoritative read follows
  const marker = markerRaw();
  expect(marker).not.toBeNull();
  expect(marker).toMatchObject({ operationId: opId, startedAt });
  await flushUntil(() => {
    expect(container.textContent).toContain("bounded");
  });
  const pub = publishButton();
  expect(pub === undefined || pub.disabled).toBe(true);
});

// ── P19 ─────────────────────────────────────────────────────────────────────

it("P19 admin: re-send → challenge → confirmation → transport loss keeps the ORIGINAL bindings (dispatch time, candidate digest)", async () => {
  let nowValue = 1_700_000_000_000;
  vi.spyOn(Date, "now").mockImplementation(() => nowValue);
  const { opId, startedAt } = await resendThroughChallenge(() =>
    Promise.reject(new TypeError("connection lost")),
  );
  nowValue += 5 * 60 * 1000;
  typeInto("Type", "hq:1a2b3c4d");
  clickButton((t) => t === "Publish bypass");
  await flushUntil(() => {
    expect(mutations).toHaveLength(3);
  });
  await flushUntil(() => {
    expect(container.textContent).toContain("Outcome unknown");
  });
  const marker = markerRaw();
  expect(marker).toMatchObject({
    operationId: opId,
    startedAt,
    candidateSpecDigest: "sha256:cand",
    expectedActiveRevision: 3,
  });
});

// ── P20 (control) ───────────────────────────────────────────────────────────

it("P20 CONTROL admin: a reload while the re-send's challenge is open keeps the unresolved operation, its marker and the withheld publish", async () => {
  const { opId, startedAt } = await resendThroughChallenge(() =>
    okJSON({ ok: true }),
  );
  act(() => {
    root.unmount();
  });
  await mountPage("admin");
  await openProfile();
  await flushUntil(() => {
    expect(container.textContent).toContain("Outcome unknown");
  });
  expect(markerRaw()).toMatchObject({ operationId: opId, startedAt });
  const pub = publishButton();
  expect(pub === undefined || pub.disabled).toBe(true);
  expect(mutations).toHaveLength(2);
});

// ── P21 ─────────────────────────────────────────────────────────────────────

it("P21 admin: a committed operation whose spec was replaced by a direct profile PUT is reported as no longer active", async () => {
  const sent = await publishAndLoseResponse();
  const opId = String(sent["operationId"]);
  const lc = baseLifecycle();
  const revs = Array.isArray(lc["revisions"]) ? lc["revisions"] : [];
  lookup = {
    ...lc,
    revisions: [
      revs[0],
      {
        ...(isRecord(revs[1]) ? revs[1] : {}),
        operationId: opId,
        storeRevision: 3,
      },
    ],
    // activeN still points at the committed revision 2, but a direct PUT
    // replaced the spec and advanced the active store to revision 5
    activeN: 2,
    activeRevision: 5,
    activeSpecDigest: "sha256:put-spec",
    operations: [
      {
        operationId: opId,
        action: "publish",
        state: "recorded",
        ts: "t",
        status: 200,
        result: null,
      },
    ],
    operationsRetained: 1,
    operation: {
      operationId: opId,
      found: true,
      state: "recorded",
      status: 200,
      ts: "t",
      revisionN: 2,
      specDigest: "sha256:bbbb",
      storeRevision: 3,
    },
  };
  clickButton((t) => t === "Recover");
  await flushUntil(() => {
    expect(container.textContent).toContain("committed as history revision 2");
  });
  expect(container.textContent).toContain("no longer the active revision");
  expect(container.textContent).not.toContain("It is the active revision");
  expect(markerRaw()).toBeNull();
});
