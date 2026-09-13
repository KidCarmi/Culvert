// FE-6A.2 RED matrix — the create/update operation RECOVERY MARKER, written
// against the frozen FE-6A.1 baseline 98d4a6c8 BEFORE any product change.
//
//   M1 the marker is subject-bound and NON-SECRET: it carries the operation
//      identity, the canonical candidate identity, the fence and the intent —
//      never a secret, never the request body.
//   M2 write-before-dispatch is verified by read-back; an unavailable or
//      unreadable store means NO dispatch (false).
//   M3 an empty subject is `unresolved` (nothing classified, nothing deleted);
//      a foreign subject's marker is never inherited.
//   M4 the same operationId is reusable only for the SAME bound candidate;
//      a different candidate under the same id is refused locally.
//   M5 clearing is ownership-matched; the auth boundary purges.
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  IDP_RECOVERY_KEY,
  clearIdPRecovery,
  purgeIdPRecovery,
  readIdPRecovery,
  writeIdPRecovery,
} from "../features/objects/idpRecovery";
import type { IdPRecoveryMarker } from "../features/objects/idpRecovery";
import { runAuthTeardown } from "../auth/teardown";
import { QueryClient } from "@tanstack/react-query";
import { BIND_PASSWORD, CLIENT_SECRET, OP_ID, OP_ID_2 } from "./fe6a2-fixtures";

const MARKER: IdPRecoveryMarker = {
  operationId: OP_ID,
  action: "create",
  profileId: "",
  name: "Corp OIDC",
  type: "oidc",
  candidateDigest: "0123456789abcdef",
  fence: "r-doc-1",
  cutover: false,
  startedAt: 1_757_600_000_000,
};

// eslint-disable-next-line no-restricted-globals -- RED harness inspects the sanctioned marker store directly
const store = (): Storage => sessionStorage;

beforeEach(() => {
  store().clear();
});
afterEach(() => {
  store().clear();
});

describe("M1 marker shape", () => {
  it("persists exactly the allowlisted non-secret fields under the subject", () => {
    expect(writeIdPRecovery("admin", MARKER)).toBe(true);
    const raw = store().getItem(IDP_RECOVERY_KEY);
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw ?? "{}") as Record<string, unknown>;
    expect(Object.keys(parsed).sort()).toEqual(
      [
        "action",
        "candidateDigest",
        "cutover",
        "fence",
        "name",
        "operationId",
        "profileId",
        "startedAt",
        "subject",
        "type",
        "version",
      ].sort(),
    );
    expect(parsed["subject"]).toBe("admin");
    expect(raw).not.toContain(CLIENT_SECRET);
    expect(raw).not.toContain(BIND_PASSWORD);
  });
  it("refuses a malformed marker (bad operationId grammar, empty name, negative time)", () => {
    expect(
      writeIdPRecovery("admin", { ...MARKER, operationId: "not-a-uuid" }),
    ).toBe(false);
    expect(writeIdPRecovery("admin", { ...MARKER, name: "" })).toBe(false);
    expect(writeIdPRecovery("admin", { ...MARKER, startedAt: -1 })).toBe(false);
    expect(store().getItem(IDP_RECOVERY_KEY)).toBeNull();
  });
});

describe("M2 write-before-dispatch read-back", () => {
  it("reads back exactly what was written", () => {
    expect(writeIdPRecovery("admin", MARKER)).toBe(true);
    expect(readIdPRecovery("admin")).toEqual({ kind: "valid", marker: MARKER });
  });
  it("an unusable store means NO dispatch and reads unavailable", () => {
    const setItem = Storage.prototype.setItem;
    Storage.prototype.setItem = () => {
      throw new DOMException("quota", "QuotaExceededError");
    };
    try {
      expect(writeIdPRecovery("admin", MARKER)).toBe(false);
    } finally {
      Storage.prototype.setItem = setItem;
    }
    store().setItem(IDP_RECOVERY_KEY, "{not json");
    expect(readIdPRecovery("admin")).toEqual({ kind: "unreadable" });
    expect(writeIdPRecovery("admin", MARKER)).toBe(false); // never overwrite evidence you cannot read
  });
});

describe("M3 subject binding", () => {
  it("an empty subject is unresolved: nothing classified, nothing deleted", () => {
    expect(writeIdPRecovery("admin", MARKER)).toBe(true);
    expect(readIdPRecovery("")).toEqual({ kind: "unresolved" });
    expect(writeIdPRecovery("", MARKER)).toBe(false);
    expect(store().getItem(IDP_RECOVERY_KEY)).not.toBeNull();
  });
  it("a foreign subject's marker is never inherited", () => {
    expect(writeIdPRecovery("admin", MARKER)).toBe(true);
    expect(readIdPRecovery("other-admin")).toEqual({ kind: "none" });
    expect(readIdPRecovery("admin")).toEqual({ kind: "none" }); // discarded, not preserved for the owner either
  });
});

describe("M4 one operation, one candidate", () => {
  it("the same operationId is re-writable only field-for-field", () => {
    expect(writeIdPRecovery("admin", MARKER)).toBe(true);
    expect(writeIdPRecovery("admin", MARKER)).toBe(true);
    expect(
      writeIdPRecovery("admin", {
        ...MARKER,
        candidateDigest: "fedcba9876543210",
      }),
    ).toBe(false);
    expect(writeIdPRecovery("admin", { ...MARKER, fence: "r-doc-2" })).toBe(
      false,
    );
    expect(readIdPRecovery("admin")).toEqual({ kind: "valid", marker: MARKER });
  });
  it("a second operation cannot start while one is unresolved", () => {
    expect(writeIdPRecovery("admin", MARKER)).toBe(true);
    expect(writeIdPRecovery("admin", { ...MARKER, operationId: OP_ID_2 })).toBe(
      false,
    );
  });
});

describe("M5 clearing", () => {
  it("clear is ownership-matched", () => {
    expect(writeIdPRecovery("admin", MARKER)).toBe(true);
    expect(clearIdPRecovery(OP_ID_2)).toBe(false);
    expect(readIdPRecovery("admin")).toEqual({ kind: "valid", marker: MARKER });
    expect(clearIdPRecovery(OP_ID)).toBe(true);
    expect(readIdPRecovery("admin")).toEqual({ kind: "none" });
  });
  it("the auth boundary purges the marker", async () => {
    expect(writeIdPRecovery("admin", MARKER)).toBe(true);
    await runAuthTeardown(new QueryClient());
    expect(store().getItem(IDP_RECOVERY_KEY)).toBeNull();
    expect(writeIdPRecovery("admin", MARKER)).toBe(true);
    purgeIdPRecovery();
    expect(store().getItem(IDP_RECOVERY_KEY)).toBeNull();
  });
});
