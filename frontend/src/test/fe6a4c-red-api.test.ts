// FE-6A.2 CORRECTION ROUND 4 RED — API/decoding half, written against the
// frozen corrected candidate 67e2a4a8 BEFORE any product change (Blocker 2:
// the lost-response recovery is not bound to the reviewed import source).
//
//   LA1  the operation record is an ACTION-discriminated union: a committed
//        `idp.import` record REQUIRES its non-secret importSourceRevision
//        (token grammar); a non-import record FORBIDS it; a missing,
//        malformed or misplaced token is not a record.
//   LA2  the non-secret recovery marker of an import carries the EXACT
//        reviewed token (allowlisted field); an import marker without it,
//        or a create/update marker with it, is refused before dispatch.
//
// On 67e2a4a8 this file fails at type-check (no importSourceRevision on the
// operation union or the marker) and at runtime (the decoder accepts an
// import record without a token and ignores one on a create; the marker
// store drops the field).
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { decodeIdPOperation } from "../api/idp";
import {
  IDP_RECOVERY_KEY,
  readIdPRecovery,
  writeIdPRecovery,
} from "../features/objects/idpRecovery";
import type { IdPRecoveryMarker } from "../features/objects/idpRecovery";
import { isRecord } from "../api/decode";
import { OP_ID, OTHER_SOURCE_TOKEN, SOURCE_TOKEN } from "./fe6a2-fixtures";

const COMMITTED = {
  operationId: OP_ID,
  state: "committed",
  actor: "admin@10.0.0.9",
  profileId: "imp000000001",
  registryRevision: "r-doc-1",
  cutover: false,
  startedAt: "2026-09-16T10:00:00Z",
  audited: true,
  finishedAt: "2026-09-16T10:00:02Z",
  committedRevision: "r-doc-2",
};

describe("LA1 action-discriminated operation record", () => {
  it("a committed idp.import record carries its reviewed-source token, typed", () => {
    const op = decodeIdPOperation({
      ...COMMITTED,
      action: "idp.import",
      importSourceRevision: SOURCE_TOKEN,
    });
    expect(op.action).toBe("idp.import");
    if (op.action !== "idp.import") throw new Error("narrowing");
    expect(op.importSourceRevision).toBe(SOURCE_TOKEN);
    expect(op.state).toBe("committed");
  });
  it("an import record WITHOUT a token, or with a malformed one, is not a record", () => {
    expect(() =>
      decodeIdPOperation({ ...COMMITTED, action: "idp.import" }),
    ).toThrow();
    expect(() =>
      decodeIdPOperation({
        ...COMMITTED,
        action: "idp.import",
        importSourceRevision: "unavailable",
      }),
    ).toThrow();
    expect(() =>
      decodeIdPOperation({
        ...COMMITTED,
        action: "idp.import",
        importSourceRevision: "isr1:" + "z".repeat(64),
      }),
    ).toThrow();
    expect(() =>
      decodeIdPOperation({
        ...COMMITTED,
        action: "idp.import",
        importSourceRevision: 42,
      }),
    ).toThrow();
  });
  it("a non-import record FORBIDS the token", () => {
    for (const action of ["idp.create", "idp.update"]) {
      expect(() =>
        decodeIdPOperation({
          ...COMMITTED,
          action,
          importSourceRevision: SOURCE_TOKEN,
        }),
      ).toThrow();
      const op = decodeIdPOperation({ ...COMMITTED, action });
      expect("importSourceRevision" in op).toBe(false);
    }
  });
  it("pending / aborted / outcome_unknown import records keep the token too", () => {
    const pending = decodeIdPOperation({
      operationId: OP_ID,
      state: "pending",
      action: "idp.import",
      actor: "a",
      profileId: "p",
      registryRevision: "r",
      cutover: false,
      startedAt: "2026-09-16T10:00:00Z",
      audited: false,
      importSourceRevision: SOURCE_TOKEN,
    });
    if (pending.action !== "idp.import") throw new Error("narrowing");
    expect(pending.importSourceRevision).toBe(SOURCE_TOKEN);
    const aborted = decodeIdPOperation({
      operationId: OP_ID,
      state: "aborted",
      action: "idp.import",
      actor: "a",
      profileId: "p",
      registryRevision: "r",
      cutover: false,
      startedAt: "2026-09-16T10:00:00Z",
      audited: false,
      finishedAt: "2026-09-16T10:00:01Z",
      code: "stale",
      importSourceRevision: OTHER_SOURCE_TOKEN,
    });
    if (aborted.action !== "idp.import") throw new Error("narrowing");
    expect(aborted.importSourceRevision).toBe(OTHER_SOURCE_TOKEN);
  });
});

const IMPORT_MARKER: IdPRecoveryMarker = {
  operationId: OP_ID,
  action: "import",
  profileId: "",
  name: "Imported legacy LDAP",
  type: "ldap",
  candidateDigest: "0123456789abcdef",
  fence: "r-doc-1",
  cutover: false,
  startedAt: 1000,
  importSourceRevision: SOURCE_TOKEN,
};

describe("LA2 the import marker binds the exact reviewed token", () => {
  beforeEach(() => {
    sessionStorage.clear();
  });
  afterEach(() => {
    sessionStorage.clear();
  });
  it("persists the token as an allowlisted non-secret field and reads it back", () => {
    expect(writeIdPRecovery("admin", IMPORT_MARKER)).toBe(true);
    const raw = sessionStorage.getItem(IDP_RECOVERY_KEY);
    const parsed: unknown = JSON.parse(raw ?? "{}");
    if (!isRecord(parsed)) throw new Error("not a record");
    expect(parsed["importSourceRevision"]).toBe(SOURCE_TOKEN);
    expect(Object.keys(parsed).sort()).toEqual(
      [
        "action",
        "candidateDigest",
        "cutover",
        "fence",
        "importSourceRevision",
        "name",
        "operationId",
        "profileId",
        "startedAt",
        "subject",
        "type",
        "version",
      ].sort(),
    );
    const back = readIdPRecovery("admin");
    expect(back.kind).toBe("valid");
    if (back.kind !== "valid") throw new Error("narrowing");
    if (back.marker.action !== "import") throw new Error("narrowing");
    expect(back.marker.importSourceRevision).toBe(SOURCE_TOKEN);
  });
  it("an import marker with a malformed token is refused (nothing may be sent)", () => {
    expect(
      writeIdPRecovery("admin", {
        ...IMPORT_MARKER,
        importSourceRevision: "unavailable",
      }),
    ).toBe(false);
    expect(
      writeIdPRecovery("admin", {
        ...IMPORT_MARKER,
        importSourceRevision: "isr1:" + "z".repeat(64),
      }),
    ).toBe(false);
    expect(sessionStorage.getItem(IDP_RECOVERY_KEY)).toBeNull();
  });
  it("a create/update marker never carries a token", () => {
    expect(
      writeIdPRecovery("admin", {
        ...IMPORT_MARKER,
        action: "create",
        name: "Corp",
        type: "oidc",
      }),
    ).toBe(false);
    expect(sessionStorage.getItem(IDP_RECOVERY_KEY)).toBeNull();
  });
  it("a stored import marker whose token was tampered away is unreadable", () => {
    expect(writeIdPRecovery("admin", IMPORT_MARKER)).toBe(true);
    const raw = sessionStorage.getItem(IDP_RECOVERY_KEY);
    const parsed: unknown = JSON.parse(raw ?? "{}");
    if (!isRecord(parsed)) throw new Error("not a record");
    const { importSourceRevision: _gone, ...rest } = parsed;
    void _gone;
    sessionStorage.setItem(IDP_RECOVERY_KEY, JSON.stringify(rest));
    expect(readIdPRecovery("admin").kind).toBe("unreadable");
  });
});
