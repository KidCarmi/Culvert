// FE-6B.2 RED matrix — the certificate OPERATION RECOVERY MARKER, written
// against the frozen FE-6B.1 baseline 212b1617 BEFORE any product change
// (the module does not exist there: every row fails at import).
//
//   M1 the marker is subject-bound and NON-SECRET: exactly the allowlisted
//      fields (operation identity, intent, the fence the write carried, the
//      candidate's public identity, the CA identity a rotation replaces, a
//      timestamp) — never the challenge, a PEM, a key, a passphrase.
//   M2 write-before-dispatch is verified by read-back; an unavailable or
//      unreadable store means NO dispatch (false).
//   M3 an empty subject is `unresolved` (nothing classified, nothing
//      deleted); a foreign subject's marker is never inherited.
//   M4 ONE outstanding operation per browser: a different operationId is
//      refused while one is unresolved; the same id only field-for-field.
//   M5 clearing is ownership-matched; the auth boundary purges.
//   M6 grammar by action: candidate is a hex digest for import/replace, the
//      target word for ocsp, empty for rotate/delete; previousFingerprint
//      only for a rotate; the fence prefix matches the action's object.
//   M7 a ledger record is THIS marker's operation only when operationId,
//      action, fence AND (import/replace) the candidate all match.
//   M8 an explicit re-send is offered ONLY after an authoritative 404
//      (never recorded); pending, recoverable unknown, unproven unknown,
//      superseded (TERMINAL UNKNOWN), committed and aborted never offer it.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient } from "@tanstack/react-query";
import { isRecord } from "../api/decode";
import { runAuthTeardown } from "../auth/teardown";
import { decodeCertOperation } from "../api/certificates";
import {
  CERT_RECOVERY_KEY,
  certResendAllowed,
  clearCertRecovery,
  operationBoundToCertMarker,
  purgeCertRecovery,
  readCertRecovery,
  writeCertRecovery,
} from "../features/security/certRecovery";
import type {
  CertRecoveryMarker,
  CertRecoveryView,
} from "../features/security/certRecovery";
import {
  HEX64,
  HEX64_B,
  OP_ABORTED,
  OP_COMMITTED,
  OP_ID,
  OP_PENDING,
  OP_ROTATE_COMMITTED,
  OP_SUPERSEDED,
  OP_UI_DELETE_COMMITTED,
  OP_UI_REPLACE_COMMITTED,
  OP_UNKNOWN_RECOVERABLE,
  OP_UNKNOWN_UNPROVEN,
} from "./fe6b1-fixtures";
import { CHALLENGE, KEY_PEM_CANARY, OP_ID_2 } from "./fe6b2-fixtures";

const IMPORT_MARKER: CertRecoveryMarker = {
  operationId: OP_ID,
  action: "import",
  fence: `car1:${HEX64}`,
  candidate: HEX64_B,
  previousFingerprint: "",
  startedAt: 1_758_276_000_000,
};
const ROTATE_MARKER: CertRecoveryMarker = {
  operationId: OP_ID,
  action: "rotate",
  fence: `car1:${HEX64}`,
  candidate: "",
  previousFingerprint: HEX64,
  startedAt: 1_758_276_000_000,
};
const OCSP_MARKER: CertRecoveryMarker = {
  operationId: OP_ID,
  action: "ocsp",
  fence: `ocr1:${HEX64}`,
  candidate: "enabled",
  previousFingerprint: "",
  startedAt: 1_758_276_000_000,
};

const store = (): Storage => sessionStorage;

beforeEach(() => {
  store().clear();
});
afterEach(() => {
  store().clear();
});

describe("M1 marker shape", () => {
  it("persists exactly the allowlisted non-secret fields under the subject", () => {
    expect(writeCertRecovery("admin", IMPORT_MARKER)).toBe(true);
    const raw = store().getItem(CERT_RECOVERY_KEY);
    expect(raw).not.toBeNull();
    const parsed: unknown = JSON.parse(raw ?? "{}");
    if (!isRecord(parsed)) throw new Error("not a record");
    expect(Object.keys(parsed).sort()).toEqual(
      [
        "action",
        "candidate",
        "fence",
        "operationId",
        "previousFingerprint",
        "startedAt",
        "subject",
        "version",
      ].sort(),
    );
    expect(parsed["subject"]).toBe("admin");
    expect(raw).not.toContain(CHALLENGE);
    expect(raw).not.toContain("PRIVATE KEY");
  });
  it("never accepts a secret-bearing field", () => {
    const extra: Record<string, string> = { key: KEY_PEM_CANARY };
    const tainted: CertRecoveryMarker = { ...IMPORT_MARKER, ...extra };
    expect(writeCertRecovery("admin", tainted)).toBe(true);
    const raw = store().getItem(CERT_RECOVERY_KEY) ?? "";
    expect(raw).not.toContain("KEY-CANARY");
    expect(raw).not.toContain("PRIVATE KEY");
  });
});

describe("M2 write-before-dispatch", () => {
  it("read-back after write is the same marker", () => {
    expect(writeCertRecovery("admin", ROTATE_MARKER)).toBe(true);
    const r = readCertRecovery("admin");
    expect(r.kind).toBe("valid");
    if (r.kind === "valid") expect(r.marker).toEqual(ROTATE_MARKER);
  });
  it("an unavailable store refuses the write (⇒ no dispatch)", () => {
    const spy = vi
      .spyOn(Storage.prototype, "setItem")
      .mockImplementation(() => {
        throw new Error("QuotaExceededError");
      });
    try {
      expect(writeCertRecovery("admin", ROTATE_MARKER)).toBe(false);
    } finally {
      spy.mockRestore();
    }
  });
  it("an unreadable stored value refuses a new write", () => {
    store().setItem(CERT_RECOVERY_KEY, "{not json");
    expect(writeCertRecovery("admin", ROTATE_MARKER)).toBe(false);
    expect(readCertRecovery("admin").kind).toBe("unreadable");
  });
});

describe("M3 subject binding", () => {
  it("an empty subject is unresolved and deletes nothing", () => {
    expect(writeCertRecovery("admin", ROTATE_MARKER)).toBe(true);
    expect(readCertRecovery("").kind).toBe("unresolved");
    expect(store().getItem(CERT_RECOVERY_KEY)).not.toBeNull();
    expect(writeCertRecovery("", ROTATE_MARKER)).toBe(false);
  });
  it("a foreign subject's marker is discarded, never inherited", () => {
    expect(writeCertRecovery("alice", ROTATE_MARKER)).toBe(true);
    expect(readCertRecovery("bob").kind).toBe("none");
    expect(store().getItem(CERT_RECOVERY_KEY)).toBeNull();
    expect(writeCertRecovery("alice", ROTATE_MARKER)).toBe(true);
    expect(
      writeCertRecovery("bob", { ...ROTATE_MARKER, operationId: OP_ID_2 }),
    ).toBe(false);
  });
});

describe("M4 one outstanding operation", () => {
  it("refuses a second operationId while one is unresolved; the same id only field-for-field", () => {
    expect(writeCertRecovery("admin", IMPORT_MARKER)).toBe(true);
    expect(
      writeCertRecovery("admin", { ...IMPORT_MARKER, operationId: OP_ID_2 }),
    ).toBe(false);
    expect(
      writeCertRecovery("admin", { ...IMPORT_MARKER, candidate: HEX64 }),
    ).toBe(false);
    expect(
      writeCertRecovery("admin", {
        ...IMPORT_MARKER,
        fence: `car1:${HEX64_B}`,
      }),
    ).toBe(false);
    expect(writeCertRecovery("admin", IMPORT_MARKER)).toBe(true);
  });
});

describe("M5 clearing", () => {
  it("clear is ownership-matched", () => {
    expect(writeCertRecovery("admin", IMPORT_MARKER)).toBe(true);
    expect(clearCertRecovery(OP_ID_2)).toBe(false);
    expect(readCertRecovery("admin").kind).toBe("valid");
    expect(clearCertRecovery(OP_ID)).toBe(true);
    expect(readCertRecovery("admin").kind).toBe("none");
  });
  it("the auth boundary purges unconditionally", async () => {
    expect(writeCertRecovery("admin", IMPORT_MARKER)).toBe(true);
    await runAuthTeardown(new QueryClient());
    expect(store().getItem(CERT_RECOVERY_KEY)).toBeNull();
    expect(writeCertRecovery("admin", IMPORT_MARKER)).toBe(true);
    purgeCertRecovery();
    expect(store().getItem(CERT_RECOVERY_KEY)).toBeNull();
  });
});

describe("M6 grammar by action", () => {
  const bad: Array<[string, CertRecoveryMarker]> = [
    ["import without a candidate", { ...IMPORT_MARKER, candidate: "" }],
    [
      "import with a non-hex candidate",
      { ...IMPORT_MARKER, candidate: "enabled" },
    ],
    [
      "import with a rotate fence prefix",
      { ...IMPORT_MARKER, fence: `ocr1:${HEX64}` },
    ],
    [
      "import carrying previousFingerprint",
      { ...IMPORT_MARKER, previousFingerprint: HEX64 },
    ],
    ["rotate with a candidate", { ...ROTATE_MARKER, candidate: HEX64_B }],
    [
      "rotate without the CA it replaces",
      { ...ROTATE_MARKER, previousFingerprint: "" },
    ],
    ["ocsp with a hex candidate", { ...OCSP_MARKER, candidate: HEX64 }],
    ["ocsp with a CA fence", { ...OCSP_MARKER, fence: `car1:${HEX64}` }],
    [
      "delete with a candidate",
      {
        operationId: OP_ID,
        action: "delete",
        fence: `uic1:${HEX64_B}`,
        candidate: HEX64,
        previousFingerprint: "",
        startedAt: 1,
      },
    ],
    [
      "replace with a uic1:none candidate fence mismatch",
      {
        operationId: OP_ID,
        action: "replace",
        fence: `car1:${HEX64}`,
        candidate: HEX64_B,
        previousFingerprint: "",
        startedAt: 1,
      },
    ],
    ["a non-UUID operation", { ...IMPORT_MARKER, operationId: "op-1" }],
  ];
  for (const [name, m] of bad) {
    it(`refuses ${name}`, () => {
      expect(writeCertRecovery("admin", m)).toBe(false);
    });
  }
  it("a stored marker with an unknown action is unreadable and blocks a write", () => {
    store().setItem(
      CERT_RECOVERY_KEY,
      JSON.stringify({
        ...IMPORT_MARKER,
        action: "rename",
        version: 1,
        subject: "admin",
      }),
    );
    expect(readCertRecovery("admin").kind).toBe("unreadable");
    expect(writeCertRecovery("admin", IMPORT_MARKER)).toBe(false);
  });
  it("accepts every well-formed action", () => {
    for (const m of [
      IMPORT_MARKER,
      ROTATE_MARKER,
      OCSP_MARKER,
      { ...OCSP_MARKER, candidate: "disabled" },
      {
        operationId: OP_ID,
        action: "delete" as const,
        fence: `uic1:${HEX64_B}`,
        candidate: "",
        previousFingerprint: "",
        startedAt: 1,
      },
      {
        operationId: OP_ID,
        action: "replace" as const,
        fence: "uic1:none",
        candidate: HEX64_B,
        previousFingerprint: "",
        startedAt: 1,
      },
    ]) {
      store().clear();
      expect(writeCertRecovery("admin", m)).toBe(true);
    }
  });
});

describe("M7 binding a ledger record to the marker", () => {
  const op = (v: unknown) => decodeCertOperation(v);
  it("import: id + action + fence + candidate", () => {
    expect(operationBoundToCertMarker(op(OP_COMMITTED), IMPORT_MARKER)).toBe(
      true,
    );
    expect(operationBoundToCertMarker(op(OP_PENDING), IMPORT_MARKER)).toBe(
      true,
    );
    expect(
      operationBoundToCertMarker(op(OP_COMMITTED), {
        ...IMPORT_MARKER,
        candidate: HEX64,
      }),
    ).toBe(false);
    expect(
      operationBoundToCertMarker(op(OP_COMMITTED), {
        ...IMPORT_MARKER,
        fence: `car1:${HEX64_B}`,
      }),
    ).toBe(false);
    expect(
      operationBoundToCertMarker(
        op({
          ...OP_COMMITTED,
          operationId: OP_ID_2,
          result: { ...OP_COMMITTED.result, operationId: OP_ID_2 },
        }),
        IMPORT_MARKER,
      ),
    ).toBe(false);
    expect(
      operationBoundToCertMarker(op(OP_ROTATE_COMMITTED), IMPORT_MARKER),
    ).toBe(false);
  });
  it("rotate: id + action + fence (the candidate is server-minted)", () => {
    expect(
      operationBoundToCertMarker(op(OP_ROTATE_COMMITTED), ROTATE_MARKER),
    ).toBe(true);
    expect(operationBoundToCertMarker(op(OP_COMMITTED), ROTATE_MARKER)).toBe(
      false,
    );
  });
  it("replace: id + action + fence + the PEM digest the ledger recorded", () => {
    const m: CertRecoveryMarker = {
      operationId: OP_ID,
      action: "replace",
      fence: "uic1:none",
      candidate: HEX64_B,
      previousFingerprint: "",
      startedAt: 1,
    };
    expect(operationBoundToCertMarker(op(OP_UI_REPLACE_COMMITTED), m)).toBe(
      true,
    );
    expect(
      operationBoundToCertMarker(op(OP_UI_REPLACE_COMMITTED), {
        ...m,
        candidate: HEX64,
      }),
    ).toBe(false);
  });
  it("delete / ocsp: id + action + fence", () => {
    const d: CertRecoveryMarker = {
      operationId: OP_ID,
      action: "delete",
      fence: `uic1:${HEX64_B}`,
      candidate: "",
      previousFingerprint: "",
      startedAt: 1,
    };
    expect(operationBoundToCertMarker(op(OP_UI_DELETE_COMMITTED), d)).toBe(
      true,
    );
    expect(
      operationBoundToCertMarker(op(OP_UI_DELETE_COMMITTED), {
        ...d,
        fence: "uic1:none",
      }),
    ).toBe(false);
    const o = op({
      ...OP_PENDING,
      action: "ocsp.set",
      target: "ocsp",
      fence: `ocr1:${HEX64}`,
      candidateFingerprint: undefined,
    });
    expect(operationBoundToCertMarker(o, OCSP_MARKER)).toBe(true);
  });
});

describe("M8 re-send is offered only after an authoritative 404", () => {
  it("never_recorded ⇒ allowed; every recorded state ⇒ not", () => {
    const views: Array<[CertRecoveryView, boolean]> = [
      [{ kind: "never_recorded" }, true],
      [{ kind: "none" }, false],
      [{ kind: "looking" }, false],
      [{ kind: "unproven" }, false],
      [{ kind: "refused", code: "operation_ledger_degraded" }, false],
      [{ kind: "op", op: decodeCertOperation(OP_PENDING) }, false],
      [{ kind: "op", op: decodeCertOperation(OP_COMMITTED) }, false],
      [{ kind: "op", op: decodeCertOperation(OP_ABORTED) }, false],
      [{ kind: "op", op: decodeCertOperation(OP_UNKNOWN_RECOVERABLE) }, false],
      [{ kind: "op", op: decodeCertOperation(OP_UNKNOWN_UNPROVEN) }, false],
      [{ kind: "op", op: decodeCertOperation(OP_SUPERSEDED) }, false],
      [{ kind: "unbound", op: decodeCertOperation(OP_COMMITTED) }, false],
    ];
    for (const [v, want] of views) expect(certResendAllowed(v)).toBe(want);
  });
});
