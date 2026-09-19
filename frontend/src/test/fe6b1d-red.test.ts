// FE-6B.1 CORRECTION ROUND 2 — RED matrix (API client), committed on the
// reviewed candidate 8960ab53 BEFORE any product change (blocker B2 of the
// second external review).
//
// checkCommittedResult binds a committed record's action-specific `result`
// to its discriminant, its identities and the committed revision, but never
// reads the facts the frozen OpenAPI contract and the authoritative builders
// (certificate_operations.go caOperationResult / uiCertOperationResult) make
// mandatory and bounded — so a record asserting a FALSE durability claim, a
// FOREIGN target or an UNRECOGNISED cleanup value still enters the committed
// union and is rendered "Committed". Every E-row below starts from a record
// the builder would emit and changes ONE fact; corrected decoding must refuse
// the record whole. The K-rows are controls: the builder's own records, and
// the documented optional/alternative values, keep decoding.
//
//   E01 ca.rotate  persisted:false        (CARotateResult: persisted enum [true])
//   E02 ca.rotate  persisted missing      (required)
//   E03 ca.import  persisted:false        (CAImportResult: enum [true])
//   E04 ca.import  target:"ui"            (enum [mitm])
//   E05 ca.import  target missing         (required)
//   E06 ca.rotate  target:"ui"            (a rotate writes the root CA; a
//                                          foreign target contradicts it)
//   E07 ca.rotate  previous not an object (CAPrevious, required)
//   E08 replace    persisted:false        (UICertReplaceResult: enum [true])
//   E09 replace    target:"mitm"          (enum [ui])
//   E10 replace    activation:"immediate" (enum [restart_required])
//   E11 replace    candidate missing      (required)
//   E12 replace    candidate names another certificate than uiCert
//   E13 delete     cleanup:"partial"      (enum [complete, completed_at_settlement])
//   E14 delete     cleanup missing        (required)
//   E15 delete     target:"mitm"          (enum [ui])
//   E16 delete     activation:"immediate" (optional, enum [restart_required])
//   K01 the four builder records decode committed
//   K02 delete cleanup:"completed_at_settlement" decodes
//   K03 delete activation:"restart_required" decodes
//   K04 rotate carrying target:"mitm" decodes (additionalProperties: true;
//       the value agrees with what a rotate writes)
import { describe, expect, it } from "vitest";
import { decodeCertOperation } from "../api/certificates";
import {
  OP_COMMITTED,
  OP_ROTATE_COMMITTED,
  OP_UI_DELETE_COMMITTED,
  OP_UI_REPLACE_COMMITTED,
  SELF_FP,
} from "./fe6b1-fixtures";

type Rec = Record<string, unknown>;

function withResult(base: { result: Rec }, patch: Rec): Rec {
  return { ...base, result: { ...base.result, ...patch } };
}
function withoutResultKey(base: { result: Rec }, key: string): Rec {
  const { [key]: _drop, ...rest } = base.result;
  void _drop;
  return { ...base, result: rest };
}

describe("B2 — a committed result's facts must agree with the frozen contract", () => {
  const rows: Array<[string, Rec]> = [
    [
      "E01 rotate persisted:false",
      withResult(OP_ROTATE_COMMITTED, { persisted: false }),
    ],
    [
      "E02 rotate persisted missing",
      withoutResultKey(OP_ROTATE_COMMITTED, "persisted"),
    ],
    [
      "E03 import persisted:false",
      withResult(OP_COMMITTED, { persisted: false }),
    ],
    ["E04 import target:ui", withResult(OP_COMMITTED, { target: "ui" })],
    ["E05 import target missing", withoutResultKey(OP_COMMITTED, "target")],
    ["E06 rotate target:ui", withResult(OP_ROTATE_COMMITTED, { target: "ui" })],
    [
      "E07 rotate previous not an object",
      withResult(OP_ROTATE_COMMITTED, { previous: "car1:x" }),
    ],
    [
      "E08 replace persisted:false",
      withResult(OP_UI_REPLACE_COMMITTED, { persisted: false }),
    ],
    [
      "E09 replace target:mitm",
      withResult(OP_UI_REPLACE_COMMITTED, { target: "mitm" }),
    ],
    [
      "E10 replace activation:immediate",
      withResult(OP_UI_REPLACE_COMMITTED, { activation: "immediate" }),
    ],
    [
      "E11 replace candidate missing",
      withoutResultKey(OP_UI_REPLACE_COMMITTED, "candidate"),
    ],
    [
      "E12 replace candidate names another certificate",
      withResult(OP_UI_REPLACE_COMMITTED, {
        candidate: {
          ...OP_UI_REPLACE_COMMITTED.result.candidate,
          fingerprint: SELF_FP,
        },
      }),
    ],
    [
      "E13 delete cleanup:partial",
      withResult(OP_UI_DELETE_COMMITTED, { cleanup: "partial" }),
    ],
    [
      "E14 delete cleanup missing",
      withoutResultKey(OP_UI_DELETE_COMMITTED, "cleanup"),
    ],
    [
      "E15 delete target:mitm",
      withResult(OP_UI_DELETE_COMMITTED, { target: "mitm" }),
    ],
    [
      "E16 delete activation:immediate",
      withResult(OP_UI_DELETE_COMMITTED, { activation: "immediate" }),
    ],
  ];
  for (const [name, rec] of rows) {
    it(`refuses the record whole: ${name}`, () => {
      expect(() => decodeCertOperation(rec)).toThrow();
    });
  }

  it("K01 the builders' own records decode committed", () => {
    for (const rec of [
      OP_ROTATE_COMMITTED,
      OP_COMMITTED,
      OP_UI_REPLACE_COMMITTED,
      OP_UI_DELETE_COMMITTED,
    ]) {
      expect(decodeCertOperation(rec).state).toBe("committed");
    }
  });
  it("K02 delete cleanup:completed_at_settlement decodes", () => {
    expect(
      decodeCertOperation(
        withResult(OP_UI_DELETE_COMMITTED, {
          cleanup: "completed_at_settlement",
        }),
      ).state,
    ).toBe("committed");
  });
  it("K03 delete activation:restart_required decodes", () => {
    expect(
      decodeCertOperation(
        withResult(OP_UI_DELETE_COMMITTED, { activation: "restart_required" }),
      ).state,
    ).toBe("committed");
  });
  it("K04 rotate carrying target:mitm decodes", () => {
    expect(
      decodeCertOperation(withResult(OP_ROTATE_COMMITTED, { target: "mitm" }))
        .state,
    ).toBe("committed");
  });
});
