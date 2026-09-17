// FE-6A.2 CORRECTION ROUND 5 RED — API/decoding half, written against the
// frozen corrected candidate a56ac527 BEFORE any product change (Blocker 1:
// a `legacy_ldap_retired` sentinel WITHOUT its record is degraded recovery
// evidence, never healthy truth — the read model reports it with the
// explicit bounded word `record_missing`).
//
//   DA1  `cutoverDurability: "record_missing"` is a contracted, decodable
//        word (absent and present blocks alike), carried without a cutover
//        record; the enum lists exactly the four bounded words.
//   DA2  (control) an unknown durability word is still refused; the three
//        existing words still decode.
//
// On a56ac527 DA1 fails (the decoder refuses `record_missing`); DA2 passes.
import { describe, expect, it } from "vitest";
import { DecodeError } from "../api/decode";
import { LEGACY_CUTOVER_DURABILITY, decodeLegacyLDAP } from "../api/idp";
import { LEGACY_PRESENT } from "./fe6a2-fixtures";

describe("DA1 record_missing is a contracted durability word", () => {
  it("decodes an absent block reporting record_missing without a record", () => {
    const l = decodeLegacyLDAP({
      present: false,
      retired: true,
      scope: "node-local",
      cutoverDurability: "record_missing",
    });
    expect(l.retired).toBe(true);
    expect(l.cutoverDurability).toBe("record_missing");
    expect(l.cutover).toBeUndefined();
  });
  it("decodes a present block reporting record_missing without a record", () => {
    const l = decodeLegacyLDAP({
      ...LEGACY_PRESENT,
      retired: true,
      shadowed: true,
      cutoverDurability: "record_missing",
    });
    expect(l.retired).toBe(true);
    expect(l.cutoverDurability).toBe("record_missing");
    expect(l.cutover).toBeUndefined();
  });
  it("the bounded enum carries exactly the four words", () => {
    expect([...LEGACY_CUTOVER_DURABILITY].sort()).toEqual(
      [
        "durable",
        "not_retired",
        "pending_reconciliation",
        "record_missing",
      ].sort(),
    );
  });
});

describe("DA2 control", () => {
  it("still refuses an unknown durability word and decodes the three existing ones", () => {
    const base = {
      present: false,
      retired: false,
      scope: "node-local",
    };
    expect(() =>
      decodeLegacyLDAP({ ...base, cutoverDurability: "durable_maybe" }),
    ).toThrow(DecodeError);
    expect(() => decodeLegacyLDAP({ ...base, cutoverDurability: "" })).toThrow(
      DecodeError,
    );
    for (const w of ["not_retired", "durable", "pending_reconciliation"]) {
      expect(
        decodeLegacyLDAP({ ...base, cutoverDurability: w }).cutoverDurability,
      ).toBe(w);
    }
  });
});
