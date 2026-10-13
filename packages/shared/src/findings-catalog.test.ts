import assert from "node:assert/strict";
import { test } from "node:test";
import { FINDINGS_CATALOG, findingMeta, makeFinding } from "./findings-catalog.js";

const codes = Object.keys(FINDINGS_CATALOG);

test("katalog boş değil", () => {
  assert.ok(codes.length >= 13, `beklenen >=13, bulunan ${codes.length}`);
});

test("her bulguda eksiksiz standart eşlemesi ve metinler var", () => {
  for (const code of codes) {
    const def = FINDINGS_CATALOG[code]!;
    assert.ok(def.whyItMatters.trim().length > 0, `${code}: whyItMatters boş`);
    assert.ok(def.falsePositiveNote.trim().length > 0, `${code}: falsePositiveNote boş`);
    assert.ok(def.standards, `${code}: standards yok`);
    // OWASP 2025 / 2021 biçimi: "A0X:YYYY ..."
    assert.match(
      def.standards.owaspTop10_2025,
      /^A\d{2}:2025 .+/,
      `${code}: owaspTop10_2025 biçimi hatalı (${def.standards.owaspTop10_2025})`,
    );
    assert.match(
      def.standards.owaspTop10_2021,
      /^A\d{2}:2021 .+/,
      `${code}: owaspTop10_2021 biçimi hatalı (${def.standards.owaspTop10_2021})`,
    );
    // CWE biçimi: "CWE-123: ..."
    assert.match(
      def.standards.cwe,
      /^CWE-\d+: .+/,
      `${code}: cwe biçimi hatalı (${def.standards.cwe})`,
    );
    // ASVS varsa 5.0 bölümüne atıf yapmalı.
    if (def.standards.asvs) {
      assert.match(def.standards.asvs, /^ASVS 5\.0 V\d+/, `${code}: asvs biçimi hatalı`);
    }
  }
});

test("makeFinding standart eşlemelerini taşır", () => {
  const f = makeFinding("missing_hsts");
  assert.equal(f.findingCode, "missing_hsts");
  assert.ok(f.standards?.cwe.startsWith("CWE-"));
  assert.ok(f.whyItMatters && f.whyItMatters.length > 0);
  assert.ok(f.falsePositiveNote && f.falsePositiveNote.length > 0);
});

test("makeFinding bilinmeyen kod için hata verir", () => {
  assert.throws(() => makeFinding("bilinmeyen_kod"));
});

test("findingMeta bilinen kodda meta, bilinmeyende null döner", () => {
  assert.ok(findingMeta("no_https"));
  assert.equal(findingMeta("yok_boyle_bir_kod"), null);
});
