import assert from "node:assert/strict";
import { test } from "node:test";
import { makeFinding } from "./findings-catalog.js";
import {
  CATEGORY_WEIGHTS,
  computeModuleScore,
  computeTotalScore,
  scoreToGrade,
} from "./scoring.js";
import type { ModuleResult } from "./types.js";

function moduleWith(
  moduleType: ModuleResult["moduleType"],
  codes: string[],
): ModuleResult {
  return {
    moduleType,
    status: "completed",
    findings: codes.map((c) => makeFinding(c)),
    rawData: {},
  };
}

test("scoreToGrade eşikleri", () => {
  assert.equal(scoreToGrade(100), "A");
  assert.equal(scoreToGrade(90), "A");
  assert.equal(scoreToGrade(89), "B");
  assert.equal(scoreToGrade(75), "B");
  assert.equal(scoreToGrade(60), "C");
  assert.equal(scoreToGrade(40), "D");
  assert.equal(scoreToGrade(39), "F");
});

test("bulgusuz modül tam puan alır", () => {
  const m = computeModuleScore(moduleWith("header_tls", []));
  assert.equal(m.moduleScore, CATEGORY_WEIGHTS.header_tls);
});

test("tek kritik bulgu kategoriyi en az %60 düşürür", () => {
  const m = computeModuleScore(moduleWith("header_tls", ["tls_cert_expired"]));
  const weight = CATEGORY_WEIGHTS.header_tls;
  const dropRatio = (weight - (m.moduleScore ?? 0)) / weight;
  assert.ok(dropRatio >= 0.6, `düşüş oranı ${dropRatio} < 0.6`);
});

test("kategori puanı 0'ın altına inmez", () => {
  const m = computeModuleScore(
    moduleWith("header_tls", ["tls_cert_expired", "missing_hsts", "missing_csp"]),
  );
  assert.ok((m.moduleScore ?? -1) >= 0);
});

test("toplam skor çalışan modüllere göre normalize edilir", () => {
  // Temiz iki modül → 100/A
  const clean = [
    computeModuleScore(moduleWith("header_tls", [])),
    computeModuleScore(moduleWith("dns", [])),
  ];
  assert.deepEqual(computeTotalScore(clean), { score: 100, grade: "A" });
});

test("hiç modül çalışmazsa skor null", () => {
  assert.deepEqual(computeTotalScore([]), { score: null, grade: null });
});
