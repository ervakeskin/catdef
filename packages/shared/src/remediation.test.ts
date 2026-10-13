import assert from "node:assert/strict";
import { test } from "node:test";
import { FINDINGS_CATALOG } from "./findings-catalog.js";
import { PLATFORM_LABELS, REMEDIATION, getRemediation } from "./remediation.js";

const catalogCodes = Object.keys(FINDINGS_CATALOG);
const remediationCodes = Object.keys(REMEDIATION);

test("her katalog bulgusunun bir düzeltme rehberi var", () => {
  for (const code of catalogCodes) {
    assert.ok(getRemediation(code), `${code}: düzeltme rehberi eksik`);
  }
});

test("her düzeltme rehberi geçerli bir bulguya ait", () => {
  for (const code of remediationCodes) {
    assert.ok(FINDINGS_CATALOG[code], `${code}: karşılığı olmayan rehber`);
  }
});

test("her rehberde en az bir config ve bir verify var; platformlar bilinen", () => {
  for (const code of remediationCodes) {
    const g = REMEDIATION[code]!;
    const platforms = Object.keys(g.configs);
    assert.ok(platforms.length >= 1, `${code}: config yok`);
    for (const p of platforms) {
      assert.ok(p in PLATFORM_LABELS, `${code}: bilinmeyen platform ${p}`);
      assert.ok((g.configs as Record<string, string>)[p]!.trim().length > 0, `${code}/${p}: boş config`);
    }
    assert.ok(g.verify.trim().length > 0, `${code}: verify boş`);
  }
});

test("DNS bulguları dns platformunda, güvenlik başlıkları web platformlarında", () => {
  assert.ok(REMEDIATION.missing_spf!.configs.dns, "missing_spf dns config bekleniyor");
  assert.ok(REMEDIATION.missing_dmarc!.configs.dns, "missing_dmarc dns config bekleniyor");
  assert.ok(REMEDIATION.missing_hsts!.configs.nginx, "missing_hsts nginx config bekleniyor");
});
