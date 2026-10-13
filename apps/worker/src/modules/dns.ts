import { resolve4, resolveCname, resolveTxt } from "node:dns/promises";
import type { Finding, ModuleResult } from "@catdef/shared";
import { makeFinding } from "@catdef/shared";

async function txtRecords(name: string): Promise<string[]> {
  try {
    const records = await resolveTxt(name);
    // Her kayıt string dizisi (chunk) olarak gelir → birleştir.
    return records.map((chunks) => chunks.join(""));
  } catch {
    return [];
  }
}

/** Bir CNAME hedefinin çözülüp çözülmediğini kontrol eder (dangling tespiti). */
async function isDangling(name: string): Promise<{ dangling: boolean; target?: string }> {
  try {
    const targets = await resolveCname(name);
    const target = targets[0];
    if (!target) return { dangling: false };
    try {
      const addrs = await resolve4(target);
      return { dangling: addrs.length === 0, target };
    } catch {
      // CNAME var ama hedef A kaydı yok → sahipsiz olabilir.
      return { dangling: true, target };
    }
  } catch {
    return { dangling: false };
  }
}

export async function runDns(domain: string): Promise<ModuleResult> {
  const findings: Finding[] = [];
  const rawData: Record<string, unknown> = {};

  // SPF
  const apexTxt = await txtRecords(domain);
  const hasSpf = apexTxt.some((r) => r.toLowerCase().startsWith("v=spf1"));
  rawData.txt = apexTxt;
  rawData.hasSpf = hasSpf;
  if (!hasSpf) findings.push(makeFinding("missing_spf"));

  // DMARC
  const dmarcTxt = await txtRecords(`_dmarc.${domain}`);
  const hasDmarc = dmarcTxt.some((r) => r.toLowerCase().startsWith("v=dmarc1"));
  rawData.hasDmarc = hasDmarc;
  if (!hasDmarc) findings.push(makeFinding("missing_dmarc"));

  // Dangling CNAME (www alt alan adı üzerinden temel sinyal)
  const wwwCname = await isDangling(`www.${domain}`);
  rawData.wwwCname = wwwCname;
  if (wwwCname.dangling) {
    findings.push(
      makeFinding("dangling_cname", {
        evidence: `www.${domain} → ${wwwCname.target ?? "?"} (çözülemedi)`,
      }),
    );
  }

  return { moduleType: "dns", status: "completed", findings, rawData };
}
