// CatDef — toplu ölçüm betiği (Faz 5).
//
// AMAÇ: verilen alan adı listesini tarayıp YALNIZCA toplu, ANONİM istatistik
// üretmek (ör. "sitelerin %X'inde HSTS yok"). Çıktıda TEK BİR site adı bile
// yer almaz; sadece oranlar ve sayımlar yazılır.
//
// ETİK / SINIRLAR (bkz. docs/MEASUREMENT.md):
//   - Yalnızca herkese açık, PASİF istekler (kök sayfaya tek GET + DNS sorgusu).
//     Zafiyet sömürülmez, yük bindirilmez.
//   - Varsayılan olarak istekler arası gecikme (politeness) uygulanır.
//   - SSRF guard her hedefte çalışır; iç/özel adresler atlanır.
//   - Alan adı listesini SİZ sağlarsınız; betik hiçbir liste gömmez.
//   - Sonuç dosyasında site adı TUTULMAZ.
//
// KULLANIM:
//   node --import tsx apps/worker/src/measure.ts <domains.txt> [--delay=1000] [--limit=N]
//
// NOT: Bu betiği proje sahibi çalıştırır. Taranan sitelerin kullanım koşullarına
// (ToS) ve makul hıza uyun; yalnızca ölçmeye izinli/kamuya açık sitelerde kullanın.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { ModuleResult } from "@catdef/shared";
import { computeModuleScore, computeTotalScore } from "@catdef/shared";
import { normalizeDomain, resolveAndGuard } from "@catdef/shared/net-guard";
import { runDns } from "./modules/dns.js";
import { runHeaderTls } from "./modules/headerTls.js";

interface Args {
  file: string;
  delayMs: number;
  limit: number;
}

function parseArgs(argv: string[]): Args | null {
  const positional = argv.filter((a) => !a.startsWith("--"));
  const file = positional[0];
  if (!file) return null;
  const getOpt = (name: string, def: number) => {
    const hit = argv.find((a) => a.startsWith(`--${name}=`));
    if (!hit) return def;
    const n = Number(hit.split("=")[1]);
    return Number.isFinite(n) ? n : def;
  };
  return { file, delayMs: getOpt("delay", 1000), limit: getOpt("limit", Infinity) };
}

function usage(): void {
  console.error(
    [
      "CatDef toplu ölçüm — yalnızca toplu/anonim istatistik üretir.",
      "",
      "Kullanım:",
      "  node --import tsx apps/worker/src/measure.ts <domains.txt> [--delay=1000] [--limit=N]",
      "",
      "  <domains.txt>  Satır başına bir alan adı (listeyi SİZ sağlarsınız).",
      "  --delay=MS     İstekler arası gecikme (varsayılan 1000ms, politeness).",
      "  --limit=N      En fazla N alan adı tara.",
      "",
      "Etik: yalnızca herkese açık, pasif istekler; ToS'a ve makul hıza uyun.",
      "Çıktı: measurement-results/ altında site adı İÇERMEYEN toplu JSON + özet.",
    ].join("\n"),
  );
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function scoreDomain(
  domain: string,
): Promise<{ grade: string | null; codes: string[]; moduleFail: string[] } | null> {
  const guard = await resolveAndGuard(domain);
  if (!guard.ok) return null; // geçersiz/özel/çözülemeyen → ölçümden hariç

  const modules: ModuleResult[] = await Promise.all([
    runHeaderTls(domain).catch(
      (): ModuleResult => ({ moduleType: "header_tls", status: "failed", findings: [], rawData: {} }),
    ),
    runDns(domain).catch(
      (): ModuleResult => ({ moduleType: "dns", status: "failed", findings: [], rawData: {} }),
    ),
  ]);

  const scored = modules.map((m) => (m.status === "completed" ? computeModuleScore(m) : m));
  const { grade } = computeTotalScore(scored);
  const codes = scored.flatMap((m) => m.findings.map((f) => f.findingCode));
  const moduleFail = modules.filter((m) => m.status === "failed").map((m) => m.moduleType);
  return { grade, codes, moduleFail };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (!args) {
    usage();
    process.exit(1);
  }

  const domains = [
    ...new Set(
      readFileSync(args.file, "utf8")
        .split(/\r?\n/)
        .map((l) => normalizeDomain(l.trim()))
        .filter((l) => l.length > 0 && !l.startsWith("#")),
    ),
  ].slice(0, args.limit);

  console.error(`${domains.length} alan adı taranacak (gecikme ${args.delayMs}ms). Yalnızca toplu istatistik tutulacak.`);

  const gradeDist: Record<string, number> = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  const findingCounts: Record<string, number> = {};
  const moduleFailCounts: Record<string, number> = {};
  let scanned = 0;
  let skipped = 0;

  for (let i = 0; i < domains.length; i++) {
    const result = await scoreDomain(domains[i]!);
    if (!result) {
      skipped++;
    } else {
      scanned++;
      if (result.grade) gradeDist[result.grade] = (gradeDist[result.grade] ?? 0) + 1;
      for (const c of new Set(result.codes)) findingCounts[c] = (findingCounts[c] ?? 0) + 1;
      for (const m of result.moduleFail) moduleFailCounts[m] = (moduleFailCounts[m] ?? 0) + 1;
    }
    // İlerleme: yalnızca sayaç, site adı YOK.
    process.stderr.write(`\r[${i + 1}/${domains.length}] tarandı:${scanned} atlandı:${skipped}   `);
    if (i < domains.length - 1) await sleep(args.delayMs);
  }
  process.stderr.write("\n");

  const pct = (n: number) => (scanned ? Math.round((n / scanned) * 1000) / 10 : 0);
  const findingRates = Object.fromEntries(
    Object.entries(findingCounts)
      .sort((a, b) => b[1] - a[1])
      .map(([code, count]) => [code, { count, percentOfScanned: pct(count) }]),
  );

  const report = {
    generatedAt: new Date().toISOString(),
    note: "Toplu ve anonim — tek tek site adı içermez.",
    totalInput: domains.length,
    scanned,
    skipped, // geçersiz/özel/çözülemeyen (SSRF guard dahil)
    gradeDistribution: gradeDist,
    gradeDistributionPercent: Object.fromEntries(
      Object.entries(gradeDist).map(([g, n]) => [g, pct(n)]),
    ),
    findingRates,
    moduleFailures: moduleFailCounts,
  };

  const outDir = join(process.cwd(), "measurement-results");
  mkdirSync(outDir, { recursive: true });
  const outFile = join(outDir, `summary-${Date.now()}.json`);
  writeFileSync(outFile, JSON.stringify(report, null, 2), "utf8");

  console.error("\n=== TOPLU SONUÇ (anonim) ===");
  console.error(`Taranan: ${scanned} · Atlanan: ${skipped} · Toplam girdi: ${domains.length}`);
  console.error("Not dağılımı:", report.gradeDistributionPercent);
  console.error("En sık bulgular (% taranan):");
  for (const [code, v] of Object.entries(findingRates)) {
    console.error(`  ${code}: %${(v as { percentOfScanned: number }).percentOfScanned}`);
  }
  console.error(`\nJSON: ${outFile}`);
}

main().catch((err) => {
  console.error("Ölçüm hatası:", err);
  process.exit(1);
});
