import type { ModuleResult, ModuleType } from "@catdef/shared";
import { computeModuleScore, computeTotalScore } from "@catdef/shared";
import { guardDomain } from "@catdef/shared/net-guard";
import { pool } from "./db.js";
import { runDns } from "./modules/dns.js";
import { runHeaderTls } from "./modules/headerTls.js";

/** Bir modülü çalıştırır; hata verirse 'failed' ModuleResult'a çevirir (biri diğerini etkilemesin). */
async function safeRun(
  moduleType: ModuleType,
  fn: (domain: string) => Promise<ModuleResult>,
  domain: string,
): Promise<ModuleResult> {
  try {
    return await fn(domain);
  } catch (err) {
    return {
      moduleType,
      status: "failed",
      findings: [],
      rawData: { error: err instanceof Error ? err.message : String(err) },
    };
  }
}

export async function runScan(scanId: string, domain: string): Promise<void> {
  // Belt-and-suspenders SSRF guard (API'de de kontrol edildi).
  const guard = await guardDomain(domain);
  if (!guard.ok) {
    await pool.query(
      `INSERT INTO audit_log (ip, action, domain, detail)
       SELECT requester_ip, 'scan_blocked', domain, $2 FROM scans WHERE id = $1`,
      [scanId, guard.reason],
    );
    await pool.query(
      `UPDATE scans SET status='failed', error=$2, completed_at=now() WHERE id=$1`,
      [scanId, `guard:${guard.reason}`],
    );
    return;
  }

  await pool.query(`UPDATE scans SET status='running', started_at=now() WHERE id=$1`, [scanId]);

  // Modülleri paralel çalıştır — biri hata verse diğerleri etkilenmez.
  const modules = await Promise.all([
    safeRun("header_tls", runHeaderTls, domain),
    safeRun("dns", runDns, domain),
  ]);

  // Skorla (yalnızca completed modüller puanlanır ve normalize edilir).
  const scored = modules.map((m) =>
    m.status === "completed" ? computeModuleScore(m) : m,
  );
  const { score, grade } = computeTotalScore(scored);

  // DB yazımı — tek transaction.
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    for (const m of scored) {
      await client.query(
        `INSERT INTO scan_modules (scan_id, module_type, status, module_score, raw_data, completed_at)
         VALUES ($1, $2, $3, $4, $5, now())`,
        [scanId, m.moduleType, m.status, m.moduleScore ?? null, JSON.stringify(m.rawData)],
      );

      for (const f of m.findings) {
        await client.query(
          `INSERT INTO findings
             (scan_id, module_type, finding_code, severity, title, description,
              plain_explanation, evidence, points_deducted)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [
            scanId,
            f.moduleType,
            f.findingCode,
            f.severity,
            f.title,
            f.description,
            f.plainExplanation,
            f.evidence ?? null,
            f.pointsDeducted,
          ],
        );
      }
    }

    await client.query(
      `UPDATE scans SET status='completed', score=$2, grade=$3, completed_at=now() WHERE id=$1`,
      [scanId, score, grade],
    );

    await client.query(
      `INSERT INTO domain_cache (domain, latest_scan_id, last_scanned_at)
       VALUES ($1, $2, now())
       ON CONFLICT (domain) DO UPDATE
         SET latest_scan_id = EXCLUDED.latest_scan_id,
             last_scanned_at = EXCLUDED.last_scanned_at`,
      [domain, scanId],
    );

    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    await pool.query(
      `UPDATE scans SET status='failed', error=$2, completed_at=now() WHERE id=$1`,
      [scanId, err instanceof Error ? err.message : String(err)],
    );
    throw err;
  } finally {
    client.release();
  }
}
