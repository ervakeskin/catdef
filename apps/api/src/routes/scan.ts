import type { FastifyInstance } from "fastify";
import type { Grade, ModuleStatus, ModuleType, ScanResult, Severity } from "@catdef/shared";
import { findingMeta } from "@catdef/shared";
import { guardDomain, isValidDomain, normalizeDomain } from "@catdef/shared/net-guard";
import { pool } from "../db.js";
import { config } from "../config.js";
import { enqueueScan } from "../queue.js";
import { isRateLimited, logAudit } from "../ratelimit.js";

const GUARD_MESSAGES: Record<string, string> = {
  invalid_domain: "Geçersiz alan adı. Örnek: example.com",
  resolve_failed: "Alan adı çözümlenemedi (DNS bulunamadı).",
  private_ip: "Bu alan adı iç/özel bir IP'ye işaret ediyor; güvenlik nedeniyle taranamaz.",
};

export async function scanRoutes(app: FastifyInstance): Promise<void> {
  // Yeni tarama başlat
  app.post<{ Body: { domain?: string } }>("/scan", async (req, reply) => {
    const ip = req.ip;
    const raw = req.body?.domain ?? "";
    const domain = normalizeDomain(raw);

    if (!isValidDomain(domain)) {
      return reply.code(400).send({ error: GUARD_MESSAGES.invalid_domain });
    }

    // 1) SSRF/private-IP koruması
    const guard = await guardDomain(domain);
    if (!guard.ok) {
      await logAudit(ip, "scan_blocked", domain, guard.reason);
      return reply.code(400).send({ error: GUARD_MESSAGES[guard.reason ?? "invalid_domain"] });
    }

    // 2) Cache kontrolü (24 saat)
    const cached = await pool.query<{ latest_scan_id: string }>(
      `SELECT latest_scan_id
         FROM domain_cache
        WHERE domain = $1
          AND last_scanned_at > now() - ($2 || ' hours')::interval
          AND latest_scan_id IS NOT NULL`,
      [domain, String(config.cacheTtlHours)],
    );
    if (cached.rows[0]?.latest_scan_id) {
      await logAudit(ip, "cache_hit", domain);
      return reply.send({ scanId: cached.rows[0].latest_scan_id, cached: true });
    }

    // 3) Rate limit (IP başına günlük)
    if (await isRateLimited(ip)) {
      await logAudit(ip, "rate_limited", domain);
      return reply
        .code(429)
        .send({ error: `Günlük tarama limitine ulaştınız (${config.rateLimitPerDay}/gün).` });
    }

    // 4) Tarama kaydı + kuyruğa ekleme
    const inserted = await pool.query<{ id: string }>(
      `INSERT INTO scans (domain, requester_ip, status) VALUES ($1, $2, 'pending') RETURNING id`,
      [domain, ip],
    );
    const scanId = inserted.rows[0]!.id;

    await logAudit(ip, "scan_requested", domain);
    await enqueueScan({ scanId, domain });

    return reply.code(202).send({ scanId, cached: false });
  });

  // Tarama durumu / sonucu
  app.get<{ Params: { id: string } }>("/scan/:id", async (req, reply) => {
    const { id } = req.params;

    const scanRes = await pool.query<{
      id: string;
      domain: string;
      status: string;
      score: number | null;
      grade: string | null;
      created_at: Date;
      completed_at: Date | null;
    }>(
      `SELECT id, domain, status, score, grade, created_at, completed_at
         FROM scans WHERE id = $1`,
      [id],
    );
    const scan = scanRes.rows[0];
    if (!scan) {
      return reply.code(404).send({ error: "Tarama bulunamadı." });
    }

    const modulesRes = await pool.query<{
      module_type: ModuleType;
      status: string;
      module_score: number | null;
      raw_data: Record<string, unknown> | null;
    }>(
      `SELECT module_type, status, module_score, raw_data
         FROM scan_modules WHERE scan_id = $1 ORDER BY module_type`,
      [id],
    );

    const findingsRes = await pool.query<{
      module_type: ModuleType;
      finding_code: string;
      severity: Severity;
      title: string;
      description: string | null;
      plain_explanation: string | null;
      evidence: string | null;
      points_deducted: number;
    }>(
      `SELECT module_type, finding_code, severity, title, description,
              plain_explanation, evidence, points_deducted
         FROM findings WHERE scan_id = $1`,
      [id],
    );

    const result: ScanResult = {
      id: scan.id,
      domain: scan.domain,
      status: scan.status as ScanResult["status"],
      score: scan.score,
      grade: (scan.grade as Grade | null) ?? null,
      createdAt: scan.created_at.toISOString(),
      completedAt: scan.completed_at ? scan.completed_at.toISOString() : null,
      modules: modulesRes.rows.map((m) => ({
        moduleType: m.module_type,
        status: m.status as ModuleStatus,
        moduleScore: m.module_score ?? undefined,
        findings: [],
        rawData: m.raw_data ?? {},
      })),
      findings: findingsRes.rows.map((f) => {
        // Standart eşlemeleri DB'de saklanmaz; katalogdan yanıt anında eklenir.
        const meta = findingMeta(f.finding_code);
        return {
          moduleType: f.module_type,
          findingCode: f.finding_code,
          severity: f.severity,
          title: f.title,
          description: f.description ?? "",
          plainExplanation: f.plain_explanation ?? "",
          whyItMatters: meta?.whyItMatters,
          falsePositiveNote: meta?.falsePositiveNote,
          standards: meta?.standards,
          evidence: f.evidence ?? undefined,
          pointsDeducted: f.points_deducted,
        };
      }),
    };

    return reply.send(result);
  });
}
