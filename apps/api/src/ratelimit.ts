import { pool } from "./db.js";
import { config } from "./config.js";

/** audit_log'a bir olay yazar (yasal koruma + rate limit kaynağı). */
export async function logAudit(
  ip: string,
  action: string,
  domain: string | null,
  detail?: string,
): Promise<void> {
  await pool.query(
    `INSERT INTO audit_log (ip, action, domain, detail) VALUES ($1, $2, $3, $4)`,
    [ip, action, domain, detail ?? null],
  );
}

/**
 * IP'nin son 24 saatte başlattığı tarama sayısını sayar ve limiti aşıp
 * aşmadığını döner. Sayım audit_log'daki 'scan_requested' olaylarına dayanır.
 */
export async function isRateLimited(ip: string): Promise<boolean> {
  const { rows } = await pool.query<{ count: string }>(
    `SELECT COUNT(*)::text AS count
       FROM audit_log
      WHERE ip = $1
        AND action = 'scan_requested'
        AND created_at > now() - interval '24 hours'`,
    [ip],
  );
  const count = Number(rows[0]?.count ?? "0");
  return count >= config.rateLimitPerDay;
}
