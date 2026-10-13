import "dotenv/config";

function num(name: string, fallback: number): number {
  const v = process.env[name];
  const n = v ? Number(v) : NaN;
  return Number.isFinite(n) ? n : fallback;
}

export const config = {
  port: num("API_PORT", 3001),
  databaseUrl: process.env.DATABASE_URL ?? "postgres://catdef:catdef@localhost:5432/catdef",
  redisUrl: process.env.REDIS_URL ?? "redis://localhost:6379",
  rateLimitPerDay: num("RATE_LIMIT_PER_DAY", 5),
  cacheTtlHours: num("CACHE_TTL_HOURS", 24),
  webOrigin: process.env.WEB_ORIGIN ?? "http://localhost:3000",
  // Yerel mod: Redis/BullMQ yerine DB-polling (Docker/Redis gerektirmez).
  // scripts/dev-local.mjs bu bayrağı set eder.
  local: process.env.CATDEF_LOCAL === "1",
} as const;

/** BullMQ kuyruğunun adı — api (producer) ve worker (consumer) aynı adı kullanır. */
export const SCAN_QUEUE_NAME = "scan";
