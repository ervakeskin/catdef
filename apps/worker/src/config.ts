import "dotenv/config";

export const config = {
  databaseUrl: process.env.DATABASE_URL ?? "postgres://catdef:catdef@localhost:5432/catdef",
  redisUrl: process.env.REDIS_URL ?? "redis://localhost:6379",
  userAgent:
    process.env.SCANNER_USER_AGENT ?? "CatDefBot/0.1 (+https://catdef.example/about-bot)",
  // Yerel mod: Redis/BullMQ yerine DB-polling (Docker/Redis gerektirmez).
  local: process.env.CATDEF_LOCAL === "1",
} as const;

export const SCAN_QUEUE_NAME = "scan";
