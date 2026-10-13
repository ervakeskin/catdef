import { config, SCAN_QUEUE_NAME } from "./config.js";
import { runScan } from "./runScan.js";
import { pool } from "./db.js";

/** Bir taramayı işler; hatayı yut (runScan başarısızlıkta status'ü zaten 'failed' yapar). */
async function handleScan(scanId: string, domain: string): Promise<void> {
  console.log(`[worker] tarama başladı: ${domain} (${scanId})`);
  try {
    await runScan(scanId, domain);
    console.log(`[worker] tarama bitti: ${domain} (${scanId})`);
  } catch (err) {
    console.error(
      `[worker] job başarısız (${scanId}):`,
      err instanceof Error ? err.message : String(err),
    );
  }
}

// ── Yerel mod: Redis yok, 'pending' taramaları DB'den poll ederek al ──────────
async function runLocalPoller(): Promise<void> {
  console.log("[worker] yerel mod (DB-polling), kuyruk yerine DB dinleniyor...");
  let stopped = false;
  process.on("SIGINT", async () => {
    console.log("[worker] kapanıyor...");
    stopped = true;
    await pool.end();
    process.exit(0);
  });
  process.on("SIGTERM", () => {
    stopped = true;
  });

  while (!stopped) {
    // Bir 'pending' taramayı atomik olarak sahiplen (çift işleme karşı SKIP LOCKED).
    const { rows } = await pool.query<{ id: string; domain: string }>(
      `UPDATE scans SET status='running', started_at=now()
         WHERE id = (
           SELECT id FROM scans
            WHERE status='pending'
            ORDER BY created_at
            LIMIT 1
            FOR UPDATE SKIP LOCKED
         )
       RETURNING id, domain`,
    );
    const job = rows[0];
    if (job) {
      await handleScan(job.id, job.domain);
    } else {
      await new Promise((r) => setTimeout(r, 500));
    }
  }
}

// ── Gerçek mod: BullMQ + Redis ────────────────────────────────────────────────
async function runBullWorker(): Promise<void> {
  const { Worker } = await import("bullmq");
  const { Redis } = await import("ioredis");
  const connection = new Redis(config.redisUrl, { maxRetriesPerRequest: null });

  const worker = new Worker<{ scanId: string; domain: string }>(
    SCAN_QUEUE_NAME,
    async (job) => {
      await handleScan(job.data.scanId, job.data.domain);
    },
    { connection, concurrency: 4 },
  );

  worker.on("failed", (job, err) => {
    console.error(`[worker] job başarısız (${job?.id}):`, err.message);
  });
  worker.on("ready", () => console.log("[worker] hazır, kuyruk dinleniyor..."));

  async function shutdown() {
    console.log("[worker] kapanıyor...");
    await worker.close();
    await connection.quit();
    process.exit(0);
  }
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

if (config.local) {
  await runLocalPoller();
} else {
  await runBullWorker();
}
