import { Queue } from "bullmq";
import { Redis } from "ioredis";
import { config, SCAN_QUEUE_NAME } from "./config.js";

export interface ScanJobData {
  scanId: string;
  domain: string;
}

// Yerel modda Redis/BullMQ yoktur: tarama kaydı 'pending' durumunda kalır ve
// worker DB'yi poll ederek işi alır. Bu yüzden bağlantıyı tembel (lazy) kurup
// yalnızca gerçek (Redis'li) modda oluşturuyoruz — import anında bağlanmasın.
let scanQueue: Queue<ScanJobData> | null = null;

function getQueue(): Queue<ScanJobData> {
  if (!scanQueue) {
    // BullMQ, bloklayan komutlar için maxRetriesPerRequest=null ister.
    const connection = new Redis(config.redisUrl, { maxRetriesPerRequest: null });
    scanQueue = new Queue<ScanJobData>(SCAN_QUEUE_NAME, { connection });
  }
  return scanQueue;
}

export async function enqueueScan(data: ScanJobData): Promise<void> {
  if (config.local) {
    // Kuyruğa gerek yok — worker 'pending' taramaları DB'den alır.
    return;
  }
  await getQueue().add("scan", data, {
    attempts: 2,
    backoff: { type: "exponential", delay: 2000 },
    removeOnComplete: 1000,
    removeOnFail: 1000,
  });
}
