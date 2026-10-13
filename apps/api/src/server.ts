import cors from "@fastify/cors";
import Fastify from "fastify";
import { config } from "./config.js";
import { closeDb } from "./db.js";
import { scanRoutes } from "./routes/scan.js";

const app = Fastify({
  logger: true,
  // Reverse proxy arkasında gerçek istemci IP'si için (rate limit doğruluğu).
  trustProxy: true,
});

await app.register(cors, { origin: config.webOrigin });

app.get("/health", async () => ({ ok: true }));

await app.register(scanRoutes);

async function shutdown() {
  app.log.info("kapanıyor...");
  await app.close();
  await closeDb();
  process.exit(0);
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

try {
  await app.listen({ port: config.port, host: "0.0.0.0" });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
