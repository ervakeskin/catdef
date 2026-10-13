// Sıfır-kurulum yerel geliştirme orkestratörü.
// Docker / harici Postgres / Redis GEREKTİRMEZ:
//   1) embedded-postgres ile gerçek bir Postgres cluster'ı başlatır (ilk çalıştırmada indirilen binary),
//   2) db/migrations/*.sql migration'larını uygular,
//   3) api + worker + web'i CATDEF_LOCAL=1 ile başlatır (worker Redis yerine DB'yi poll eder).
// Ctrl+C hepsini düzgünce kapatır.
import { spawn } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import EmbeddedPostgres from "embedded-postgres";
import pg from "pg";

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, "..");
const dataDir = join(rootDir, ".devdata", "pgdata");
const migrationsDir = join(rootDir, "db", "migrations");

const PG = {
  host: "127.0.0.1",
  port: 5432,
  user: "catdef",
  password: "catdef",
  database: "catdef",
};
const DATABASE_URL = `postgres://${PG.user}:${PG.password}@${PG.host}:${PG.port}/${PG.database}`;

const isWin = process.platform === "win32";
const children = [];
let pgServer = null;
let shuttingDown = false;

function log(msg) {
  console.log(`\x1b[36m[dev-local]\x1b[0m ${msg}`);
}

async function startPostgres() {
  pgServer = new EmbeddedPostgres({
    databaseDir: dataDir,
    user: PG.user,
    password: PG.password,
    port: PG.port,
    persistent: true,
    // initdb, non-ASCII sistem locale'ini (ör. "Turkish_Türkiye.1254") reddeder;
    // deterministik olması için C-locale + UTF8 ile başlat.
    initdbFlags: ["--encoding=UTF8", "--no-locale"],
    onLog: () => {}, // gürültüyü bastır; hata yine de onError'a düşer
    onError: (e) => console.error("[postgres]", e instanceof Error ? e.message : e),
  });

  // İlk çalıştırmada cluster'ı oluştur (PG_VERSION yoksa henüz initialise edilmemiştir).
  if (!existsSync(join(dataDir, "PG_VERSION"))) {
    log("Postgres cluster'ı oluşturuluyor (ilk çalıştırma)...");
    await pgServer.initialise();
  }
  log("Postgres başlatılıyor...");
  await pgServer.start();

  // Uygulama veritabanını oluştur (varsa yok say).
  try {
    await pgServer.createDatabase(PG.database);
    log(`'${PG.database}' veritabanı oluşturuldu.`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (!/already exists/i.test(msg)) throw err;
  }
}

async function runMigrations() {
  const client = new pg.Client({ connectionString: DATABASE_URL });
  await client.connect();
  try {
    const files = readdirSync(migrationsDir)
      .filter((f) => f.endsWith(".sql"))
      .sort();
    for (const file of files) {
      const sql = readFileSync(join(migrationsDir, file), "utf8");
      await client.query(sql);
      log(`migration uygulandı: ${file}`);
    }
  } finally {
    await client.end();
  }
}

function startApp(label, filter) {
  const env = {
    ...process.env,
    DATABASE_URL,
    CATDEF_LOCAL: "1",
    API_PORT: "3001",
    WEB_ORIGIN: "http://localhost:3000",
    NEXT_PUBLIC_API_URL: "http://localhost:3001",
  };
  const child = spawn("pnpm", ["--filter", filter, "dev"], {
    cwd: rootDir,
    env,
    stdio: "inherit",
    shell: true,
  });
  child.on("exit", (code) => {
    if (!shuttingDown) {
      log(`${label} beklenmedik şekilde durdu (code ${code}). Kapatılıyor...`);
      shutdown(1);
    }
  });
  children.push(child);
  return child;
}

async function shutdown(code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  log("kapatılıyor...");
  for (const child of children) {
    if (child.pid == null) continue;
    try {
      if (isWin) {
        // Windows'ta pnpm/shell alt ağacını komple sonlandır.
        spawn("taskkill", ["/pid", String(child.pid), "/t", "/f"], { stdio: "ignore" });
      } else {
        child.kill("SIGTERM");
      }
    } catch {
      /* yut */
    }
  }
  try {
    if (pgServer) await pgServer.stop();
  } catch {
    /* yut */
  }
  process.exit(code);
}

process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));

try {
  await startPostgres();
  await runMigrations();
  log("altyapı hazır. Uygulamalar başlatılıyor...");
  startApp("api", "@catdef/api");
  startApp("worker", "@catdef/worker");
  startApp("web", "@catdef/web");
  log("");
  log("  Web:  http://localhost:3000");
  log("  API:  http://localhost:3001/health");
  log("  Durdurmak için Ctrl+C");
} catch (err) {
  console.error("[dev-local] başlatma hatası:", err);
  await shutdown(1);
}
