// Basit migration runner — db/migrations/*.sql dosyalarını sırayla çalıştırır.
// Faz 0 için yeterli; ileride migration takip tablosuna geçilebilir.
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import "dotenv/config";
import pg from "pg";

const __dirname = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(__dirname, "..", "db", "migrations");

const databaseUrl = process.env.DATABASE_URL ?? "postgres://catdef:catdef@localhost:5432/catdef";

const client = new pg.Client({ connectionString: databaseUrl });

async function main() {
  await client.connect();
  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();

  for (const file of files) {
    const sql = readFileSync(join(migrationsDir, file), "utf8");
    process.stdout.write(`→ ${file} ... `);
    await client.query(sql);
    process.stdout.write("ok\n");
  }
  console.log(`${files.length} migration uygulandı.`);
}

main()
  .catch((err) => {
    console.error("Migration hatası:", err);
    process.exitCode = 1;
  })
  .finally(() => client.end());
