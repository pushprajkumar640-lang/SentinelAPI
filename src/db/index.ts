import { drizzle as drizzlePg } from 'drizzle-orm/node-postgres';
import { drizzle as drizzlePglite } from 'drizzle-orm/pglite';
import { PGlite } from '@electric-sql/pglite';
import { Pool } from 'pg';
import fs from 'fs';
import path from 'path';
import * as schema from './schema';

declare global {
  var _postgresPool: Pool | undefined;
  var _pgliteClient: PGlite | undefined;
}

/**
 * The app uses a real PostgreSQL / Cloud SQL instance when SQL_HOST is configured.
 * When it is not (local dev, demo, CI), it falls back to an embedded PGlite
 * PostgreSQL database stored inside node_modules/.cache so every API route keeps working
 * without any external service.
 */
export const isExternalPostgresConfigured = Boolean(process.env.SQL_HOST);

export const createPool = () => {
  if (!global._postgresPool) {
    global._postgresPool = new Pool({
      host: process.env.SQL_HOST,
      port: Number(process.env.SQL_PORT) || 5432,
      user: process.env.SQL_USER,
      password: process.env.SQL_PASSWORD,
      database: process.env.SQL_DB_NAME,
      max: 10,
      connectionTimeoutMillis: 15000,
    });

    global._postgresPool.on('error', (err) => {
      console.error('Unexpected error on idle SQL pool client:', err);
    });
  }
  return global._postgresPool;
};

function readMigrationSql(): string {
  const dir = path.resolve(process.cwd(), 'drizzle');
  if (!fs.existsSync(dir)) return '';
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .sort()
    .map((f) => fs.readFileSync(path.join(dir, f), 'utf-8'))
    .join('\n');
}

async function createEmbeddedDatabase() {
  if (!global._pgliteClient) {
    const dataDir =
      process.env.PGLITE_DATA_DIR ||
      path.resolve(process.cwd(), 'node_modules/.cache/sentinel-pglite');
    fs.mkdirSync(dataDir, { recursive: true });
    const client = new PGlite(dataDir);
    await client.waitReady;

    const sql = readMigrationSql();
    for (const statement of sql.split('--> statement-breakpoint')) {
      const trimmed = statement.trim();
      if (!trimmed) continue;
      try {
        await client.exec(trimmed);
      } catch (error: any) {
        // Tables/constraints already exist on a warm database - safe to ignore.
        if (!/already exists/i.test(String(error?.message))) {
          console.error('Embedded database setup statement failed:', error?.message);
        }
      }
    }

    global._pgliteClient = client;
    console.warn(
      '[SentinelAPI] SQL_HOST is not set - using the embedded PostgreSQL database'
    );
  }
  return global._pgliteClient;
}

export const db = isExternalPostgresConfigured
  ? drizzlePg(createPool(), { schema })
  : drizzlePglite(await createEmbeddedDatabase(), { schema });
