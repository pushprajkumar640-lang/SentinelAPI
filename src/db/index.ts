import { drizzle as drizzlePg } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import * as schema from './schema';

declare global {
  var _postgresPool: Pool | undefined;
}

/**
 * Production and development use Supabase or another PostgreSQL instance.
 * There is no in-memory or embedded database fallback.
 */
export const isExternalPostgresConfigured = Boolean(process.env.DATABASE_URL);

export const createPool = () => {
  if (!global._postgresPool) {
    global._postgresPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_URL?.includes('supabase') ? { rejectUnauthorized: false } : undefined,
      max: 10,
      connectionTimeoutMillis: 15000,
    });

    global._postgresPool.on('error', (err) => {
      console.error('Unexpected error on idle SQL pool client:', err);
    });
  }
  return global._postgresPool;
};

export const db = drizzlePg(
  isExternalPostgresConfigured
    ? createPool()
    : new Pool({ connectionString: 'postgresql://database-not-configured' }),
  { schema }
);

export async function verifyDatabase() {
  if (!isExternalPostgresConfigured) {
    return { configured: false, connected: false, usersTable: false };
  }

  try {
    const result = await createPool().query("select to_regclass('public.users') as users_table");
    return {
      configured: true,
      connected: true,
      usersTable: Boolean(result.rows[0]?.users_table)
    };
  } catch {
    return {
      configured: isExternalPostgresConfigured,
      connected: false,
      usersTable: false
    };
  }
}
