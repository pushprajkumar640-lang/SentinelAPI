import { defineConfig } from "drizzle-kit";
import * as dotenv from "dotenv";

dotenv.config();

const sqlHost = process.env.SQL_HOST;
const sqlDbName = process.env.SQL_DB_NAME;
const user = process.env.SQL_ADMIN_USER || process.env.SQL_USER;
const password = process.env.SQL_ADMIN_PASSWORD || process.env.SQL_PASSWORD;

const hasExternalDatabase = Boolean(sqlHost && sqlDbName && user && password);
const hasDatabaseUrl = Boolean(process.env.DATABASE_URL);

/**
 * `drizzle-kit generate` only needs the schema, so it works with no environment
 * variables. `drizzle-kit push` / `migrate` talk to a real database and require
 * SQL_HOST, SQL_DB_NAME, SQL_ADMIN_USER and SQL_ADMIN_PASSWORD to be set.
 */
export default defineConfig({
  schema: "./src/db/schema.ts",
  out: "./drizzle",
  dialect: "postgresql",
  schemaFilter: ["public"],
  ...(hasDatabaseUrl
    ? {
        dbCredentials: {
          url: process.env.DATABASE_URL!
        }
      }
    : hasExternalDatabase
    ? {
        dbCredentials: {
          host: sqlHost!,
          port: Number(process.env.SQL_PORT) || 5432,
          user: user!,
          password: password!,
          database: sqlDbName!,
          ssl: false,
        },
      }
    : {}),
  verbose: true,
});
