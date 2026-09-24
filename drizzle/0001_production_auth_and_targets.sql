ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "password_hash" text;
--> statement-breakpoint
ALTER TABLE "projects" ADD COLUMN IF NOT EXISTS "api_url" text;
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS "users_email_unique" ON "users" ("email");
--> statement-breakpoint
ALTER TABLE "scans" ADD COLUMN IF NOT EXISTS "user_id" integer REFERENCES "users"("id") ON DELETE CASCADE;
--> statement-breakpoint
UPDATE "scans" AS s SET "user_id" = p."user_id" FROM "projects" AS p WHERE s."project_id" = p."id" AND s."user_id" IS NULL;
--> statement-breakpoint
ALTER TABLE "scans" ALTER COLUMN "user_id" SET NOT NULL;
--> statement-breakpoint
ALTER TABLE "scans" ADD COLUMN IF NOT EXISTS "endpoints_scanned" integer NOT NULL DEFAULT 0;
--> statement-breakpoint
ALTER TABLE "scans" ADD COLUMN IF NOT EXISTS "created_at" timestamp NOT NULL DEFAULT now();
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS "sessions" (
	"id" serial PRIMARY KEY,
	"user_id" integer NOT NULL REFERENCES "users"("id") ON DELETE CASCADE,
	"token_hash" text NOT NULL UNIQUE,
	"expires_at" timestamp NOT NULL,
	"revoked_at" timestamp,
	"created_at" timestamp NOT NULL DEFAULT now()
);
