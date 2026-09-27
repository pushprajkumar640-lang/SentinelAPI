import { db } from './index';
import { sql } from 'drizzle-orm';
import { createHash, randomUUID } from 'crypto';

export interface SyncUserParams {
  uid: string;
  email: string;
  displayName?: string | null;
  photoUrl?: string | null;
}

function mapUser(row: any) {
  return {
    id: String(row.id),
    uid: String(row.id),
    email: String(row.email),
    passwordHash: row.password_hash ?? null,
    displayName: row.name ?? null,
    photoUrl: null,
    role: row.role ?? 'security_analyst',
    createdAt: row.created_at,
  };
}

export async function getUserByEmail(email: string) {
  const result = await db.execute(sql`
    SELECT id, email, password_hash, name, role, created_at
    FROM public.users
    WHERE LOWER(email) = LOWER(${email})
    LIMIT 1
  `);

  const row = result.rows?.[0];
  return row ? mapUser(row) : null;
}

export async function getUserByUid(uid: string) {
  const result = await db.execute(sql`
    SELECT id, email, password_hash, name, role, created_at
    FROM public.users
    WHERE id = ${uid}
    LIMIT 1
  `);

  const row = result.rows?.[0];
  return row ? mapUser(row) : null;
}

export async function createLocalUser(params: {
  email: string;
  displayName: string;
  passwordHash: string;
}) {
  const id = `user_${Date.now()}_${randomUUID().slice(0, 8)}`;

  const result = await db.execute(sql`
    INSERT INTO public.users
      (id, email, password_hash, name, role, created_at, updated_at)
    VALUES
      (
        ${id},
        ${params.email.toLowerCase()},
        ${params.passwordHash},
        ${params.displayName},
        'security_analyst',
        NOW(),
        NOW()
      )
    RETURNING id, email, password_hash, name, role, created_at
  `);

  return mapUser(result.rows[0]);
}

function hashToken(token: string) {
  return createHash('sha256').update(token).digest('hex');
}

export async function createSession(
  userId: string | number,
  token: string,
  expiresAt: Date
) {
  const sessionId = `session_${Date.now()}_${randomUUID().slice(0, 8)}`;

  await db.execute(sql`
    INSERT INTO public.sessions
      (id, user_id, token, expires_at, created_at)
    VALUES
      (
        ${sessionId},
        ${String(userId)},
        ${token},
        ${expiresAt},
        NOW()
      )
  `);
}

export async function isSessionActive(token: string) {
  const result = await db.execute(sql`
    SELECT id, expires_at
    FROM public.sessions
    WHERE token = ${token}
      AND expires_at > NOW()
    LIMIT 1
  `);

  return Boolean(result.rows?.length);
}

export async function revokeSession(token: string) {
  await db.execute(sql`
    DELETE FROM public.sessions
    WHERE token = ${token}
  `);
}

export async function getOrCreateUser(params: SyncUserParams) {
  const existing = await getUserByEmail(params.email);

  if (existing) {
    return existing;
  }

  return createLocalUser({
    email: params.email,
    displayName: params.displayName || params.email.split('@')[0],
    passwordHash: '',
  });
}