import { db } from './index';
import { sessions, users } from './schema';
import { eq } from 'drizzle-orm';
import { createHash, randomUUID } from 'crypto';

export interface SyncUserParams {
  uid: string;
  email: string;
  displayName?: string | null;
  photoUrl?: string | null;
}

export async function getUserByEmail(email: string) {
  const result = await db.select().from(users).where(eq(users.email, email.toLowerCase())).limit(1);
  return result[0] || null;
}

export async function getUserByUid(uid: string) {
  const result = await db.select().from(users).where(eq(users.uid, uid)).limit(1);
  return result[0] || null;
}

export async function createLocalUser(params: { email: string; displayName: string; passwordHash: string }) {
  const result = await db.insert(users).values({
    uid: `local_${randomUUID()}`,
    email: params.email.toLowerCase(),
    displayName: params.displayName,
    passwordHash: params.passwordHash
  }).returning();
  return result[0];
}

function hashToken(token: string) {
  return createHash('sha256').update(token).digest('hex');
}

export async function createSession(userId: number, token: string, expiresAt: Date) {
  await db.insert(sessions).values({ userId, tokenHash: hashToken(token), expiresAt });
}

export async function isSessionActive(token: string) {
  const session = await db.select().from(sessions).where(eq(sessions.tokenHash, hashToken(token))).limit(1);
  return Boolean(session[0] && !session[0].revokedAt && session[0].expiresAt > new Date());
}

export async function revokeSession(token: string) {
  await db.update(sessions)
    .set({ revokedAt: new Date() })
    .where(eq(sessions.tokenHash, hashToken(token)));
}

export async function getOrCreateUser(params: SyncUserParams) {
  try {
    const result = await db
      .insert(users)
      .values({
        uid: params.uid,
        email: params.email,
        displayName: params.displayName || null,
        photoUrl: params.photoUrl || null,
        passwordHash: null
      })
      .onConflictDoUpdate({
        target: users.uid,
        set: {
          email: params.email,
          displayName: params.displayName || null,
          photoUrl: params.photoUrl || null
        }
      })
      .returning();

    return result[0];
  } catch (error) {
    console.error('Error syncing user to PostgreSQL:', error);
    // Fallback: select user if insert failed due to existing record
    const existing = await db.select().from(users).where(eq(users.uid, params.uid)).limit(1);
    if (existing.length > 0) {
      return existing[0];
    }
    throw new Error('Failed to synchronize user profile', { cause: error });
  }
}
