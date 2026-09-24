import { db } from './index';
import { users } from './schema';
import { eq } from 'drizzle-orm';

export interface SyncUserParams {
  uid: string;
  email: string;
  displayName?: string | null;
  photoUrl?: string | null;
}

export async function getOrCreateUser(params: SyncUserParams) {
  try {
    const result = await db
      .insert(users)
      .values({
        uid: params.uid,
        email: params.email,
        displayName: params.displayName || null,
        photoUrl: params.photoUrl || null
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
