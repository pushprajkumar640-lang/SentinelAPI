import { Request, Response, NextFunction } from 'express';
import { adminAuth } from '../lib/firebase-admin';
import { getOrCreateUser } from '../db/users';
import { DecodedIdToken } from 'firebase-admin/auth';

export interface AuthUserRecord {
  id: number;
  uid: string;
  email: string;
  displayName: string | null;
  photoUrl: string | null;
}

export interface AuthRequest extends Request {
  user?: DecodedIdToken;
  dbUser?: AuthUserRecord;
}

export const requireAuth = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid token' });
  }

  const token = authHeader.split('Bearer ')[1];
  try {
    const decodedToken = await adminAuth.verifyIdToken(token);
    req.user = decodedToken;

    // Synchronize to PostgreSQL users table
    const dbUser = await getOrCreateUser({
      uid: decodedToken.uid,
      email: decodedToken.email || `${decodedToken.uid}@sentinelapi.local`,
      displayName: decodedToken.name || null,
      photoUrl: decodedToken.picture || null
    });

    req.dbUser = dbUser;
    next();
  } catch (error) {
    console.error('Error verifying Firebase ID token:', error);
    return res.status(401).json({ error: 'Unauthorized: Invalid authentication token' });
  }
};

// Optional auth middleware: populates req.dbUser if a token is present
export const optionalAuth = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split('Bearer ')[1];
    try {
      const decodedToken = await adminAuth.verifyIdToken(token);
      req.user = decodedToken;
      const dbUser = await getOrCreateUser({
        uid: decodedToken.uid,
        email: decodedToken.email || `${decodedToken.uid}@sentinelapi.local`,
        displayName: decodedToken.name || null,
        photoUrl: decodedToken.picture || null
      });
      req.dbUser = dbUser;
    } catch {
      // Ignore token verification errors for optional routes
    }
  }
  next();
};
