import { Request, Response, NextFunction } from 'express';
import { getOrCreateUser, isSessionActive } from '../db/users';
import jwt from 'jsonwebtoken';

export interface AuthUserRecord {
  id: number;
  uid: string;
  email: string;
  displayName: string | null;
  photoUrl: string | null;
}

export interface AuthRequest extends Request {
  user?: { uid: string; email?: string; name?: string };
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

  const token = authHeader.slice('Bearer '.length);
  try {
    if (!process.env.JWT_SECRET) return res.status(503).json({ error: 'JWT_SECRET is not configured' });
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET) as { uid: string; email?: string; name?: string };
    if (!(await isSessionActive(token))) {
      return res.status(401).json({ error: 'Unauthorized: Session expired or revoked' });
    }
    req.user = decodedToken;

    // Synchronize to PostgreSQL users table
    const dbUser = await getOrCreateUser({
      uid: decodedToken.uid,
      email: decodedToken.email || `${decodedToken.uid}@sentinelapi.local`,
      displayName: decodedToken.name || null,
      photoUrl: null
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
    const token = authHeader.slice('Bearer '.length);
    try {
      if (!process.env.JWT_SECRET) return next();
      const decodedToken = jwt.verify(token, process.env.JWT_SECRET) as { uid: string; email?: string; name?: string };
      if (!(await isSessionActive(token))) return next();
      req.user = decodedToken;
      const dbUser = await getOrCreateUser({
        uid: decodedToken.uid,
        email: decodedToken.email || `${decodedToken.uid}@sentinelapi.local`,
        displayName: decodedToken.name || null,
        photoUrl: null
      });
      req.dbUser = dbUser;
    } catch {
      // Ignore token verification errors for optional routes
    }
  }
  next();
};
