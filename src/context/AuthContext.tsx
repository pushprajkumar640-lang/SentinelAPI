import React, { createContext, useContext, useEffect, useState } from 'react';
import {
  User,
  signInWithPopup,
  signInAnonymously,
  signOut as fbSignOut,
  onAuthStateChanged
} from 'firebase/auth';
import { auth, googleAuthProvider } from '../lib/firebase';
import { syncUserProfileToFirestore } from '../lib/firestoreService';

export interface DbUserProfile {
  id: number;
  uid: string;
  email: string;
  displayName: string | null;
  photoUrl: string | null;
}

interface AuthContextType {
  user: User | null;
  dbUser: DbUserProfile | null;
  loading: boolean;
  signInWithGoogle: () => Promise<void>;
  signInDemoAuditor: () => Promise<void>;
  signOut: () => Promise<void>;
  getToken: () => Promise<string | null>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  dbUser: null,
  loading: true,
  signInWithGoogle: async () => {},
  signInDemoAuditor: async () => {},
  signOut: async () => {},
  getToken: async () => null
});

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [dbUser, setDbUser] = useState<DbUserProfile | null>(null);
  const [loading, setLoading] = useState(true);

  const syncBackendUser = async (token?: string) => {
    try {
      const headers: Record<string, string> = {};
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      const res = await fetch('/api/auth/me', { headers });
      if (res.ok) {
        const data = await res.json();
        setDbUser(data.user);
      }
    } catch (err) {
      console.error('Error syncing auth profile with backend:', err);
    }
  };

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
      setUser(currentUser);
      if (currentUser) {
        // Sync to Firestore 'users' collection
        await syncUserProfileToFirestore({
          uid: currentUser.uid,
          email: currentUser.email,
          displayName: currentUser.displayName,
          photoURL: currentUser.photoURL
        });

        const token = await currentUser.getIdToken();
        await syncBackendUser(token);
      } else {
        await syncBackendUser();
      }
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);

  const signInWithGoogle = async () => {
    try {
      const result = await signInWithPopup(auth, googleAuthProvider);
      setUser(result.user);
      await syncUserProfileToFirestore({
        uid: result.user.uid,
        email: result.user.email,
        displayName: result.user.displayName,
        photoURL: result.user.photoURL
      });
      const token = await result.user.getIdToken();
      await syncBackendUser(token);
    } catch (err: any) {
      console.warn('Google popup sign-in note/error:', err);
      // If popup was blocked or failed, fallback to anonymous sign in so the user is never locked out
      if (err.code === 'auth/popup-blocked' || err.code === 'auth/cancelled-popup-request') {
        const anon = await signInAnonymously(auth);
        setUser(anon.user);
      } else {
        throw err;
      }
    }
  };

  const signInDemoAuditor = async () => {
    try {
      const anon = await signInAnonymously(auth);
      setUser(anon.user);
      await syncUserProfileToFirestore({
        uid: anon.user.uid,
        email: 'auditor@sentinelapi.internal',
        displayName: 'Security Auditor (Authorized Demo)',
        photoURL: null
      });
    } catch (err) {
      console.error('Demo sign-in error:', err);
      throw err;
    }
  };

  const signOut = async () => {
    try {
      await fbSignOut(auth);
      setUser(null);
      await syncBackendUser();
    } catch (err) {
      console.error('Sign-out error:', err);
    }
  };

  const getToken = async (): Promise<string | null> => {
    if (!user) return null;
    try {
      return await user.getIdToken();
    } catch {
      return null;
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        dbUser,
        loading,
        signInWithGoogle,
        signInDemoAuditor,
        signOut,
        getToken
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
