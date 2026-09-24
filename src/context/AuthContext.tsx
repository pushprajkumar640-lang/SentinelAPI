import React, { createContext, useContext, useEffect, useState } from 'react';
import { apiJson } from '../lib/api';

export interface AuthUser {
  id: number;
  uid: string;
  email: string;
  displayName: string | null;
  photoURL?: string | null;
}

interface AuthContextType {
  user: AuthUser | null;
  dbUser: AuthUser | null;
  loading: boolean;
  signInWithGoogle: () => Promise<void>;
  signIn: (email: string, password: string) => Promise<void>;
  signUp: (name: string, email: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
  getToken: () => Promise<string | null>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  dbUser: null,
  loading: true,
  signInWithGoogle: async () => {},
  signIn: async () => {},
  signUp: async () => {},
  signOut: async () => {},
  getToken: async () => null
});

function setSession(data: { token: string; user: AuthUser }, setUser: (user: AuthUser) => void, setDbUser: (user: AuthUser) => void) {
  localStorage.setItem('sentinelapi_token', data.token);
  setUser(data.user);
  setDbUser(data.user);
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [dbUser, setDbUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!localStorage.getItem('sentinelapi_token')) {
      setLoading(false);
      return;
    }
    apiJson<{ user: AuthUser }>('/api/auth/me')
      .then((data) => {
        setUser(data.user);
        setDbUser(data.user);
      })
      .catch(() => localStorage.removeItem('sentinelapi_token'))
      .finally(() => setLoading(false));
  }, []);

  const signIn = async (email: string, password: string) => {
    const data = await apiJson<{ token: string; user: AuthUser }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
    setSession(data, setUser, setDbUser);
  };

  const signUp = async (name: string, email: string, password: string) => {
    const data = await apiJson<{ token: string; user: AuthUser }>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ name, email, password })
    });
    setSession(data, setUser, setDbUser);
  };

  const signOut = async () => {
    await apiJson('/api/auth/logout', { method: 'POST' }).catch(() => {});
    localStorage.removeItem('sentinelapi_token');
    setUser(null);
    setDbUser(null);
  };

  return (
    <AuthContext.Provider value={{
      user,
      dbUser,
      loading,
      signInWithGoogle: async () => {
        throw new Error('Use email and password sign-in. Google OAuth is not configured.');
      },
      signIn,
      signUp,
      signOut,
      getToken: async () => localStorage.getItem('sentinelapi_token')
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);