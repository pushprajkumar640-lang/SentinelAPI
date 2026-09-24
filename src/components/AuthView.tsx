import React, { useState } from 'react';
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  LockKeyhole,
  Shield,
  UserPlus
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const AuthView: React.FC = () => {
  const { signIn, signUp } = useAuth();
  const [mode, setMode] = useState<'signin' | 'signup'>('signin');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === 'signup') await signUp(name, email, password);
      else await signIn(email, password);
    } catch (err: any) {
      setError(err.message || 'Authentication failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="auth-shell cyber-grid">
      <div className="auth-shell__wash" />
      <div className="auth-layout">
        <section className="auth-hero">
          <div className="brand-lockup">
            <div className="brand-mark"><Shield className="h-5 w-5" /></div>
            <span>SENTINEL<span className="text-emerald-400">API</span></span>
          </div>

          <div className="auth-hero__copy">
            <div className="eyebrow"><span className="status-dot" /> Authorized API defense platform</div>
            <h1>See the breach path<br /><span>before it becomes real.</span></h1>
            <p>Map your API attack surface. Validate access controls. Ship with evidence.</p>
          </div>

          <div className="auth-signal-grid">
            <div className="signal-card">
              <Activity className="h-4 w-4 text-cyan-300" />
              <div><strong>Live posture</strong><span>Continuous signal</span></div>
            </div>
            <div className="signal-card">
              <LockKeyhole className="h-4 w-4 text-emerald-300" />
              <div><strong>Safe probes</strong><span>Sandbox scoped</span></div>
            </div>
          </div>

          <div className="auth-hero__footer">
            <span><CheckCircle2 className="h-3.5 w-3.5" /> OWASP API coverage</span>
            <span><CheckCircle2 className="h-3.5 w-3.5" /> PostgreSQL persistence</span>
          </div>
        </section>

        <section className="auth-card glass-panel">
          <div className="auth-card__topline">
            <span>{mode === 'signup' ? 'Create workspace' : 'Secure sign in'}</span>
            <span className="auth-card__code">SNTL / 01</span>
          </div>
          <div className="auth-card__heading">
            <h2>{mode === 'signup' ? 'Start with a clean signal.' : 'Welcome back, analyst.'}</h2>
            <p>{mode === 'signup' ? 'Create an account for your private security workspace.' : 'Resume your authorized API security work.'}</p>
          </div>

          <div className="auth-tabs" role="tablist" aria-label="Authentication mode">
            <button type="button" className={mode === 'signin' ? 'is-active' : ''} onClick={() => { setMode('signin'); setError(null); }}>Sign in</button>
            <button type="button" className={mode === 'signup' ? 'is-active' : ''} onClick={() => { setMode('signup'); setError(null); }}>Create account</button>
          </div>

          {error && <div className="auth-error" role="alert">{error}</div>}

          <form onSubmit={submit} className="auth-form">
            {mode === 'signup' && (
              <label className="field-label">Full name<input required value={name} onChange={(e) => setName(e.target.value)} placeholder="Your name" autoComplete="name" /></label>
            )}
            <label className="field-label">Work email<input required type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" autoComplete="email" /></label>
            <label className="field-label">Password<div className="password-field"><input required minLength={8} type={showPassword ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} placeholder="8+ characters" autoComplete={mode === 'signup' ? 'new-password' : 'current-password'} /><button type="button" onClick={() => setShowPassword((value) => !value)} aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button></div></label>
            <button className="auth-submit" disabled={busy} type="submit">
              {mode === 'signup' ? <UserPlus className="h-4 w-4" /> : <KeyRound className="h-4 w-4" />}
              <span>{busy ? 'Checking secure channel...' : mode === 'signup' ? 'Create secure account' : 'Enter workspace'}</span>
              {!busy && <ArrowRight className="ml-auto h-4 w-4" />}
            </button>
          </form>

          <p className="auth-card__note">By continuing, you confirm that all scan targets are authorized test environments.</p>
        </section>
      </div>
    </main>
  );
};